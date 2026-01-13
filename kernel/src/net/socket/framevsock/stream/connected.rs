// SPDX-License-Identifier: MPL-2.0

//! Connected socket state for FrameVsock
//!
//! # Zero-Copy Design
//!
//! - Incoming data packets are stored as RRef<DataPacket> in a queue
//! - No intermediate buffer copies (RingBuffer removed)
//! - The only copy happens at syscall boundary (user-space ↔ kernel-space)
//! - Outgoing data is read directly from user buffer into DataPacket
//!
//! # Flow Control Optimizations
//!
//! - Adaptive credit update threshold based on packet sizes
//! - Proactive credit updates when sender credit is low
//! - Credit piggybacking on data packets to reduce control overhead

use alloc::{collections::VecDeque, vec::Vec};
use core::hash::{Hash, Hasher};

use aster_framevisor::vsock as framevisor_vsock;
use aster_framevisor_exchangeable::RRef;
use aster_framevsock::{
    ConnectionId, ControlPacket, DataPacket, SHUTDOWN_FLAG_BOTH, create_credit_request,
    create_credit_update, create_data_packet_with_credit, create_rst, create_shutdown,
    flow_control::{
        DEFAULT_BUF_ALLOC, MAX_PENDING_PACKETS, URGENT_CREDIT_UPDATE_THRESHOLD,
        adaptive_threshold, low_credit_watermark,
    },
};
use log::debug;

use super::connecting::Connecting;
use crate::{
    events::IoEvents,
    net::socket::{
        framevsock::addr::FrameVsockAddr,
        util::{SendRecvFlags, SockShutdownCmd},
    },
    prelude::*,
    process::signal::{PollHandle, Pollee},
    util::{MultiRead, MultiWrite},
};

/// Partial read state - tracks remaining data from a partially consumed packet
struct PartialRead {
    /// The packet being partially read
    packet: RRef<DataPacket>,
    /// Offset into the packet's data
    offset: usize,
}

/// RX state - protected by rx_state lock
struct RxState {
    /// Pending data packets (zero-copy: stored as RRef)
    pending_packets: VecDeque<RRef<DataPacket>>,
    /// Partial read state (for when user buffer is smaller than packet)
    partial_read: Option<PartialRead>,
    /// Last fwd_cnt when we sent credit update
    last_credit_update_fwd_cnt: u32,
    /// Running average of received packet sizes (for adaptive threshold)
    avg_rx_packet_size: u32,
    /// Number of packets received (for averaging)
    rx_packet_count: u32,
    /// Current adaptive credit update threshold
    credit_update_threshold: u32,
}

/// TX state - protected by tx_state lock
struct TxState {
    /// Total bytes we've sent
    tx_cnt: u32,
    /// Whether we have a pending credit request (to avoid busy-loop)
    credit_request_pending: bool,
}

/// Peer credit info - updated atomically without lock
struct PeerCredit {
    /// Peer's buffer allocation
    peer_buf_alloc: core::sync::atomic::AtomicU32,
    /// Peer's forward count
    peer_fwd_cnt: core::sync::atomic::AtomicU32,
}

pub struct Connected {
    /// RX state - separate lock for receive path
    rx_state: SpinLock<RxState>,
    /// TX state - separate lock for send path
    tx_state: SpinLock<TxState>,
    /// Peer credit info - lock-free atomic access
    peer_credit: PeerCredit,
    /// Connection ID (immutable after creation)
    id: ConnectionId,
    /// Our buffer allocation - lock-free atomic access
    buf_alloc: core::sync::atomic::AtomicU32,
    /// Our forward count (已消费的字节数) - lock-free atomic access
    fwd_cnt: core::sync::atomic::AtomicU32,
    /// Peer requested shutdown - lock-free atomic access
    peer_requested_shutdown: core::sync::atomic::AtomicBool,
    /// Local shutdown - lock-free atomic access
    local_shutdown: core::sync::atomic::AtomicBool,
    /// Cached vCPU ID for this connection (computed once at creation)
    cached_vcpu_id: usize,
    pollee: Pollee,
}

use core::sync::atomic::Ordering;

impl Connected {
    pub fn new(peer_addr: FrameVsockAddr, local_addr: FrameVsockAddr) -> Self {
        let id = ConnectionId::from_addrs(local_addr, peer_addr);
        let cached_vcpu_id = Self::compute_vcpu_id(&id);
        Self {
            rx_state: SpinLock::new(RxState {
                pending_packets: VecDeque::with_capacity(MAX_PENDING_PACKETS),
                partial_read: None,
                last_credit_update_fwd_cnt: 0,
                avg_rx_packet_size: 1024,
                rx_packet_count: 0,
                credit_update_threshold: adaptive_threshold(1024),
            }),
            tx_state: SpinLock::new(TxState {
                tx_cnt: 0,
                credit_request_pending: false,
            }),
            peer_credit: PeerCredit {
                peer_buf_alloc: core::sync::atomic::AtomicU32::new(DEFAULT_BUF_ALLOC),
                peer_fwd_cnt: core::sync::atomic::AtomicU32::new(0),
            },
            id,
            buf_alloc: core::sync::atomic::AtomicU32::new(DEFAULT_BUF_ALLOC),
            fwd_cnt: core::sync::atomic::AtomicU32::new(0),
            peer_requested_shutdown: core::sync::atomic::AtomicBool::new(false),
            local_shutdown: core::sync::atomic::AtomicBool::new(false),
            cached_vcpu_id,
            pollee: Pollee::new(),
        }
    }

    /// Create with initial peer credit info (from connection request)
    pub fn new_with_credit(
        peer_addr: FrameVsockAddr,
        local_addr: FrameVsockAddr,
        peer_buf_alloc: u32,
        peer_fwd_cnt: u32,
    ) -> Self {
        let effective_peer_buf_alloc = if peer_buf_alloc == 0 {
            DEFAULT_BUF_ALLOC
        } else {
            peer_buf_alloc
        };

        let id = ConnectionId::from_addrs(local_addr, peer_addr);
        let cached_vcpu_id = Self::compute_vcpu_id(&id);

        Self {
            rx_state: SpinLock::new(RxState {
                pending_packets: VecDeque::with_capacity(MAX_PENDING_PACKETS),
                partial_read: None,
                last_credit_update_fwd_cnt: 0,
                avg_rx_packet_size: 1024,
                rx_packet_count: 0,
                credit_update_threshold: adaptive_threshold(1024),
            }),
            tx_state: SpinLock::new(TxState {
                tx_cnt: 0,
                credit_request_pending: false,
            }),
            peer_credit: PeerCredit {
                peer_buf_alloc: core::sync::atomic::AtomicU32::new(effective_peer_buf_alloc),
                peer_fwd_cnt: core::sync::atomic::AtomicU32::new(peer_fwd_cnt),
            },
            id,
            buf_alloc: core::sync::atomic::AtomicU32::new(DEFAULT_BUF_ALLOC),
            fwd_cnt: core::sync::atomic::AtomicU32::new(0),
            peer_requested_shutdown: core::sync::atomic::AtomicBool::new(false),
            local_shutdown: core::sync::atomic::AtomicBool::new(false),
            cached_vcpu_id,
            pollee: Pollee::new(),
        }
    }

    pub fn from_connecting(connecting: Arc<Connecting>) -> Self {
        Self::new(connecting.peer_addr(), connecting.local_addr())
    }

    pub fn peer_addr(&self) -> aster_framevsock::FrameVsockAddr {
        self.id.peer_addr
    }

    pub fn local_addr(&self) -> aster_framevsock::FrameVsockAddr {
        self.id.local_addr
    }

    pub fn id(&self) -> ConnectionId {
        self.id
    }

    /// Get our buffer allocation (for credit info in packets)
    pub fn buf_alloc(&self) -> u32 {
        self.buf_alloc.load(Ordering::Relaxed)
    }

    /// Get our forward count (for credit info in packets)
    pub fn fwd_cnt(&self) -> u32 {
        self.fwd_cnt.load(Ordering::Relaxed)
    }

    /// Calculate available credit to send to peer (lock-free)
    fn available_credit(&self, tx_cnt: u32) -> u32 {
        let peer_fwd_cnt = self.peer_credit.peer_fwd_cnt.load(Ordering::Relaxed);
        let peer_buf_alloc = self.peer_credit.peer_buf_alloc.load(Ordering::Relaxed);
        let outstanding = tx_cnt.wrapping_sub(peer_fwd_cnt);
        peer_buf_alloc.saturating_sub(outstanding)
    }

    /// Receive data to a MultiWrite (user buffer)
    ///
    /// Zero-copy path:
    /// 1. Get packet from pending queue (RRef<DataPacket>)
    /// 2. Copy data directly from packet to user buffer (ONE copy)
    pub fn try_recv(&self, writer: &mut dyn MultiWrite) -> Result<usize> {
        let mut rx = self.rx_state.disable_irq().lock();

        // First check if there's a partial read in progress
        if rx.partial_read.is_some() {
            let pr = rx.partial_read.as_ref().unwrap();
            let remaining = &pr.packet.data[pr.offset..];
            let mut vm_reader = ostd::mm::VmReader::from(remaining);
            let bytes_written = writer.write(&mut vm_reader)?;

            // Now update the partial read state
            let pr = rx.partial_read.as_mut().unwrap();
            pr.offset += bytes_written;
            let fully_consumed = pr.offset >= pr.packet.data.len();

            // Update fwd_cnt atomically (lock-free)
            self.fwd_cnt.fetch_add(bytes_written as u32, Ordering::Relaxed);

            // If packet fully consumed, clear partial read
            if fully_consumed {
                rx.partial_read = None;
            }

            // Check if we should send credit update
            if self.should_send_credit_update_rx(&rx) {
                let buf_alloc = self.buf_alloc.load(Ordering::Relaxed);
                self.send_credit_update_internal(&mut rx, buf_alloc);
            }

            drop(rx);
            self.pollee.invalidate();
            return Ok(bytes_written);
        }

        // Try to get a new packet from the queue
        if let Some(packet) = rx.pending_packets.pop_front() {
            let data_len = packet.data.len();
            let mut vm_reader = ostd::mm::VmReader::from(packet.data.as_slice());
            let bytes_written = writer.write(&mut vm_reader)?;

            // Update fwd_cnt atomically (lock-free)
            self.fwd_cnt.fetch_add(bytes_written as u32, Ordering::Relaxed);

            // If packet not fully consumed, save for partial read
            if bytes_written < data_len {
                rx.partial_read = Some(PartialRead {
                    packet,
                    offset: bytes_written,
                });
            }

            // Check if we should send credit update
            if self.should_send_credit_update_rx(&rx) {
                let buf_alloc = self.buf_alloc.load(Ordering::Relaxed);
                self.send_credit_update_internal(&mut rx, buf_alloc);
            }

            drop(rx);
            self.pollee.invalidate();
            return Ok(bytes_written);
        }

        // No data available
        let is_peer_shutdown = self.peer_requested_shutdown.load(Ordering::Acquire);
        drop(rx);
        self.pollee.invalidate();

        if is_peer_shutdown {
            return_errno_with_message!(Errno::ECONNRESET, "the connection is reset");
        }
        return_errno_with_message!(Errno::EAGAIN, "the receive buffer is empty");
    }

    /// Check if we should send a credit update (called with rx lock held)
    fn should_send_credit_update_rx(&self, rx: &RxState) -> bool {
        let fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed);
        let consumed_since_last = fwd_cnt.wrapping_sub(rx.last_credit_update_fwd_cnt);
        consumed_since_last >= rx.credit_update_threshold
    }

    /// Send credit update (called with rx lock held)
    fn send_credit_update_internal(&self, rx: &mut RxState, buf_alloc: u32) {
        let fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed);
        rx.last_credit_update_fwd_cnt = fwd_cnt;
        let packet = create_credit_update(
            self.local_addr().cid,
            self.local_addr().port,
            self.peer_addr().cid,
            self.peer_addr().port,
            buf_alloc,
            fwd_cnt,
        );
        let vcpu_id = self.select_vcpu();
        let _ = framevisor_vsock::deliver_control_packet(vcpu_id, packet);
    }

    /// Send data from a MultiRead (user buffer)
    ///
    /// Zero-copy path:
    /// 1. Read from user buffer into Vec<u8> (ONE copy)
    /// 2. Create DataPacket with the Vec
    /// 3. Send via FrameVisor (zero-copy RRef transfer)
    ///
    /// Optimized lock pattern:
    /// - Lock held only for credit check and reservation (fast)
    /// - Data read from user buffer happens outside lock (potentially slow)
    pub fn try_send(&self, reader: &mut dyn MultiRead, _flags: SendRecvFlags) -> Result<usize> {
        let buf_len = reader.sum_lens();
        if buf_len == 0 {
            return Ok(0);
        }

        // Phase 1: Check credit and reserve (short lock hold)
        let to_send = {
            let mut tx = self.tx_state.disable_irq().lock();

            // Check available credit (lock-free atomic read)
            let available_credit = self.available_credit(tx.tx_cnt) as usize;
            if available_credit == 0 {
                let should_send_request = !tx.credit_request_pending;
                if should_send_request {
                    tx.credit_request_pending = true;
                }
                drop(tx);

                if should_send_request {
                    self.send_credit_request();
                }
                return_errno_with_message!(Errno::EAGAIN, "no credit available");
            }

            // Reserve credit by updating tx_cnt now
            let to_send = buf_len.min(available_credit);
            tx.tx_cnt = tx.tx_cnt.wrapping_add(to_send as u32);
            to_send
            // Lock released here
        };

        // Phase 2: Read data from user buffer (outside lock - potentially slow)
        let mut data = Vec::with_capacity(to_send);
        data.resize(to_send, 0u8);

        let mut vm_writer = ostd::mm::VmWriter::from(data.as_mut_slice());
        let bytes_read = match reader.read(&mut vm_writer) {
            Ok(n) => n,
            Err(e) => {
                // Unreserve credit on failure
                let mut tx = self.tx_state.disable_irq().lock();
                tx.tx_cnt = tx.tx_cnt.wrapping_sub(to_send as u32);
                return Err(e);
            }
        };

        // Adjust reservation if we read less than expected
        if bytes_read < to_send {
            let mut tx = self.tx_state.disable_irq().lock();
            tx.tx_cnt = tx.tx_cnt.wrapping_sub((to_send - bytes_read) as u32);
        }

        data.truncate(bytes_read);

        // Phase 3: Create and send packet (outside lock)
        let buf_alloc = self.buf_alloc.load(Ordering::Relaxed);
        let fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed);

        let packet = create_data_packet_with_credit(
            self.local_addr().cid,
            self.local_addr().port,
            self.peer_addr().cid,
            self.peer_addr().port,
            data,
            buf_alloc,
            fwd_cnt,
        );

        // Select vCPU and deliver
        let vcpu_id = self.select_vcpu();
        if framevisor_vsock::deliver_data_packet(vcpu_id, packet).is_err() {
            return_errno_with_message!(Errno::ECONNRESET, "failed to send data to guest");
        }

        Ok(bytes_read)
    }

    pub fn should_close(&self) -> bool {
        let rx = self.rx_state.disable_irq().lock();
        self.peer_requested_shutdown.load(Ordering::Acquire)
            && rx.pending_packets.is_empty()
            && rx.partial_read.is_none()
    }

    pub fn is_closed(&self) -> bool {
        self.local_shutdown.load(Ordering::Acquire)
    }

    pub fn shutdown(&self, cmd: SockShutdownCmd) -> Result<()> {
        // Check if already shutdown (lock-free)
        if self.local_shutdown.load(Ordering::Acquire) {
            return Ok(());
        }

        let shutdown_flags = match cmd {
            SockShutdownCmd::SHUT_RD => aster_framevsock::SHUTDOWN_FLAG_RECV,
            SockShutdownCmd::SHUT_WR => aster_framevsock::SHUTDOWN_FLAG_SEND,
            SockShutdownCmd::SHUT_RDWR => SHUTDOWN_FLAG_BOTH,
        };

        let packet = create_shutdown(
            self.local_addr().cid,
            self.local_addr().port,
            self.peer_addr().cid,
            self.peer_addr().port,
            shutdown_flags,
        );

        let vcpu_id = self.select_vcpu();
        let _ = framevisor_vsock::deliver_control_packet(vcpu_id, packet);

        if self.should_close() || cmd == SockShutdownCmd::SHUT_RDWR {
            self.local_shutdown.store(true, Ordering::Release);
        }

        Ok(())
    }

    /// Send RST packet to peer and close connection
    pub fn reset(&self) -> Result<()> {
        // Check if already shutdown (lock-free)
        if self.local_shutdown.load(Ordering::Acquire) {
            return Ok(());
        }

        let packet = create_rst(
            self.local_addr().cid,
            self.local_addr().port,
            self.peer_addr().cid,
            self.peer_addr().port,
        );

        let vcpu_id = self.select_vcpu();
        let _ = framevisor_vsock::deliver_control_packet(vcpu_id, packet);

        self.local_shutdown.store(true, Ordering::Release);
        Ok(())
    }

    /// Handle incoming data packet (zero-copy: packet ownership transferred)
    pub fn on_data_packet_received(&self, packet: RRef<DataPacket>) -> Result<()> {
        // Update peer credit info atomically (lock-free)
        self.peer_credit.peer_buf_alloc.store(packet.header.buf_alloc, Ordering::Relaxed);
        self.peer_credit.peer_fwd_cnt.store(packet.header.fwd_cnt, Ordering::Relaxed);

        // Only lock RX state for packet queue operations
        let mut rx = self.rx_state.disable_irq().lock();
        let packet_size = packet.data.len();

        // Update packet size statistics for adaptive threshold
        rx.rx_packet_count = rx.rx_packet_count.saturating_add(1);
        rx.avg_rx_packet_size = (rx.avg_rx_packet_size * 7 + packet_size as u32) / 8;
        if rx.rx_packet_count & 0xF == 0 {
            rx.credit_update_threshold = adaptive_threshold(rx.avg_rx_packet_size);
        }

        // Store packet in pending queue (zero-copy)
        if rx.pending_packets.len() < MAX_PENDING_PACKETS {
            rx.pending_packets.push_back(packet);
        } else {
            debug!(
                "[FrameVsock] Pending packet queue full, dropping packet (len={})",
                packet_size
            );
        }

        drop(rx);

        // Notify both IN and OUT events
        self.pollee.notify(IoEvents::IN | IoEvents::OUT);

        Ok(())
    }

    /// Handle credit update from peer
    pub fn on_credit_update(&self, buf_alloc: u32, fwd_cnt: u32) {
        // Update peer credit atomically (lock-free)
        self.peer_credit.peer_buf_alloc.store(buf_alloc, Ordering::Relaxed);
        self.peer_credit.peer_fwd_cnt.store(fwd_cnt, Ordering::Relaxed);

        // Clear credit request pending flag
        self.tx_state.disable_irq().lock().credit_request_pending = false;

        self.pollee.notify(IoEvents::OUT);
    }

    /// Send credit update to peer
    pub fn send_credit_update(&self) {
        let mut rx = self.rx_state.disable_irq().lock();
        let buf_alloc = self.buf_alloc.load(Ordering::Relaxed);
        self.send_credit_update_internal(&mut rx, buf_alloc);
    }

    /// Send credit request to peer to get their credit info
    /// This is used when peer_buf_alloc is 0 (possibly due to race condition during connection setup)
    fn send_credit_request(&self) {
        let packet = create_credit_request(
            self.local_addr().cid,
            self.local_addr().port,
            self.peer_addr().cid,
            self.peer_addr().port,
        );
        let vcpu_id = self.select_vcpu();
        let _ = framevisor_vsock::deliver_control_packet(vcpu_id, packet);
    }

    /// Handle shutdown from peer
    pub fn on_shutdown_received(&self) -> Result<()> {
        self.peer_requested_shutdown.store(true, Ordering::Release);
        self.pollee.notify(IoEvents::IN | IoEvents::OUT | IoEvents::HUP);
        Ok(())
    }

    /// Handle reset from peer
    pub fn on_rst_received(&self) -> Result<()> {
        // Update shutdown flags atomically
        self.peer_requested_shutdown.store(true, Ordering::Release);
        self.local_shutdown.store(true, Ordering::Release);

        // Clear pending packets
        {
            let mut rx = self.rx_state.disable_irq().lock();
            rx.pending_packets.clear();
            rx.partial_read = None;
        }
        self.pollee.notify(IoEvents::IN | IoEvents::OUT | IoEvents::ERR | IoEvents::HUP);
        Ok(())
    }

    pub fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(mask, poller, || self.check_io_events())
    }

    fn check_io_events(&self) -> IoEvents {
        let rx = self.rx_state.disable_irq().lock();
        let tx = self.tx_state.disable_irq().lock();
        let mut events = IoEvents::empty();

        // Read shutdown flags atomically (lock-free)
        let local_shutdown = self.local_shutdown.load(Ordering::Acquire);
        let peer_shutdown = self.peer_requested_shutdown.load(Ordering::Acquire);

        // Readable if we have pending packets or partial read
        if !rx.pending_packets.is_empty() || rx.partial_read.is_some() {
            events |= IoEvents::IN;
        }

        // Writable if we can send (check peer credit)
        let available = self.available_credit(tx.tx_cnt);
        if available > 0 && !local_shutdown {
            events |= IoEvents::OUT;
        }

        // HUP if peer shutdown
        if peer_shutdown {
            events |= IoEvents::HUP;
        }

        // Error if connection reset
        if local_shutdown && peer_shutdown {
            events |= IoEvents::ERR;
        }

        events
    }

    /// Select vCPU for this connection (uses cached value)
    #[inline]
    fn select_vcpu(&self) -> usize {
        self.cached_vcpu_id
    }

    /// Compute vCPU ID using consistent hashing (called once at creation)
    fn compute_vcpu_id(id: &ConnectionId) -> usize {
        let mut hasher = SimpleHasher::new();
        id.local_addr.cid.hash(&mut hasher);
        id.local_addr.port.hash(&mut hasher);
        id.peer_addr.cid.hash(&mut hasher);
        id.peer_addr.port.hash(&mut hasher);

        let hash = hasher.finish() as usize;
        let vcpu_count = framevisor_vsock::get_vcpu_count().max(1);
        hash % vcpu_count
    }
}

/// Simple hasher for vCPU selection
struct SimpleHasher {
    state: u64,
}

impl SimpleHasher {
    fn new() -> Self {
        Self { state: 0 }
    }
}

impl Hasher for SimpleHasher {
    fn finish(&self) -> u64 {
        self.state
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.state = self.state.wrapping_mul(31).wrapping_add(*byte as u64);
        }
    }
}
