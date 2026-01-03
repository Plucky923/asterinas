// SPDX-License-Identifier: MPL-2.0

//! Connected socket state for FrameVsock
//!
//! # Zero-Copy Design
//!
//! - Incoming data packets are stored as RRef<DataPacket> in a queue
//! - No intermediate buffer copies (RingBuffer removed)
//! - The only copy happens at syscall boundary (user-space ↔ kernel-space)
//! - Outgoing data is read directly from user buffer into DataPacket

use alloc::{collections::VecDeque, vec::Vec};
use core::hash::{Hash, Hasher};

use aster_framevisor::vsock as framevisor_vsock;
use aster_framevisor_exchangeable::RRef;
use aster_framevsock::{
    ConnectionId, ControlPacket, DataPacket, SHUTDOWN_FLAG_BOTH, create_credit_update,
    create_data_packet_with_credit, create_rst, create_shutdown,
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

/// Maximum pending packets per connection
const MAX_PENDING_PACKETS: usize = 64;

/// Default buffer allocation advertised to peer
const DEFAULT_BUF_ALLOC: u32 = 64 * 1024; // 64KB

/// Credit update threshold - send update when this many bytes consumed
const CREDIT_UPDATE_THRESHOLD: u32 = DEFAULT_BUF_ALLOC / 4;

/// Partial read state - tracks remaining data from a partially consumed packet
struct PartialRead {
    /// The packet being partially read
    packet: RRef<DataPacket>,
    /// Offset into the packet's data
    offset: usize,
}

pub struct Connected {
    connection: SpinLock<Connection>,
    id: ConnectionId,
    pollee: Pollee,
}

impl Connected {
    pub fn new(peer_addr: FrameVsockAddr, local_addr: FrameVsockAddr) -> Self {
        Self {
            connection: SpinLock::new(Connection::new(peer_addr, local_addr)),
            id: ConnectionId::from_addrs(local_addr, peer_addr),
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
        Self {
            connection: SpinLock::new(Connection::new_with_credit(
                peer_addr,
                local_addr,
                peer_buf_alloc,
                peer_fwd_cnt,
            )),
            id: ConnectionId::from_addrs(local_addr, peer_addr),
            pollee: Pollee::new(),
        }
    }

    pub fn from_connecting(connecting: Arc<Connecting>) -> Self {
        Self {
            connection: SpinLock::new(Connection::new(
                connecting.peer_addr(),
                connecting.local_addr(),
            )),
            id: connecting.id(),
            pollee: Pollee::new(),
        }
    }

    pub fn peer_addr(&self) -> FrameVsockAddr {
        self.id.peer_addr
    }

    pub fn local_addr(&self) -> FrameVsockAddr {
        self.id.local_addr
    }

    pub fn id(&self) -> ConnectionId {
        self.id
    }

    /// Receive data to a MultiWrite (user buffer)
    ///
    /// Zero-copy path:
    /// 1. Get packet from pending queue (RRef<DataPacket>)
    /// 2. Copy data directly from packet to user buffer (ONE copy)
    pub fn try_recv(&self, writer: &mut dyn MultiWrite) -> Result<usize> {
        let mut connection = self.connection.disable_irq().lock();

        // First check if there's a partial read in progress
        if connection.partial_read.is_some() {
            // Extract partial read info without keeping a mutable borrow
            let pr = connection.partial_read.as_ref().unwrap();
            let remaining = &pr.packet.data[pr.offset..];
            let mut vm_reader = ostd::mm::VmReader::from(remaining);
            let bytes_written = writer.write(&mut vm_reader)?;

            // Now update the partial read state
            let pr = connection.partial_read.as_mut().unwrap();
            pr.offset += bytes_written;
            let fully_consumed = pr.offset >= pr.packet.data.len();

            connection.done_forwarding(bytes_written);

            // If packet fully consumed, clear partial read
            if fully_consumed {
                connection.partial_read = None;
            }

            // Check if we should send credit update
            if connection.should_send_credit_update() {
                self.send_credit_update_internal(&mut connection);
            }

            drop(connection);
            self.pollee.invalidate();
            return Ok(bytes_written);
        }

        // Try to get a new packet from the queue
        if let Some(packet) = connection.pending_packets.pop_front() {
            let data_len = packet.data.len();
            let mut vm_reader = ostd::mm::VmReader::from(packet.data.as_slice());
            let bytes_written = writer.write(&mut vm_reader)?;

            connection.done_forwarding(bytes_written);

            // If packet not fully consumed, save for partial read
            if bytes_written < data_len {
                connection.partial_read = Some(PartialRead {
                    packet,
                    offset: bytes_written,
                });
            }

            // Check if we should send credit update
            if connection.should_send_credit_update() {
                self.send_credit_update_internal(&mut connection);
            }

            drop(connection);
            self.pollee.invalidate();
            return Ok(bytes_written);
        }

        // No data available
        drop(connection);
        self.pollee.invalidate();

        let connection = self.connection.disable_irq().lock();
        if connection.is_peer_requested_shutdown() {
            return_errno_with_message!(Errno::ECONNRESET, "the connection is reset");
        }
        return_errno_with_message!(Errno::EAGAIN, "the receive buffer is empty");
    }

    /// Send data from a MultiRead (user buffer)
    ///
    /// Zero-copy path:
    /// 1. Read from user buffer into Vec<u8> (ONE copy)
    /// 2. Create DataPacket with the Vec
    /// 3. Send via FrameVisor (zero-copy RRef transfer)
    pub fn try_send(&self, reader: &mut dyn MultiRead, _flags: SendRecvFlags) -> Result<usize> {
        let buf_len = reader.sum_lens();
        if buf_len == 0 {
            return Ok(0);
        }

        let mut connection = self.connection.disable_irq().lock();

        // Check available credit
        let available_credit = connection.available_credit() as usize;
        if available_credit == 0 {
            return_errno_with_message!(Errno::EAGAIN, "no credit available");
        }

        // Limit send size to available credit
        let to_send = buf_len.min(available_credit);

        // Read data from the MultiRead into a Vec (ONE copy - syscall boundary)
        let mut data = Vec::with_capacity(to_send);
        data.resize(to_send, 0u8);

        let mut vm_writer = ostd::mm::VmWriter::from(data.as_mut_slice());
        let bytes_read = reader.read(&mut vm_writer)?;
        data.truncate(bytes_read);

        // Get credit info for packet header
        let buf_alloc = connection.buf_alloc();
        let fwd_cnt = connection.fwd_cnt();
        let local_addr = self.local_addr();
        let peer_addr = self.peer_addr();

        // Update tx count
        connection.record_sent(data.len() as u32);
        drop(connection);

        // Create DataPacket with the data (zero-copy: Vec is moved)
        let packet = create_data_packet_with_credit(
            local_addr.cid,
            local_addr.port,
            peer_addr.cid,
            peer_addr.port,
            data,
            buf_alloc,
            fwd_cnt,
        );

        // Select vCPU and deliver
        let vcpu_id = self.select_vcpu();
        if framevisor_vsock::deliver_data_packet(vcpu_id, packet).is_err() {
            debug!("[FrameVsock] Failed to deliver data packet to Guest");
            return_errno_with_message!(Errno::ECONNRESET, "failed to send data to guest");
        }

        Ok(bytes_read)
    }

    pub fn should_close(&self) -> bool {
        let connection = self.connection.disable_irq().lock();
        connection.is_peer_requested_shutdown()
            && connection.pending_packets.is_empty()
            && connection.partial_read.is_none()
    }

    pub fn is_closed(&self) -> bool {
        let connection = self.connection.disable_irq().lock();
        connection.is_local_shutdown()
    }

    pub fn shutdown(&self, cmd: SockShutdownCmd) -> Result<()> {
        let mut connection = self.connection.disable_irq().lock();

        if connection.is_local_shutdown() {
            return Ok(());
        }

        // Send shutdown packet to peer
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
            connection.set_local_shutdown();
        }

        Ok(())
    }

    /// Send RST packet to peer and close connection
    pub fn reset(&self) -> Result<()> {
        let mut connection = self.connection.disable_irq().lock();

        if connection.is_local_shutdown() {
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

        connection.set_local_shutdown();
        Ok(())
    }

    /// Handle incoming data packet (zero-copy: packet ownership transferred)
    pub fn on_data_packet_received(&self, packet: RRef<DataPacket>) -> Result<()> {
        let mut connection = self.connection.disable_irq().lock();

        // Update peer credit info from packet header
        connection.update_peer_credit(packet.header.buf_alloc, packet.header.fwd_cnt);

        // Store packet in pending queue (zero-copy)
        if connection.pending_packets.len() < MAX_PENDING_PACKETS {
            connection.pending_packets.push_back(packet);
        } else {
            debug!(
                "[FrameVsock] Pending packet queue full, dropping packet (len={})",
                packet.data.len()
            );
        }

        drop(connection);
        self.pollee.notify(IoEvents::IN);

        Ok(())
    }

    /// Handle credit update from peer
    pub fn on_credit_update(&self, buf_alloc: u32, fwd_cnt: u32) {
        let mut connection = self.connection.disable_irq().lock();
        connection.update_peer_credit(buf_alloc, fwd_cnt);
        drop(connection);

        // Notify that we might be able to send now
        self.pollee.notify(IoEvents::OUT);
    }

    /// Send credit update to peer
    pub fn send_credit_update(&self) {
        let mut connection = self.connection.disable_irq().lock();
        self.send_credit_update_internal(&mut connection);
    }

    fn send_credit_update_internal(&self, connection: &mut Connection) {
        let packet = connection.create_credit_update_packet(self.local_addr(), self.peer_addr());
        let vcpu_id = self.select_vcpu();
        let _ = framevisor_vsock::deliver_control_packet(vcpu_id, packet);
    }

    /// Handle shutdown from peer
    pub fn on_shutdown_received(&self) -> Result<()> {
        let mut connection = self.connection.disable_irq().lock();
        connection.set_peer_shutdown();
        drop(connection);

        self.pollee.notify(IoEvents::IN | IoEvents::HUP);
        Ok(())
    }

    /// Handle reset from peer
    pub fn on_rst_received(&self) -> Result<()> {
        let mut connection = self.connection.disable_irq().lock();
        connection.set_peer_shutdown();
        connection.set_local_shutdown();
        connection.pending_packets.clear();
        connection.partial_read = None;
        drop(connection);

        self.pollee.notify(IoEvents::ERR | IoEvents::HUP);
        Ok(())
    }

    pub fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(mask, poller, || self.check_io_events())
    }

    fn check_io_events(&self) -> IoEvents {
        let connection = self.connection.disable_irq().lock();
        let mut events = IoEvents::empty();

        // Readable if we have pending packets or partial read
        if !connection.pending_packets.is_empty() || connection.partial_read.is_some() {
            events |= IoEvents::IN;
        }

        // Writable if we can send (check peer credit)
        if connection.can_send() {
            events |= IoEvents::OUT;
        }

        // HUP if peer shutdown
        if connection.is_peer_requested_shutdown() {
            events |= IoEvents::HUP;
        }

        // Error if connection reset
        if connection.is_local_shutdown() && connection.is_peer_requested_shutdown() {
            events |= IoEvents::ERR;
        }

        events
    }

    /// Select vCPU for this connection using consistent hashing
    fn select_vcpu(&self) -> usize {
        // Use connection ID hash for consistent routing
        let mut hasher = SimpleHasher::new();
        self.id.local_addr.cid.hash(&mut hasher);
        self.id.local_addr.port.hash(&mut hasher);
        self.id.peer_addr.cid.hash(&mut hasher);
        self.id.peer_addr.port.hash(&mut hasher);

        let hash = hasher.finish() as usize;

        // Get vCPU count (default to 1 if not initialized)
        let vcpu_count = framevisor_vsock::get_vcpu_count().max(1);
        hash % vcpu_count
    }
}

struct Connection {
    local_addr: FrameVsockAddr,
    peer_addr: FrameVsockAddr,

    /// Pending data packets (zero-copy: stored as RRef)
    pending_packets: VecDeque<RRef<DataPacket>>,
    /// Partial read state (for when user buffer is smaller than packet)
    partial_read: Option<PartialRead>,

    peer_requested_shutdown: bool,
    local_shutdown: bool,

    // Flow control fields
    /// Our buffer allocation (告知对端我们的缓冲区大小)
    buf_alloc: u32,
    /// Our forward count (已消费的字节数)
    fwd_cnt: u32,
    /// Last fwd_cnt when we sent credit update
    last_credit_update_fwd_cnt: u32,
    /// Peer's buffer allocation
    peer_buf_alloc: u32,
    /// Peer's forward count
    peer_fwd_cnt: u32,
    /// Total bytes we've sent
    tx_cnt: u32,
}

impl Connection {
    fn new(peer_addr: FrameVsockAddr, local_addr: FrameVsockAddr) -> Self {
        Self {
            local_addr,
            peer_addr,
            pending_packets: VecDeque::with_capacity(MAX_PENDING_PACKETS),
            partial_read: None,
            peer_requested_shutdown: false,
            local_shutdown: false,
            buf_alloc: DEFAULT_BUF_ALLOC,
            fwd_cnt: 0,
            last_credit_update_fwd_cnt: 0,
            peer_buf_alloc: DEFAULT_BUF_ALLOC,
            peer_fwd_cnt: 0,
            tx_cnt: 0,
        }
    }

    fn new_with_credit(
        peer_addr: FrameVsockAddr,
        local_addr: FrameVsockAddr,
        peer_buf_alloc: u32,
        peer_fwd_cnt: u32,
    ) -> Self {
        Self {
            local_addr,
            peer_addr,
            pending_packets: VecDeque::with_capacity(MAX_PENDING_PACKETS),
            partial_read: None,
            peer_requested_shutdown: false,
            local_shutdown: false,
            buf_alloc: DEFAULT_BUF_ALLOC,
            fwd_cnt: 0,
            last_credit_update_fwd_cnt: 0,
            peer_buf_alloc,
            peer_fwd_cnt,
            tx_cnt: 0,
        }
    }

    fn is_peer_requested_shutdown(&self) -> bool {
        self.peer_requested_shutdown
    }

    fn is_local_shutdown(&self) -> bool {
        self.local_shutdown
    }

    fn set_local_shutdown(&mut self) {
        self.local_shutdown = true
    }

    fn set_peer_shutdown(&mut self) {
        self.peer_requested_shutdown = true;
    }

    /// Calculate available credit to send to peer
    fn available_credit(&self) -> u32 {
        let outstanding = self.tx_cnt.wrapping_sub(self.peer_fwd_cnt);
        self.peer_buf_alloc.saturating_sub(outstanding)
    }

    /// Check if we can send data
    fn can_send(&self) -> bool {
        self.available_credit() > 0 && !self.local_shutdown
    }

    /// Update peer credit info from received packet
    fn update_peer_credit(&mut self, buf_alloc: u32, fwd_cnt: u32) {
        self.peer_buf_alloc = buf_alloc;
        self.peer_fwd_cnt = fwd_cnt;
    }

    /// Record bytes sent
    fn record_sent(&mut self, bytes: u32) {
        self.tx_cnt = self.tx_cnt.wrapping_add(bytes);
    }

    /// Record bytes consumed from receive queue
    fn done_forwarding(&mut self, bytes: usize) {
        self.fwd_cnt = self.fwd_cnt.wrapping_add(bytes as u32);
    }

    /// Check if we should send a credit update to peer
    fn should_send_credit_update(&self) -> bool {
        let consumed_since_last = self.fwd_cnt.wrapping_sub(self.last_credit_update_fwd_cnt);
        consumed_since_last >= CREDIT_UPDATE_THRESHOLD
    }

    /// Create credit update packet
    fn create_credit_update_packet(
        &mut self,
        local_addr: FrameVsockAddr,
        peer_addr: FrameVsockAddr,
    ) -> RRef<ControlPacket> {
        self.last_credit_update_fwd_cnt = self.fwd_cnt;
        create_credit_update(
            local_addr.cid,
            local_addr.port,
            peer_addr.cid,
            peer_addr.port,
            self.buf_alloc,
            self.fwd_cnt,
        )
    }

    fn buf_alloc(&self) -> u32 {
        self.buf_alloc
    }

    fn fwd_cnt(&self) -> u32 {
        self.fwd_cnt
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
