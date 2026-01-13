// SPDX-License-Identifier: MPL-2.0

//! FrameVsock socket implementation for FrameVM (Guest side)
//!
//! # Architecture
//! - TX: Guest creates DataPacket and submits via RRef (zero-copy)
//! - RX: Guest receives RRef<DataPacket> and reads data (zero-copy)
//!
//! # Zero-Copy Design
//! - The only copy happens at syscall boundary (user-space ↔ kernel-space)
//! - Packets are stored as RRef<DataPacket> in pending queue
//! - No intermediate buffer copies
//!
//! # Flow Control
//! Uses credit-based flow control similar to virtio-vsock:
//! - buf_alloc: Buffer space allocated by receiver
//! - fwd_cnt: Bytes consumed by receiver
//! - available_credit = peer_buf_alloc - (tx_cnt - peer_fwd_cnt)
//!
//! # Flow Control Optimizations
//! - Adaptive credit update threshold based on packet sizes
//! - Proactive credit updates when sender credit is low

#![deny(unsafe_code)]

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use aster_framevisor::{sync::WaitQueue, task::Task};
use aster_framevsock::{
    create_credit_update, create_rst, create_shutdown, ControlPacket, DataPacket, VsockOp,
    SHUTDOWN_FLAG_BOTH, VMADDR_CID_GUEST,
    flow_control::{
        DEFAULT_BUF_ALLOC, MAX_PENDING_PACKETS, URGENT_CREDIT_UPDATE_THRESHOLD,
        adaptive_threshold,
    },
};
use exchangeable::RRef;
use spin::Mutex;

use super::addr::{FrameVsockAddr, VMADDR_CID_ANY, VMADDR_PORT_ANY};
use crate::{
    error::{Errno, Error, Result},
    return_errno, return_errno_with_message,
};

/// Socket state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    /// Initial state, not bound
    Init,
    /// Bound to local address
    Bound,
    /// Listening for connections
    Listening,
    /// Connecting to peer (client side)
    Connecting,
    /// Connected (data transfer ready)
    Connected,
    /// Shutdown initiated by local
    ShutdownLocal,
    /// Shutdown initiated by peer
    ShutdownPeer,
    /// Fully shutdown
    Shutdown,
}

/// Partial read state - tracks remaining data from a partially consumed packet
struct PartialRead {
    /// The packet being partially read
    packet: RRef<DataPacket>,
    /// Offset into the packet's data
    offset: usize,
}

/// FrameVsock socket for FrameVM (Guest side)
///
/// # Zero-Copy Design
/// - Pending packets are stored as RRef<DataPacket>
/// - No intermediate VecDeque<u8> buffer
/// - Data is read directly from packet to user buffer
///
/// # Low-Latency Optimizations
/// - Uses `recv_waiters` counter for Host to know when to inject interrupts
/// - Host only injects interrupt when Guest is actually waiting, avoiding overhead
pub struct FrameVsockSocket {
    /// Socket state
    state: Mutex<SocketState>,
    /// Local address (set after bind)
    local_addr: Mutex<Option<FrameVsockAddr>>,
    /// Peer address (set after connect)
    peer_addr: Mutex<Option<FrameVsockAddr>>,

    /// Pending data packets (zero-copy: stored as RRef)
    pending_data_packets: Mutex<VecDeque<RRef<DataPacket>>>,
    /// Partial read state (for when user buffer is smaller than packet)
    partial_read: Mutex<Option<PartialRead>>,

    /// Pending connections (for listening socket)
    pending_connections: Mutex<VecDeque<Arc<FrameVsockSocket>>>,
    /// Backlog size
    backlog: AtomicU32,
    /// Non-blocking flag
    nonblocking: AtomicBool,

    // Flow control fields
    /// Our buffer allocation (告知对端我们的缓冲区大小)
    buf_alloc: AtomicU32,
    /// Our forward count (已消费的字节数)
    fwd_cnt: AtomicU32,
    /// Last fwd_cnt when we sent credit update
    last_credit_update_fwd_cnt: AtomicU32,
    /// Peer's buffer allocation
    peer_buf_alloc: AtomicU32,
    /// Peer's forward count
    peer_fwd_cnt: AtomicU32,
    /// Total bytes we've sent
    tx_cnt: AtomicU32,

    // Adaptive flow control
    /// Running average of received packet sizes (for adaptive threshold)
    avg_rx_packet_size: AtomicU32,
    /// Current adaptive credit update threshold
    credit_update_threshold: AtomicU32,

    /// WaitQueue for blocking operations (recv, accept)
    wait_queue: WaitQueue,

    /// Number of tasks currently waiting for data in recv operations.
    /// Used by Host for conditional interrupt injection: Host only injects
    /// interrupt when this counter > 0, avoiding unnecessary overhead when
    /// Guest is actively polling (fast path).
    recv_waiters: AtomicU32,
}

impl FrameVsockSocket {
    /// Create a new socket
    pub fn new(nonblocking: bool) -> Self {
        Self {
            state: Mutex::new(SocketState::Init),
            local_addr: Mutex::new(None),
            peer_addr: Mutex::new(None),
            pending_data_packets: Mutex::new(VecDeque::with_capacity(MAX_PENDING_PACKETS)),
            partial_read: Mutex::new(None),
            pending_connections: Mutex::new(VecDeque::new()),
            backlog: AtomicU32::new(0),
            nonblocking: AtomicBool::new(nonblocking),
            buf_alloc: AtomicU32::new(DEFAULT_BUF_ALLOC),
            fwd_cnt: AtomicU32::new(0),
            last_credit_update_fwd_cnt: AtomicU32::new(0),
            peer_buf_alloc: AtomicU32::new(DEFAULT_BUF_ALLOC),
            peer_fwd_cnt: AtomicU32::new(0),
            tx_cnt: AtomicU32::new(0),
            avg_rx_packet_size: AtomicU32::new(1024),
            credit_update_threshold: AtomicU32::new(adaptive_threshold(1024)),
            wait_queue: WaitQueue::new(),
            recv_waiters: AtomicU32::new(0),
        }
    }

    /// Create a connected socket (for accept)
    pub fn new_connected(local_addr: FrameVsockAddr, peer_addr: FrameVsockAddr) -> Self {
        Self {
            state: Mutex::new(SocketState::Connected),
            local_addr: Mutex::new(Some(local_addr)),
            peer_addr: Mutex::new(Some(peer_addr)),
            pending_data_packets: Mutex::new(VecDeque::with_capacity(MAX_PENDING_PACKETS)),
            partial_read: Mutex::new(None),
            pending_connections: Mutex::new(VecDeque::new()),
            backlog: AtomicU32::new(0),
            nonblocking: AtomicBool::new(false),
            buf_alloc: AtomicU32::new(DEFAULT_BUF_ALLOC),
            fwd_cnt: AtomicU32::new(0),
            last_credit_update_fwd_cnt: AtomicU32::new(0),
            peer_buf_alloc: AtomicU32::new(DEFAULT_BUF_ALLOC),
            peer_fwd_cnt: AtomicU32::new(0),
            tx_cnt: AtomicU32::new(0),
            avg_rx_packet_size: AtomicU32::new(1024),
            credit_update_threshold: AtomicU32::new(adaptive_threshold(1024)),
            wait_queue: WaitQueue::new(),
            recv_waiters: AtomicU32::new(0),
        }
    }

    /// Get current state
    pub fn state(&self) -> SocketState {
        *self.state.lock()
    }

    /// Get local address
    pub fn local_addr(&self) -> Option<FrameVsockAddr> {
        *self.local_addr.lock()
    }

    /// Get peer address
    pub fn peer_addr(&self) -> Option<FrameVsockAddr> {
        *self.peer_addr.lock()
    }

    /// Get both addresses (for packet creation)
    pub fn addrs(&self) -> Result<(FrameVsockAddr, FrameVsockAddr)> {
        let local = self
            .local_addr
            .lock()
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "socket not bound"))?;
        let peer = self
            .peer_addr
            .lock()
            .ok_or_else(|| Error::with_message(Errno::ENOTCONN, "socket not connected"))?;
        Ok((local, peer))
    }

    /// Calculate available credit to send to peer
    fn available_credit(&self) -> u32 {
        let tx_cnt = self.tx_cnt.load(Ordering::Relaxed);
        let peer_fwd_cnt = self.peer_fwd_cnt.load(Ordering::Relaxed);
        let peer_buf_alloc = self.peer_buf_alloc.load(Ordering::Relaxed);

        let outstanding = tx_cnt.wrapping_sub(peer_fwd_cnt);
        peer_buf_alloc.saturating_sub(outstanding)
    }

    /// Update running average of received packet sizes and adjust threshold
    fn update_packet_stats(&self, packet_size: usize) {
        let size = packet_size as u32;
        let old_avg = self.avg_rx_packet_size.load(Ordering::Relaxed);

        // Exponential moving average with alpha = 1/8 for stability
        let new_avg = (old_avg * 7 + size) / 8;
        self.avg_rx_packet_size.store(new_avg, Ordering::Relaxed);

        // Update threshold
        let new_threshold = adaptive_threshold(new_avg);
        self.credit_update_threshold.store(new_threshold, Ordering::Relaxed);
    }

    /// Check if we should send a credit update to peer (adaptive threshold)
    fn should_send_credit_update(&self) -> bool {
        let fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed);
        let last_update = self.last_credit_update_fwd_cnt.load(Ordering::Relaxed);
        let threshold = self.credit_update_threshold.load(Ordering::Relaxed);
        let consumed_since_last = fwd_cnt.wrapping_sub(last_update);
        consumed_since_last >= threshold
    }

    /// Check if we should send an urgent credit update (peer might be stalled)
    fn should_send_urgent_credit_update(&self) -> bool {
        let fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed);
        let last_update = self.last_credit_update_fwd_cnt.load(Ordering::Relaxed);
        let consumed_since_last = fwd_cnt.wrapping_sub(last_update);
        consumed_since_last >= URGENT_CREDIT_UPDATE_THRESHOLD
    }

    /// Send credit update to peer
    fn send_credit_update(&self) -> Result<()> {
        let local_addr = self.local_addr.lock();
        let peer_addr = self.peer_addr.lock();

        if let (Some(local), Some(peer)) = (*local_addr, *peer_addr) {
            let buf_alloc = self.buf_alloc.load(Ordering::Relaxed);
            let fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed);

            let packet = create_credit_update(
                local.cid, local.port, peer.cid, peer.port, buf_alloc, fwd_cnt,
            );

            super::submit_control_packet(packet)?;

            // Update last credit update fwd_cnt
            self.last_credit_update_fwd_cnt
                .store(fwd_cnt, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Bind to local address
    pub fn bind(self: &Arc<Self>, addr: FrameVsockAddr) -> Result<()> {
        let mut state = self.state.lock();
        if *state != SocketState::Init {
            return_errno_with_message!(Errno::EINVAL, "socket already bound");
        }

        // Assign local CID if ANY
        let mut local = addr;
        if local.cid == VMADDR_CID_ANY {
            local.cid = VMADDR_CID_GUEST;
        }

        // Assign ephemeral port if ANY
        if local.port == VMADDR_PORT_ANY {
            static NEXT_PORT: AtomicU32 = AtomicU32::new(10000);
            local.port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        }

        *self.local_addr.lock() = Some(local);
        *state = SocketState::Bound;

        // Register port in the index for fast lookup
        super::register_port(local.port, self.clone());

        Ok(())
    }

    /// Listen for connections
    pub fn listen(&self, backlog: u32) -> Result<()> {
        let mut state = self.state.lock();
        if *state != SocketState::Bound {
            return_errno_with_message!(Errno::EINVAL, "socket not bound");
        }

        self.backlog.store(backlog, Ordering::Relaxed);
        *state = SocketState::Listening;
        Ok(())
    }

    /// Accept a connection (for listening socket)
    pub fn accept(&self) -> Result<Arc<FrameVsockSocket>> {
        let state = self.state.lock();
        if *state != SocketState::Listening {
            return_errno_with_message!(Errno::EINVAL, "socket not listening");
        }
        drop(state);

        // Try to get pending connection
        let mut pending = self.pending_connections.lock();
        if let Some(conn) = pending.pop_front() {
            return Ok(conn);
        }
        drop(pending);

        // No pending connection
        if self.nonblocking.load(Ordering::Relaxed) {
            return_errno!(Errno::EAGAIN);
        }

        // Blocking mode: loop indefinitely until connection arrives
        // For a server socket, we should wait forever for connections
        self.wait_queue.wait_until(|| {
            // Check for pending connection again
            let mut pending = self.pending_connections.lock();
            if let Some(conn) = pending.pop_front() {
                return Some(Ok(conn));
            }
            drop(pending);

            // Check if socket state changed (e.g., closed)
            let state = *self.state.lock();
            if state != SocketState::Listening {
                return Some(Err(Error::with_message(
                    Errno::EINVAL,
                    "socket no longer listening",
                )));
            }

            None
        })
    }

    /// Connect to peer address
    pub fn connect(self: &Arc<Self>, peer: FrameVsockAddr) -> Result<()> {
        let mut state = self.state.lock();

        match *state {
            SocketState::Init => {
                // Auto-bind
                drop(state);
                self.bind(FrameVsockAddr::any())?;
                state = self.state.lock();
            }
            SocketState::Bound => {}
            SocketState::Connected => {
                return_errno_with_message!(Errno::EISCONN, "already connected");
            }
            _ => {
                return_errno_with_message!(Errno::EINVAL, "invalid state for connect");
            }
        }

        let local_addr = self.local_addr.lock().unwrap();
        *self.peer_addr.lock() = Some(peer);
        *state = SocketState::Connecting;
        drop(state);

        // Create connection request packet with credit info
        let mut packet = ControlPacket::with_header(
            local_addr.cid,
            peer.cid,
            local_addr.port,
            peer.port,
            VsockOp::Request,
        );
        packet.header.buf_alloc = self.buf_alloc.load(Ordering::Relaxed);
        packet.header.fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed);

        // TX: Synchronously send to host
        super::submit_control_packet(RRef::new(packet))?;

        // Wait for Response packet from host
        // For connect, we use a reasonable timeout since we expect a quick response
        const MAX_RETRIES: u32 = 10_000_000;
        for _ in 0..MAX_RETRIES {
            let current_state = *self.state.lock();
            match current_state {
                SocketState::Connected => return Ok(()),
                SocketState::Shutdown => {
                    // Connection was rejected (RST received)
                    return_errno_with_message!(Errno::ECONNREFUSED, "connection refused");
                }
                SocketState::Connecting => {
                    // Still waiting, yield to allow packet processing
                    Task::yield_now();
                }
                _ => {
                    return_errno_with_message!(Errno::EINVAL, "unexpected state during connect");
                }
            }
        }

        // Timeout - reset state
        let mut state = self.state.lock();
        *state = SocketState::Bound;
        return_errno_with_message!(Errno::ETIMEDOUT, "connection timed out");
    }

    /// Send a data packet (zero-copy from caller's perspective)
    /// The data Vec is moved into the packet
    pub fn send_packet(&self, packet: RRef<DataPacket>) -> Result<()> {
        let state = self.state.lock();
        match *state {
            SocketState::Connected => {}
            SocketState::ShutdownLocal | SocketState::Shutdown => {
                return_errno_with_message!(Errno::EPIPE, "connection shutdown");
            }
            _ => {
                return_errno_with_message!(Errno::ENOTCONN, "not connected");
            }
        }
        drop(state);

        // Update tx count
        let len = packet.data.len() as u32;
        self.tx_cnt.fetch_add(len, Ordering::Relaxed);

        // Submit packet to host
        super::submit_data_packet(packet)
    }

    /// Send owned bytes to peer with **zero-copy inside the kernel**.
    ///
    /// # Zero-copy semantics
    /// - No extra copies in Guest kernel: `data: Vec<u8>` is moved directly into `DataPacket`.
    /// - Copies only happen at syscall boundary (user <-> kernel) if the caller is a syscall.
    ///
    /// # Flow control semantics
    /// This method waits until the peer has enough credit to accept the entire buffer,
    /// so it can keep the transfer strictly zero-copy (no slicing/splitting that would
    /// require copying).
    ///
    /// # Mixing with `recv_to_buffer`
    /// This method is independent from `recv_to_buffer`, but for RX side see `recv_owned()`.
    pub fn send_owned(&self, data: Vec<u8>) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }

        // Must be connected.
        let state = *self.state.lock();
        match state {
            SocketState::Connected => {}
            SocketState::ShutdownLocal | SocketState::Shutdown => {
                return_errno_with_message!(Errno::EPIPE, "connection shutdown");
            }
            _ => return_errno_with_message!(Errno::ENOTCONN, "not connected"),
        }

        // Wait until we have enough credit to send the whole Vec without splitting.
        let need = data.len() as u32;
        while self.available_credit() < need {
            // If peer shutdowns while we are waiting, fail the send.
            let state = *self.state.lock();
            if matches!(state, SocketState::ShutdownPeer | SocketState::Shutdown) {
                return_errno_with_message!(Errno::ECONNRESET, "connection reset by peer");
            }

            Task::yield_now();
        }

        // Build a data packet by moving the Vec (zero-copy).
        let (local, peer) = self.addrs()?;
        let mut packet = DataPacket::new_rw(local.cid, peer.cid, local.port, peer.port, data);
        packet.header.buf_alloc = self.get_buf_alloc();
        packet.header.fwd_cnt = self.get_fwd_cnt();

        self.send_packet(RRef::new(packet))?;
        Ok(need as usize)
    }

    /// Try to receive a packet without blocking (fast path)
    fn try_recv_packet_fast(&self) -> Option<RRef<DataPacket>> {
        let mut pending = self.pending_data_packets.lock();
        if let Some(packet) = pending.pop_front() {
            let len = packet.data.len() as u32;
            self.fwd_cnt.fetch_add(len, Ordering::Relaxed);
            drop(pending);

            if self.should_send_credit_update() {
                let _ = self.send_credit_update();
            }
            return Some(packet);
        }
        None
    }

    /// Receive a data packet (zero-copy)
    /// Returns the packet with ownership transferred to caller
    ///
    /// # Race Condition Fix
    /// The wait-notify pattern is fixed by registering as waiter BEFORE checking
    /// the queue condition. This ensures that any notification after registration
    /// will wake us up, avoiding the classic race:
    /// ```text
    /// T1: Guest checks queue.is_empty() -> true
    /// T2: Host delivers packet to queue
    /// T3: Host checks recv_waiters -> 0 (Guest not yet waiting)
    /// T4: Host decides not to inject interrupt
    /// T5: Guest enters wait and blocks forever
    /// ```
    pub fn recv_packet(&self) -> Result<RRef<DataPacket>> {
        // Fast path: Check queue first without state lock
        if let Some(packet) = self.try_recv_packet_fast() {
            return Ok(packet);
        }

        let state = self.state.lock();
        match *state {
            SocketState::Connected | SocketState::ShutdownPeer => {}
            SocketState::ShutdownLocal | SocketState::Shutdown => {
                return_errno_with_message!(Errno::ECONNRESET, "connection shutdown");
            }
            _ => {
                return_errno_with_message!(Errno::ENOTCONN, "not connected");
            }
        }
        drop(state);

        // No packet available
        if self.nonblocking.load(Ordering::Relaxed) {
            return_errno!(Errno::EAGAIN);
        }

        // Blocking mode: Register as waiter FIRST to avoid race condition
        // This must happen BEFORE any condition check in the wait loop
        self.recv_waiters.fetch_add(1, Ordering::Release);

        // Double-check after registering (critical for race-free operation)
        if let Some(packet) = self.try_recv_packet_fast() {
            self.recv_waiters.fetch_sub(1, Ordering::Release);
            return Ok(packet);
        }

        let result = self.wait_queue.wait_until(|| {
            if let Some(packet) = self.try_recv_packet_fast() {
                return Some(Ok(packet));
            }

            // Check if peer has shutdown or connection state changed
            let state = *self.state.lock();
            match state {
                SocketState::Connected => None,
                SocketState::ShutdownPeer => {
                    // Check one more time for any remaining data
                    if let Some(packet) = self.try_recv_packet_fast() {
                        return Some(Ok(packet));
                    }
                    return Some(Err(Error::with_message(
                        Errno::ECONNRESET,
                        "connection reset by peer",
                    )));
                }
                _ => {
                    return Some(Err(Error::with_message(
                        Errno::ENOTCONN,
                        "connection closed",
                    )));
                }
            }
        });

        self.recv_waiters.fetch_sub(1, Ordering::Release);
        result
    }

    /// Receive owned bytes from peer with **zero-copy inside the kernel**.
    ///
    /// # Zero-copy semantics
    /// - No extra copies in Guest kernel: the returned `Vec<u8>` is moved out from `DataPacket`.
    /// - Copies only happen at syscall boundary (user <-> kernel) if the caller is a syscall.
    ///
    /// # Important
    /// This API is **packet-oriented**: it returns the full payload of one `DataPacket`.
    /// If you need stream-like partial reads into a caller-provided buffer, use
    /// `recv_to_buffer(&mut [u8])` (which necessarily copies at the boundary).
    ///
    /// Mixing `recv_owned()` with `recv_to_buffer()` is not supported while a partial read
    /// is in progress, because producing a \"tail Vec\" without copying is impossible with
    /// `Vec<u8>` payload. In that case this returns `EINVAL`.
    pub fn recv_owned(&self) -> Result<Vec<u8>> {
        if self.partial_read.lock().is_some() {
            return_errno_with_message!(
                Errno::EINVAL,
                "partial read in progress; use recv_to_buffer() until drained"
            );
        }

        let packet = self.recv_packet()?;
        Ok(packet.into_inner().data)
    }

    /// Read data from pending packets into a user buffer (for partial read support)
    /// Returns the number of bytes read
    pub fn recv_to_buffer(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let state = *self.state.lock();
        match state {
            SocketState::Connected | SocketState::ShutdownPeer => {}
            SocketState::ShutdownLocal | SocketState::Shutdown => {
                return Ok(0); // EOF
            }
            _ => {
                return_errno_with_message!(Errno::ENOTCONN, "not connected");
            }
        }

        // First check if there's a partial read in progress
        let mut partial = self.partial_read.lock();
        if let Some(ref mut pr) = *partial {
            let remaining = &pr.packet.data[pr.offset..];
            let to_copy = buf.len().min(remaining.len());
            buf[..to_copy].copy_from_slice(&remaining[..to_copy]);
            pr.offset += to_copy;

            // Update forward count
            self.fwd_cnt.fetch_add(to_copy as u32, Ordering::Relaxed);

            // If packet fully consumed, clear partial read
            if pr.offset >= pr.packet.data.len() {
                *partial = None;
            }

            drop(partial);

            if self.should_send_credit_update() {
                let _ = self.send_credit_update();
            }

            return Ok(to_copy);
        }
        drop(partial);

        // Try to get a new packet from the queue (fast path, no blocking)
        {
            let mut pending = self.pending_data_packets.lock();
            if let Some(packet) = pending.pop_front() {
                drop(pending);

                let data = &packet.data;
                let to_copy = buf.len().min(data.len());
                buf[..to_copy].copy_from_slice(&data[..to_copy]);

                // Only update fwd_cnt by the amount actually consumed
                self.fwd_cnt.fetch_add(to_copy as u32, Ordering::Relaxed);

                // If packet not fully consumed, save for partial read
                if to_copy < data.len() {
                    *self.partial_read.lock() = Some(PartialRead {
                        packet,
                        offset: to_copy,
                    });
                }

                if self.should_send_credit_update() {
                    let _ = self.send_credit_update();
                }

                return Ok(to_copy);
            }
        }

        let mut pending = self.pending_data_packets.lock();

        // If no packets, handle blocking/non-blocking
        if pending.is_empty() {
            drop(pending);

            if state == SocketState::ShutdownPeer {
                return Ok(0); // EOF
            }

            if self.nonblocking.load(Ordering::Relaxed) {
                return_errno!(Errno::EAGAIN);
            }

            // Blocking mode: Register as waiter FIRST to avoid race condition
            self.recv_waiters.fetch_add(1, Ordering::Release);

            // Double-check after registering (critical for race-free operation)
            {
                let pending_check = self.pending_data_packets.lock();
                if !pending_check.is_empty() {
                    drop(pending_check);
                    self.recv_waiters.fetch_sub(1, Ordering::Release);
                    // Retry from the beginning
                    return self.recv_to_buffer(buf);
                }
            }

            let wait_result: Result<()> = self.wait_queue.wait_until(|| {
                let pending = self.pending_data_packets.lock();
                if !pending.is_empty() {
                    return Some(Ok(()));
                }
                drop(pending);

                let current_state = *self.state.lock();
                if current_state == SocketState::ShutdownPeer {
                    return Some(Ok(())); // EOF
                }
                if current_state != SocketState::Connected {
                    return Some(Err(Error::with_message(
                        Errno::ENOTCONN,
                        "connection closed",
                    )));
                }

                None
            });

            self.recv_waiters.fetch_sub(1, Ordering::Release);

            wait_result?;

            pending = self.pending_data_packets.lock();
            if pending.is_empty() {
                // Must be EOF
                return Ok(0);
            }
        }

        let packet = pending.pop_front().unwrap();
        drop(pending);

        let data = &packet.data;
        let to_copy = buf.len().min(data.len());
        buf[..to_copy].copy_from_slice(&data[..to_copy]);

        // Update forward count
        self.fwd_cnt.fetch_add(to_copy as u32, Ordering::Relaxed);

        // If packet not fully consumed, save for partial read
        if to_copy < data.len() {
            *self.partial_read.lock() = Some(PartialRead {
                packet,
                offset: to_copy,
            });
        }

        if self.should_send_credit_update() {
            let _ = self.send_credit_update();
        }

        Ok(to_copy)
    }

    /// Shutdown socket
    pub fn shutdown(&self, _how: i32) -> Result<()> {
        let mut state = self.state.lock();
        match *state {
            SocketState::Connected => {
                *state = SocketState::ShutdownLocal;
            }
            SocketState::ShutdownPeer => {
                *state = SocketState::Shutdown;
            }
            SocketState::ShutdownLocal | SocketState::Shutdown => {
                return Ok(()); // Already shutdown
            }
            _ => {
                return_errno_with_message!(Errno::ENOTCONN, "not connected");
            }
        }
        drop(state);

        // Send shutdown notification to host
        let local_addr = self.local_addr.lock();
        let peer_addr = self.peer_addr.lock();
        if let (Some(local), Some(peer)) = (*local_addr, *peer_addr) {
            let packet = create_shutdown(
                local.cid,
                local.port,
                peer.cid,
                peer.port,
                SHUTDOWN_FLAG_BOTH,
            );
            let _ = super::submit_control_packet(packet);
        }

        Ok(())
    }

    /// Close socket
    pub fn close(&self) -> Result<()> {
        let mut state = self.state.lock();
        let was_connected = *state == SocketState::Connected || *state == SocketState::ShutdownPeer;

        if was_connected {
            // Send RST if still connected
            let local_addr = self.local_addr.lock();
            let peer_addr = self.peer_addr.lock();
            if let (Some(local), Some(peer)) = (*local_addr, *peer_addr) {
                let packet = create_rst(local.cid, local.port, peer.cid, peer.port);
                let _ = super::submit_control_packet(packet);

                // Unregister from connection index (for connected sockets)
                super::unregister_connection(local.port, peer.cid, peer.port);
            }
        } else {
            // Unregister from port index (for listening sockets)
            if let Some(local) = *self.local_addr.lock() {
                super::unregister_port(local.port);
            }
        }

        *state = SocketState::Shutdown;
        Ok(())
    }

    /// Handle incoming data packet (called from RX interrupt handler)
    /// Zero-copy: packet is stored directly in pending queue
    pub fn on_data_packet_received(&self, packet: RRef<DataPacket>) {
        let data_len = packet.data.len();

        // Update peer credit info from packet header (piggyback credit)
        self.peer_buf_alloc
            .store(packet.header.buf_alloc, Ordering::Relaxed);
        self.peer_fwd_cnt
            .store(packet.header.fwd_cnt, Ordering::Relaxed);

        // Update packet size statistics for adaptive threshold
        self.update_packet_stats(data_len);

        // Store packet in pending queue (zero-copy)
        let mut pending = self.pending_data_packets.lock();
        if pending.len() < MAX_PENDING_PACKETS {
            pending.push_back(packet);
            drop(pending); // Release lock before wake

            // Wake up waiting tasks - this is sufficient since we're already
            // running in Guest context (called from RX interrupt handler).
            // No need for additional interrupt injection here.
            self.wait_queue.wake_one();
        }
        // If queue is full, packet is dropped (flow control should prevent this)
    }

    /// Handle incoming control packet (called from RX interrupt handler)
    pub fn on_control_packet_received(&self, packet: RRef<ControlPacket>) {
        let op = packet.operation();

        match op {
            VsockOp::Response => {
                // Connection response - transition to Connected
                self.peer_buf_alloc
                    .store(packet.header.buf_alloc, Ordering::Relaxed);
                self.peer_fwd_cnt
                    .store(packet.header.fwd_cnt, Ordering::Relaxed);

                let mut state = self.state.lock();
                if *state == SocketState::Connecting {
                    *state = SocketState::Connected;
                }
            }
            VsockOp::Shutdown => {
                // Peer shutdown
                let mut state = self.state.lock();
                match *state {
                    SocketState::Connected => {
                        *state = SocketState::ShutdownPeer;
                    }
                    SocketState::ShutdownLocal => {
                        *state = SocketState::Shutdown;
                    }
                    _ => {}
                }
                self.wait_queue.wake_all();
            }
            VsockOp::Rst => {
                // Connection reset
                let mut state = self.state.lock();
                *state = SocketState::Shutdown;
                // Clear pending packets
                self.pending_data_packets.lock().clear();
                *self.partial_read.lock() = None;
                self.wait_queue.wake_all();
            }
            VsockOp::CreditUpdate => {
                // Update peer credit info
                self.peer_buf_alloc
                    .store(packet.header.buf_alloc, Ordering::Relaxed);
                self.peer_fwd_cnt
                    .store(packet.header.fwd_cnt, Ordering::Relaxed);

                // Wake up any tasks waiting for credit to send data
                // This fixes the issue where senders block waiting for credit
                // but never get woken up when credit becomes available
                if self.available_credit() > 0 {
                    self.wait_queue.wake_all();
                }
            }
            VsockOp::CreditRequest => {
                // Peer requests our credit info, send update
                let _ = self.send_credit_update();
            }
            VsockOp::Request => {
                // Connection request from Host - only listening sockets handle this
                let state = self.state.lock();
                if *state != SocketState::Listening {
                    drop(state);
                    // Send RST to reject connection
                    self.send_rst_to_peer(packet.header.src_cid, packet.header.src_port);
                    return;
                }
                drop(state);

                // Create new connected socket
                let peer_addr = FrameVsockAddr::new(packet.header.src_cid, packet.header.src_port);
                let local_addr = self.local_addr.lock().unwrap();

                let conn = Arc::new(FrameVsockSocket::new_connected(local_addr, peer_addr));
                conn.set_peer_credit(packet.header.buf_alloc, packet.header.fwd_cnt);

                // Register the new socket in connection index for data packet routing
                // Key: (local_port, peer_cid, peer_port) to distinguish multiple connections
                super::register_connection(
                    local_addr.port,
                    peer_addr.cid,
                    peer_addr.port,
                    conn.clone(),
                );

                // Add to pending connections queue
                if self.push_pending_connection(conn.clone()).is_ok() {
                    // Send Response back to Host
                    conn.send_response();
                } else {
                    // Backlog full, send RST
                    super::unregister_connection(local_addr.port, peer_addr.cid, peer_addr.port);
                    self.send_rst_to_peer(packet.header.src_cid, packet.header.src_port);
                }
            }
            _ => {}
        }
    }

    /// Push pending connection (called when connection request arrives)
    pub fn push_pending_connection(&self, conn: Arc<FrameVsockSocket>) -> Result<()> {
        let mut pending = self.pending_connections.lock();
        let backlog = self.backlog.load(Ordering::Relaxed) as usize;
        if pending.len() >= backlog {
            return_errno_with_message!(Errno::ECONNREFUSED, "backlog full");
        }
        pending.push_back(conn);
        self.wait_queue.wake_all();
        Ok(())
    }

    /// Set non-blocking mode
    pub fn set_nonblocking(&self, nonblocking: bool) {
        self.nonblocking.store(nonblocking, Ordering::Relaxed);
    }

    /// Check if non-blocking
    pub fn is_nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Relaxed)
    }

    /// Check if socket has data available to read
    pub fn has_data(&self) -> bool {
        self.partial_read.lock().is_some() || !self.pending_data_packets.lock().is_empty()
    }

    /// Check if socket can write (based on peer credit)
    pub fn can_write(&self) -> bool {
        let state = *self.state.lock();
        matches!(state, SocketState::Connected) && self.available_credit() > 0
    }

    /// Get the number of pending data packets
    pub fn pending_packet_count(&self) -> usize {
        self.pending_data_packets.lock().len()
    }

    /// Get buffer allocation value (for packet headers)
    pub fn get_buf_alloc(&self) -> u32 {
        self.buf_alloc.load(Ordering::Relaxed)
    }

    /// Get forward count value (for packet headers)
    pub fn get_fwd_cnt(&self) -> u32 {
        self.fwd_cnt.load(Ordering::Relaxed)
    }

    /// Set peer credit info (from incoming packet)
    pub fn set_peer_credit(&self, buf_alloc: u32, fwd_cnt: u32) {
        self.peer_buf_alloc.store(buf_alloc, Ordering::Relaxed);
        self.peer_fwd_cnt.store(fwd_cnt, Ordering::Relaxed);
    }

    /// Send connection response to peer (for accept flow)
    pub fn send_response(&self) {
        let local = match *self.local_addr.lock() {
            Some(addr) => addr,
            None => return,
        };
        let peer = match *self.peer_addr.lock() {
            Some(addr) => addr,
            None => return,
        };

        let buf_alloc = self.buf_alloc.load(Ordering::Relaxed);
        let fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed);

        let mut packet = ControlPacket::with_header(
            local.cid,
            peer.cid,
            local.port,
            peer.port,
            VsockOp::Response,
        );
        packet.header.buf_alloc = buf_alloc;
        packet.header.fwd_cnt = fwd_cnt;

        let _ = super::submit_control_packet(RRef::new(packet));
    }

    /// Send RST to reject a connection
    fn send_rst_to_peer(&self, peer_cid: u64, peer_port: u32) {
        let local = match *self.local_addr.lock() {
            Some(addr) => addr,
            None => return,
        };

        let packet = create_rst(local.cid, local.port, peer_cid, peer_port);
        let _ = super::submit_control_packet(packet);
    }
}
