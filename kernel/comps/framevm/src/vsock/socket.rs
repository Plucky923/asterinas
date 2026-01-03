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

#![deny(unsafe_code)]

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use aster_framevisor::task::Task;
use aster_framevsock::{
    create_credit_update, create_rst, create_shutdown, ControlPacket, DataPacket, VsockOp,
    SHUTDOWN_FLAG_BOTH, VMADDR_CID_GUEST,
};
use exchangeable::RRef;
use spin::Mutex;

/// Maximum number of poll iterations for blocking operations
const MAX_POLL_ITERATIONS: u32 = 1_000_000;

/// Maximum pending packets per socket
const MAX_PENDING_PACKETS: usize = 64;

/// Credit update threshold - send update when this many bytes consumed
const CREDIT_UPDATE_THRESHOLD: u32 = 4096 / 4;

/// Default buffer allocation advertised to peer
const DEFAULT_BUF_ALLOC: u32 = 64 * 1024; // 64KB

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

    /// Check if we should send a credit update to peer
    fn should_send_credit_update(&self) -> bool {
        let fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed);
        let last_update = self.last_credit_update_fwd_cnt.load(Ordering::Relaxed);
        let consumed_since_last = fwd_cnt.wrapping_sub(last_update);
        consumed_since_last >= CREDIT_UPDATE_THRESHOLD
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

        // Blocking mode: poll with yield until connection arrives
        for _ in 0..MAX_POLL_ITERATIONS {
            // Process any pending RX packets that might contain connection requests
            super::process_rx_packets();

            // Check for pending connection again
            let mut pending = self.pending_connections.lock();
            if let Some(conn) = pending.pop_front() {
                return Ok(conn);
            }
            drop(pending);

            // Yield to allow other tasks to run
            Task::yield_now();
        }

        // Timeout after MAX_POLL_ITERATIONS
        return_errno_with_message!(Errno::ETIMEDOUT, "accept timed out waiting for connection");
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
        const MAX_RETRIES: u32 = 1000;
        for _ in 0..MAX_RETRIES {
            // Process any pending RX packets
            super::process_rx_packets();

            let current_state = *self.state.lock();
            match current_state {
                SocketState::Connected => return Ok(()),
                SocketState::Shutdown => {
                    // Connection was rejected (RST received)
                    return_errno_with_message!(Errno::ECONNREFUSED, "connection refused");
                }
                SocketState::Connecting => {
                    // Still waiting, continue
                    core::hint::spin_loop();
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
        for _ in 0..MAX_POLL_ITERATIONS {
            if self.available_credit() >= need {
                break;
            }

            // Let RX/control packets make progress (credit updates, shutdown, etc.).
            super::process_rx_packets();

            // If peer shutdowns while we are waiting, fail the send.
            let state = *self.state.lock();
            if matches!(state, SocketState::ShutdownPeer | SocketState::Shutdown) {
                return_errno_with_message!(Errno::ECONNRESET, "connection reset by peer");
            }

            Task::yield_now();
        }

        if self.available_credit() < need {
            return_errno_with_message!(Errno::ETIMEDOUT, "send timed out waiting for credit");
        }

        // Build a data packet by moving the Vec (zero-copy).
        let (local, peer) = self.addrs()?;
        let mut packet = DataPacket::new_rw(local.cid, peer.cid, local.port, peer.port, data);
        packet.header.buf_alloc = self.get_buf_alloc();
        packet.header.fwd_cnt = self.get_fwd_cnt();

        self.send_packet(RRef::new(packet))?;
        Ok(need as usize)
    }

    /// Receive a data packet (zero-copy)
    /// Returns the packet with ownership transferred to caller
    pub fn recv_packet(&self) -> Result<RRef<DataPacket>> {
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

        // Try to get a pending packet
        let mut pending = self.pending_data_packets.lock();
        if let Some(packet) = pending.pop_front() {
            // Update forward count
            let len = packet.data.len() as u32;
            self.fwd_cnt.fetch_add(len, Ordering::Relaxed);
            drop(pending);

            // Check if we should send credit update
            if self.should_send_credit_update() {
                let _ = self.send_credit_update();
            }

            return Ok(packet);
        }
        drop(pending);

        // No packet available
        if self.nonblocking.load(Ordering::Relaxed) {
            return_errno!(Errno::EAGAIN);
        }

        // Blocking mode: poll with yield until packet arrives
        for _ in 0..MAX_POLL_ITERATIONS {
            super::process_rx_packets();

            let mut pending = self.pending_data_packets.lock();
            if let Some(packet) = pending.pop_front() {
                let len = packet.data.len() as u32;
                self.fwd_cnt.fetch_add(len, Ordering::Relaxed);
                drop(pending);

                if self.should_send_credit_update() {
                    let _ = self.send_credit_update();
                }

                return Ok(packet);
            }
            drop(pending);

            // Check if peer has shutdown
            if *self.state.lock() == SocketState::ShutdownPeer {
                return_errno_with_message!(Errno::ECONNRESET, "connection reset by peer");
            }

            Task::yield_now();
        }

        return_errno_with_message!(Errno::ETIMEDOUT, "recv timed out waiting for data");
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

        // Try to get a new packet
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

            // Blocking mode: poll with yield
            for _ in 0..MAX_POLL_ITERATIONS {
                super::process_rx_packets();

                let pending = self.pending_data_packets.lock();
                if !pending.is_empty() {
                    break;
                }
                drop(pending);

                if *self.state.lock() == SocketState::ShutdownPeer {
                    return Ok(0);
                }

                Task::yield_now();
            }

            pending = self.pending_data_packets.lock();
            if pending.is_empty() {
                return_errno_with_message!(Errno::ETIMEDOUT, "recv timed out");
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
        // Update peer credit info from packet header
        self.peer_buf_alloc
            .store(packet.header.buf_alloc, Ordering::Relaxed);
        self.peer_fwd_cnt
            .store(packet.header.fwd_cnt, Ordering::Relaxed);

        // Store packet in pending queue (zero-copy)
        let mut pending = self.pending_data_packets.lock();
        if pending.len() < MAX_PENDING_PACKETS {
            pending.push_back(packet);
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
            }
            VsockOp::Rst => {
                // Connection reset
                let mut state = self.state.lock();
                *state = SocketState::Shutdown;
                // Clear pending packets
                self.pending_data_packets.lock().clear();
                *self.partial_read.lock() = None;
            }
            VsockOp::CreditUpdate => {
                // Update peer credit info
                self.peer_buf_alloc
                    .store(packet.header.buf_alloc, Ordering::Relaxed);
                self.peer_fwd_cnt
                    .store(packet.header.fwd_cnt, Ordering::Relaxed);
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

        let mut packet = ControlPacket::with_header(
            local.cid,
            peer.cid,
            local.port,
            peer.port,
            VsockOp::Response,
        );
        packet.header.buf_alloc = self.buf_alloc.load(Ordering::Relaxed);
        packet.header.fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed);

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
