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
//! # SMP Optimizations
//! - Minimized lock usage: state and addresses use atomic operations
//! - Only RX data path uses a SpinLock (pending_data_packets)
//! - TX and RX paths don't share locks

#![deny(unsafe_code)]

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use aster_framevisor::{
    mm::{VmReader, VmSpace, io::FallibleVmWrite},
    sync::WaitQueue,
};
use aster_framevsock::{
    ControlPacket, DataPacket, SHUTDOWN_FLAG_BOTH, VMADDR_CID_GUEST, VsockOp,
    create_credit_request, create_credit_update, create_rst, create_shutdown,
    flow_control::{DEFAULT_BUF_ALLOC, MAX_PENDING_PACKETS, MAX_PKT_BUF_SIZE},
    trace,
};
use exchangeable::RRef;
use spin::Mutex;

// ============================================================================
// Tuning Constants for Optimization
// ============================================================================
const RX_NEAR_FULL_WATERMARK_PERCENT: u32 = 90;
const RX_OVERFLOW_RETRY_SPINS: usize = 8;
/// Reserve headroom between advertised credit window and hard RX buffer limit.
///
/// Architecture rationale:
/// - `buf_alloc` is the hard local buffer limit (4MB default).
/// - In multi-queue/high-jitter paths, sender-side credit view can lag by a few
///   packets around scheduling boundaries.
/// - If we advertise the full hard limit, one burst can hit exact boundary and
///   trigger fail-fast reset on next packet.
///
/// By advertising a slightly smaller window we preserve stream correctness while
/// absorbing transient burst skew without immediate connection reset.
use super::addr::{FrameVsockAddr, VMADDR_CID_ANY, VMADDR_PORT_ANY};
use crate::{
    error::{Errno, Error, Result},
    return_errno, return_errno_with_message,
};

// ============================================================================
// Socket State (atomic, no lock needed)
// ============================================================================

/// Socket state as atomic value
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocketState {
    /// Initial state, not bound
    Init = 0,
    /// Bound to local address
    Bound = 1,
    /// Listening for connections
    Listening = 2,
    /// Connecting to peer (client side)
    Connecting = 3,
    /// Connected (data transfer ready)
    Connected = 4,
    /// Shutdown initiated by local
    ShutdownLocal = 5,
    /// Shutdown initiated by peer
    ShutdownPeer = 6,
    /// Fully shutdown
    Shutdown = 7,
}

impl SocketState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => SocketState::Init,
            1 => SocketState::Bound,
            2 => SocketState::Listening,
            3 => SocketState::Connecting,
            4 => SocketState::Connected,
            5 => SocketState::ShutdownLocal,
            6 => SocketState::ShutdownPeer,
            7 => SocketState::Shutdown,
            _ => SocketState::Shutdown,
        }
    }
}

/// Atomic socket state wrapper
struct AtomicSocketState(AtomicU32);

impl AtomicSocketState {
    const fn new(state: SocketState) -> Self {
        Self(AtomicU32::new(state as u32))
    }

    #[inline]
    fn load(&self) -> SocketState {
        SocketState::from_u8(self.0.load(Ordering::Acquire) as u8)
    }

    #[inline]
    fn store(&self, state: SocketState) {
        self.0.store(state as u32, Ordering::Release);
    }

    /// Compare and swap, returns true if successful
    #[inline]
    fn compare_exchange(&self, current: SocketState, new: SocketState) -> bool {
        self.0
            .compare_exchange(
                current as u32,
                new as u32,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

// ============================================================================
// Atomic Address (pack cid + port into u64)
// ============================================================================

/// Address wrapper (set once) - protected by a lightweight Mutex
struct AtomicAddr {
    inner: Mutex<Option<FrameVsockAddr>>,
}

impl AtomicAddr {
    const fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    const fn with_addr(addr: FrameVsockAddr) -> Self {
        Self {
            inner: Mutex::new(Some(addr)),
        }
    }

    #[inline]
    fn load(&self) -> Option<FrameVsockAddr> {
        *self.inner.lock()
    }

    #[inline]
    fn store(&self, addr: FrameVsockAddr) {
        *self.inner.lock() = Some(addr);
    }
}

// ============================================================================
// RX Data (the only state that needs Mutex)
// ============================================================================

/// Partial read state - tracks remaining data from a partially consumed packet
struct PartialRead {
    /// The packet being partially read
    packet: RRef<DataPacket>,
    /// Offset into the packet's data
    offset: usize,
}

/// RX data - protected by single SpinLock
struct RxData {
    /// Pending data packets (zero-copy: stored as RRef)
    pending_packets: VecDeque<RRef<DataPacket>>,
    /// Partial read state (for when user buffer is smaller than packet)
    partial_read: Option<PartialRead>,
}

impl RxData {
    fn new() -> Self {
        Self {
            // Start small; VecDeque will grow on demand.
            // Avoids a multi-MB upfront allocation per socket
            // (MAX_PENDING_PACKETS=65536 × ~100B ≈ 6.5MB).
            pending_packets: VecDeque::with_capacity(256),
            partial_read: None,
        }
    }
}

// ============================================================================
// FrameVsockSocket - Optimized for SMP
// ============================================================================

/// FrameVsock socket for FrameVM (Guest side)
///
/// # SMP Optimizations
/// - State and addresses use atomic operations (no locks)
/// - Only RX data path uses Mutex
/// - TX path is lock-free (only atomic operations)
/// - Minimized lock contention between TX and RX
///
/// # Zero-Copy Design
/// - Pending packets are stored as RRef<DataPacket>
/// - No intermediate VecDeque<u8> buffer
/// - Data is read directly from packet to user buffer
pub struct FrameVsockSocket {
    // === Atomic state (no lock needed) ===
    /// Socket state (atomic)
    state: AtomicSocketState,
    /// Local address (atomic, set once after bind)
    local_addr: AtomicAddr,
    /// Peer address (atomic, set once after connect)
    peer_addr: AtomicAddr,

    // === RX path (single lock) ===
    /// RX data - pending packets and partial read state
    rx_data: Mutex<RxData>,

    // === Listening socket only ===
    /// Pending connections (for listening socket)
    pending_connections: Mutex<VecDeque<Arc<FrameVsockSocket>>>,
    /// Backlog size
    backlog: AtomicU32,

    // === Flags (atomic) ===
    /// Non-blocking flag
    nonblocking: AtomicBool,
    /// Whether a passive connection has been returned by accept().
    ///
    /// Passive children are created at request time and can receive data
    /// before user space accepts them. Track acceptance so we can fail fast
    /// on permanently unaccepted, credit-saturated children.
    accepted: AtomicBool,

    // === Flow control (all atomic, no locks) ===
    /// Our buffer allocation (告知对端我们的缓冲区大小)
    buf_alloc: AtomicU32,
    /// Our forward count (已消费的字节数)
    fwd_cnt: AtomicU64,
    /// Last fwd_cnt when we sent credit update
    last_credit_update_fwd_cnt: AtomicU64,
    /// Total bytes currently buffered (for Linux-style credit update)
    buf_used: AtomicU32,
    /// Peer's buffer allocation
    peer_buf_alloc: AtomicU32,
    /// Peer's forward count
    peer_fwd_cnt: AtomicU64,
    /// Total bytes we've sent
    tx_cnt: AtomicU64,
    /// Number of times RX usage reached near-full watermark.
    rx_near_full_events: AtomicU64,
    /// Number of RX overflow resets.
    rx_overflow_events: AtomicU64,
    /// Number of overflow retries that succeeded after short spin.
    rx_overflow_retry_successes: AtomicU64,

    // === Synchronization ===
    /// WaitQueue for blocking operations (recv, accept)
    wait_queue: WaitQueue,
    /// Number of tasks currently waiting for data in recv operations
    recv_waiters: AtomicU32,
    /// Serialize recv operations to preserve stream order
    recv_lock: Mutex<()>,
}

impl FrameVsockSocket {
    /// Compute advertised receive window from local hard limit.
    #[inline]
    fn advertised_buf_alloc_from(actual: u32) -> u32 {
        let min_window = MAX_PKT_BUF_SIZE.max(4 * 1024);
        let configured = super::rx_credit_headroom_bytes();
        let capped_headroom = configured.min(actual.saturating_sub(min_window));
        actual.saturating_sub(capped_headroom).max(min_window)
    }

    /// Get the receive window value advertised to peer.
    #[inline]
    fn advertised_buf_alloc(&self) -> u32 {
        Self::advertised_buf_alloc_from(self.get_buf_alloc())
    }

    /// Create a new socket
    pub fn new(nonblocking: bool) -> Self {
        Self {
            state: AtomicSocketState::new(SocketState::Init),
            local_addr: AtomicAddr::new(),
            peer_addr: AtomicAddr::new(),
            rx_data: Mutex::new(RxData::new()),
            pending_connections: Mutex::new(VecDeque::new()),
            backlog: AtomicU32::new(0),
            nonblocking: AtomicBool::new(nonblocking),
            accepted: AtomicBool::new(true),
            buf_alloc: AtomicU32::new(DEFAULT_BUF_ALLOC),
            fwd_cnt: AtomicU64::new(0),
            last_credit_update_fwd_cnt: AtomicU64::new(0),
            buf_used: AtomicU32::new(0),
            peer_buf_alloc: AtomicU32::new(DEFAULT_BUF_ALLOC),
            peer_fwd_cnt: AtomicU64::new(0),
            tx_cnt: AtomicU64::new(0),
            rx_near_full_events: AtomicU64::new(0),
            rx_overflow_events: AtomicU64::new(0),
            rx_overflow_retry_successes: AtomicU64::new(0),
            wait_queue: WaitQueue::new(),
            recv_waiters: AtomicU32::new(0),
            recv_lock: Mutex::new(()),
        }
    }
    pub fn new_connected(local_addr: FrameVsockAddr, peer_addr: FrameVsockAddr) -> Self {
        Self {
            state: AtomicSocketState::new(SocketState::Connected),
            local_addr: AtomicAddr::with_addr(local_addr),
            peer_addr: AtomicAddr::with_addr(peer_addr),
            rx_data: Mutex::new(RxData::new()),
            pending_connections: Mutex::new(VecDeque::new()),
            backlog: AtomicU32::new(0),
            nonblocking: AtomicBool::new(false),
            accepted: AtomicBool::new(false),
            buf_alloc: AtomicU32::new(DEFAULT_BUF_ALLOC),
            fwd_cnt: AtomicU64::new(0),
            last_credit_update_fwd_cnt: AtomicU64::new(0),
            buf_used: AtomicU32::new(0),
            peer_buf_alloc: AtomicU32::new(DEFAULT_BUF_ALLOC),
            peer_fwd_cnt: AtomicU64::new(0),
            tx_cnt: AtomicU64::new(0),
            rx_near_full_events: AtomicU64::new(0),
            rx_overflow_events: AtomicU64::new(0),
            rx_overflow_retry_successes: AtomicU64::new(0),
            wait_queue: WaitQueue::new(),
            recv_waiters: AtomicU32::new(0),
            recv_lock: Mutex::new(()),
        }
    }

    /// Get current state (lock-free)
    #[inline]
    pub fn state(&self) -> SocketState {
        self.state.load()
    }

    /// Get local address (lock-free)
    #[inline]
    pub fn local_addr(&self) -> Option<FrameVsockAddr> {
        self.local_addr.load()
    }

    /// Get peer address (lock-free)
    #[inline]
    pub fn peer_addr(&self) -> Option<FrameVsockAddr> {
        self.peer_addr.load()
    }

    /// Get both addresses (lock-free)
    #[inline]
    pub fn addrs(&self) -> Result<(FrameVsockAddr, FrameVsockAddr)> {
        let local = self
            .local_addr
            .load()
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "socket not bound"))?;
        let peer = self
            .peer_addr
            .load()
            .ok_or_else(|| Error::with_message(Errno::ENOTCONN, "socket not connected"))?;
        Ok((local, peer))
    }

    /// Update peer_fwd_cnt, reconstructing the full u64 from the u32 wire value.
    ///
    /// The vsock protocol transmits fwd_cnt as u32, but tx_cnt is u64.
    /// We reconstruct the high bits by detecting when the low 32 bits wrap.
    ///
    /// Uses CAS loop for thread safety — concurrent credit updates from
    /// different vCPUs can call this for the same connection.
    ///
    /// Wrap detection uses signed comparison (like TCP sequence numbers):
    /// if `new_low` is "ahead" of `prev_low` in the circular u32 space
    /// (i.e., `new_low.wrapping_sub(prev_low)` interpreted as i32 > 0),
    /// we advance. A genuine wrap crosses the 2^31 boundary, while stale
    /// out-of-order updates stay within buf_alloc (~4MB) distance.
    fn update_peer_fwd_cnt(&self, new_low: u32) {
        loop {
            let prev = self.peer_fwd_cnt.load(Ordering::Acquire);
            let prev_low = prev as u32;
            let prev_high = prev & !0xFFFF_FFFF_u64;

            let delta = new_low.wrapping_sub(prev_low) as i32;
            if delta <= 0 {
                return;
            }

            let new_full = if new_low < prev_low {
                prev_high.wrapping_add(1u64 << 32) | (new_low as u64)
            } else {
                prev_high | (new_low as u64)
            };

            if self
                .peer_fwd_cnt
                .compare_exchange_weak(prev, new_full, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Try to increase buf_used without exceeding buf_alloc.
    #[inline]
    fn try_inc_buf_used(&self, len: u32) -> bool {
        let buf_alloc = self.buf_alloc.load(Ordering::Acquire);
        let mut current = self.buf_used.load(Ordering::Acquire);
        loop {
            if current.saturating_add(len) > buf_alloc {
                return false;
            }
            match self.buf_used.compare_exchange(
                current,
                current + len,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(updated) => current = updated,
            }
        }
    }

    /// Decrease buf_used with saturation to avoid underflow.
    #[inline]
    fn dec_buf_used(&self, len: u32) {
        let mut current = self.buf_used.load(Ordering::Acquire);
        loop {
            let next = current.saturating_sub(len);
            match self
                .buf_used
                .compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return,
                Err(updated) => current = updated,
            }
        }
    }

    /// Account for a fully dequeued packet (credit release).
    #[inline]
    fn account_rx_dequeued(&self, len: usize) {
        if len == 0 {
            return;
        }
        self.fwd_cnt.fetch_add(len as u64, Ordering::Release);
        self.dec_buf_used(len as u32);
    }

    /// Batch account for multiple dequeued packets (credit release).
    /// More efficient than calling account_rx_dequeued multiple times.
    #[inline]
    fn account_rx_dequeued_batch(&self, total_len: usize) {
        if total_len == 0 {
            return;
        }
        self.fwd_cnt.fetch_add(total_len as u64, Ordering::Release);
        self.dec_buf_used(total_len as u32);
    }

    /// Calculate available credit to send to peer (lock-free)
    #[inline]
    fn available_credit(&self) -> u32 {
        let tx_cnt = self.tx_cnt.load(Ordering::Acquire);
        let peer_fwd_cnt = self.peer_fwd_cnt.load(Ordering::Acquire);
        let peer_buf_alloc = self.peer_buf_alloc.load(Ordering::Acquire);
        let in_flight = tx_cnt.saturating_sub(peer_fwd_cnt);
        if in_flight > peer_buf_alloc as u64 {
            0
        } else {
            (peer_buf_alloc as u64 - in_flight) as u32
        }
    }

    #[inline]
    fn rx_near_full_watermark(buf_alloc: u32) -> u32 {
        ((buf_alloc as u64 * RX_NEAR_FULL_WATERMARK_PERCENT as u64) / 100u64) as u32
    }

    /// Check if we should send a credit update to peer (lock-free)
    ///
    /// Uses the flow_control module's adaptive threshold logic:
    /// - Send update if consumed bytes >= adaptive threshold (1MB for 4MB buffer)
    /// - This reduces credit update frequency from per-packet to ~4 times per buffer cycle
    #[expect(dead_code, reason = "kept for alternative credit-update tuning paths")]
    fn should_send_credit_update(&self) -> bool {
        let buf_alloc = self.buf_alloc.load(Ordering::Relaxed);
        let fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed) as u32;
        let last_fwd_cnt = self.last_credit_update_fwd_cnt.load(Ordering::Relaxed) as u32;
        let buf_used = self.buf_used.load(Ordering::Relaxed);

        aster_framevsock::flow_control::should_send_credit_update(
            buf_alloc,
            buf_used,
            fwd_cnt,
            last_fwd_cnt,
        )
    }

    /// Send credit update to peer with an explicit advertised buffer window.
    ///
    /// `advertised_buf_alloc` can be smaller than the real local buffer to
    /// implement admission control before accept().
    fn send_credit_update_with_buf_alloc(&self, advertised_buf_alloc: u32) -> Result<()> {
        if let (Some(local), Some(peer)) = (self.local_addr.load(), self.peer_addr.load()) {
            let fwd_cnt = self.fwd_cnt.load(Ordering::Acquire);

            let packet = create_credit_update(
                local.cid,
                local.port,
                peer.cid,
                peer.port,
                advertised_buf_alloc,
                fwd_cnt as u32,
            );

            super::submit_control_packet(packet)?;

            self.last_credit_update_fwd_cnt
                .store(fwd_cnt, Ordering::Release);
        }

        Ok(())
    }

    /// Send credit update to peer (lock-free address access)
    fn send_credit_update(&self) -> Result<()> {
        self.send_credit_update_with_buf_alloc(self.advertised_buf_alloc())
    }

    /// Send credit request to peer.
    ///
    /// This is used by blocking send paths when local credit is exhausted,
    /// asking the peer to immediately advertise fresh credit instead of
    /// waiting for its next periodic credit update threshold.
    fn send_credit_request(&self) -> Result<()> {
        if let (Some(local), Some(peer)) = (self.local_addr.load(), self.peer_addr.load()) {
            let mut packet = create_credit_request(local.cid, local.port, peer.cid, peer.port);
            packet.header.buf_alloc = self.advertised_buf_alloc();
            packet.header.fwd_cnt = self.get_fwd_cnt();
            super::submit_control_packet(packet)?;
        }

        Ok(())
    }

    /// Bind to local address
    pub fn bind(self: &Arc<Self>, addr: FrameVsockAddr) -> Result<()> {
        // Check and update state atomically
        if !self
            .state
            .compare_exchange(SocketState::Init, SocketState::Bound)
        {
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

        self.local_addr.store(local);

        // Register port in the index for fast lookup
        super::register_port(local.port, self.clone());

        Ok(())
    }

    /// Listen for connections
    pub fn listen(&self, backlog: u32) -> Result<()> {
        if !self
            .state
            .compare_exchange(SocketState::Bound, SocketState::Listening)
        {
            return_errno_with_message!(Errno::EINVAL, "socket not bound");
        }

        self.backlog.store(backlog, Ordering::Relaxed);
        Ok(())
    }

    /// Accept a connection (for listening socket)
    pub fn accept(&self) -> Result<Arc<FrameVsockSocket>> {
        let state = self.state.load();
        if state != SocketState::Listening {
            return_errno_with_message!(Errno::EINVAL, "socket not listening");
        }

        // Try to get pending connection
        if let Some(conn) = self.pop_next_pending_connection() {
            return Ok(conn);
        }

        // No pending connection
        if self.nonblocking.load(Ordering::Relaxed) {
            return_errno!(Errno::EAGAIN);
        }

        // Blocking mode: loop indefinitely until connection arrives
        self.wait_queue.wait_until(|| {
            if let Some(conn) = self.pop_next_pending_connection() {
                return Some(Ok(conn));
            }

            let state = self.state.load();
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
        let state = self.state.load();

        match state {
            SocketState::Init => {
                // Auto-bind
                self.bind(FrameVsockAddr::any())?;
            }
            SocketState::Bound => {}
            SocketState::Connected => {
                return_errno_with_message!(Errno::EISCONN, "already connected");
            }
            _ => {
                return_errno_with_message!(Errno::EINVAL, "invalid state for connect");
            }
        }

        // Try to transition to Connecting
        if !self
            .state
            .compare_exchange(SocketState::Bound, SocketState::Connecting)
        {
            return_errno_with_message!(Errno::EINVAL, "invalid state for connect");
        }

        let local_addr = self
            .local_addr
            .load()
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "local address is not bound"))?;
        self.peer_addr.store(peer);

        // Register active (client-side) connection early so subsequent
        // control/data packets are routed by connection tuple consistently.
        super::register_connection(local_addr.port, peer.cid, peer.port, self.clone());

        // Create connection request packet with credit info
        let mut packet = ControlPacket::with_header(
            local_addr.cid,
            peer.cid,
            local_addr.port,
            peer.port,
            VsockOp::Request,
        );
        packet.header.buf_alloc = self.advertised_buf_alloc();
        packet.header.fwd_cnt = self.fwd_cnt.load(Ordering::Acquire) as u32;

        // TX: Synchronously send to host
        if let Err(e) = super::submit_control_packet(RRef::new(packet)) {
            super::unregister_connection(local_addr.port, peer.cid, peer.port);
            return Err(e);
        }

        // Progress fallback: drain pending backend packets before potentially
        // sleeping, in case IRQ delivery is delayed.
        super::service_pending_packets();

        // Wait for Response packet from host (blocking).
        let wait_result: Result<()> = self.wait_queue.wait_until(|| {
            super::service_pending_packets();
            let current_state = self.state.load();
            match current_state {
                SocketState::Connected => Some(Ok(())),
                SocketState::Shutdown => Some(Err(Error::with_message(
                    Errno::ECONNREFUSED,
                    "connection refused",
                ))),
                SocketState::Connecting => None,
                _ => Some(Err(Error::with_message(
                    Errno::EINVAL,
                    "unexpected state during connect",
                ))),
            }
        });

        if wait_result.is_err() && self.state.load() != SocketState::Connected {
            super::unregister_connection(local_addr.port, peer.cid, peer.port);
        }

        wait_result
    }

    /// Send a data packet (lock-free)
    pub fn send_packet(&self, packet: RRef<DataPacket>) -> Result<()> {
        let _trace = trace::TraceGuard::new(&trace::GUEST_SOCKET_SEND_PACKET);
        let state = self.state.load();
        match state {
            SocketState::Connected => {}
            SocketState::ShutdownLocal | SocketState::Shutdown => {
                return_errno_with_message!(Errno::EPIPE, "connection shutdown");
            }
            _ => {
                return_errno_with_message!(Errno::ENOTCONN, "not connected");
            }
        }

        // Update tx count
        let len = packet.data.len() as u32;
        self.tx_cnt.fetch_add(len as u64, Ordering::Release);

        // Submit packet to host
        super::submit_data_packet(packet)
    }

    /// Send owned bytes to peer with **zero-copy inside the kernel**.
    pub fn send_owned(&self, mut data: Vec<u8>) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }

        // Must be connected (lock-free check)
        let state = self.state.load();
        match state {
            SocketState::Connected => {}
            SocketState::ShutdownLocal | SocketState::Shutdown => {
                return_errno_with_message!(Errno::EPIPE, "connection shutdown");
            }
            _ => return_errno_with_message!(Errno::ENOTCONN, "not connected"),
        }

        // Stream semantics: allow partial send when only partial credit is
        // available. This prevents all-or-nothing stalls at credit boundaries.
        let need = data.len();
        let to_send = loop {
            let state = self.state.load();
            if matches!(state, SocketState::ShutdownPeer | SocketState::Shutdown) {
                return_errno_with_message!(Errno::ECONNRESET, "connection reset by peer");
            }

            let credit = self.available_credit() as usize;
            if credit > 0 {
                break need.min(credit);
            }

            if self.nonblocking.load(Ordering::Relaxed) {
                return_errno!(Errno::EAGAIN);
            }

            // Ask peer for immediate credit refresh when exhausted.
            let _ = self.send_credit_request();

            // Progress fallback before sleeping.
            super::service_pending_packets();

            let wait_result: Result<()> = self.wait_queue.wait_until(|| {
                super::service_pending_packets();

                let state = self.state.load();
                if matches!(state, SocketState::ShutdownPeer | SocketState::Shutdown) {
                    return Some(Err(Error::with_message(
                        Errno::ECONNRESET,
                        "connection reset by peer",
                    )));
                }
                if self.available_credit() > 0 {
                    return Some(Ok(()));
                }
                None
            });
            wait_result?;
        };

        if to_send < data.len() {
            data.truncate(to_send);
        }

        // Build a data packet by moving the Vec (zero-copy)
        let (local, peer) = self.addrs()?;
        let mut packet = DataPacket::new_rw(local.cid, peer.cid, local.port, peer.port, data);
        packet.header.buf_alloc = self.advertised_buf_alloc();
        packet.header.fwd_cnt = self.get_fwd_cnt();

        self.send_packet(RRef::new(packet))?;
        Ok(to_send)
    }

    /// Try to receive a packet without blocking (fast path)
    /// Note: Does NOT check credit update - caller should batch credit updates
    fn try_recv_packet_fast(&self) -> Option<RRef<DataPacket>> {
        {
            let mut rx = self.rx_data.lock();
            let packet = rx.pending_packets.pop_front();
            if let Some(ref pkt) = packet {
                self.account_rx_dequeued(pkt.data.len());
                // Don't check credit update here - let caller batch it
            }
            packet
        }
    }

    #[inline]
    fn has_rx_payload(&self) -> bool {
        let rx = self.rx_data.lock();
        rx.partial_read.is_some() || !rx.pending_packets.is_empty()
    }

    fn wait_for_recv_packet(&self) -> Result<RRef<DataPacket>> {
        self.recv_waiters.fetch_add(1, Ordering::Release);
        let wait_result: Result<RRef<DataPacket>> = self.wait_queue.wait_until(|| {
            if let Some(packet) = self.try_recv_packet_fast() {
                return Some(Ok(packet));
            }

            super::service_pending_packets();

            if let Some(packet) = self.try_recv_packet_fast() {
                return Some(Ok(packet));
            }

            match self.state.load() {
                SocketState::Connected => None,
                SocketState::ShutdownPeer => {
                    if let Some(packet) = self.try_recv_packet_fast() {
                        return Some(Ok(packet));
                    }
                    Some(Err(Error::with_message(
                        Errno::ECONNRESET,
                        "connection reset by peer",
                    )))
                }
                _ => Some(Err(Error::with_message(
                    Errno::ENOTCONN,
                    "connection closed",
                ))),
            }
        });
        self.recv_waiters.fetch_sub(1, Ordering::Release);
        wait_result
    }

    fn wait_for_recv_data_or_state_change(&self) -> Result<bool> {
        self.recv_waiters.fetch_add(1, Ordering::Release);
        let wait_result: Result<bool> = self.wait_queue.wait_until(|| {
            if self.has_rx_payload() {
                return Some(Ok(true));
            }

            super::service_pending_packets();

            if self.has_rx_payload() {
                return Some(Ok(true));
            }

            match self.state.load() {
                SocketState::Connected => None,
                SocketState::ShutdownPeer => Some(Ok(false)),
                _ => Some(Err(Error::with_message(
                    Errno::ENOTCONN,
                    "connection closed",
                ))),
            }
        });
        self.recv_waiters.fetch_sub(1, Ordering::Release);

        wait_result
    }

    /// Receive a data packet (zero-copy), assumes recv_lock held.
    fn recv_packet_locked(&self) -> Result<RRef<DataPacket>> {
        // Fast path: Check queue first
        if let Some(packet) = self.try_recv_packet_fast() {
            // Batch credit update after getting packet
            let _ = self.send_credit_update();
            return Ok(packet);
        }

        let state = self.state.load();
        match state {
            SocketState::Connected | SocketState::ShutdownPeer => {}
            SocketState::ShutdownLocal | SocketState::Shutdown => {
                return_errno_with_message!(Errno::ECONNRESET, "connection shutdown");
            }
            _ => {
                return_errno_with_message!(Errno::ENOTCONN, "not connected");
            }
        }

        if self.nonblocking.load(Ordering::Relaxed) {
            return_errno!(Errno::EAGAIN);
        }

        // Progress fallback before blocking.
        super::service_pending_packets();
        if let Some(packet) = self.try_recv_packet_fast() {
            let _ = self.send_credit_update();
            return Ok(packet);
        }

        let packet = self.wait_for_recv_packet()?;
        let _ = self.send_credit_update();
        Ok(packet)
    }

    /// Receive a data packet (zero-copy)
    pub fn recv_packet(&self) -> Result<RRef<DataPacket>> {
        let _trace = trace::TraceGuard::new(&trace::GUEST_SOCKET_RECV_PACKET);
        let _recv_guard = self.recv_lock.lock();
        {
            let rx = self.rx_data.lock();
            if rx.partial_read.is_some() {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "partial read in progress; use recv_to_buffer() until drained"
                );
            }
        }
        self.recv_packet_locked()
    }

    /// Receive owned bytes from peer with **zero-copy inside the kernel**.
    pub fn recv_owned(&self) -> Result<Vec<u8>> {
        let _recv_guard = self.recv_lock.lock();
        {
            let rx = self.rx_data.lock();
            if rx.partial_read.is_some() {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "partial read in progress; use recv_to_buffer() until drained"
                );
            }
        }

        let packet = self.recv_packet_locked()?;
        Ok(packet.into_inner().data.take())
    }

    /// Read data into a user-provided buffer via a writer callback.
    ///
    /// Optimized lock pattern:
    /// - Batch extract packets from rx_data in a single lock acquisition
    /// - Process packets outside the lock to minimize contention
    /// - Credit update is batched - only checked once after all data is copied.
    pub fn recv_to_user<F>(&self, len: usize, mut write: F) -> Result<usize>
    where
        F: FnMut(&[u8]) -> Result<usize>,
    {
        let _trace = trace::TraceGuard::new(&trace::GUEST_SOCKET_RECV_TO_USER);
        if len == 0 {
            return Ok(0);
        }

        // Acquire recv_lock to serialize recv operations
        let lock_start = trace::now_cycles();
        let _recv_guard = self.recv_lock.lock();
        trace::GUEST_SOCKET_RECV_LOCK.record_cycles(trace::now_cycles() - lock_start);

        let state = self.state.load();
        match state {
            SocketState::Connected | SocketState::ShutdownPeer => {}
            SocketState::ShutdownLocal | SocketState::Shutdown => {
                return Ok(0); // EOF
            }
            _ => {
                return_errno_with_message!(Errno::ENOTCONN, "not connected");
            }
        }

        let mut total_copied = 0usize;
        let mut remaining = len;

        loop {
            if remaining == 0 {
                // Batch credit update: only check once after filling the buffer
                if total_copied > 0 {
                    let _ = self.send_credit_update();
                }
                return Ok(total_copied);
            }

            // Fast path: Batch extract packets in a single lock acquisition
            let extract_start = trace::now_cycles();
            let mut packets_to_process: Vec<(RRef<DataPacket>, usize)> = Vec::new();
            let mut estimated_bytes = 0usize;
            {
                let mut rx = self.rx_data.lock();

                // Take partial_read if present
                if let Some(pr) = rx.partial_read.take() {
                    let available = pr.packet.data.len() - pr.offset;
                    estimated_bytes += available;
                    packets_to_process.push((pr.packet, pr.offset));
                }

                // Drain available packets up to what we might need
                while estimated_bytes < remaining && !rx.pending_packets.is_empty() {
                    if let Some(pkt) = rx.pending_packets.pop_front() {
                        estimated_bytes += pkt.data.len();
                        packets_to_process.push((pkt, 0));
                    }
                }
            } // rx lock released here
            trace::GUEST_SOCKET_RECV_EXTRACT.record_cycles(trace::now_cycles() - extract_start);

            // Process packets outside rx lock
            if !packets_to_process.is_empty() {
                let copy_start = trace::now_cycles();
                let mut leftover_packet: Option<(RRef<DataPacket>, usize)> = None;
                let mut unused_packets: Vec<(RRef<DataPacket>, usize)> = Vec::new();
                let mut error: Option<Error> = None;
                let mut stop = false;

                let mut iter = packets_to_process.into_iter();
                while let Some((packet, mut offset)) = iter.next() {
                    if remaining == 0 {
                        // This packet wasn't consumed at all, save for putting back
                        unused_packets.push((packet, offset));
                        continue; // Continue to collect remaining unused packets
                    }

                    let data = packet.data.as_slice();
                    let total_len = data.len();
                    let remaining_data = &data[offset..];
                    let to_copy = remaining.min(remaining_data.len());

                    let write_result = write(&remaining_data[..to_copy]);
                    let bytes_written = match write_result {
                        Ok(n) => n,
                        Err(e) => {
                            unused_packets.push((packet, offset));
                            error = Some(e);
                            for (pkt, off) in iter {
                                unused_packets.push((pkt, off));
                            }
                            stop = true;
                            break;
                        }
                    };

                    if bytes_written == 0 {
                        unused_packets.push((packet, offset));
                        for (pkt, off) in iter {
                            unused_packets.push((pkt, off));
                        }
                        error = Some(Error::with_message(
                            Errno::EFAULT,
                            "recv writer made no progress",
                        ));
                        stop = true;
                        break;
                    }

                    offset += bytes_written;
                    total_copied += bytes_written;
                    remaining -= bytes_written;

                    if offset < total_len {
                        // Packet not fully consumed, save for later
                        leftover_packet = Some((packet, offset));
                        for (pkt, off) in iter {
                            unused_packets.push((pkt, off));
                        }
                        stop = true;
                        break;
                    }

                    // Fully consumed: release credit for the whole packet.
                    self.account_rx_dequeued(total_len);
                }
                trace::GUEST_SOCKET_RECV_COPY.record_cycles(trace::now_cycles() - copy_start);

                // Put back unused packets and leftover in correct order
                if !unused_packets.is_empty() || leftover_packet.is_some() {
                    let mut rx = self.rx_data.lock();
                    let mut partial_restore = leftover_packet;

                    // Put unused packets back at front (in reverse order to maintain original order)
                    for (pkt, off) in unused_packets.into_iter().rev() {
                        if off != 0 && partial_restore.is_none() {
                            partial_restore = Some((pkt, off));
                        } else {
                            rx.pending_packets.push_front(pkt);
                        }
                    }

                    // Store leftover packet as partial_read
                    if let Some((packet, offset)) = partial_restore {
                        rx.partial_read = Some(PartialRead { packet, offset });
                    }
                }

                if stop {
                    if total_copied > 0 {
                        let _ = self.send_credit_update();
                        return Ok(total_copied);
                    }
                    if let Some(e) = error {
                        return Err(e);
                    }
                }

                continue;
            }

            // No more data available - send credit update before potentially blocking
            if total_copied > 0 {
                let _ = self.send_credit_update();
            }

            let current_state = self.state.load();
            if current_state == SocketState::ShutdownPeer {
                return Ok(total_copied); // EOF
            }
            if current_state != SocketState::Connected {
                return_errno_with_message!(Errno::ENOTCONN, "connection closed");
            }
            if self.nonblocking.load(Ordering::Relaxed) {
                if total_copied > 0 {
                    return Ok(total_copied);
                }
                return_errno!(Errno::EAGAIN);
            }

            // Check local queue first. If data is already here, avoid touching
            // global service path and retry immediately.
            {
                let rx = self.rx_data.lock();
                if rx.partial_read.is_some() || !rx.pending_packets.is_empty() {
                    continue;
                }
            }
            // Progress fallback before sleeping.
            super::service_pending_packets();
            {
                let rx = self.rx_data.lock();
                if rx.partial_read.is_some() || !rx.pending_packets.is_empty() {
                    continue;
                }
            }

            let has_data = self.wait_for_recv_data_or_state_change()?;
            if !has_data {
                return Ok(total_copied);
            }
        }
    }

    /// Optimized receive directly to user space buffer.
    ///
    /// This version creates a single VmWriter covering the entire user buffer upfront,
    /// then processes all packets without per-packet VmWriter creation overhead.
    /// This is especially beneficial for small packet scenarios (e.g., 512B packets).
    pub fn recv_to_user_direct(
        &self,
        vm_space: &VmSpace,
        buf_addr: usize,
        len: usize,
    ) -> Result<isize> {
        let _trace = trace::TraceGuard::new(&trace::GUEST_SOCKET_RECV_TO_USER);
        if len == 0 {
            return Ok(0);
        }

        // Acquire recv_lock to serialize recv operations
        let lock_start = trace::now_cycles();
        let _recv_guard = self.recv_lock.lock();
        trace::GUEST_SOCKET_RECV_LOCK.record_cycles(trace::now_cycles() - lock_start);

        let state = self.state.load();
        match state {
            SocketState::Connected | SocketState::ShutdownPeer => {}
            SocketState::ShutdownLocal | SocketState::Shutdown => {
                return Ok(0); // EOF
            }
            _ => {
                return_errno_with_message!(Errno::ENOTCONN, "not connected");
            }
        }

        // Create VmWriter once for the entire buffer - avoids per-packet creation overhead
        let mut vm_writer = vm_space.writer(buf_addr, len).map_err(|e| Error::from(e))?;

        let mut total_copied = 0usize;
        let mut stalled_write_error: Option<Error> = None;

        loop {
            let remaining = len - total_copied;
            if remaining == 0 {
                if total_copied > 0 {
                    let _ = self.send_credit_update();
                }
                return Ok(total_copied as isize);
            }

            // Fast path: Batch extract packets - extract more aggressively for small packets
            let extract_start = trace::now_cycles();
            {
                let mut rx = self.rx_data.lock();
                let mut dequeued_in_pass = 0usize;

                // Process partial_read first if present
                if let Some(mut pr) = rx.partial_read.take() {
                    let data = pr.packet.data.as_slice();
                    let remaining_data = &data[pr.offset..];
                    let to_copy = remaining.min(remaining_data.len());

                    let mut reader = VmReader::from(&remaining_data[..to_copy]);
                    let mut write_error: Option<Error> = None;
                    let bytes_written = match vm_writer.write_fallible(&mut reader) {
                        Ok(n) => n,
                        Err((e, n)) => {
                            if n == 0 {
                                write_error = Some(Error::from(e));
                            }
                            n
                        }
                    };

                    if bytes_written > 0 {
                        pr.offset += bytes_written;
                        total_copied += bytes_written;

                        if pr.offset < data.len() {
                            // Still has data, put back
                            rx.partial_read = Some(pr);
                        } else {
                            // Fully consumed - batch account before releasing lock.
                            dequeued_in_pass += data.len();
                        }
                    } else {
                        // Write failed, put back
                        rx.partial_read = Some(pr);
                        stalled_write_error = Some(write_error.unwrap_or_else(|| {
                            Error::with_message(Errno::EFAULT, "recv writer made no progress")
                        }));
                    }
                }

                // Process pending packets inline while holding lock (reduces lock overhead)
                while total_copied < len && !rx.pending_packets.is_empty() {
                    let Some(packet) = rx.pending_packets.pop_front() else {
                        break;
                    };
                    let data = packet.data.as_slice();
                    let data_len = data.len();
                    let to_copy = (len - total_copied).min(data_len);

                    let mut reader = VmReader::from(&data[..to_copy]);
                    let mut write_error: Option<Error> = None;
                    let bytes_written = match vm_writer.write_fallible(&mut reader) {
                        Ok(n) => n,
                        Err((e, n)) => {
                            if n == 0 {
                                write_error = Some(Error::from(e));
                            }
                            n
                        }
                    };

                    if bytes_written == 0 {
                        // Write failed, put packet back
                        rx.pending_packets.push_front(packet);
                        stalled_write_error = Some(write_error.unwrap_or_else(|| {
                            Error::with_message(Errno::EFAULT, "recv writer made no progress")
                        }));
                        break;
                    }

                    total_copied += bytes_written;

                    if bytes_written < data_len {
                        // Partial read, save remainder
                        rx.partial_read = Some(PartialRead {
                            packet,
                            offset: bytes_written,
                        });
                        break;
                    }

                    // Fully consumed - batch account before releasing lock.
                    dequeued_in_pass += data_len;
                }

                // Keep queue accounting synchronized with dequeue progress:
                // once payload is copied to user buffer, release credit immediately
                // before dropping rx lock.
                if dequeued_in_pass > 0 {
                    self.account_rx_dequeued_batch(dequeued_in_pass);
                }
            }
            trace::GUEST_SOCKET_RECV_EXTRACT.record_cycles(trace::now_cycles() - extract_start);

            // If we copied any data, return immediately (stream semantics)
            if total_copied > 0 {
                let _ = self.send_credit_update();
                return Ok(total_copied as isize);
            }

            if let Some(err) = stalled_write_error.take() {
                return Err(err);
            }

            // No data available - check state and possibly block
            let current_state = self.state.load();
            if current_state == SocketState::ShutdownPeer {
                return Ok(0); // EOF
            }
            if current_state != SocketState::Connected {
                return_errno_with_message!(Errno::ENOTCONN, "connection closed");
            }
            if self.nonblocking.load(Ordering::Relaxed) {
                return_errno!(Errno::EAGAIN);
            }

            // Check local queue first; avoid blocking on global drain locks
            // when data is already available for this socket.
            {
                let rx = self.rx_data.lock();
                if rx.partial_read.is_some() || !rx.pending_packets.is_empty() {
                    continue;
                }
            }
            // Progress fallback before sleeping.
            super::service_pending_packets();
            {
                let rx = self.rx_data.lock();
                if rx.partial_read.is_some() || !rx.pending_packets.is_empty() {
                    continue;
                }
            }

            let has_data = self.wait_for_recv_data_or_state_change()?;
            if !has_data {
                return Ok(0);
            }
        }
    }

    /// Read data from pending packets into a user buffer
    pub fn recv_to_buffer(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let _recv_guard = self.recv_lock.lock();

        let state = self.state.load();
        match state {
            SocketState::Connected | SocketState::ShutdownPeer => {}
            SocketState::ShutdownLocal | SocketState::Shutdown => {
                return Ok(0); // EOF
            }
            _ => {
                return_errno_with_message!(Errno::ENOTCONN, "not connected");
            }
        }

        loop {
            // Check partial read first
            {
                let mut rx = self.rx_data.lock();
                if let Some(ref mut pr) = rx.partial_read {
                    let remaining = &pr.packet.data.as_slice()[pr.offset..];
                    let to_copy = buf.len().min(remaining.len());
                    buf[..to_copy].copy_from_slice(&remaining[..to_copy]);
                    pr.offset += to_copy;
                    let packet_len = pr.packet.data.len();
                    let fully_consumed = pr.offset >= packet_len;

                    if fully_consumed {
                        rx.partial_read = None;
                        self.account_rx_dequeued(packet_len);
                    }

                    drop(rx);

                    if fully_consumed {
                        let _ = self.send_credit_update();
                    }
                    return Ok(to_copy);
                }

                // Try to get a new packet
                if let Some(packet) = rx.pending_packets.pop_front() {
                    let data_len = packet.data.len();
                    let to_copy = buf.len().min(data_len);
                    buf[..to_copy].copy_from_slice(&packet.data.as_slice()[..to_copy]);

                    if to_copy < data_len {
                        rx.partial_read = Some(PartialRead {
                            packet,
                            offset: to_copy,
                        });
                    } else {
                        self.account_rx_dequeued(data_len);
                    }

                    drop(rx);

                    if to_copy == data_len {
                        let _ = self.send_credit_update();
                    }
                    return Ok(to_copy);
                }
            }

            // No data available
            let current_state = self.state.load();
            if current_state == SocketState::ShutdownPeer {
                return Ok(0); // EOF
            }

            if self.nonblocking.load(Ordering::Relaxed) {
                return_errno!(Errno::EAGAIN);
            }

            // Prefer local queue check first; this avoids stalling on global
            // service locks when this socket already has pending data.
            {
                let rx = self.rx_data.lock();
                if !rx.pending_packets.is_empty() || rx.partial_read.is_some() {
                    continue;
                }
            }
            // Progress fallback before sleeping.
            super::service_pending_packets();
            {
                let rx = self.rx_data.lock();
                if !rx.pending_packets.is_empty() || rx.partial_read.is_some() {
                    continue;
                }
            }

            let has_data = self.wait_for_recv_data_or_state_change()?;
            if !has_data {
                return Ok(0);
            }
        }
    }

    /// Shutdown socket
    pub fn shutdown(&self, _how: i32) -> Result<()> {
        let state = self.state.load();
        let new_state = match state {
            SocketState::Connected => SocketState::ShutdownLocal,
            SocketState::ShutdownPeer => SocketState::Shutdown,
            SocketState::ShutdownLocal | SocketState::Shutdown => {
                return Ok(()); // Already shutdown
            }
            _ => {
                return_errno_with_message!(Errno::ENOTCONN, "not connected");
            }
        };

        self.state.store(new_state);

        // Send shutdown notification
        if let (Some(local), Some(peer)) = (self.local_addr.load(), self.peer_addr.load()) {
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
        let state = self.state.load();
        let was_connected = state == SocketState::Connected || state == SocketState::ShutdownPeer;

        if was_connected {
            if let (Some(local), Some(peer)) = (self.local_addr.load(), self.peer_addr.load()) {
                let packet = create_rst(local.cid, local.port, peer.cid, peer.port);
                let _ = super::submit_control_packet(packet);

                super::unregister_connection(local.port, peer.cid, peer.port);
            }
        } else {
            if let Some(local) = self.local_addr.load() {
                super::unregister_port(local.port);
            }
        }

        self.state.store(SocketState::Shutdown);
        Ok(())
    }

    /// Handle incoming data packet (called from RX interrupt handler)
    ///
    /// Optimized for minimal critical section:
    /// - Lock-free credit/flow control updates
    /// - Minimal lock hold time for queue operations
    /// - Coalescing moved out of critical path for IRQ context
    ///
    /// IMPORTANT: buf_used check and queue insert are done atomically under
    /// the same lock to prevent race conditions where multiple packets pass
    /// the buf_used check but then overflow the queue.
    pub fn on_data_packet_received(&self, packet: RRef<DataPacket>, _vcpu_id: usize) {
        let _trace = trace::TraceGuard::new(&trace::GUEST_SOCKET_ON_DATA);
        let data_len = packet.data.len() as u32;
        let src_port = packet.header.src_port;

        // Update peer credit info (lock-free)
        self.peer_buf_alloc
            .store(packet.header.buf_alloc, Ordering::Relaxed);
        self.update_peer_fwd_cnt(packet.header.fwd_cnt);

        let lock_start = trace::now_cycles();
        let mut rx_lock_wait_cycles = 0u64;
        // Critical section: check buf_used AND enqueue atomically
        // This prevents race where multiple packets pass buf_used check but overflow queue
        let should_wake = {
            let mut rx = self.rx_data.lock();
            rx_lock_wait_cycles = trace::now_cycles().wrapping_sub(lock_start);

            // Check queue capacity first (fast path rejection)
            if rx.pending_packets.len() >= MAX_PENDING_PACKETS {
                drop(rx);

                aster_framevisor::println!(
                    "[FrameVM] FATAL: RX pending queue overflow from port {} (len={}, queue_len={}). Reset connection.",
                    src_port,
                    data_len,
                    MAX_PENDING_PACKETS
                );

                self.reset_connected_socket();
                return;
            }

            // Reserve RX buffer space with CAS to avoid false overflow under
            // concurrent dequeue progress (buf_used can change outside rx lock).
            let mut reserved = self.try_inc_buf_used(data_len);
            if !reserved {
                // In rare cases dequeue accounting can advance concurrently right
                // around this check. Retry briefly to avoid spurious fail-fast reset.
                for _ in 0..RX_OVERFLOW_RETRY_SPINS {
                    core::hint::spin_loop();
                    if self.try_inc_buf_used(data_len) {
                        reserved = true;
                        self.rx_overflow_retry_successes
                            .fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
            }

            if !reserved {
                let buf_alloc = self.buf_alloc.load(Ordering::Acquire);
                let current_used = self.buf_used.load(Ordering::Acquire);
                let fwd_cnt = self.fwd_cnt.load(Ordering::Acquire);
                let advertised_buf_alloc = self.advertised_buf_alloc();
                let pending_pkts = rx.pending_packets.len();
                let partial_read_bytes = rx
                    .partial_read
                    .as_ref()
                    .map(|pr| pr.packet.data.len().saturating_sub(pr.offset))
                    .unwrap_or(0usize);
                let pending_bytes_est: usize =
                    rx.pending_packets.iter().map(|pkt| pkt.data.len()).sum();
                let overflow_cnt = self.rx_overflow_events.fetch_add(1, Ordering::Relaxed) + 1;
                let near_full_cnt = self.rx_near_full_events.load(Ordering::Relaxed);
                let retry_successes = self.rx_overflow_retry_successes.load(Ordering::Relaxed);
                aster_framevisor::println!(
                    "[FrameVM] FATAL: RX buffer overflow from port {} (len={}, buf_used={}, buf_alloc={}, adv_buf_alloc={}, fwd_cnt={}, pending_pkts={}, pending_bytes_est={}, partial_read_bytes={}, pkt_fwd_cnt={}, pkt_buf_alloc={}, lock_wait_cycles={}, near_full_cnt={}, overflow_cnt={}, retry_successes={}). Reset connection.",
                    src_port,
                    data_len,
                    current_used,
                    buf_alloc,
                    advertised_buf_alloc,
                    fwd_cnt,
                    pending_pkts,
                    pending_bytes_est,
                    partial_read_bytes,
                    packet.header.fwd_cnt,
                    packet.header.buf_alloc,
                    rx_lock_wait_cycles,
                    near_full_cnt,
                    overflow_cnt,
                    retry_successes
                );
                drop(rx);

                self.reset_connected_socket();
                return;
            }

            let buf_alloc = self.buf_alloc.load(Ordering::Acquire);
            let near_full_watermark = Self::rx_near_full_watermark(buf_alloc);
            let buf_used_after_reserve = self.buf_used.load(Ordering::Acquire);
            if buf_used_after_reserve >= near_full_watermark {
                self.rx_near_full_events.fetch_add(1, Ordering::Relaxed);
            }

            // Buffer space reserved; enqueue packet.
            rx.pending_packets.push_back(packet);

            // Check waiters while holding lock to avoid race
            self.recv_waiters.load(Ordering::Acquire) > 0
        }; // Lock released here

        // Wake outside of lock to reduce contention
        if should_wake {
            self.wait_queue.wake_one();
        }
    }

    /// Handle incoming control packet
    pub fn on_control_packet_received(&self, packet: RRef<ControlPacket>) {
        let _trace = trace::TraceGuard::new(&trace::GUEST_SOCKET_ON_CONTROL);
        let op = packet.operation();

        match op {
            VsockOp::Response => {
                self.peer_buf_alloc
                    .store(packet.header.buf_alloc, Ordering::Release);
                self.update_peer_fwd_cnt(packet.header.fwd_cnt);

                self.state
                    .compare_exchange(SocketState::Connecting, SocketState::Connected);
                self.wait_queue.wake_all();
            }
            VsockOp::Shutdown => {
                let state = self.state.load();
                let new_state = match state {
                    SocketState::Connected => SocketState::ShutdownPeer,
                    SocketState::ShutdownLocal => SocketState::Shutdown,
                    _ => state,
                };
                self.state.store(new_state);
                self.wait_queue.wake_all();
            }
            VsockOp::Rst => {
                let _old_state = self.state.load();
                self.state.store(SocketState::Shutdown);
                {
                    let mut rx = self.rx_data.lock();
                    rx.pending_packets.clear();
                    rx.partial_read = None;
                }
                if let (Some(local), Some(peer)) = (self.local_addr.load(), self.peer_addr.load()) {
                    super::unregister_connection(local.port, peer.cid, peer.port);
                }
                self.wait_queue.wake_all();
            }
            VsockOp::CreditUpdate => {
                self.peer_buf_alloc
                    .store(packet.header.buf_alloc, Ordering::Release);
                self.update_peer_fwd_cnt(packet.header.fwd_cnt);

                if self.available_credit() > 0 {
                    self.wait_queue.wake_all();
                }
            }
            VsockOp::CreditRequest => {
                if packet.header.buf_alloc != 0 {
                    self.peer_buf_alloc
                        .store(packet.header.buf_alloc, Ordering::Release);
                    self.update_peer_fwd_cnt(packet.header.fwd_cnt);
                    if self.available_credit() > 0 {
                        self.wait_queue.wake_all();
                    }
                }

                // Forward-progress guard:
                // if sender is actively asking for credit while this socket has
                // buffered RX data, nudge one blocked receiver to re-check queue.
                let should_wake_recv = if self.recv_waiters.load(Ordering::Acquire) > 0 {
                    let rx = self.rx_data.lock();
                    rx.partial_read.is_some() || !rx.pending_packets.is_empty()
                } else {
                    false
                };
                if should_wake_recv {
                    self.wait_queue.wake_all();
                }

                // Pre-accept admission control: keep advertised receive window at
                // zero until user space accepts this passive child connection.
                if !self.accepted.load(Ordering::Acquire) {
                    let _ = self.send_credit_update_with_buf_alloc(0);
                    return;
                }

                let _ = self.send_credit_update();
            }
            VsockOp::Request => {
                let state = self.state.load();
                if state != SocketState::Listening {
                    self.send_rst_to_peer(packet.header.src_cid, packet.header.src_port);
                    return;
                }

                let peer_addr = FrameVsockAddr::new(packet.header.src_cid, packet.header.src_port);
                let Some(local_addr) = self.local_addr.load() else {
                    self.send_rst_to_peer(packet.header.src_cid, packet.header.src_port);
                    return;
                };

                // Linux-like idempotency for retransmitted connection requests:
                // if a passive child for the same tuple already exists, do not
                // create/overwrite another socket. Re-send response and keep the
                // existing connection mapping stable.
                if let Some(existing) =
                    super::get_socket_by_connection(local_addr.port, peer_addr.cid, peer_addr.port)
                {
                    let existing_state = existing.state();
                    if matches!(
                        existing_state,
                        SocketState::Connected
                            | SocketState::ShutdownPeer
                            | SocketState::Connecting
                    ) {
                        existing.set_peer_credit(packet.header.buf_alloc, packet.header.fwd_cnt);
                        existing.send_response();
                        return;
                    }

                    // Stale entry in non-connected state; replace it with a new child.
                    super::unregister_connection(local_addr.port, peer_addr.cid, peer_addr.port);
                }

                let conn = Arc::new(FrameVsockSocket::new_connected(local_addr, peer_addr));
                conn.set_peer_credit(packet.header.buf_alloc, packet.header.fwd_cnt);

                super::register_connection(
                    local_addr.port,
                    peer_addr.cid,
                    peer_addr.port,
                    conn.clone(),
                );

                if self.push_pending_connection(conn.clone()).is_ok() {
                    conn.send_response();
                } else {
                    super::unregister_connection(local_addr.port, peer_addr.cid, peer_addr.port);
                    self.send_rst_to_peer(packet.header.src_cid, packet.header.src_port);
                }
            }
            _ => {}
        }
    }

    /// Push pending connection
    pub fn push_pending_connection(&self, conn: Arc<FrameVsockSocket>) -> Result<()> {
        let mut pending = self.pending_connections.lock();
        let backlog = self.backlog.load(Ordering::Relaxed) as usize;
        if pending.len() >= backlog {
            return_errno_with_message!(Errno::ECONNREFUSED, "backlog full");
        }
        pending.push_back(conn);
        drop(pending);
        self.wait_queue.wake_all();
        Ok(())
    }

    /// Pop next valid pending connection for accept().
    ///
    /// Closed/stale children may remain in pending queue after fail-fast reset.
    /// Skip them so accept() doesn't return unusable sockets.
    fn pop_next_pending_connection(&self) -> Option<Arc<FrameVsockSocket>> {
        let mut pending = self.pending_connections.lock();
        while let Some(conn) = pending.pop_front() {
            let state = conn.state();
            if matches!(state, SocketState::Connected | SocketState::ShutdownPeer) {
                conn.accepted.store(true, Ordering::Release);
                // Open full receive window only after accept() hands the child
                // socket to user space.
                let _ = conn.send_credit_update();
                return Some(conn);
            }
        }
        None
    }

    /// Set non-blocking mode
    pub fn set_nonblocking(&self, nonblocking: bool) {
        self.nonblocking.store(nonblocking, Ordering::Relaxed);
    }

    /// Check if non-blocking
    pub fn is_nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Relaxed)
    }

    /// Check if socket has data available
    pub fn has_data(&self) -> bool {
        let rx = self.rx_data.lock();
        rx.partial_read.is_some() || !rx.pending_packets.is_empty()
    }

    /// Check if socket can write
    pub fn can_write(&self) -> bool {
        let state = self.state.load();
        matches!(state, SocketState::Connected) && self.available_credit() > 0
    }

    /// Get pending packet count
    pub fn pending_packet_count(&self) -> usize {
        self.rx_data.lock().pending_packets.len()
    }

    /// Get buffer allocation value
    #[inline]
    pub fn get_buf_alloc(&self) -> u32 {
        self.buf_alloc.load(Ordering::Relaxed)
    }

    /// Get forward count value
    #[inline]
    pub fn get_fwd_cnt(&self) -> u32 {
        self.fwd_cnt.load(Ordering::Relaxed) as u32
    }

    /// Set peer credit info
    pub fn set_peer_credit(&self, buf_alloc: u32, fwd_cnt: u32) {
        self.peer_buf_alloc.store(buf_alloc, Ordering::Release);
        self.update_peer_fwd_cnt(fwd_cnt);
    }

    /// Send connection response
    pub fn send_response(&self) {
        let local = match self.local_addr.load() {
            Some(addr) => addr,
            None => return,
        };
        let peer = match self.peer_addr.load() {
            Some(addr) => addr,
            None => return,
        };

        let fwd_cnt = self.fwd_cnt.load(Ordering::Acquire);

        let mut packet = ControlPacket::with_header(
            local.cid,
            peer.cid,
            local.port,
            peer.port,
            VsockOp::Response,
        );
        // Keep initial credit window closed until accept() completes.
        packet.header.buf_alloc = if self.accepted.load(Ordering::Acquire) {
            self.advertised_buf_alloc()
        } else {
            0
        };
        packet.header.fwd_cnt = fwd_cnt as u32;

        let _ = super::submit_control_packet(RRef::new(packet));
    }

    /// Send RST to reject a connection
    fn send_rst_to_peer(&self, peer_cid: u64, peer_port: u32) {
        let local = match self.local_addr.load() {
            Some(addr) => addr,
            None => return,
        };

        let packet = create_rst(local.cid, local.port, peer_cid, peer_port);
        let _ = super::submit_control_packet(packet);
    }

    /// Reset a connected socket and unregister it from connection index.
    fn reset_connected_socket(&self) {
        if let (Some(local), Some(peer)) = (self.local_addr.load(), self.peer_addr.load()) {
            self.send_rst_to_peer(peer.cid, peer.port);
            super::unregister_connection(local.port, peer.cid, peer.port);
        }
        self.state.store(SocketState::Shutdown);
        {
            let mut rx = self.rx_data.lock();
            rx.pending_packets.clear();
            rx.partial_read = None;
        }
        self.wait_queue.wake_all();
    }
}
