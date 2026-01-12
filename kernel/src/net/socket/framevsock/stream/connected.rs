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
//!
//! # SMP Optimizations
//!
//! - Cache-line padded fields to prevent false sharing between CPUs
//! - RX and TX paths use separate locks and separate cache lines
//! - Minimized lock hold times during data copy operations

use alloc::{collections::VecDeque, vec::Vec};
use core::hash::Hasher;

use aster_framevisor::vsock as framevisor_vsock;
use aster_framevisor_exchangeable::RRef;
use aster_framevsock::{
    ConnectionId, DataPacket, SHUTDOWN_FLAG_BOTH, create_credit_request, create_credit_update,
    create_data_packet_with_credit, create_rst, create_shutdown,
    flow_control::{DEFAULT_BUF_ALLOC, MAX_PENDING_PACKETS, MAX_PKT_BUF_SIZE},
    trace,
};
use log::error;

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

// ============================================================================
// Cache-line padding for SMP optimization
// ============================================================================

/// Cache line size for x86_64/aarch64
const CACHE_LINE_SIZE: usize = 64;

/// Retry interval for credit requests when no credit update is received.
///
/// Keep this conservative to avoid control-plane storms under single-vCPU
/// contention. Linux virtio-vsock relies on reliable transport delivery and
/// does not aggressively resend credit requests in tight loops.
const CREDIT_REQUEST_RETRY_NS: u64 = 5_000_000; // 5ms

/// Cache-line padded wrapper to prevent false sharing between CPUs.
///
/// When multiple atomic variables or locks are accessed by different CPUs,
/// placing them in the same cache line causes "false sharing" - the cache
/// line bounces between CPUs even though they access different fields.
#[repr(C, align(64))]
struct CachePadded<T> {
    value: T,
}

impl<T> CachePadded<T> {
    const fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T> core::ops::Deref for CachePadded<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T> core::ops::DerefMut for CachePadded<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

// ============================================================================
// State structures
// ============================================================================

/// Partial read state - tracks remaining data from a partially consumed packet
struct PartialRead {
    /// The packet being partially read
    packet: RRef<DataPacket>,
    /// Offset into the packet's data
    offset: usize,
}

enum PendingRead {
    Partial(PartialRead),
    Packet(RRef<DataPacket>),
}

impl PendingRead {
    fn remaining_data(&self) -> &[u8] {
        match self {
            Self::Partial(partial) => &partial.packet.data.as_slice()[partial.offset..],
            Self::Packet(packet) => packet.data.as_slice(),
        }
    }

    fn total_packet_len(&self) -> usize {
        match self {
            Self::Partial(partial) => partial.packet.data.len(),
            Self::Packet(packet) => packet.data.len(),
        }
    }

    fn into_partial_read(self, bytes_written: usize) -> PartialRead {
        match self {
            Self::Partial(mut partial) => {
                partial.offset += bytes_written;
                partial
            }
            Self::Packet(packet) => PartialRead {
                packet,
                offset: bytes_written,
            },
        }
    }

    fn restore_no_progress(self, rx: &mut RxState) {
        match self {
            Self::Partial(partial) => rx.partial_read = Some(partial),
            Self::Packet(packet) => rx.pending_packets.push_front(packet),
        }
    }
}

/// RX state - protected by rx_state lock
struct RxState {
    /// Pending data packets (zero-copy: stored as RRef)
    pending_packets: VecDeque<RRef<DataPacket>>,
    /// Partial read state (for when user buffer is smaller than packet)
    partial_read: Option<PartialRead>,
    /// Last fwd_cnt when we sent credit update
    last_credit_update_fwd_cnt: u64,
    /// Total bytes currently buffered (for Linux-style credit update)
    buf_used: u32,
}

/// TX state - protected by tx_state lock
struct TxState {
    /// Total bytes we've sent
    tx_cnt: u64,
    /// Whether we have a pending credit request (to avoid busy-loop)
    credit_request_pending: bool,
    /// Last TSC timestamp when credit request was sent successfully
    last_credit_request_tsc: u64,
    /// Whether TX is currently blocked by backend queue pressure.
    ///
    /// This is orthogonal to peer credit. When set, `OUT` should not be
    /// reported until we observe a control-path progress signal.
    tx_blocked_on_queue: bool,
    /// Monotonic progress epoch for TX forward progress.
    ///
    /// Incremented on signals that indicate send side may have become
    /// unblocked (credit updates, backend queue drain, successful enqueue).
    tx_progress_epoch: u64,
}

/// Peer credit info - updated atomically without lock
struct PeerCredit {
    /// Peer's buffer allocation
    peer_buf_alloc: core::sync::atomic::AtomicU32,
    /// Peer's forward count low 32 bits (Linux virtio-vsock semantics).
    peer_fwd_cnt: core::sync::atomic::AtomicU64,
}

// ============================================================================
// Connected socket - cache-line optimized layout
// ============================================================================

/// Connected socket state with cache-line optimized layout for SMP performance.
///
/// Fields are grouped and padded to prevent false sharing:
/// - RX-related fields (accessed by receiver CPU) are in their own cache line(s)
/// - TX-related fields (accessed by sender CPU) are in their own cache line(s)
/// - Read-only fields (id, cached_vcpu_id) don't need padding
pub struct Connected {
    // === RX path fields (receiver CPU) - cache line 1 ===
    /// RX state - separate lock for receive path
    rx_state: CachePadded<SpinLock<RxState>>,

    // === RX atomic counters - cache line 2 ===
    /// Our buffer allocation - lock-free atomic access
    buf_alloc: CachePadded<core::sync::atomic::AtomicU32>,
    /// Our forward count (已消费的字节数) - lock-free atomic access
    fwd_cnt: CachePadded<core::sync::atomic::AtomicU64>,

    // === TX path fields (sender CPU) - cache line 3 ===
    /// TX state - separate lock for send path
    tx_state: CachePadded<SpinLock<TxState>>,

    // === TX peer credit (sender reads) - cache line 4 ===
    /// Peer credit info - lock-free atomic access
    peer_credit: CachePadded<PeerCredit>,

    // === Shared/read-only fields (no padding needed) ===
    /// Connection ID (immutable after creation)
    id: ConnectionId,
    /// Cached vCPU ID for this connection (computed once at creation)
    cached_vcpu_id: usize,
    /// Peer requested shutdown - lock-free atomic access
    peer_requested_shutdown: core::sync::atomic::AtomicBool,
    /// Local shutdown - lock-free atomic access
    local_shutdown: core::sync::atomic::AtomicBool,
    pollee: Pollee,
}

use core::sync::atomic::Ordering;

impl Connected {
    pub fn new(peer_addr: FrameVsockAddr, local_addr: FrameVsockAddr) -> Self {
        let id = ConnectionId::from_addrs(local_addr, peer_addr);
        let cached_vcpu_id = Self::compute_vcpu_id(&id);
        Self {
            // RX path fields (cache line 1)
            rx_state: CachePadded::new(SpinLock::new(RxState {
                pending_packets: VecDeque::with_capacity(256),
                partial_read: None,
                last_credit_update_fwd_cnt: 0,
                buf_used: 0,
            })),
            // RX atomic counters (cache line 2)
            buf_alloc: CachePadded::new(core::sync::atomic::AtomicU32::new(DEFAULT_BUF_ALLOC)),
            fwd_cnt: CachePadded::new(core::sync::atomic::AtomicU64::new(0)),
            // TX path fields (cache line 3)
            tx_state: CachePadded::new(SpinLock::new(TxState {
                tx_cnt: 0,
                credit_request_pending: false,
                last_credit_request_tsc: 0,
                tx_blocked_on_queue: false,
                tx_progress_epoch: 0,
            })),
            // TX peer credit (cache line 4)
            peer_credit: CachePadded::new(PeerCredit {
                peer_buf_alloc: core::sync::atomic::AtomicU32::new(DEFAULT_BUF_ALLOC),
                peer_fwd_cnt: core::sync::atomic::AtomicU64::new(0),
            }),
            // Shared/read-only fields
            id,
            cached_vcpu_id,
            peer_requested_shutdown: core::sync::atomic::AtomicBool::new(false),
            local_shutdown: core::sync::atomic::AtomicBool::new(false),
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
        let id = ConnectionId::from_addrs(local_addr, peer_addr);
        let cached_vcpu_id = Self::compute_vcpu_id(&id);

        Self {
            // RX path fields (cache line 1)
            rx_state: CachePadded::new(SpinLock::new(RxState {
                pending_packets: VecDeque::with_capacity(256),
                partial_read: None,
                last_credit_update_fwd_cnt: 0,
                buf_used: 0,
            })),
            // RX atomic counters (cache line 2)
            buf_alloc: CachePadded::new(core::sync::atomic::AtomicU32::new(DEFAULT_BUF_ALLOC)),
            fwd_cnt: CachePadded::new(core::sync::atomic::AtomicU64::new(0)),
            // TX path fields (cache line 3)
            tx_state: CachePadded::new(SpinLock::new(TxState {
                tx_cnt: 0,
                credit_request_pending: false,
                last_credit_request_tsc: 0,
                tx_blocked_on_queue: false,
                tx_progress_epoch: 0,
            })),
            // TX peer credit (cache line 4)
            peer_credit: CachePadded::new(PeerCredit {
                // Keep explicit zero-credit advertisement from peer so
                // pre-accept admission control can close the send window.
                peer_buf_alloc: core::sync::atomic::AtomicU32::new(peer_buf_alloc),
                peer_fwd_cnt: core::sync::atomic::AtomicU64::new(peer_fwd_cnt as u64),
            }),
            // Shared/read-only fields
            id,
            cached_vcpu_id,
            peer_requested_shutdown: core::sync::atomic::AtomicBool::new(false),
            local_shutdown: core::sync::atomic::AtomicBool::new(false),
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

    /// Snapshot current TX progress epoch.
    #[inline]
    pub fn tx_progress_epoch(&self) -> u64 {
        self.tx_state.disable_irq().lock().tx_progress_epoch
    }

    /// Whether TX is currently blocked by backend queue pressure.
    #[inline]
    pub fn is_tx_blocked_on_queue(&self) -> bool {
        self.tx_state.disable_irq().lock().tx_blocked_on_queue
    }

    pub fn id(&self) -> ConnectionId {
        self.id
    }

    /// Cached vCPU mapping for this connection.
    #[inline]
    pub fn cached_vcpu_id(&self) -> usize {
        self.cached_vcpu_id
    }

    /// Get our buffer allocation (for credit info in packets)
    pub fn buf_alloc(&self) -> u32 {
        self.buf_alloc.load(Ordering::Acquire)
    }

    /// Get our forward count (for credit info in packets)
    pub fn fwd_cnt(&self) -> u32 {
        self.fwd_cnt.load(Ordering::Acquire) as u32
    }

    /// Calculate available credit to send to peer (lock-free with proper SMP ordering)
    fn available_credit(&self, tx_cnt: u64) -> u32 {
        let peer_fwd_cnt = self.peer_credit.peer_fwd_cnt.load(Ordering::Acquire);
        let peer_buf_alloc = self.peer_credit.peer_buf_alloc.load(Ordering::Acquire);
        Self::calc_available_credit(tx_cnt, peer_buf_alloc, peer_fwd_cnt)
    }

    #[inline]
    fn calc_available_credit(tx_cnt: u64, peer_buf_alloc: u32, peer_fwd_cnt: u64) -> u32 {
        if peer_fwd_cnt >= tx_cnt {
            // peer consumed everything in flight (or credit update arrived
            // slightly ahead of tx_cnt update due to SMP ordering).
            // Full send window is available.
            return peer_buf_alloc;
        }
        let in_flight = tx_cnt - peer_fwd_cnt;
        if in_flight > peer_buf_alloc as u64 {
            0
        } else {
            (peer_buf_alloc as u64 - in_flight) as u32
        }
    }

    #[inline]
    fn credit_request_retry_cycles() -> u64 {
        let freq = ostd::arch::tsc_freq();
        if freq == 0 {
            return 0;
        }

        (((freq as u128) * (CREDIT_REQUEST_RETRY_NS as u128)) / 1_000_000_000u128).max(1) as u64
    }

    #[inline]
    fn should_send_credit_request(tx: &TxState, now_tsc: u64) -> bool {
        if !tx.credit_request_pending {
            return true;
        }

        let retry_cycles = Self::credit_request_retry_cycles();
        if retry_cycles == 0 {
            return true;
        }

        now_tsc.wrapping_sub(tx.last_credit_request_tsc) >= retry_cycles
    }

    /// Update peer_fwd_cnt, reconstructing the full u64 from the u32 wire value.
    ///
    /// The vsock protocol transmits fwd_cnt as u32, but tx_cnt is u64.
    /// We reconstruct the high bits using tx_cnt as an upper bound:
    /// peer_fwd_cnt can never exceed tx_cnt (peer can't consume more than sent).
    ///
    /// Algorithm:
    /// 1. Start with prev_high (high 32 bits of previous peer_fwd_cnt)
    /// 2. Combine with new_low to get candidate
    /// 3. If candidate > tx_cnt, it's impossible - try prev_high (no wrap yet)
    /// 4. If candidate < prev, check if wrapping up makes sense (candidate + 2^32 <= tx_cnt)
    ///
    /// Uses CAS loop for thread safety — concurrent credit updates from
    /// different vCPUs can call this for the same connection.
    ///
    /// `tx_cnt` must be passed by caller to avoid lock ordering issues.
    fn update_peer_fwd_cnt(&self, new_low: u32, tx_cnt: u64) {
        loop {
            let prev = self.peer_credit.peer_fwd_cnt.load(Ordering::Acquire);
            let prev_high = prev & !0xFFFF_FFFF_u64;

            // Try same high bits first
            let candidate = prev_high | (new_low as u64);

            let new_full = if candidate > tx_cnt {
                // Impossible: peer can't consume more than sent.
                // This means new_low hasn't wrapped yet, use lower high bits.
                if prev_high == 0 {
                    // Can't go lower, this update is stale/invalid
                    return;
                }
                (prev_high - (1u64 << 32)) | (new_low as u64)
            } else if candidate < prev {
                // new_low appears to go backward. Check if wrap-around makes sense.
                let wrapped = prev_high.wrapping_add(1u64 << 32) | (new_low as u64);
                if wrapped <= tx_cnt {
                    wrapped
                } else {
                    // Wrapped value exceeds tx_cnt, this is a stale update
                    return;
                }
            } else {
                candidate
            };

            // Sanity: new value should not exceed tx_cnt
            if new_full > tx_cnt {
                return;
            }

            // Only accept if it advances (or equals for idempotent updates)
            if new_full < prev {
                return;
            }

            if self
                .peer_credit
                .peer_fwd_cnt
                .compare_exchange_weak(prev, new_full, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Receive data to a MultiWrite (user buffer)
    ///
    /// Zero-copy path:
    /// 1. Get packet from pending queue (RRef<DataPacket>)
    /// 2. Copy data directly from packet to user buffer (ONE copy)
    pub fn try_recv(&self, writer: &mut dyn MultiWrite) -> Result<usize> {
        let _trace = trace::TraceGuard::new(&trace::HOST_TRY_RECV);
        let mut total_written = 0usize;
        let mut terminal_result = None;

        loop {
            let Some(pending_read) = ({
                let mut rx = self.rx_state.disable_irq().lock();
                if let Some(partial) = rx.partial_read.take() {
                    Some(PendingRead::Partial(partial))
                } else {
                    rx.pending_packets.pop_front().map(PendingRead::Packet)
                }
            }) else {
                break;
            };

            let remaining = pending_read.remaining_data();
            let remaining_len = remaining.len();
            let mut vm_reader = ostd::mm::VmReader::from(remaining);
            let before = writer.sum_lens();
            let bytes_written = match writer.write(&mut vm_reader) {
                Ok(n) => n,
                Err(e) => {
                    let after = writer.sum_lens();
                    let progressed = before.saturating_sub(after).min(remaining_len);
                    let mut rx = self.rx_state.disable_irq().lock();

                    if progressed > 0 {
                        total_written += progressed;
                        if progressed < remaining_len {
                            rx.partial_read = Some(pending_read.into_partial_read(progressed));
                        } else {
                            let packet_len = pending_read.total_packet_len() as u32;
                            self.fwd_cnt.fetch_add(packet_len as u64, Ordering::Relaxed);
                            rx.buf_used = rx.buf_used.saturating_sub(packet_len);
                        }
                        terminal_result = Some(Ok(total_written));
                        break;
                    }

                    pending_read.restore_no_progress(&mut rx);
                    terminal_result = Some(if total_written > 0 {
                        Ok(total_written)
                    } else {
                        Err(e)
                    });
                    break;
                }
            };

            total_written += bytes_written;
            let mut rx = self.rx_state.disable_irq().lock();

            // If packet not fully consumed, save for partial read
            if bytes_written < remaining_len {
                rx.partial_read = Some(pending_read.into_partial_read(bytes_written));
                break;
            } else {
                // Fully consumed: release credit for the whole packet.
                let packet_len = pending_read.total_packet_len() as u32;
                self.fwd_cnt.fetch_add(packet_len as u64, Ordering::Relaxed);
                rx.buf_used = rx.buf_used.saturating_sub(packet_len);
            }
        }

        if total_written > 0 {
            let mut rx = self.rx_state.disable_irq().lock();
            let buf_alloc = self.buf_alloc.load(Ordering::Relaxed);
            self.send_credit_update_internal(&mut rx, buf_alloc);
        }

        if let Some(result) = terminal_result {
            return result;
        }

        // No data available
        let is_peer_shutdown = self.peer_requested_shutdown.load(Ordering::Acquire);
        self.pollee.invalidate();

        if total_written > 0 {
            return Ok(total_written);
        }

        if is_peer_shutdown {
            return_errno_with_message!(Errno::ECONNRESET, "the connection is reset");
        }
        return_errno_with_message!(Errno::EAGAIN, "the receive buffer is empty");
    }

    /// Check if we should send a credit update (Linux-style heuristic).
    ///
    /// Uses the flow_control module's adaptive threshold logic:
    /// - Send update if consumed bytes >= adaptive threshold (1MB for 4MB buffer)
    /// - This reduces credit update frequency from per-packet to ~4 times per buffer cycle
    fn should_send_credit_update_rx(&self, rx: &mut RxState) -> bool {
        let buf_alloc = self.buf_alloc.load(Ordering::Relaxed);
        let fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed) as u32;

        aster_framevsock::flow_control::should_send_credit_update(
            buf_alloc,
            rx.buf_used,
            fwd_cnt,
            rx.last_credit_update_fwd_cnt as u32,
        )
    }

    /// Send credit update (called with rx lock held)
    fn send_credit_update_internal(&self, rx: &mut RxState, buf_alloc: u32) {
        let _trace = trace::TraceGuard::new(&trace::HOST_SEND_CREDIT_UPDATE);
        let fwd_cnt = self.fwd_cnt.load(Ordering::Acquire);
        rx.last_credit_update_fwd_cnt = fwd_cnt;
        let packet = create_credit_update(
            self.local_addr().cid,
            self.local_addr().port,
            self.peer_addr().cid,
            self.peer_addr().port,
            buf_alloc,
            fwd_cnt as u32,
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
    pub fn try_send(
        &self,
        reader: &mut dyn MultiRead,
        _flags: SendRecvFlags,
        pending_packet: &mut Option<RRef<DataPacket>>,
    ) -> Result<usize> {
        let _trace = trace::TraceGuard::new(&trace::HOST_TRY_SEND);

        // Fast fail on closed/reset connection.
        //
        // Without this, send() may loop forever on EAGAIN paths even after
        // connection teardown, especially when credit can no longer progress.
        if self.local_shutdown.load(Ordering::Acquire)
            || self.peer_requested_shutdown.load(Ordering::Acquire)
        {
            return_errno_with_message!(Errno::ECONNRESET, "connection shutdown");
        }

        // Phase 0: flush previously buffered packet first.
        //
        // This preserves stream semantics when previous enqueue failed due to
        // guest RX queue full: caller retries send(), and we must send the same
        // bytes instead of consuming fresh user data.
        if let Some(packet) = pending_packet.take() {
            if self.local_shutdown.load(Ordering::Acquire)
                || self.peer_requested_shutdown.load(Ordering::Acquire)
            {
                return_errno_with_message!(Errno::ECONNRESET, "connection shutdown");
            }

            let mut tx = self.tx_state.disable_irq().lock();
            let pending_len = packet.data.len();
            let available_credit = self.available_credit(tx.tx_cnt) as usize;

            if available_credit < pending_len {
                *pending_packet = Some(packet);
                tx.tx_blocked_on_queue = false;

                let now_tsc = ostd::arch::read_tsc();
                if Self::should_send_credit_request(&tx, now_tsc) {
                    if self.send_credit_request() {
                        tx.credit_request_pending = true;
                        tx.last_credit_request_tsc = now_tsc;
                        tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);
                    } else {
                        // Keep retry path open if request enqueue failed.
                        tx.credit_request_pending = false;
                    }
                }

                drop(tx);
                return_errno_with_message!(Errno::EAGAIN, "no credit available");
            }

            // Remember if we were already blocked to avoid spurious epoch bumps.
            // Epoch should only change on actual state transitions, not on every
            // retry attempt - otherwise the send loop skips waiting.
            let was_blocked = tx.tx_blocked_on_queue;
            tx.tx_cnt = tx.tx_cnt.saturating_add(pending_len as u64);
            tx.tx_blocked_on_queue = false;
            drop(tx);

            let vcpu_id = self.select_vcpu();
            if let Err(packet) = framevisor_vsock::deliver_data_packet(vcpu_id, packet) {
                let mut tx = self.tx_state.disable_irq().lock();
                tx.tx_cnt = tx.tx_cnt.saturating_sub(pending_len as u64);
                // Only increment epoch on first transition to blocked state.
                // Repeated failures while already blocked should NOT bump epoch,
                // otherwise the send loop will skip waiting and spin.
                if !was_blocked {
                    tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);
                }
                tx.tx_blocked_on_queue = true;

                *pending_packet = Some(packet);
                drop(tx);
                return_errno_with_message!(Errno::EAGAIN, "guest queue full, retry later");
            }

            // Success: if we were blocked before, bump epoch to wake waiters.
            if was_blocked {
                let mut tx = self.tx_state.disable_irq().lock();
                tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);
            }

            return Ok(pending_len);
        }

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
                tx.tx_blocked_on_queue = false;

                let now_tsc = ostd::arch::read_tsc();
                if Self::should_send_credit_request(&tx, now_tsc) {
                    if self.send_credit_request() {
                        tx.credit_request_pending = true;
                        tx.last_credit_request_tsc = now_tsc;
                        tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);
                    } else {
                        // Keep retry path open if request enqueue failed.
                        tx.credit_request_pending = false;
                    }
                }

                drop(tx);
                return_errno_with_message!(Errno::EAGAIN, "no credit available");
            }

            // Reserve credit by updating tx_cnt now
            let to_send = buf_len.min(available_credit).min(MAX_PKT_BUF_SIZE as usize);
            tx.tx_cnt = tx.tx_cnt.saturating_add(to_send as u64);
            to_send
            // Lock released here
        };

        // Phase 2: Allocate buffer
        // Allocate exactly what we are going to send.
        //
        // Over-allocating here (e.g. 2x for a 2048-byte payload) can push
        // allocations into page-sized large slots (0x1000), which amplifies
        // allocator pressure under long-running multi-connection workloads.
        let mut data = Vec::with_capacity(to_send);
        data.resize(to_send, 0u8);

        // Phase 3: Read data from user buffer (outside lock - potentially slow)
        let mut vm_writer = ostd::mm::VmWriter::from(data.as_mut_slice());
        let bytes_read = match reader.read(&mut vm_writer) {
            Ok(n) => n,
            Err(e) => {
                // Unreserve credit on failure
                let mut tx = self.tx_state.disable_irq().lock();
                tx.tx_cnt = tx.tx_cnt.saturating_sub(to_send as u64);
                return Err(e);
            }
        };

        // Adjust reservation if we read less than expected
        if bytes_read < to_send {
            let mut tx = self.tx_state.disable_irq().lock();
            tx.tx_cnt = tx.tx_cnt.saturating_sub((to_send - bytes_read) as u64);
        }

        data.truncate(bytes_read);

        // Phase 4: Create and send packet
        let buf_alloc = self.buf_alloc.load(Ordering::Relaxed);
        let fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed);

        let packet = create_data_packet_with_credit(
            self.local_addr().cid,
            self.local_addr().port,
            self.peer_addr().cid,
            self.peer_addr().port,
            data,
            buf_alloc,
            fwd_cnt as u32,
        );

        // Select vCPU and deliver
        let vcpu_id = self.select_vcpu();
        if let Err(packet) = framevisor_vsock::deliver_data_packet(vcpu_id, packet) {
            // Queue full - return EAGAIN so caller can retry, not ECONNRESET
            // This happens when Guest is slow to consume (e.g., during fork)
            // Unreserve the credit we consumed
            let mut tx = self.tx_state.disable_irq().lock();
            tx.tx_cnt = tx.tx_cnt.saturating_sub(bytes_read as u64);
            // Any queue-full result means queue-pressure block.
            if !tx.tx_blocked_on_queue {
                tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);
            }
            tx.tx_blocked_on_queue = true;

            *pending_packet = Some(packet);

            drop(tx);
            return_errno_with_message!(Errno::EAGAIN, "guest queue full, retry later");
        }

        // Successful enqueue means backend queue pressure is relieved.
        let mut tx = self.tx_state.disable_irq().lock();
        tx.tx_blocked_on_queue = false;
        tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);

        Ok(bytes_read)
    }

    /// Handle backend Host->Guest queue drain notification.
    ///
    /// This indicates Guest has popped at least one data packet from the
    /// backend queue, so queue-pressure stalls may now be relieved.
    pub fn on_tx_queue_drained(&self, _queue_reserved_len_before_pop: usize) {
        // Queue-pressure wakeup is already filtered at FrameVsockSpace by
        // full-edge and blocked-state checks. Here we only perform state
        // transition and notify for sockets that were truly blocked.

        let mut tx = self.tx_state.disable_irq().lock();
        if tx.tx_blocked_on_queue {
            tx.tx_blocked_on_queue = false;
            tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);
            drop(tx);

            self.pollee.notify(IoEvents::OUT);
        }
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
        let _trace = trace::TraceGuard::new(&trace::HOST_SHUTDOWN);
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
        let _trace = trace::TraceGuard::new(&trace::HOST_RESET);
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
    ///
    /// IMPORTANT: All checks (buf_used, queue capacity) are done atomically under
    /// the same lock to prevent race conditions.
    ///
    /// Stream sockets must not silently drop data. On RX overflow, reset the
    /// connection so peers fail fast instead of stalling forever.
    pub fn on_data_packet_received(&self, packet: RRef<DataPacket>) -> Result<()> {
        let _trace = trace::TraceGuard::new(&trace::HOST_ON_DATA);
        let src_port = packet.header.src_port;

        // Read tx_cnt for fwd_cnt reconstruction (before locking rx_state)
        let tx_cnt = {
            let tx = self.tx_state.disable_irq().lock();
            tx.tx_cnt
        };

        // Update peer credit info atomically with proper memory ordering for SMP
        self.peer_credit
            .peer_buf_alloc
            .store(packet.header.buf_alloc, Ordering::Release);
        self.update_peer_fwd_cnt(packet.header.fwd_cnt, tx_cnt);

        // Only lock RX state for packet queue operations
        let mut rx = self.rx_state.disable_irq().lock();
        let packet_size = packet.data.len() as u32;

        // Check queue capacity first (fast path rejection)
        if rx.pending_packets.len() >= MAX_PENDING_PACKETS {
            drop(rx);

            error!(
                "[FrameVsock] FATAL: RX pending queue overflow from port {} (len={}, queue_len={}). Reset connection.",
                src_port, packet_size, MAX_PENDING_PACKETS
            );

            let rst_packet = create_rst(
                self.local_addr().cid,
                self.local_addr().port,
                self.peer_addr().cid,
                self.peer_addr().port,
            );
            let vcpu_id = self.select_vcpu();
            let _ = framevisor_vsock::deliver_control_packet(vcpu_id, rst_packet);

            self.peer_requested_shutdown.store(true, Ordering::Release);
            self.local_shutdown.store(true, Ordering::Release);
            self.pollee
                .notify(IoEvents::IN | IoEvents::OUT | IoEvents::ERR | IoEvents::HUP);

            return_errno_with_message!(Errno::ENOBUFS, "receiver queue overflow");
        }

        // Enforce credit window like Linux: reject if RX buffer would overflow.
        let buf_alloc = self.buf_alloc.load(Ordering::Acquire);
        if rx.buf_used.saturating_add(packet_size) > buf_alloc {
            let buf_used = rx.buf_used;
            drop(rx);

            error!(
                "[FrameVsock] FATAL: RX buffer overflow from port {} (buf_used={} + {} > {}). Reset connection.",
                src_port, buf_used, packet_size, buf_alloc
            );

            let rst_packet = create_rst(
                self.local_addr().cid,
                self.local_addr().port,
                self.peer_addr().cid,
                self.peer_addr().port,
            );
            let vcpu_id = self.select_vcpu();
            let _ = framevisor_vsock::deliver_control_packet(vcpu_id, rst_packet);

            self.peer_requested_shutdown.store(true, Ordering::Release);
            self.local_shutdown.store(true, Ordering::Release);
            self.pollee
                .notify(IoEvents::IN | IoEvents::OUT | IoEvents::ERR | IoEvents::HUP);

            return_errno_with_message!(Errno::ENOBUFS, "receiver buffer overflow");
        }

        // Update buf_used for Linux-style credit tracking
        rx.buf_used = rx.buf_used.saturating_add(packet_size);

        // Store packet in pending queue (zero-copy)
        rx.pending_packets.push_back(packet);

        // Check if we should send credit update (with lock held for consistency)
        if self.should_send_credit_update_rx(&mut rx) {
            let buf_alloc = self.buf_alloc.load(Ordering::Acquire);
            self.send_credit_update_internal(&mut rx, buf_alloc);
        }

        drop(rx);

        // Notify both IN and OUT events
        self.pollee.notify(IoEvents::IN | IoEvents::OUT);
        Ok(())
    }

    /// Handle credit update from peer
    pub fn on_credit_update(&self, buf_alloc: u32, fwd_cnt: u32) {
        let _trace = trace::TraceGuard::new(&trace::HOST_ON_CREDIT_UPDATE);

        let prev_peer_buf_alloc = self.peer_credit.peer_buf_alloc.load(Ordering::Acquire);
        let prev_peer_fwd_cnt = self.peer_credit.peer_fwd_cnt.load(Ordering::Acquire);

        let mut tx = self.tx_state.disable_irq().lock();
        let prev_available_credit =
            Self::calc_available_credit(tx.tx_cnt, prev_peer_buf_alloc, prev_peer_fwd_cnt);

        // Update peer credit atomically with proper SMP memory ordering
        self.peer_credit
            .peer_buf_alloc
            .store(buf_alloc, Ordering::Release);
        self.update_peer_fwd_cnt(fwd_cnt, tx.tx_cnt);

        let available_credit = self.available_credit(tx.tx_cnt);
        let credit_advanced = available_credit > prev_available_credit;

        // Only clear pending request when peer credit actually advanced.
        // This avoids CreditRequest/CreditUpdate ping-pong when updates carry
        // no new credit.
        if credit_advanced {
            tx.credit_request_pending = false;
            tx.last_credit_request_tsc = 0;
        }
        // Recovery path for tiny-packet queue pressure:
        // if queue-drain wake was missed but peer credit is moving, reopen TX once.
        let unblocked_by_credit = tx.tx_blocked_on_queue && credit_advanced;
        if unblocked_by_credit {
            tx.tx_blocked_on_queue = false;
        }
        tx.tx_progress_epoch = tx.tx_progress_epoch.wrapping_add(1);

        let can_send_now = available_credit > 0 && !tx.tx_blocked_on_queue;
        drop(tx);

        if can_send_now {
            self.pollee.notify(IoEvents::OUT);
        }
    }

    /// Send credit update to peer
    pub fn send_credit_update(&self) {
        let mut rx = self.rx_state.disable_irq().lock();
        let buf_alloc = self.buf_alloc.load(Ordering::Acquire);
        self.send_credit_update_internal(&mut rx, buf_alloc);
    }

    /// Send credit request to peer to get their credit info
    /// This is used when peer_buf_alloc is 0 (possibly due to race condition during connection setup)
    fn send_credit_request(&self) -> bool {
        let _trace = trace::TraceGuard::new(&trace::HOST_SEND_CREDIT_REQUEST);
        let mut packet = create_credit_request(
            self.local_addr().cid,
            self.local_addr().port,
            self.peer_addr().cid,
            self.peer_addr().port,
        );
        packet.header.buf_alloc = self.buf_alloc.load(Ordering::Acquire);
        packet.header.fwd_cnt = self.fwd_cnt.load(Ordering::Acquire) as u32;
        let vcpu_id = self.select_vcpu();
        framevisor_vsock::deliver_control_packet(vcpu_id, packet).is_ok()
    }

    /// Handle shutdown from peer
    pub fn on_shutdown_received(&self) -> Result<()> {
        self.peer_requested_shutdown.store(true, Ordering::Release);
        self.pollee
            .notify(IoEvents::IN | IoEvents::OUT | IoEvents::HUP);
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
        self.pollee
            .notify(IoEvents::IN | IoEvents::OUT | IoEvents::ERR | IoEvents::HUP);
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
        if available > 0 && !local_shutdown && !tx.tx_blocked_on_queue {
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

    /// Compute vCPU ID using improved distribution (called once at creation)
    ///
    /// Uses XOR of local and peer ports combined with FNV-1a hash for better
    /// distribution across vCPUs, especially when connections have sequential ports.
    fn compute_vcpu_id(id: &ConnectionId) -> usize {
        const FORCE_VCPU0: bool = false;
        if FORCE_VCPU0 {
            return 0;
        }

        // Use FNV-1a hash for better distribution
        // Combine both local and peer info for symmetric connections
        let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
        const FNV_PRIME: u64 = 0x100000001b3;

        // Hash local address
        for byte in id.local_addr.cid.to_le_bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        for byte in id.local_addr.port.to_le_bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        // Hash peer address
        for byte in id.peer_addr.cid.to_le_bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        for byte in id.peer_addr.port.to_le_bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        let vcpu_count = framevisor_vsock::get_vcpu_count().max(1);
        (hash as usize) % vcpu_count
    }
}

/// Simple hasher for vCPU selection.
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

// SimpleHasher removed: vCPU selection is forced to vCPU 0 for now.
