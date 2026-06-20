// SPDX-License-Identifier: MPL-2.0

//! Connected socket state for FrameVsock
//!
//! # Zero-Copy Design
//!
//! - Incoming data packets are stored as RRef<DataPacket> in a queue
//! - No intermediate buffer copies (RingBuffer removed)
//! - The only copy happens at syscall boundary between user space and kernel space
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

mod basic;
mod recv;
mod send;
mod shutdown;
mod utils;

use aster_framevisor_exchangeable::RRef;
use aster_framevsock::{ConnectionId, DataPacket, flow_control::DEFAULT_BUF_ALLOC};

use crate::{net::socket::framevsock::addr::FrameVsockAddr, prelude::*, process::signal::Pollee};

// ============================================================================
// Cache-line padding for SMP optimization
// ============================================================================

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

/// RX state - protected by rx_state lock
struct RxState {
    /// Pending data packets (zero-copy: stored as RRef)
    pending_packets: VecDeque<RRef<DataPacket>>,
    /// Partial read state (for when user buffer is smaller than packet)
    partial_read: Option<recv::PartialRead>,
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
    /// Our forward count in consumed bytes - lock-free atomic access
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
    /// Peer closed its send side, so local reads drain to EOF.
    peer_send_shutdown: core::sync::atomic::AtomicBool,
    /// Peer closed its receive side, so local sends cannot progress.
    peer_recv_shutdown: core::sync::atomic::AtomicBool,
    /// The connection was reset instead of orderly shut down.
    connection_reset: core::sync::atomic::AtomicBool,
    /// Pending socket error reported through `SO_ERROR`.
    error: SpinLock<Option<Error>>,
    /// Local read side has been shut down.
    local_read_shutdown: core::sync::atomic::AtomicBool,
    /// Local write side has been shut down.
    local_write_shutdown: core::sync::atomic::AtomicBool,
    /// Whether this connection owns and should recycle its local port.
    owns_local_port: bool,
    pollee: Pollee,
}

impl Connected {
    /// Create with initial peer credit info (from connection request)
    pub fn new_with_credit(
        peer_addr: FrameVsockAddr,
        local_addr: FrameVsockAddr,
        peer_buf_alloc: u32,
        peer_fwd_cnt: u32,
    ) -> Self {
        Self::new_with_credit_and_port_ownership(
            peer_addr,
            local_addr,
            peer_buf_alloc,
            peer_fwd_cnt,
            true,
        )
    }

    pub fn new_passive_with_credit(
        peer_addr: FrameVsockAddr,
        local_addr: FrameVsockAddr,
        peer_buf_alloc: u32,
        peer_fwd_cnt: u32,
    ) -> Self {
        Self::new_with_credit_and_port_ownership(
            peer_addr,
            local_addr,
            peer_buf_alloc,
            peer_fwd_cnt,
            false,
        )
    }

    fn new_with_credit_and_port_ownership(
        peer_addr: FrameVsockAddr,
        local_addr: FrameVsockAddr,
        peer_buf_alloc: u32,
        peer_fwd_cnt: u32,
        owns_local_port: bool,
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
            peer_send_shutdown: core::sync::atomic::AtomicBool::new(false),
            peer_recv_shutdown: core::sync::atomic::AtomicBool::new(false),
            connection_reset: core::sync::atomic::AtomicBool::new(false),
            error: SpinLock::new(None),
            local_read_shutdown: core::sync::atomic::AtomicBool::new(false),
            local_write_shutdown: core::sync::atomic::AtomicBool::new(false),
            owns_local_port,
            pollee: Pollee::new(),
        }
    }
}
