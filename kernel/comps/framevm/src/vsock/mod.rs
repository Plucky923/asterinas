// SPDX-License-Identifier: MPL-2.0

//! FrameVsock module for FrameVM (Guest side)
//!
//! Provides vsock socket for communication between FrameVM and Kernel.
//!
//! # Architecture
//! - TX: Guest synchronously calls `submit_data_packet()` or `submit_control_packet()`
//! - RX: Host pushes to RxQueue, Guest reads in interrupt handler
//!
//! # Zero-Copy Design
//! - Packets are transferred via RRef<DataPacket> or RRef<ControlPacket>
//! - The only copy happens at syscall boundary (user-space ↔ kernel-space)

#![deny(unsafe_code)]

pub mod addr;
pub mod socket;

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use aster_framevisor::{
    iht,
    irq::{FRAMEVSOCK_IRQ_NUM, IrqLine},
};
use aster_framevsock::{ControlPacket, DataPacket, VsockOp, create_rst, trace};
use exchangeable::RRef;
pub use socket::{FrameVsockSocket, SocketState};
use spin::{Mutex, Once, RwLock};

use crate::error::Result;

/// Batch size for RX processing - smaller is better for latency,
/// larger is better for throughput. 64 is a good balance.
const RX_BATCH_SIZE: usize = 64;

/// Vsock IRQ line for RX notifications
static VSOCK_IRQ: Once<IrqLine> = Once::new();
static VSOCK_IRQ_ENABLED: AtomicBool = AtomicBool::new(false);

/// Port to socket mapping for fast lookup (used for listening sockets)
static PORT_INDEX: Once<RwLock<BTreeMap<u32, Arc<FrameVsockSocket>>>> = Once::new();

/// Connection ID for connected sockets: (local_port, peer_cid, peer_port)
pub type ConnectionId = (u32, u64, u32);

/// Connection index for connected sockets (used for data packet routing)
/// Key: (local_port, peer_cid, peer_port)
static CONNECTION_INDEX: Once<RwLock<BTreeMap<ConnectionId, Arc<FrameVsockSocket>>>> = Once::new();

/// Cache for the last accessed connection to speed up data plane lookups
/// This avoids BTreeMap O(log n) lookup and RwLock overhead for the hot path
/// Uses Weak to avoid preventing socket cleanup when connection is closed
static LAST_CONNECTION_CACHE: Once<RwLock<Option<(ConnectionId, Weak<FrameVsockSocket>)>>> =
    Once::new();
/// Per-vCPU connection cache using Weak to avoid preventing socket cleanup
static VCPU_CONNECTION_CACHE: Once<Vec<Mutex<Option<(ConnectionId, Weak<FrameVsockSocket>)>>>> =
    Once::new();

/// Per-vCPU drain locks - allows parallel processing across vCPUs
static VCPU_DRAIN_LOCKS: Once<Vec<Mutex<()>>> = Once::new();
/// Round-robin cursor for process-context fallback drain selection.
static SERVICE_NEXT_QUEUE: AtomicUsize = AtomicUsize::new(0);
/// Cap packets drained per process-context service pass.
///
/// This keeps recv-path fallback from over-draining unrelated queues under
/// multi-vCPU mode, which can otherwise burst-fill socket RX buffers.
const PROCESS_SERVICE_BUDGET_CAP_PKTS: usize = 64;

/// Initialize vsock subsystem
pub fn init() {
    PORT_INDEX.call_once(|| RwLock::new(BTreeMap::new()));
    CONNECTION_INDEX.call_once(|| RwLock::new(BTreeMap::new()));
    LAST_CONNECTION_CACHE.call_once(|| RwLock::new(None));
    let _ = vcpu_connection_cache();

    // Register vsock IRQ handler - like a normal driver.
    if VSOCK_IRQ.get().is_none() {
        let Ok(mut irq) = IrqLine::alloc_specific(FRAMEVSOCK_IRQ_NUM) else {
            framevm_logln!(
                "[FrameVM] Failed to allocate vsock IRQ {}. Disabling guest vsock IRQ handling.",
                FRAMEVSOCK_IRQ_NUM
            );
            VSOCK_IRQ_ENABLED.store(false, Ordering::Release);
            aster_framevisor::vsock::set_guest_active(false);
            return;
        };
        irq.on_active(|_trap_frame| {
            vsock_irq_handler();
        });
        VSOCK_IRQ.call_once(|| irq);
    }
    VSOCK_IRQ_ENABLED.store(true, Ordering::Release);
    // Always enable cross_sweep: in single-core environments, multiple vCPU
    // queues are processed by the same physical CPU, so cross_sweep helps
    // avoid starvation when connections are distributed across queues.
    set_irq_cross_sweep_enabled(true);
    // Urgent first-packet only matters for single vCPU (latency optimization)
    let vcpu_count = aster_framevisor::get_vcpu_count().max(1);
    set_irq_urgent_first_packet(vcpu_count <= 1);

    // Mark Guest vsock as active
    aster_framevisor::vsock::set_guest_active(true);
}

/// Get the IRQ work budget in packets.
#[inline]
pub fn irq_work_budget_pkts() -> usize {
    aster_framevisor::vsock::irq_work_budget_pkts().max(1) as usize
}

/// Set the IRQ work budget in packets.
#[inline]
pub fn set_irq_work_budget_pkts(pkts: u32) {
    aster_framevisor::vsock::set_irq_work_budget_pkts(pkts.max(1));
}

/// Check if cross-queue sweep is enabled.
#[inline]
pub fn irq_cross_sweep_enabled() -> bool {
    aster_framevisor::vsock::irq_cross_sweep_enabled()
}

/// Enable or disable cross-queue sweep.
#[inline]
pub fn set_irq_cross_sweep_enabled(enabled: bool) {
    aster_framevisor::vsock::set_irq_cross_sweep_enabled(enabled);
}

/// Enable or disable urgent first-packet IRQ behavior.
#[inline]
pub fn set_irq_urgent_first_packet(enabled: bool) {
    aster_framevisor::vsock::set_irq_urgent_first_packet(enabled);
}

/// Get RX credit headroom in bytes.
#[inline]
pub fn rx_credit_headroom_bytes() -> u32 {
    aster_framevisor::vsock::rx_credit_headroom_bytes()
}

/// Shutdown vsock subsystem
/// Should be called when the Guest is about to exit
pub fn shutdown() {
    // Mark Guest vsock as inactive to prevent Host from calling Guest callbacks
    aster_framevisor::vsock::set_guest_active(false);
    VSOCK_IRQ_ENABLED.store(false, Ordering::Release);
}

/// Disable vsock IRQ handling and drain all pending packets.
///
/// This is used during guest teardown to avoid callbacks touching freed state.
pub fn disable_irq_and_drain() {
    VSOCK_IRQ_ENABLED.store(false, Ordering::SeqCst);
    // Memory barrier to ensure all vCPUs see the disabled flag
    core::sync::atomic::fence(Ordering::SeqCst);

    // Acquire all per-vCPU locks to ensure no concurrent drains
    let locks = vcpu_drain_locks();
    let _guards: Vec<_> = locks.iter().map(|l| l.lock()).collect();
    drain_all_queues();
}

fn port_index() -> &'static RwLock<BTreeMap<u32, Arc<FrameVsockSocket>>> {
    PORT_INDEX.call_once(|| RwLock::new(BTreeMap::new()))
}

fn connection_index() -> &'static RwLock<BTreeMap<ConnectionId, Arc<FrameVsockSocket>>> {
    CONNECTION_INDEX.call_once(|| RwLock::new(BTreeMap::new()))
}

fn last_connection_cache() -> &'static RwLock<Option<(ConnectionId, Weak<FrameVsockSocket>)>> {
    LAST_CONNECTION_CACHE.call_once(|| RwLock::new(None))
}

fn vcpu_connection_cache() -> &'static Vec<Mutex<Option<(ConnectionId, Weak<FrameVsockSocket>)>>> {
    VCPU_CONNECTION_CACHE.call_once(|| {
        let vcpu_count = aster_framevisor::get_vcpu_count().max(1);
        let mut entries = Vec::with_capacity(vcpu_count);
        for _ in 0..vcpu_count {
            entries.push(Mutex::new(None));
        }
        entries
    })
}

/// Get per-vCPU drain locks for parallel IRQ processing
fn vcpu_drain_locks() -> &'static Vec<Mutex<()>> {
    VCPU_DRAIN_LOCKS.call_once(|| {
        let vcpu_count = aster_framevisor::get_vcpu_count().max(1);
        (0..vcpu_count).map(|_| Mutex::new(())).collect()
    })
}

/// Fast path socket lookup with per-vCPU cache using Weak to allow proper cleanup
fn get_socket_by_connection_cached(
    vcpu_id: usize,
    id: ConnectionId,
) -> Option<Arc<FrameVsockSocket>> {
    let caches = vcpu_connection_cache();
    if vcpu_id < caches.len() {
        // Fast path: check cache first
        {
            let mut entry = caches[vcpu_id].lock();
            if let Some((cached_id, weak)) = entry.as_ref() {
                if *cached_id == id {
                    // Try to upgrade Weak to Arc
                    if let Some(socket) = weak.upgrade() {
                        return Some(socket);
                    }
                    // Weak reference is dead, clear the cache entry
                    *entry = None;
                }
            }
        }

        // Slow path: lookup and update cache
        if let Some(socket) = get_socket_by_connection(id.0, id.1, id.2) {
            let mut entry = caches[vcpu_id].lock();
            *entry = Some((id, Arc::downgrade(&socket)));
            return Some(socket);
        }
        return None;
    }

    get_socket_by_connection(id.0, id.1, id.2)
}

/// Allocate fd for a new socket
/// Register socket's port in the port index for fast lookup
pub fn register_port(port: u32, socket: Arc<FrameVsockSocket>) {
    let mut index = port_index().write();
    index.insert(port, socket);
}

/// Unregister socket's port from the port index
pub fn unregister_port(port: u32) {
    let mut index = port_index().write();
    index.remove(&port);
}

/// Get socket by port (O(log n) lookup)
/// Used for listening sockets and control packets
pub fn get_socket_by_port(port: u32) -> Option<Arc<FrameVsockSocket>> {
    let index = port_index().read();
    index.get(&port).cloned()
}

/// Register a connected socket in the connection index
/// Key: (local_port, peer_cid, peer_port)
pub fn register_connection(
    local_port: u32,
    peer_cid: u64,
    peer_port: u32,
    socket: Arc<FrameVsockSocket>,
) {
    let mut index = connection_index().write();
    index.insert((local_port, peer_cid, peer_port), socket);
}

/// Unregister a connected socket from the connection index
pub fn unregister_connection(local_port: u32, peer_cid: u64, peer_port: u32) {
    let id = (local_port, peer_cid, peer_port);
    let mut index = connection_index().write();
    index.remove(&id);

    // Invalidate global cache if needed
    let mut cache = last_connection_cache().write();
    if let Some((cached_id, _)) = &*cache {
        if *cached_id == id {
            *cache = None;
        }
    }

    // Invalidate per-vCPU caches (now using Arc, just clear the entry)
    if let Some(caches) = VCPU_CONNECTION_CACHE.get() {
        for entry in caches.iter() {
            let mut guard = entry.lock();
            if let Some((cached_id, _)) = guard.as_ref() {
                if *cached_id == id {
                    *guard = None;
                }
            }
        }
    }
}

/// Get socket by connection ID (O(1) cached or O(log n) lookup)
/// Used for connected sockets and data packets
pub fn get_socket_by_connection(
    local_port: u32,
    peer_cid: u64,
    peer_port: u32,
) -> Option<Arc<FrameVsockSocket>> {
    let id = (local_port, peer_cid, peer_port);

    // Fast path: Check cache with read lock (allows concurrent cache hits)
    {
        let cache = last_connection_cache().read();
        if let Some((cached_id, weak)) = &*cache {
            if *cached_id == id {
                if let Some(socket) = weak.upgrade() {
                    return Some(socket);
                }
                // Weak reference is dead — fall through to slow path
                // which will update the cache with a valid entry
            }
        }
    }

    // Slow path: Check index
    let index = connection_index().read();
    if let Some(socket) = index.get(&id).cloned() {
        // Update cache with write lock (store Weak reference)
        *last_connection_cache().write() = Some((id, Arc::downgrade(&socket)));
        return Some(socket);
    }
    None
}

// ========== TX Path: Guest -> Host ==========

/// Submit a data packet to the host (synchronous call)
/// This is called by socket operations to send data to Host
pub fn submit_data_packet(packet: RRef<DataPacket>) -> Result<()> {
    let _trace = trace::TraceGuard::new(&trace::GUEST_SUBMIT_DATA);
    aster_framevisor::vsock::submit_data_packet(packet);
    Ok(())
}

/// Submit a control packet to the host (synchronous call)
/// This is called by socket operations to send control messages to Host
pub fn submit_control_packet(packet: RRef<ControlPacket>) -> Result<()> {
    let _trace = trace::TraceGuard::new(&trace::GUEST_SUBMIT_CONTROL);
    aster_framevisor::vsock::submit_control_packet(packet);
    Ok(())
}

/// Vsock IRQ handler - called by IHT when packets arrive
/// Pops packets from FrameVisor queues and dispatches to sockets
///
/// IMPORTANT: Each IHT only processes its own vCPU's queue.
/// Uses per-vCPU locks to allow parallel processing across vCPUs.
fn vsock_irq_handler() {
    // Early exit check without lock
    if !VSOCK_IRQ_ENABLED.load(Ordering::Acquire) {
        return;
    }
    let _trace = trace::TraceGuard::new(&trace::GUEST_VSOCK_IRQ);

    // Get the current vCPU ID.
    //
    // Architecture note:
    // - IRQ is typically targeted to one queue, but under high load packets for
    //   other queues may still be pending.
    // - If we only drain current queue, those queues can starve and eventually
    //   stall host senders on queue pressure/credit progress.
    // - So we drain current queue first (locality), then opportunistically drain
    //   other non-empty queues.
    if let Some(vcpu_id) = iht::current_vcpu_id() {
        let locks = vcpu_drain_locks();
        if vcpu_id < locks.len() {
            let _guard = locks[vcpu_id].lock();
            // Double-check after acquiring lock
            if VSOCK_IRQ_ENABLED.load(Ordering::Acquire) {
                let budget = irq_work_budget_pkts();
                let _ = drain_vcpu_queue_with_budget(vcpu_id, budget);
            }
        }

        if irq_cross_sweep_enabled() {
            // Opportunistic cross-queue sweep for fairness and forward progress.
            // Use try_lock to avoid blocking on another vCPU's drain lock —
            // if that vCPU is already draining, it will handle its own queue.
            for (queue_id, lock) in locks.iter().enumerate() {
                if queue_id == vcpu_id {
                    continue;
                }
                if !VSOCK_IRQ_ENABLED.load(Ordering::Acquire) {
                    break;
                }
                if !aster_framevisor::vsock::has_pending_data(queue_id)
                    && !aster_framevisor::vsock::has_pending_control(queue_id)
                {
                    continue;
                }
                if let Some(_guard) = lock.try_lock() {
                    if VSOCK_IRQ_ENABLED.load(Ordering::Acquire) {
                        let budget = irq_work_budget_pkts();
                        let _ = drain_vcpu_queue_with_budget(queue_id, budget);
                    }
                }
            }
        }
    } else {
        let locks = vcpu_drain_locks();
        for (queue_id, lock) in locks.iter().enumerate() {
            let _guard = lock.lock();
            if !VSOCK_IRQ_ENABLED.load(Ordering::Acquire) {
                break;
            }
            let budget = irq_work_budget_pkts();
            let _ = drain_vcpu_queue_with_budget(queue_id, budget);
        }
    }
}

fn drain_all_queues() {
    let vcpu_count = aster_framevisor::get_vcpu_count();
    for vcpu_id in 0..vcpu_count {
        loop {
            let mut did_work = false;
            for _ in 0..RX_BATCH_SIZE {
                if aster_framevisor::vsock::pop_control_packet(vcpu_id).is_some() {
                    did_work = true;
                } else {
                    break;
                }
            }
            for _ in 0..RX_BATCH_SIZE {
                if aster_framevisor::vsock::pop_data_packet(vcpu_id).is_some() {
                    did_work = true;
                } else {
                    break;
                }
            }
            if !did_work {
                break;
            }
        }
    }
}

/// Drain one vCPU queue with an explicit packet budget.
///
/// Returns the number of packets processed.
fn drain_vcpu_queue_with_budget(vcpu_id: usize, budget: usize) -> usize {
    if budget == 0 {
        return 0;
    }

    let mut remaining_budget = budget;
    let mut processed = 0usize;

    loop {
        if remaining_budget == 0 {
            break;
        }

        let mut did_work = false;

        // Process control packets first (usually fewer, higher priority).
        for _ in 0..RX_BATCH_SIZE {
            if remaining_budget == 0 {
                break;
            }
            if let Some(packet) = aster_framevisor::vsock::pop_control_packet(vcpu_id) {
                did_work = true;
                remaining_budget -= 1;
                processed += 1;
                dispatch_control_packet(vcpu_id, packet);
            } else {
                break;
            }
        }

        if remaining_budget == 0 {
            break;
        }

        // Process data packets in batch for better cache locality.
        let data_batch_limit = RX_BATCH_SIZE.min(remaining_budget);
        if data_batch_limit > 0 {
            let data_packets = aster_framevisor::vsock::pop_data_batch(vcpu_id, data_batch_limit);
            if !data_packets.is_empty() {
                did_work = true;
                let count = data_packets.len();
                remaining_budget = remaining_budget.saturating_sub(count);
                processed += count;
                dispatch_data_packets_batch(vcpu_id, data_packets);
            }
        }

        if !did_work {
            break;
        }
    }

    processed
}

/// Service pending packets from backend queues in process context.
///
/// This is a forward-progress fallback for blocking recv paths: if IRQ delivery
/// is delayed or coalesced aggressively, a receiver thread can still drain and
/// dispatch pending packets before sleeping.
pub fn service_pending_packets() {
    if !VSOCK_IRQ_ENABLED.load(Ordering::Acquire) {
        return;
    }

    let locks = vcpu_drain_locks();
    let queue_count = locks.len();
    if queue_count == 0 {
        return;
    }

    // In multi-vCPU mode with cross-sweep disabled, keep process-context
    // fallback conservative: service at most one queue per call with a small
    // capped budget. This avoids one busy receiver path over-draining other
    // queues and triggering socket-side RX overflows.
    if queue_count > 1 && !irq_cross_sweep_enabled() {
        let start = SERVICE_NEXT_QUEUE.fetch_add(1, Ordering::Relaxed) % queue_count;
        for offset in 0..queue_count {
            let queue_id = (start + offset) % queue_count;
            let has_pending = aster_framevisor::vsock::has_pending_data(queue_id)
                || aster_framevisor::vsock::has_pending_control(queue_id);
            if !has_pending {
                continue;
            }

            if let Some(_guard) = locks[queue_id].try_lock() {
                if VSOCK_IRQ_ENABLED.load(Ordering::Acquire) {
                    let budget = irq_work_budget_pkts().min(PROCESS_SERVICE_BUDGET_CAP_PKTS);
                    let _ = drain_vcpu_queue_with_budget(queue_id, budget);
                }
                break;
            }
        }
        return;
    }

    for (queue_id, lock) in locks.iter().enumerate() {
        let has_pending = aster_framevisor::vsock::has_pending_data(queue_id)
            || aster_framevisor::vsock::has_pending_control(queue_id);
        if !has_pending {
            continue;
        }

        // Do not block process-context recv/send paths on a busy IRQ drain lock.
        // If IRQ handler is currently draining this queue, skip and let the next
        // service pass retry.
        if let Some(_guard) = lock.try_lock() {
            if VSOCK_IRQ_ENABLED.load(Ordering::Acquire) {
                let budget = irq_work_budget_pkts().min(PROCESS_SERVICE_BUDGET_CAP_PKTS);
                let _ = drain_vcpu_queue_with_budget(queue_id, budget);
            }
        }
    }
}

/// Batch dispatch data packets with connection affinity optimization
/// Reduces repeated cache lookups for packets from the same connection
fn dispatch_data_packets_batch(vcpu_id: usize, packets: Vec<RRef<DataPacket>>) {
    let _trace = trace::TraceGuard::new(&trace::GUEST_DISPATCH_DATA);

    // Track last socket to avoid repeated lookups for same connection
    let mut last_socket: Option<(ConnectionId, Arc<FrameVsockSocket>)> = None;

    for packet in packets {
        let dst_port = packet.header.dst_port;
        let src_cid = packet.header.src_cid;
        let src_port = packet.header.src_port;
        let id = (dst_port, src_cid, src_port);

        // Fast path: same connection as previous packet
        if let Some((cached_id, ref socket)) = last_socket {
            if cached_id == id {
                socket.on_data_packet_received(packet, vcpu_id);
                continue;
            }
        }

        // Slow path: lookup connected socket only.
        //
        // IMPORTANT: data packets must never fallback to port index, otherwise
        // packets can be misrouted to a listening socket and never consumed,
        // eventually causing sender-side stalls under large transfer volumes.
        if let Some(socket) = get_socket_by_connection_cached(vcpu_id, id) {
            last_socket = Some((id, socket.clone()));
            socket.on_data_packet_received(packet, vcpu_id);
        } else {
            // No matching connected socket: actively reset peer so host sender
            // can fail fast instead of hanging on stale flow control state.
            let rst = create_rst(packet.header.dst_cid, dst_port, src_cid, src_port);
            let _ = submit_control_packet(rst);
        }
    }
}

/// Dispatch a control packet to the appropriate socket
fn dispatch_control_packet(vcpu_id: usize, packet: RRef<ControlPacket>) {
    let _trace = trace::TraceGuard::new(&trace::GUEST_DISPATCH_CONTROL);
    let dst_port = packet.header.dst_port;
    let dst_cid = packet.header.dst_cid;
    let src_cid = packet.header.src_cid;
    let src_port = packet.header.src_port;
    let op = packet.operation();
    let id = (dst_port, src_cid, src_port);

    match op {
        VsockOp::Request => {
            if let Some(socket) = get_socket_by_port(dst_port) {
                socket.on_control_packet_received(packet);
            } else {
                let rst = create_rst(dst_cid, dst_port, src_cid, src_port);
                let _ = submit_control_packet(rst);
            }
        }
        VsockOp::Response => {
            if let Some(socket) = get_socket_by_connection_cached(vcpu_id, id)
                .or_else(|| get_socket_by_port(dst_port))
            {
                socket.on_control_packet_received(packet);
            }
        }
        VsockOp::Rst => {
            if let Some(socket) = get_socket_by_connection_cached(vcpu_id, id) {
                socket.on_control_packet_received(packet);
            } else if let Some(socket) = get_socket_by_port(dst_port) {
                // RST fallback to port is only valid for connecting sockets.
                if socket.state() == SocketState::Connecting {
                    socket.on_control_packet_received(packet);
                }
            }
        }
        VsockOp::Shutdown | VsockOp::CreditUpdate | VsockOp::CreditRequest => {
            if let Some(socket) = get_socket_by_connection_cached(vcpu_id, id) {
                socket.on_control_packet_received(packet);
            }
        }
        VsockOp::Rw | VsockOp::Invalid => {}
    }
}
