// SPDX-License-Identifier: MPL-2.0

//! FrameVsock Backend Device
//!
//! This module implements the vsock backend device in FrameVisor, acting as
//! the virtual hardware that bridges communication between Host and Guest.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Host Kernel (Asterinas)                          │
//! │  ┌─────────────────────────────────────────────────────────────────┐    │
//! │  │  Host Socket Layer (kernel/src/net/socket/framevsock/)          │    │
//! │  │  - Registers handlers via register_host_*_handler()             │    │
//! │  └─────────────────────────────────────────────────────────────────┘    │
//! │                              ↓ send_to_guest()                          │
//! │  ┌─────────────────────────────────────────────────────────────────┐    │
//! │  │  Backend Device (this module)                                   │    │
//! │  │  - Queues packets for Guest                                     │    │
//! │  │  - Routes by CID to correct VM                                  │    │
//! │  │  - Injects IRQ to notify Guest                                  │    │
//! │  └─────────────────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────────────┘
//!                               ↕ RRef zero-copy
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         FrameVM Guest                                   │
//! │  ┌─────────────────────────────────────────────────────────────────┐    │
//! │  │  Frontend Driver (kernel/comps/framevm/src/vsock/)              │    │
//! │  │  - Handles IRQ, pops packets via recv_from_backend()            │    │
//! │  │  - Sends packets via send_to_host()                             │    │
//! │  └─────────────────────────────────────────────────────────────────┘    │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Data Flow
//!
//! ## Host → Guest (RX path)
//! 1. Host calls `send_to_guest()` with packet
//! 2. Backend routes by CID, enqueues in VcpuQueues
//! 3. Backend injects IRQ to Guest
//! 4. Guest IRQ handler calls `recv_from_backend()` to pop packets
//!
//! ## Guest → Host (TX path)
//! 1. Guest calls `send_to_host()` with packet
//! 2. Backend transfers ownership to Host domain
//! 3. Backend calls registered Host handler synchronously
//!
//! # Multi-VM Support
//!
//! Packets are routed to the correct VM based on destination CID.
//! CID mapping: `CID = VM_ID + 3` (GUEST_CID_BASE)

#![deny(unsafe_code)]

mod queues;
mod state;

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use aster_framevisor_exchangeable::{DomainId, RRef};
use aster_framevsock::{ControlPacket, DataPacket, HOST_CID, cid_to_vm_id, trace};
pub use queues::{VcpuQueueStats, VcpuQueues};
use spin::Once;
pub use state::{is_guest_active, is_vm_active, set_guest_active, set_vm_active};

pub use crate::vm::VmId;
use crate::{irq, vm};

const DEFAULT_IRQ_WORK_BUDGET_PKTS: u32 = 256;
static IRQ_WORK_BUDGET_PKTS: AtomicU32 = AtomicU32::new(DEFAULT_IRQ_WORK_BUDGET_PKTS);
static IRQ_CROSS_SWEEP_ENABLED: AtomicBool = AtomicBool::new(true);
static IRQ_URGENT_FIRST_PACKET: AtomicBool = AtomicBool::new(true);
const DEFAULT_RX_CREDIT_HEADROOM_BYTES: u32 = 256 * 1024; // 256KB
static RX_CREDIT_HEADROOM_BYTES: AtomicU32 = AtomicU32::new(DEFAULT_RX_CREDIT_HEADROOM_BYTES);

/// Backend breadcrumbs for Host -> Guest enqueue/IRQ behavior.
#[derive(Debug, Clone, Copy, Default)]
pub struct BackendTxDebugStats {
    pub data_send_attempts: u64,
    pub data_send_success: u64,
    pub data_send_err_bad_cid: u64,
    pub data_send_err_vm_inactive: u64,
    pub data_send_err_vm_missing: u64,
    pub data_send_err_queue_missing: u64,
    pub data_send_err_queue_full: u64,
    pub data_irq_forced_on_full: u64,
    pub data_irq_policy_inject: u64,
    pub control_send_attempts: u64,
    pub control_send_success: u64,
    pub control_send_err_bad_cid: u64,
    pub control_send_err_vm_inactive: u64,
    pub control_send_err_vm_missing: u64,
    pub control_send_err_queue_missing: u64,
    pub control_send_err_queue_full: u64,
    pub control_irq_forced_on_full: u64,
    pub control_irq_policy_inject: u64,
    pub host_queue_drain_notifies: u64,
}

static DATA_SEND_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static DATA_SEND_SUCCESS: AtomicU64 = AtomicU64::new(0);
static DATA_SEND_ERR_BAD_CID: AtomicU64 = AtomicU64::new(0);
static DATA_SEND_ERR_VM_INACTIVE: AtomicU64 = AtomicU64::new(0);
static DATA_SEND_ERR_VM_MISSING: AtomicU64 = AtomicU64::new(0);
static DATA_SEND_ERR_QUEUE_MISSING: AtomicU64 = AtomicU64::new(0);
static DATA_SEND_ERR_QUEUE_FULL: AtomicU64 = AtomicU64::new(0);
static DATA_IRQ_FORCED_ON_FULL: AtomicU64 = AtomicU64::new(0);
static DATA_IRQ_POLICY_INJECT: AtomicU64 = AtomicU64::new(0);

static CONTROL_SEND_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static CONTROL_SEND_SUCCESS: AtomicU64 = AtomicU64::new(0);
static CONTROL_SEND_ERR_BAD_CID: AtomicU64 = AtomicU64::new(0);
static CONTROL_SEND_ERR_VM_INACTIVE: AtomicU64 = AtomicU64::new(0);
static CONTROL_SEND_ERR_VM_MISSING: AtomicU64 = AtomicU64::new(0);
static CONTROL_SEND_ERR_QUEUE_MISSING: AtomicU64 = AtomicU64::new(0);
static CONTROL_SEND_ERR_QUEUE_FULL: AtomicU64 = AtomicU64::new(0);
static CONTROL_IRQ_FORCED_ON_FULL: AtomicU64 = AtomicU64::new(0);
static CONTROL_IRQ_POLICY_INJECT: AtomicU64 = AtomicU64::new(0);

static HOST_QUEUE_DRAIN_NOTIFIES: AtomicU64 = AtomicU64::new(0);

fn current_time_ns() -> u64 {
    let freq = ostd::arch::tsc_freq();
    if freq == 0 {
        return 0;
    }
    let tsc = ostd::arch::read_tsc();
    ((tsc as u128) * 1_000_000_000u128 / freq as u128) as u64
}

/// Get per-pass IRQ drain budget in packets.
#[inline]
pub fn irq_work_budget_pkts() -> u32 {
    IRQ_WORK_BUDGET_PKTS.load(Ordering::Relaxed).max(1)
}

/// Set per-pass IRQ drain budget in packets.
#[inline]
pub fn set_irq_work_budget_pkts(pkts: u32) {
    IRQ_WORK_BUDGET_PKTS.store(pkts.max(1), Ordering::Relaxed);
}

/// Check if cross-queue sweep is enabled for guest RX IRQ handling.
#[inline]
pub fn irq_cross_sweep_enabled() -> bool {
    IRQ_CROSS_SWEEP_ENABLED.load(Ordering::Relaxed)
}

/// Enable/disable cross-queue sweep for guest RX IRQ handling.
#[inline]
pub fn set_irq_cross_sweep_enabled(enabled: bool) {
    IRQ_CROSS_SWEEP_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Check if first data packet after empty queue should force IRQ.
#[inline]
pub fn irq_urgent_first_packet() -> bool {
    IRQ_URGENT_FIRST_PACKET.load(Ordering::Relaxed)
}

/// Enable/disable urgent IRQ on first data packet after empty queue.
#[inline]
pub fn set_irq_urgent_first_packet(enabled: bool) {
    IRQ_URGENT_FIRST_PACKET.store(enabled, Ordering::Relaxed);
}

/// Get RX credit headroom in bytes.
#[inline]
pub fn rx_credit_headroom_bytes() -> u32 {
    RX_CREDIT_HEADROOM_BYTES.load(Ordering::Relaxed)
}

/// Set RX credit headroom in bytes.
#[inline]
pub fn set_rx_credit_headroom_bytes(bytes: u32) {
    RX_CREDIT_HEADROOM_BYTES.store(bytes, Ordering::Relaxed);
}

/// Snapshot backend Host->Guest debug counters.
pub fn backend_tx_debug_stats() -> BackendTxDebugStats {
    BackendTxDebugStats {
        data_send_attempts: DATA_SEND_ATTEMPTS.load(Ordering::Relaxed),
        data_send_success: DATA_SEND_SUCCESS.load(Ordering::Relaxed),
        data_send_err_bad_cid: DATA_SEND_ERR_BAD_CID.load(Ordering::Relaxed),
        data_send_err_vm_inactive: DATA_SEND_ERR_VM_INACTIVE.load(Ordering::Relaxed),
        data_send_err_vm_missing: DATA_SEND_ERR_VM_MISSING.load(Ordering::Relaxed),
        data_send_err_queue_missing: DATA_SEND_ERR_QUEUE_MISSING.load(Ordering::Relaxed),
        data_send_err_queue_full: DATA_SEND_ERR_QUEUE_FULL.load(Ordering::Relaxed),
        data_irq_forced_on_full: DATA_IRQ_FORCED_ON_FULL.load(Ordering::Relaxed),
        data_irq_policy_inject: DATA_IRQ_POLICY_INJECT.load(Ordering::Relaxed),
        control_send_attempts: CONTROL_SEND_ATTEMPTS.load(Ordering::Relaxed),
        control_send_success: CONTROL_SEND_SUCCESS.load(Ordering::Relaxed),
        control_send_err_bad_cid: CONTROL_SEND_ERR_BAD_CID.load(Ordering::Relaxed),
        control_send_err_vm_inactive: CONTROL_SEND_ERR_VM_INACTIVE.load(Ordering::Relaxed),
        control_send_err_vm_missing: CONTROL_SEND_ERR_VM_MISSING.load(Ordering::Relaxed),
        control_send_err_queue_missing: CONTROL_SEND_ERR_QUEUE_MISSING.load(Ordering::Relaxed),
        control_send_err_queue_full: CONTROL_SEND_ERR_QUEUE_FULL.load(Ordering::Relaxed),
        control_irq_forced_on_full: CONTROL_IRQ_FORCED_ON_FULL.load(Ordering::Relaxed),
        control_irq_policy_inject: CONTROL_IRQ_POLICY_INJECT.load(Ordering::Relaxed),
        host_queue_drain_notifies: HOST_QUEUE_DRAIN_NOTIFIES.load(Ordering::Relaxed),
    }
}

/// Reset backend Host->Guest debug counters.
pub fn reset_backend_tx_debug_stats() {
    DATA_SEND_ATTEMPTS.store(0, Ordering::Relaxed);
    DATA_SEND_SUCCESS.store(0, Ordering::Relaxed);
    DATA_SEND_ERR_BAD_CID.store(0, Ordering::Relaxed);
    DATA_SEND_ERR_VM_INACTIVE.store(0, Ordering::Relaxed);
    DATA_SEND_ERR_VM_MISSING.store(0, Ordering::Relaxed);
    DATA_SEND_ERR_QUEUE_MISSING.store(0, Ordering::Relaxed);
    DATA_SEND_ERR_QUEUE_FULL.store(0, Ordering::Relaxed);
    DATA_IRQ_FORCED_ON_FULL.store(0, Ordering::Relaxed);
    DATA_IRQ_POLICY_INJECT.store(0, Ordering::Relaxed);
    CONTROL_SEND_ATTEMPTS.store(0, Ordering::Relaxed);
    CONTROL_SEND_SUCCESS.store(0, Ordering::Relaxed);
    CONTROL_SEND_ERR_BAD_CID.store(0, Ordering::Relaxed);
    CONTROL_SEND_ERR_VM_INACTIVE.store(0, Ordering::Relaxed);
    CONTROL_SEND_ERR_VM_MISSING.store(0, Ordering::Relaxed);
    CONTROL_SEND_ERR_QUEUE_MISSING.store(0, Ordering::Relaxed);
    CONTROL_SEND_ERR_QUEUE_FULL.store(0, Ordering::Relaxed);
    CONTROL_IRQ_FORCED_ON_FULL.store(0, Ordering::Relaxed);
    CONTROL_IRQ_POLICY_INJECT.store(0, Ordering::Relaxed);
    HOST_QUEUE_DRAIN_NOTIFIES.store(0, Ordering::Relaxed);
}

// ============================================================================
// Host Handlers (registered by Host socket layer)
// ============================================================================

/// Handler type for data packets from Guest to Host.
pub type HostDataHandler = fn(RRef<DataPacket>);

/// Handler type for control packets from Guest to Host.
pub type HostControlHandler = fn(RRef<ControlPacket>);

/// Handler type for Host->Guest TX queue drain notifications.
///
/// Called when a data packet is popped from a Host->Guest data queue.
/// Arguments are (vcpu_id, queue_reserved_len_before_pop).
pub type HostQueueDrainHandler = fn(usize, usize);

static HOST_DATA_HANDLER: Once<HostDataHandler> = Once::new();
static HOST_CONTROL_HANDLER: Once<HostControlHandler> = Once::new();
static HOST_QUEUE_DRAIN_HANDLER: Once<HostQueueDrainHandler> = Once::new();

/// Register handler for data packets from Guest.
///
/// Called by Host socket layer during initialization.
pub fn register_host_data_handler(handler: HostDataHandler) {
    HOST_DATA_HANDLER.call_once(|| handler);
}

/// Register handler for control packets from Guest.
///
/// Called by Host socket layer during initialization.
pub fn register_host_control_handler(handler: HostControlHandler) {
    HOST_CONTROL_HANDLER.call_once(|| handler);
}

/// Register handler for Host->Guest TX queue drain notifications.
///
/// Called by Host socket layer during initialization.
pub fn register_host_queue_drain_handler(handler: HostQueueDrainHandler) {
    HOST_QUEUE_DRAIN_HANDLER.call_once(|| handler);
}

#[inline]
fn notify_host_queue_drain(vcpu_id: usize, queue_reserved_len_before_pop: usize) {
    HOST_QUEUE_DRAIN_NOTIFIES.fetch_add(1, Ordering::Relaxed);
    if let Some(handler) = HOST_QUEUE_DRAIN_HANDLER.get() {
        handler(vcpu_id, queue_reserved_len_before_pop);
    }
}

// ============================================================================
// TX Path: Guest → Host
// ============================================================================

/// Send a data packet from Guest to Host.
///
/// This is called by the Frontend Driver when Guest wants to send data.
/// The packet ownership is transferred to Host domain and the registered
/// handler is invoked synchronously.
pub fn send_to_host_data(packet: RRef<DataPacket>) {
    let _trace = trace::TraceGuard::new(&trace::FRAMEVISOR_SEND_TO_HOST_DATA);
    if packet.header.dst_cid != HOST_CID {
        return;
    }
    let packet = packet.transfer_to(DomainId::Host);
    if let Some(handler) = HOST_DATA_HANDLER.get() {
        handler(packet);
    }
}

/// Send a control packet from Guest to Host.
///
/// This is called by the Frontend Driver when Guest wants to send control messages.
pub fn send_to_host_control(packet: RRef<ControlPacket>) {
    let _trace = trace::TraceGuard::new(&trace::FRAMEVISOR_SEND_TO_HOST_CONTROL);
    if packet.header.dst_cid != HOST_CID {
        return;
    }
    let packet = packet.transfer_to(DomainId::Host);
    if let Some(handler) = HOST_CONTROL_HANDLER.get() {
        handler(packet);
    }
}

// Backward compatible aliases
pub use send_to_host_control as submit_control_packet;
pub use send_to_host_data as submit_data_packet;

// ============================================================================
// RX Path: Host → Guest
// ============================================================================

/// Send a data packet from Host to Guest.
///
/// Routes to the correct VM based on destination CID.
/// The packet is enqueued and an IRQ is injected to notify the Guest.
///
/// # Arguments
/// * `vcpu_id` - Target vCPU for IRQ injection
/// * `packet` - Data packet to deliver
///
/// # Returns
/// * `Ok(())` - Packet successfully enqueued
/// * `Err(packet)` - VM not found, not active, or queue full
///
/// Returning the packet on error allows callers to retry without losing payload
/// ownership (important for stream-socket send correctness).
pub fn send_to_guest_data(
    vcpu_id: usize,
    packet: RRef<DataPacket>,
) -> Result<(), RRef<DataPacket>> {
    DATA_SEND_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let dst_cid = packet.header.dst_cid;

    // Get VM ID from destination CID
    let vm_id = match cid_to_vm_id(dst_cid) {
        Some(vm_id) => vm_id,
        None => {
            DATA_SEND_ERR_BAD_CID.fetch_add(1, Ordering::Relaxed);
            return Err(packet);
        }
    };

    // Check if VM is active
    if !is_vm_active(vm_id) {
        DATA_SEND_ERR_VM_INACTIVE.fetch_add(1, Ordering::Relaxed);
        return Err(packet);
    }

    // Get VM instance
    let vm = match vm::get_vm_by_id(vm_id) {
        Some(vm) => vm,
        None => {
            DATA_SEND_ERR_VM_MISSING.fetch_add(1, Ordering::Relaxed);
            return Err(packet);
        }
    };
    let queues = match vm.vsock_queues(vcpu_id) {
        Some(queues) => queues,
        None => {
            DATA_SEND_ERR_QUEUE_MISSING.fetch_add(1, Ordering::Relaxed);
            return Err(packet);
        }
    };

    // Transfer ownership to the correct FrameVM domain
    let packet = packet.transfer_to(DomainId::FrameVM(vm_id));

    if let Err(packet) = queues.push_data(packet) {
        // Queue is full (or temporarily cannot reserve).
        //
        // Forward-progress guarantee:
        // under high pressure, host senders may keep retrying while guest side
        // relies on IRQ-driven drain. If an earlier coalesced IRQ was delayed,
        // the queue can stay full and create a long stall. Force an IRQ kick on
        // enqueue failure so guest gets a deterministic chance to drain.
        DATA_SEND_ERR_QUEUE_FULL.fetch_add(1, Ordering::Relaxed);
        DATA_IRQ_FORCED_ON_FULL.fetch_add(1, Ordering::Relaxed);
        irq::inject_vsock_rx_interrupt_for_vm(vm_id, vcpu_id);
        return Err(packet);
    }

    // Decide whether to inject IRQ:
    // - If queue was empty before this push (first packet), inject immediately
    //   to avoid latency for low-frequency scenarios (e.g., RTT test)
    // - Otherwise, rely on batch/time thresholds for high-throughput scenarios
    let now_ns = current_time_ns();
    queues.refresh_irq_strategy();
    let urgent_first_packet = irq_urgent_first_packet();
    let is_urgent = urgent_first_packet && queues.data_queue_len() == 1;
    if queues.should_inject_irq(is_urgent, true, now_ns) {
        DATA_IRQ_POLICY_INJECT.fetch_add(1, Ordering::Relaxed);
        irq::inject_vsock_rx_interrupt_for_vm(vm_id, vcpu_id);
    }

    DATA_SEND_SUCCESS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Send a control packet from Host to Guest.
///
/// Routes to the correct VM based on destination CID.
pub fn send_to_guest_control(vcpu_id: usize, packet: RRef<ControlPacket>) -> Result<(), ()> {
    CONTROL_SEND_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let _trace = trace::TraceGuard::new(&trace::FRAMEVISOR_SEND_TO_GUEST_CONTROL);
    let dst_cid = packet.header.dst_cid;

    // Get VM ID from destination CID
    let vm_id = match cid_to_vm_id(dst_cid) {
        Some(vm_id) => vm_id,
        None => {
            CONTROL_SEND_ERR_BAD_CID.fetch_add(1, Ordering::Relaxed);
            return Err(());
        }
    };

    // Check if VM is active
    if !is_vm_active(vm_id) {
        CONTROL_SEND_ERR_VM_INACTIVE.fetch_add(1, Ordering::Relaxed);
        return Err(());
    }

    // Get VM instance
    let vm = match vm::get_vm_by_id(vm_id) {
        Some(vm) => vm,
        None => {
            CONTROL_SEND_ERR_VM_MISSING.fetch_add(1, Ordering::Relaxed);
            return Err(());
        }
    };
    let queues = match vm.vsock_queues(vcpu_id) {
        Some(queues) => queues,
        None => {
            CONTROL_SEND_ERR_QUEUE_MISSING.fetch_add(1, Ordering::Relaxed);
            return Err(());
        }
    };

    // Transfer ownership to the correct FrameVM domain
    let packet = packet.transfer_to(DomainId::FrameVM(vm_id));

    if queues.push_control(packet).is_err() {
        // Control queue pressure can also block credit/shutdown signaling.
        // Force an IRQ kick to help guest drain and recover quickly.
        CONTROL_SEND_ERR_QUEUE_FULL.fetch_add(1, Ordering::Relaxed);
        CONTROL_IRQ_FORCED_ON_FULL.fetch_add(1, Ordering::Relaxed);
        irq::inject_vsock_rx_interrupt_for_vm(vm_id, vcpu_id);
        return Err(());
    }

    let now_ns = current_time_ns();
    queues.refresh_irq_strategy();
    if queues.should_inject_irq(true, true, now_ns) {
        CONTROL_IRQ_POLICY_INJECT.fetch_add(1, Ordering::Relaxed);
        irq::inject_vsock_rx_interrupt_for_vm(vm_id, vcpu_id);
    }

    CONTROL_SEND_SUCCESS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

// Backward compatible aliases
pub use send_to_guest_control as deliver_control_packet;
pub use send_to_guest_data as deliver_data_packet;

// ============================================================================
// Receive API (called by Frontend Driver's IRQ handler)
// ============================================================================

/// Receive a data packet from backend (for specific VM).
///
/// Called by Guest's IRQ handler to retrieve pending data.
pub fn recv_data_packet_for_vm(vm_id: VmId, vcpu_id: usize) -> Option<RRef<DataPacket>> {
    let vm = vm::get_vm_by_id(vm_id)?;
    let queues = vm.vsock_queues(vcpu_id)?;
    let queue_reserved_len_before_pop = queues.data_queue_reserved_len();
    let packet = queues.pop_data();
    if packet.is_some() {
        notify_host_queue_drain(vcpu_id, queue_reserved_len_before_pop);
    }
    packet
}

/// Receive multiple data packets from backend (for specific VM).
pub fn recv_data_packets_for_vm(
    vm_id: VmId,
    vcpu_id: usize,
    max_count: usize,
) -> Vec<RRef<DataPacket>> {
    if let Some(vm) = vm::get_vm_by_id(vm_id) {
        if let Some(q) = vm.vsock_queues(vcpu_id) {
            let queue_reserved_len_before_pop = q.data_queue_reserved_len();
            let packets = q.pop_data_batch(max_count);
            if !packets.is_empty() {
                notify_host_queue_drain(vcpu_id, queue_reserved_len_before_pop);
            }
            return packets;
        }
    }
    Vec::new()
}

/// Receive a control packet from backend (for specific VM).
///
/// Called by Guest's IRQ handler to retrieve pending control messages.
pub fn recv_control_packet_for_vm(vm_id: VmId, vcpu_id: usize) -> Option<RRef<ControlPacket>> {
    vm::get_vm_by_id(vm_id)?
        .vsock_queues(vcpu_id)?
        .pop_control()
}

/// Receive multiple control packets from backend (for specific VM).
pub fn recv_control_packets_for_vm(
    vm_id: VmId,
    vcpu_id: usize,
    max_count: usize,
) -> Vec<RRef<ControlPacket>> {
    if let Some(vm) = vm::get_vm_by_id(vm_id) {
        if let Some(q) = vm.vsock_queues(vcpu_id) {
            return q.pop_control_batch(max_count);
        }
    }
    Vec::new()
}

/// Receive a data packet from backend (backward compatible, uses first VM).
pub fn recv_data_packet(vcpu_id: usize) -> Option<RRef<DataPacket>> {
    let vm = vm::get_vm()?;
    let queues = vm.vsock_queues(vcpu_id)?;
    let queue_reserved_len_before_pop = queues.data_queue_reserved_len();
    let packet = queues.pop_data();
    if packet.is_some() {
        notify_host_queue_drain(vcpu_id, queue_reserved_len_before_pop);
    }
    packet
}

/// Receive multiple data packets from backend (backward compatible, uses first VM).
pub fn recv_data_packets(vcpu_id: usize, max_count: usize) -> Vec<RRef<DataPacket>> {
    if let Some(vm) = vm::get_vm() {
        if let Some(q) = vm.vsock_queues(vcpu_id) {
            let queue_reserved_len_before_pop = q.data_queue_reserved_len();
            let packets = q.pop_data_batch(max_count);
            if !packets.is_empty() {
                notify_host_queue_drain(vcpu_id, queue_reserved_len_before_pop);
            }
            return packets;
        }
    }
    Vec::new()
}

/// Receive a control packet from backend (backward compatible, uses first VM).
pub fn recv_control_packet(vcpu_id: usize) -> Option<RRef<ControlPacket>> {
    vm::get_vm()?.vsock_queues(vcpu_id)?.pop_control()
}

/// Receive multiple control packets from backend (backward compatible, uses first VM).
pub fn recv_control_packets(vcpu_id: usize, max_count: usize) -> Vec<RRef<ControlPacket>> {
    if let Some(vm) = vm::get_vm() {
        if let Some(q) = vm.vsock_queues(vcpu_id) {
            return q.pop_control_batch(max_count);
        }
    }
    Vec::new()
}

// Backward compatible aliases
pub use recv_control_packet as pop_control_packet;
pub use recv_control_packet_for_vm as pop_control_packet_for_vm;
pub use recv_control_packets as pop_control_packet_batch;
pub use recv_control_packets as pop_control_batch;
pub use recv_control_packets_for_vm as pop_control_packet_batch_for_vm;
pub use recv_data_packet as pop_data_packet;
pub use recv_data_packet_for_vm as pop_data_packet_for_vm;
pub use recv_data_packets as pop_data_packet_batch;
// Simplified aliases for batch operations
pub use recv_data_packets as pop_data_batch;
pub use recv_data_packets_for_vm as pop_data_packet_batch_for_vm;

// ============================================================================
// Query API
// ============================================================================

/// Check if there are pending data packets for a specific VM.
pub fn has_pending_data_for_vm(vm_id: VmId, vcpu_id: usize) -> bool {
    vm::get_vm_by_id(vm_id)
        .map(|vm| {
            vm.vsock_queues(vcpu_id)
                .map(|q| q.has_pending_data())
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Check if there are pending control packets for a specific VM.
pub fn has_pending_control_for_vm(vm_id: VmId, vcpu_id: usize) -> bool {
    vm::get_vm_by_id(vm_id)
        .map(|vm| {
            vm.vsock_queues(vcpu_id)
                .map(|q| q.has_pending_control())
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Check if there are pending data packets (backward compatible).
pub fn has_pending_data(vcpu_id: usize) -> bool {
    vm::get_vm()
        .map(|vm| {
            vm.vsock_queues(vcpu_id)
                .map(|q| q.has_pending_data())
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Check if there are pending control packets (backward compatible).
pub fn has_pending_control(vcpu_id: usize) -> bool {
    vm::get_vm()
        .map(|vm| {
            vm.vsock_queues(vcpu_id)
                .map(|q| q.has_pending_control())
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Get per-vCPU queue stats for the current VM (if any).
pub fn get_vcpu_queue_stats() -> Vec<(usize, VcpuQueueStats)> {
    let mut stats = Vec::new();
    let Some(vm) = vm::get_vm() else {
        return stats;
    };
    // Check if VM is still running before accessing its resources
    if !vm.is_running() {
        return stats;
    }
    let vcpu_count = vm.vcpu_count();
    for vcpu_id in 0..vcpu_count {
        if let Some(q) = vm.vsock_queues(vcpu_id) {
            stats.push((vcpu_id, q.stats()));
        }
    }
    stats
}

// ============================================================================
// Utility
// ============================================================================

/// Get vCPU count for a specific VM.
#[inline]
pub fn get_vcpu_count_for_vm(vm_id: VmId) -> usize {
    vm::get_vcpu_count_for_vm(vm_id)
}

/// Get vCPU count (backward compatible, uses first VM).
#[inline]
pub fn get_vcpu_count() -> usize {
    vm::get_vcpu_count()
}
