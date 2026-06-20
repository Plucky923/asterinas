// SPDX-License-Identifier: MPL-2.0

//! FrameVsock device boundary.
//!
//! This module is a host-only backend implementation. It routes packets, owns
//! queues, injects virtual interrupts, and exposes host debug/control state only
//! when the `host-api` feature is enabled. FrameVM code must not import this
//! module directly; it sees only the safe `aster-framevsock` protocol types and
//! its own socket layer.
//!
//! # Architecture
//!
//! ```text
//! host socket layer
//!     -> host-only backend queue/router
//!     -> RRef packet transfer
//!     -> host-only dynamic transport relay
//!     -> service socket layer
//! ```
//!
//! # Data Flow
//!
//! ## host to service
//!
//! 1. Host socket code submits a packet to the host-only backend.
//! 2. The backend routes by CID, enqueues in the service domain queue, and
//!    injects the service-visible IRQ.
//! 3. The service socket layer drains packets through its own safe API.
//!
//! ## service to host
//!
//! 1. The service socket layer submits a packet through its own safe API.
//! 2. The backend transfers ownership to the host domain.
//! 3. The backend calls the registered host socket handler synchronously.
//!
//! # Multi-VM Support
//!
//! Packets are routed to the correct VM based on destination CID.
//! CID mapping: `CID = VM_ID + 3` (GUEST_CID_BASE)

#![deny(unsafe_code)]

pub mod transport {
    //! Host-private dynamic transport relay.
    //!
    //! The functions in this module are exported only through the host-api
    //! FrameVisor crate and preserve the dynamic link boundary used by loaded
    //! services. They carry `RRef` values and therefore must not become a
    //! source-level API for FrameVM or any OSTD-compatible service payload.

    use alloc::vec::Vec;

    use aster_framevisor_exchangeable::RRef;
    use aster_framevsock::{ControlPacket, DataPacket};

    /// Marks the service-side transport active.
    pub fn activate() {
        super::state::set_guest_active(true);
    }

    /// Marks the service-side transport inactive.
    pub fn deactivate() {
        super::state::set_guest_active(false);
    }

    /// Returns the packet budget for one receive-drain pass.
    #[inline]
    pub fn irq_work_budget_pkts() -> u32 {
        super::irq_work_budget_pkts_inner()
    }

    /// Sets the packet budget for one receive-drain pass.
    #[inline]
    pub fn set_irq_work_budget_pkts(pkts: u32) {
        super::set_irq_work_budget_pkts_inner(pkts);
    }

    /// Returns whether IRQ handlers may opportunistically drain other queues.
    #[inline]
    pub fn irq_cross_sweep_enabled() -> bool {
        super::irq_cross_sweep_enabled_inner()
    }

    /// Configures whether IRQ handlers may opportunistically drain other queues.
    #[inline]
    pub fn set_irq_cross_sweep_enabled(enabled: bool) {
        super::set_irq_cross_sweep_enabled_inner(enabled);
    }

    /// Configures whether the first queued data packet should force an IRQ.
    #[inline]
    pub fn set_irq_urgent_first_packet(enabled: bool) {
        super::set_irq_urgent_first_packet_inner(enabled);
    }

    /// Returns the receive credit headroom in bytes.
    #[inline]
    pub fn rx_credit_headroom_bytes() -> u32 {
        super::rx_credit_headroom_bytes_inner()
    }

    /// Returns the queue associated with the current receive IRQ.
    #[inline]
    pub fn current_rx_queue_id() -> Option<usize> {
        super::current_rx_queue_id()
    }

    /// Submits one data packet to the device.
    #[inline]
    pub fn submit_data_packet(packet: RRef<DataPacket>) -> Result<(), RRef<DataPacket>> {
        super::submit_service_data(packet)
    }

    /// Submits one control packet to the device.
    #[inline]
    pub fn submit_control_packet(packet: RRef<ControlPacket>) -> Result<(), RRef<ControlPacket>> {
        super::submit_service_control(packet)
    }

    /// Receives one control packet from a queue.
    #[inline]
    pub fn recv_control_packet(queue_id: usize) -> Option<RRef<ControlPacket>> {
        super::recv_control_packet(queue_id)
    }

    /// Receives one data packet from a queue.
    #[inline]
    pub fn recv_data_packet(queue_id: usize) -> Option<RRef<DataPacket>> {
        super::recv_data_packet(queue_id)
    }

    /// Receives a batch of data packets from a queue.
    #[inline]
    pub fn recv_data_packets(queue_id: usize, max_count: usize) -> Vec<RRef<DataPacket>> {
        super::recv_data_packets(queue_id, max_count)
    }

    /// Returns whether a queue has pending data packets.
    #[inline]
    pub fn has_pending_data(queue_id: usize) -> bool {
        super::has_pending_data(queue_id)
    }

    /// Returns whether a queue has pending control packets.
    #[inline]
    pub fn has_pending_control(queue_id: usize) -> bool {
        super::has_pending_control(queue_id)
    }
}

mod queues;
mod state;

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use aster_framevisor_exchangeable::{DomainId, RRef, enter_domain};
#[cfg(feature = "host-api")]
use aster_framevsock::cid_to_vm_id;
use aster_framevsock::{ControlPacket, DataPacket, HOST_CID, trace};
#[cfg(feature = "host-api")]
pub use queues::VcpuQueueStats;
pub(crate) use queues::VcpuQueues;
#[cfg(feature = "host-api")]
pub use state::{is_guest_active, is_vm_active, set_guest_active, set_vm_active};

#[cfg(feature = "host-api")]
use crate::irq;
#[cfg(feature = "host-api")]
pub use crate::vm::VmId;
use crate::{iht, sync::Once, vm};

#[cfg(feature = "host-api")]
#[used]
static _PRESERVE_SERVICE_TRANSPORT_SYMBOLS: (
    fn(),
    fn(),
    fn() -> u32,
    fn(u32),
    fn() -> bool,
    fn(bool),
    fn(bool),
    fn() -> u32,
    fn() -> Option<usize>,
    fn(RRef<DataPacket>) -> Result<(), RRef<DataPacket>>,
    fn(RRef<ControlPacket>) -> Result<(), RRef<ControlPacket>>,
    fn(usize) -> Option<RRef<ControlPacket>>,
    fn(usize) -> Option<RRef<DataPacket>>,
    fn(usize, usize) -> Vec<RRef<DataPacket>>,
    fn(usize) -> bool,
    fn(usize) -> bool,
) = (
    transport::activate,
    transport::deactivate,
    transport::irq_work_budget_pkts,
    transport::set_irq_work_budget_pkts,
    transport::irq_cross_sweep_enabled,
    transport::set_irq_cross_sweep_enabled,
    transport::set_irq_urgent_first_packet,
    transport::rx_credit_headroom_bytes,
    transport::current_rx_queue_id,
    transport::submit_data_packet,
    transport::submit_control_packet,
    transport::recv_control_packet,
    transport::recv_data_packet,
    transport::recv_data_packets,
    transport::has_pending_data,
    transport::has_pending_control,
);

const DEFAULT_IRQ_WORK_BUDGET_PKTS: u32 = 256;
static IRQ_WORK_BUDGET_PKTS: AtomicU32 = AtomicU32::new(DEFAULT_IRQ_WORK_BUDGET_PKTS);
static IRQ_CROSS_SWEEP_ENABLED: AtomicBool = AtomicBool::new(true);
static IRQ_URGENT_FIRST_PACKET: AtomicBool = AtomicBool::new(true);
const DEFAULT_RX_CREDIT_HEADROOM_BYTES: u32 = 256 * 1024; // 256KB
static RX_CREDIT_HEADROOM_BYTES: AtomicU32 = AtomicU32::new(DEFAULT_RX_CREDIT_HEADROOM_BYTES);

/// Backend breadcrumbs for host-to-service enqueue/IRQ behavior.
#[cfg(feature = "host-api")]
#[derive(Debug, Clone, Copy, Default)]
pub struct BackendTxDebugStats {
    pub data_submit_attempts: u64,
    pub data_submit_success: u64,
    pub data_submit_err_bad_cid: u64,
    pub data_submit_err_no_handler: u64,
    pub data_submit_err_transfer: u64,
    pub data_send_attempts: u64,
    pub data_send_success: u64,
    pub data_send_err_bad_cid: u64,
    pub data_send_err_vm_inactive: u64,
    pub data_send_err_vm_missing: u64,
    pub data_send_err_queue_missing: u64,
    pub data_send_err_queue_full: u64,
    pub data_irq_forced_on_full: u64,
    pub data_irq_policy_inject: u64,
    pub control_submit_attempts: u64,
    pub control_submit_success: u64,
    pub control_submit_err_bad_cid: u64,
    pub control_submit_err_no_handler: u64,
    pub control_submit_err_transfer: u64,
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

static DATA_SUBMIT_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static DATA_SUBMIT_SUCCESS: AtomicU64 = AtomicU64::new(0);
static DATA_SUBMIT_ERR_BAD_CID: AtomicU64 = AtomicU64::new(0);
static DATA_SUBMIT_ERR_NO_HANDLER: AtomicU64 = AtomicU64::new(0);
static DATA_SUBMIT_ERR_TRANSFER: AtomicU64 = AtomicU64::new(0);

static DATA_SEND_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static DATA_SEND_SUCCESS: AtomicU64 = AtomicU64::new(0);
static DATA_SEND_ERR_BAD_CID: AtomicU64 = AtomicU64::new(0);
static DATA_SEND_ERR_VM_INACTIVE: AtomicU64 = AtomicU64::new(0);
static DATA_SEND_ERR_VM_MISSING: AtomicU64 = AtomicU64::new(0);
static DATA_SEND_ERR_QUEUE_MISSING: AtomicU64 = AtomicU64::new(0);
static DATA_SEND_ERR_QUEUE_FULL: AtomicU64 = AtomicU64::new(0);
static DATA_IRQ_FORCED_ON_FULL: AtomicU64 = AtomicU64::new(0);
static DATA_IRQ_POLICY_INJECT: AtomicU64 = AtomicU64::new(0);

static CONTROL_SUBMIT_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static CONTROL_SUBMIT_SUCCESS: AtomicU64 = AtomicU64::new(0);
static CONTROL_SUBMIT_ERR_BAD_CID: AtomicU64 = AtomicU64::new(0);
static CONTROL_SUBMIT_ERR_NO_HANDLER: AtomicU64 = AtomicU64::new(0);
static CONTROL_SUBMIT_ERR_TRANSFER: AtomicU64 = AtomicU64::new(0);

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
    let freq = host_ostd::arch::tsc_freq();
    if freq == 0 {
        return 0;
    }
    let tsc = host_ostd::arch::read_tsc();
    ((tsc as u128) * 1_000_000_000u128 / freq as u128) as u64
}

/// Get per-pass IRQ drain budget in packets.
#[inline]
fn irq_work_budget_pkts_inner() -> u32 {
    IRQ_WORK_BUDGET_PKTS.load(Ordering::Relaxed).max(1)
}

/// Gets per-pass IRQ drain budget in packets.
#[cfg(feature = "host-api")]
pub fn irq_work_budget_pkts() -> u32 {
    irq_work_budget_pkts_inner()
}

/// Set per-pass IRQ drain budget in packets.
#[inline]
fn set_irq_work_budget_pkts_inner(pkts: u32) {
    IRQ_WORK_BUDGET_PKTS.store(pkts.max(1), Ordering::Relaxed);
}

/// Sets per-pass IRQ drain budget in packets.
#[cfg(feature = "host-api")]
pub fn set_irq_work_budget_pkts(pkts: u32) {
    set_irq_work_budget_pkts_inner(pkts);
}

/// Check if cross-queue sweep is enabled for guest RX IRQ handling.
#[inline]
fn irq_cross_sweep_enabled_inner() -> bool {
    IRQ_CROSS_SWEEP_ENABLED.load(Ordering::Relaxed)
}

/// Checks if cross-queue sweep is enabled for service-side RX IRQ handling.
#[cfg(feature = "host-api")]
pub fn irq_cross_sweep_enabled() -> bool {
    irq_cross_sweep_enabled_inner()
}

/// Enable/disable cross-queue sweep for guest RX IRQ handling.
#[inline]
fn set_irq_cross_sweep_enabled_inner(enabled: bool) {
    IRQ_CROSS_SWEEP_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Enables or disables cross-queue sweep for service-side RX IRQ handling.
#[cfg(feature = "host-api")]
pub fn set_irq_cross_sweep_enabled(enabled: bool) {
    set_irq_cross_sweep_enabled_inner(enabled);
}

/// Check if first data packet after empty queue should force IRQ.
#[inline]
fn irq_urgent_first_packet_inner() -> bool {
    IRQ_URGENT_FIRST_PACKET.load(Ordering::Relaxed)
}

/// Checks if first data packet after empty queue should force IRQ.
#[cfg(feature = "host-api")]
pub fn irq_urgent_first_packet() -> bool {
    irq_urgent_first_packet_inner()
}

/// Enable/disable urgent IRQ on first data packet after empty queue.
#[inline]
fn set_irq_urgent_first_packet_inner(enabled: bool) {
    IRQ_URGENT_FIRST_PACKET.store(enabled, Ordering::Relaxed);
}

/// Enables or disables urgent IRQ on first data packet after empty queue.
#[cfg(feature = "host-api")]
pub fn set_irq_urgent_first_packet(enabled: bool) {
    set_irq_urgent_first_packet_inner(enabled);
}

/// Get RX credit headroom in bytes.
#[inline]
fn rx_credit_headroom_bytes_inner() -> u32 {
    RX_CREDIT_HEADROOM_BYTES.load(Ordering::Relaxed)
}

/// Gets RX credit headroom in bytes.
#[cfg(feature = "host-api")]
pub fn rx_credit_headroom_bytes() -> u32 {
    rx_credit_headroom_bytes_inner()
}

/// Set RX credit headroom in bytes.
#[inline]
#[cfg(feature = "host-api")]
pub fn set_rx_credit_headroom_bytes(bytes: u32) {
    RX_CREDIT_HEADROOM_BYTES.store(bytes, Ordering::Relaxed);
}

/// Returns the current FrameVsock RX queue being drained.
fn current_rx_queue_id() -> Option<usize> {
    iht::current_vcpu_id()
}

/// Snapshots backend host-to-service debug counters.
#[cfg(feature = "host-api")]
pub fn backend_tx_debug_stats() -> BackendTxDebugStats {
    BackendTxDebugStats {
        data_submit_attempts: DATA_SUBMIT_ATTEMPTS.load(Ordering::Relaxed),
        data_submit_success: DATA_SUBMIT_SUCCESS.load(Ordering::Relaxed),
        data_submit_err_bad_cid: DATA_SUBMIT_ERR_BAD_CID.load(Ordering::Relaxed),
        data_submit_err_no_handler: DATA_SUBMIT_ERR_NO_HANDLER.load(Ordering::Relaxed),
        data_submit_err_transfer: DATA_SUBMIT_ERR_TRANSFER.load(Ordering::Relaxed),
        data_send_attempts: DATA_SEND_ATTEMPTS.load(Ordering::Relaxed),
        data_send_success: DATA_SEND_SUCCESS.load(Ordering::Relaxed),
        data_send_err_bad_cid: DATA_SEND_ERR_BAD_CID.load(Ordering::Relaxed),
        data_send_err_vm_inactive: DATA_SEND_ERR_VM_INACTIVE.load(Ordering::Relaxed),
        data_send_err_vm_missing: DATA_SEND_ERR_VM_MISSING.load(Ordering::Relaxed),
        data_send_err_queue_missing: DATA_SEND_ERR_QUEUE_MISSING.load(Ordering::Relaxed),
        data_send_err_queue_full: DATA_SEND_ERR_QUEUE_FULL.load(Ordering::Relaxed),
        data_irq_forced_on_full: DATA_IRQ_FORCED_ON_FULL.load(Ordering::Relaxed),
        data_irq_policy_inject: DATA_IRQ_POLICY_INJECT.load(Ordering::Relaxed),
        control_submit_attempts: CONTROL_SUBMIT_ATTEMPTS.load(Ordering::Relaxed),
        control_submit_success: CONTROL_SUBMIT_SUCCESS.load(Ordering::Relaxed),
        control_submit_err_bad_cid: CONTROL_SUBMIT_ERR_BAD_CID.load(Ordering::Relaxed),
        control_submit_err_no_handler: CONTROL_SUBMIT_ERR_NO_HANDLER.load(Ordering::Relaxed),
        control_submit_err_transfer: CONTROL_SUBMIT_ERR_TRANSFER.load(Ordering::Relaxed),
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

/// Resets backend host-to-service debug counters.
#[cfg(feature = "host-api")]
pub fn reset_backend_tx_debug_stats() {
    DATA_SUBMIT_ATTEMPTS.store(0, Ordering::Relaxed);
    DATA_SUBMIT_SUCCESS.store(0, Ordering::Relaxed);
    DATA_SUBMIT_ERR_BAD_CID.store(0, Ordering::Relaxed);
    DATA_SUBMIT_ERR_NO_HANDLER.store(0, Ordering::Relaxed);
    DATA_SUBMIT_ERR_TRANSFER.store(0, Ordering::Relaxed);
    DATA_SEND_ATTEMPTS.store(0, Ordering::Relaxed);
    DATA_SEND_SUCCESS.store(0, Ordering::Relaxed);
    DATA_SEND_ERR_BAD_CID.store(0, Ordering::Relaxed);
    DATA_SEND_ERR_VM_INACTIVE.store(0, Ordering::Relaxed);
    DATA_SEND_ERR_VM_MISSING.store(0, Ordering::Relaxed);
    DATA_SEND_ERR_QUEUE_MISSING.store(0, Ordering::Relaxed);
    DATA_SEND_ERR_QUEUE_FULL.store(0, Ordering::Relaxed);
    DATA_IRQ_FORCED_ON_FULL.store(0, Ordering::Relaxed);
    DATA_IRQ_POLICY_INJECT.store(0, Ordering::Relaxed);
    CONTROL_SUBMIT_ATTEMPTS.store(0, Ordering::Relaxed);
    CONTROL_SUBMIT_SUCCESS.store(0, Ordering::Relaxed);
    CONTROL_SUBMIT_ERR_BAD_CID.store(0, Ordering::Relaxed);
    CONTROL_SUBMIT_ERR_NO_HANDLER.store(0, Ordering::Relaxed);
    CONTROL_SUBMIT_ERR_TRANSFER.store(0, Ordering::Relaxed);
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

/// Handler type for data packets submitted by a service.
type HostDataHandler = fn(RRef<DataPacket>);

/// Handler type for control packets submitted by a service.
type HostControlHandler = fn(RRef<ControlPacket>);

/// Handler type for host-to-service TX queue drain notifications.
///
/// Called when a data packet is popped from a host-to-service data queue.
/// Arguments are (vcpu_id, queue_reserved_len_before_pop).
type HostQueueDrainHandler = fn(usize, usize);

static HOST_DATA_HANDLER: Once<HostDataHandler> = Once::new();
static HOST_CONTROL_HANDLER: Once<HostControlHandler> = Once::new();
static HOST_QUEUE_DRAIN_HANDLER: Once<HostQueueDrainHandler> = Once::new();

/// Registers the host handler for service-submitted data packets.
///
/// Called by the host socket layer during initialization.
#[cfg(feature = "host-api")]
pub fn register_host_data_handler(handler: fn(RRef<DataPacket>)) {
    HOST_DATA_HANDLER.call_once(|| handler);
}

/// Registers the host handler for service-submitted control packets.
///
/// Called by the host socket layer during initialization.
#[cfg(feature = "host-api")]
pub fn register_host_control_handler(handler: fn(RRef<ControlPacket>)) {
    HOST_CONTROL_HANDLER.call_once(|| handler);
}

/// Registers the host handler for host-to-service TX queue drain notifications.
///
/// Called by the host socket layer during initialization.
#[cfg(feature = "host-api")]
pub fn register_host_queue_drain_handler(handler: fn(usize, usize)) {
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
// TX path: service to host.
// ============================================================================

/// Submits a data packet from the service to the host.
///
/// The packet ownership is transferred to host domain and the registered
/// handler is invoked synchronously.
fn submit_service_data(packet: RRef<DataPacket>) -> Result<(), RRef<DataPacket>> {
    let _trace = trace::TraceGuard::new(&trace::FRAMEVISOR_SEND_TO_HOST_DATA);
    DATA_SUBMIT_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    if packet.header.dst_cid != HOST_CID {
        DATA_SUBMIT_ERR_BAD_CID.fetch_add(1, Ordering::Relaxed);
        return Err(packet);
    }
    let Some(handler) = HOST_DATA_HANDLER.get() else {
        DATA_SUBMIT_ERR_NO_HANDLER.fetch_add(1, Ordering::Relaxed);
        return Err(packet);
    };
    let packet = match packet.try_transfer_to(DomainId::Host) {
        Ok(packet) => packet,
        Err(error) => {
            DATA_SUBMIT_ERR_TRANSFER.fetch_add(1, Ordering::Relaxed);
            return Err(error.into_rref());
        }
    };
    DATA_SUBMIT_SUCCESS.fetch_add(1, Ordering::Relaxed);
    let _host_domain = enter_domain(DomainId::Host);
    handler(packet);
    Ok(())
}

/// Submits a control packet from the service to the host.
fn submit_service_control(packet: RRef<ControlPacket>) -> Result<(), RRef<ControlPacket>> {
    let _trace = trace::TraceGuard::new(&trace::FRAMEVISOR_SEND_TO_HOST_CONTROL);
    CONTROL_SUBMIT_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    if packet.header.dst_cid != HOST_CID {
        CONTROL_SUBMIT_ERR_BAD_CID.fetch_add(1, Ordering::Relaxed);
        return Err(packet);
    }
    let Some(handler) = HOST_CONTROL_HANDLER.get() else {
        CONTROL_SUBMIT_ERR_NO_HANDLER.fetch_add(1, Ordering::Relaxed);
        return Err(packet);
    };
    let packet = match packet.try_transfer_to(DomainId::Host) {
        Ok(packet) => packet,
        Err(error) => {
            CONTROL_SUBMIT_ERR_TRANSFER.fetch_add(1, Ordering::Relaxed);
            return Err(error.into_rref());
        }
    };
    CONTROL_SUBMIT_SUCCESS.fetch_add(1, Ordering::Relaxed);
    let _host_domain = enter_domain(DomainId::Host);
    handler(packet);
    Ok(())
}

// ============================================================================
// RX path: host to service.
// ============================================================================

/// Sends a data packet from host to service.
///
/// Routes to the correct VM based on destination CID.
/// The packet is enqueued and an IRQ is injected to notify the service.
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
#[cfg(feature = "host-api")]
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

    if let Err(packet) = queues.push_data_to_domain(packet, DomainId::Service(vm_id)) {
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
    let urgent_first_packet = irq_urgent_first_packet_inner();
    let is_urgent = urgent_first_packet && queues.data_queue_len() == 1;
    if queues.should_inject_irq(is_urgent, true, now_ns) {
        DATA_IRQ_POLICY_INJECT.fetch_add(1, Ordering::Relaxed);
        irq::inject_vsock_rx_interrupt_for_vm(vm_id, vcpu_id);
    }

    DATA_SEND_SUCCESS.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Sends a control packet from host to service.
///
/// Routes to the correct VM based on destination CID.
#[cfg(feature = "host-api")]
pub fn send_to_guest_control(
    vcpu_id: usize,
    packet: RRef<ControlPacket>,
) -> Result<(), RRef<ControlPacket>> {
    CONTROL_SEND_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let _trace = trace::TraceGuard::new(&trace::FRAMEVISOR_SEND_TO_GUEST_CONTROL);
    let dst_cid = packet.header.dst_cid;

    // Get VM ID from destination CID
    let vm_id = match cid_to_vm_id(dst_cid) {
        Some(vm_id) => vm_id,
        None => {
            CONTROL_SEND_ERR_BAD_CID.fetch_add(1, Ordering::Relaxed);
            return Err(packet);
        }
    };

    // Check if VM is active
    if !is_vm_active(vm_id) {
        CONTROL_SEND_ERR_VM_INACTIVE.fetch_add(1, Ordering::Relaxed);
        return Err(packet);
    }

    // Get VM instance
    let vm = match vm::get_vm_by_id(vm_id) {
        Some(vm) => vm,
        None => {
            CONTROL_SEND_ERR_VM_MISSING.fetch_add(1, Ordering::Relaxed);
            return Err(packet);
        }
    };
    let queues = match vm.vsock_queues(vcpu_id) {
        Some(queues) => queues,
        None => {
            CONTROL_SEND_ERR_QUEUE_MISSING.fetch_add(1, Ordering::Relaxed);
            return Err(packet);
        }
    };

    if let Err(packet) = queues.push_control_to_domain(packet, DomainId::Service(vm_id)) {
        // Control queue pressure can also block credit/shutdown signaling.
        // Force an IRQ kick to help guest drain and recover quickly.
        CONTROL_SEND_ERR_QUEUE_FULL.fetch_add(1, Ordering::Relaxed);
        CONTROL_IRQ_FORCED_ON_FULL.fetch_add(1, Ordering::Relaxed);
        irq::inject_vsock_rx_interrupt_for_vm(vm_id, vcpu_id);
        return Err(packet);
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
#[cfg(feature = "host-api")]
pub use send_to_guest_control as deliver_control_packet;
#[cfg(feature = "host-api")]
pub use send_to_guest_data as deliver_data_packet;

// ============================================================================
// Receive API.
// ============================================================================

/// Receives a data packet from the backend for a specific VM.
///
/// Called by the service-visible transport path to retrieve pending data.
#[cfg(feature = "host-api")]
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

/// Receives multiple data packets from the backend for a specific VM.
#[cfg(feature = "host-api")]
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

/// Receives a control packet from the backend for a specific VM.
///
/// Called by the service-visible transport path to retrieve pending control messages.
#[cfg(feature = "host-api")]
pub fn recv_control_packet_for_vm(vm_id: VmId, vcpu_id: usize) -> Option<RRef<ControlPacket>> {
    let vm = vm::get_vm_by_id(vm_id)?;
    let queues = vm.vsock_queues(vcpu_id)?;
    let queue_reserved_len_before_pop = queues.control_queue_reserved_len();
    let packet = queues.pop_control();
    if packet.is_some() {
        notify_host_queue_drain(vcpu_id, queue_reserved_len_before_pop);
    }
    packet
}

/// Receives multiple control packets from the backend for a specific VM.
#[cfg(feature = "host-api")]
pub fn recv_control_packets_for_vm(
    vm_id: VmId,
    vcpu_id: usize,
    max_count: usize,
) -> Vec<RRef<ControlPacket>> {
    if let Some(vm) = vm::get_vm_by_id(vm_id) {
        if let Some(q) = vm.vsock_queues(vcpu_id) {
            let queue_reserved_len_before_pop = q.control_queue_reserved_len();
            let packets = q.pop_control_batch(max_count);
            if !packets.is_empty() {
                notify_host_queue_drain(vcpu_id, queue_reserved_len_before_pop);
            }
            return packets;
        }
    }
    Vec::new()
}

/// Receives a data packet from the backend for the current single-VM path.
fn recv_data_packet(vcpu_id: usize) -> Option<RRef<DataPacket>> {
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
fn recv_data_packets(vcpu_id: usize, max_count: usize) -> Vec<RRef<DataPacket>> {
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
fn recv_control_packet(vcpu_id: usize) -> Option<RRef<ControlPacket>> {
    let vm = vm::get_vm()?;
    let queues = vm.vsock_queues(vcpu_id)?;
    let queue_reserved_len_before_pop = queues.control_queue_reserved_len();
    let packet = queues.pop_control();
    if packet.is_some() {
        notify_host_queue_drain(vcpu_id, queue_reserved_len_before_pop);
    }
    packet
}

/// Receive multiple control packets from backend (backward compatible, uses first VM).
#[cfg(feature = "host-api")]
pub fn recv_control_packets(vcpu_id: usize, max_count: usize) -> Vec<RRef<ControlPacket>> {
    if let Some(vm) = vm::get_vm() {
        if let Some(q) = vm.vsock_queues(vcpu_id) {
            let queue_reserved_len_before_pop = q.control_queue_reserved_len();
            let packets = q.pop_control_batch(max_count);
            if !packets.is_empty() {
                notify_host_queue_drain(vcpu_id, queue_reserved_len_before_pop);
            }
            return packets;
        }
    }
    Vec::new()
}

// ============================================================================
// Query API
// ============================================================================

/// Check if there are pending data packets for a specific VM.
#[cfg(feature = "host-api")]
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
#[cfg(feature = "host-api")]
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
fn has_pending_data(vcpu_id: usize) -> bool {
    vm::get_vm()
        .map(|vm| {
            vm.vsock_queues(vcpu_id)
                .map(|q| q.has_pending_data())
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Check if there are pending control packets (backward compatible).
fn has_pending_control(vcpu_id: usize) -> bool {
    vm::get_vm()
        .map(|vm| {
            vm.vsock_queues(vcpu_id)
                .map(|q| q.has_pending_control())
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// Get per-vCPU queue stats for the current VM (if any).
#[cfg(feature = "host-api")]
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
#[cfg(feature = "host-api")]
pub fn get_vcpu_count_for_vm(vm_id: VmId) -> usize {
    vm::get_vcpu_count_for_vm(vm_id)
}

/// Get vCPU count (backward compatible, uses first VM).
#[inline]
#[cfg(feature = "host-api")]
pub fn get_vcpu_count() -> usize {
    vm::get_vcpu_count()
}
