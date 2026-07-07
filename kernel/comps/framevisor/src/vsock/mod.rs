// SPDX-License-Identifier: MPL-2.0

//! FrameVsock device boundary.
//!
//! This module is a host-only backend implementation. It routes packets, owns
//! queues, injects virtual interrupts, and exposes host debug/control state only
//! through the FrameVisor crate. FrameVM code must not import this module
//! directly; it sees only the safe `framev-sock-common` protocol types and its own
//! socket layer.
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
//! 2. The backend routes by CID, enqueues in the guest domain queue, and
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
    //! The functions in this module are exported only through the FrameVisor
    //! crate and preserve the dynamic link boundary used by loaded services.
    //! They carry `RRef` values and therefore must not become a source-level API
    //! for FrameVM or any OSTD-compatible service payload.

    use alloc::vec::Vec;

    use aster_framevisor_exchangeable::RRef;
    use framev_sock_common::FrameVsockPacket;

    /// Marks the service-side transport active.
    pub fn activate() {
        super::state::set_guest_active(true);
    }

    /// Marks the service-side transport inactive.
    pub fn deactivate() {
        super::state::set_guest_active(false);
    }

    /// Submits one unified FrameV Sock packet to the device.
    #[inline]
    pub fn submit_packet(
        queue_id: usize,
        packet: RRef<FrameVsockPacket>,
    ) -> Result<(), RRef<FrameVsockPacket>> {
        super::submit_service_packet(queue_id, packet)
    }

    /// Receives one unified FrameV Sock packet from a queue.
    #[inline]
    pub fn recv_packet(queue_id: usize) -> Option<RRef<FrameVsockPacket>> {
        super::recv_packet(queue_id)
    }

    /// Receives a batch of unified FrameV Sock packets from a queue.
    #[inline]
    pub fn recv_packets(queue_id: usize, max_count: usize) -> Vec<RRef<FrameVsockPacket>> {
        super::recv_packets(queue_id, max_count)
    }

    /// Returns whether a queue has pending unified FrameV Sock packets.
    #[inline]
    pub fn has_pending_packet(queue_id: usize) -> bool {
        super::has_pending_packet(queue_id)
    }
}

mod notify;
mod queues;
mod ring;
mod state;

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use aster_framevisor_exchangeable::{DomainId, RRef, enter_domain};
use framev_sock_common::{
    FlowAffinityTable, FrameVsockAddr, FrameVsockFlowKey, FrameVsockPacket, HOST_CID, VsockOp,
    cid_to_vm_id,
};
pub(crate) use queues::{IrqCoalescingConfig, VcpuQueues};

pub use crate::vm::VmId;
use crate::{
    rref_registry,
    sync::{Once, SpinLock},
    task, vm,
};

/// Host-control handle for one VM's `framev-sock` backend.
#[derive(Clone)]
pub struct FrameVmSock {
    vm: Arc<vm::FrameVm>,
}

impl FrameVmSock {
    fn device(&self) -> &crate::device::Sock {
        self.vm.devices().sock()
    }

    fn queues(&self, vcpu_id: usize) -> Option<&VcpuQueues> {
        self.device().queues(vcpu_id)
    }

    /// Returns the owning FrameVM ID.
    pub fn vm_id(&self) -> VmId {
        self.vm.id()
    }

    pub(crate) fn set_active(&self, active: bool) {
        self.device().set_active(active);
    }

    /// Returns whether this VM's `framev-sock` frontend is active.
    pub(crate) fn is_active(&self) -> bool {
        self.device().is_active()
    }

    /// Returns the fixed number of queue pairs for this VM's `framev-sock`.
    pub(crate) fn queue_count(&self) -> usize {
        self.device().queue_count()
    }

    /// Sends a unified packet through this VM's `framev-sock` backend.
    pub fn send_packet(
        &self,
        vcpu_id: usize,
        packet: RRef<FrameVsockPacket>,
    ) -> Result<(), RRef<FrameVsockPacket>> {
        send_to_guest_packet_for_sock(self, vcpu_id, packet)
    }

    fn recv_packet(&self, vcpu_id: usize) -> Option<RRef<FrameVsockPacket>> {
        let queues = self.queues(vcpu_id)?;
        let queue_reserved_len_before_pop = queues.packet_queue_reserved_len();
        let packet = queues.pop_packet();
        if packet.is_some() {
            notify_host_queue_drain(self, vcpu_id, queue_reserved_len_before_pop);
        }
        packet
    }

    fn recv_packets(&self, vcpu_id: usize, max_count: usize) -> Vec<RRef<FrameVsockPacket>> {
        let Some(queues) = self.queues(vcpu_id) else {
            return Vec::new();
        };

        let queue_reserved_len_before_pop = queues.packet_queue_reserved_len();
        let packets = queues.pop_packet_batch(max_count);
        if !packets.is_empty() {
            notify_host_queue_drain(self, vcpu_id, queue_reserved_len_before_pop);
        }
        packets
    }

    fn has_pending_packet(&self, vcpu_id: usize) -> bool {
        self.queues(vcpu_id)
            .map(|queue| queue.has_pending_packet())
            .unwrap_or(false)
    }

    fn notify_rx(&self, vcpu_id: usize) {
        let _ = self.vm.devices().notify_sock_rx(
            self.vm.id(),
            self.vm.is_running(),
            vcpu_id,
            |vcpu_id| self.vm.vcpu_irq_load(vcpu_id),
        );
    }
}

pub(crate) fn sock_for_vm_id(vm_id: VmId) -> crate::Result<FrameVmSock> {
    let vm = vm::get_vm_by_id(vm_id).ok_or(crate::Error::InvalidArgs)?;
    Ok(FrameVmSock { vm })
}

fn current_service_sock() -> Option<FrameVmSock> {
    let frame_vcpu_id = task::current_frame_vcpu_id()?;
    sock_for_vm_id(frame_vcpu_id.vm_id()).ok()
}

/// Handler type for unified packets submitted by a service.
pub(crate) type HostPacketHandler = fn(RRef<FrameVsockPacket>);

/// Handler type for host-to-service TX queue drain notifications.
///
/// Called when a packet is popped from a host-to-service queue.
/// Arguments are (vcpu_id, queue_reserved_len_before_pop).
pub(crate) type HostQueueDrainHandler = fn(usize, usize);

struct HostEndpoint {
    binding: HostEndpointBinding,
}

impl HostEndpoint {
    const fn new() -> Self {
        Self {
            binding: HostEndpointBinding::new(),
        }
    }

    fn binding_for_new_device(&self) -> HostEndpointBinding {
        HostEndpointBinding::from_endpoint(&self.binding)
    }

    fn register_packet_handler(&self, handler: HostPacketHandler) {
        self.binding.set_packet_handler(handler);
        propagate_host_endpoint_update(|device| device.set_host_packet_handler(handler));
    }

    fn register_queue_drain_handler(&self, handler: HostQueueDrainHandler) {
        self.binding.set_queue_drain_handler(handler);
        propagate_host_endpoint_update(|device| device.set_host_queue_drain_handler(handler));
    }
}

struct HostEndpointBinding {
    packet: Once<HostPacketHandler>,
    queue_drain: Once<HostQueueDrainHandler>,
}

impl HostEndpointBinding {
    const fn new() -> Self {
        Self {
            packet: Once::new(),
            queue_drain: Once::new(),
        }
    }

    fn from_endpoint(endpoint: &Self) -> Self {
        let handlers = Self::new();
        if let Some(handler) = endpoint.packet_handler() {
            handlers.set_packet_handler(handler);
        }
        if let Some(handler) = endpoint.queue_drain_handler() {
            handlers.set_queue_drain_handler(handler);
        }
        handlers
    }

    fn packet_handler(&self) -> Option<HostPacketHandler> {
        self.packet.get().copied()
    }

    fn queue_drain_handler(&self) -> Option<HostQueueDrainHandler> {
        self.queue_drain.get().copied()
    }

    fn set_packet_handler(&self, handler: HostPacketHandler) {
        self.packet.call_once(|| handler);
    }

    fn set_queue_drain_handler(&self, handler: HostQueueDrainHandler) {
        self.queue_drain.call_once(|| handler);
    }
}

static HOST_ENDPOINT: HostEndpoint = HostEndpoint::new();

fn propagate_host_endpoint_update(mut visit_fn: impl FnMut(&crate::device::Sock)) {
    for vm_id in vm::list_vms() {
        if let Ok(sock) = sock_for_vm_id(vm_id) {
            visit_fn(sock.device());
        }
    }
}

/// Backend runtime state for one required FrameVsock device.
pub(crate) struct FrameVsockDevice {
    active: AtomicBool,
    queues: Vec<VcpuQueues>,
    flow_affinity: SpinLock<FlowAffinityTable>,
    irq_urgent_first_packet: AtomicBool,
    irq_batch_threshold: AtomicU32,
    irq_time_threshold_us: AtomicU64,
    irq_config_epoch: AtomicU64,
    host_endpoint: HostEndpointBinding,
}

impl FrameVsockDevice {
    /// Creates inactive backend state for one required FrameVsock device.
    pub(crate) fn new(vcpu_count: usize) -> Self {
        let irq_config = IrqCoalescingConfig::new(
            DEFAULT_IRQ_BATCH_THRESHOLD,
            DEFAULT_IRQ_TIME_THRESHOLD_US,
            1,
        );

        Self {
            active: AtomicBool::new(false),
            queues: (0..vcpu_count)
                .map(|_| VcpuQueues::new(irq_config))
                .collect(),
            flow_affinity: SpinLock::new(FlowAffinityTable::new()),
            irq_urgent_first_packet: AtomicBool::new(true),
            irq_batch_threshold: AtomicU32::new(irq_config.batch_threshold()),
            irq_time_threshold_us: AtomicU64::new(irq_config.time_threshold_us()),
            irq_config_epoch: AtomicU64::new(irq_config.epoch()),
            host_endpoint: HOST_ENDPOINT.binding_for_new_device(),
        }
    }

    /// Sets whether the service-side FrameVsock frontend is active.
    pub(crate) fn set_active(&self, active: bool) {
        if active {
            if !self.active.swap(true, Ordering::AcqRel) {
                self.start_queues();
            }
        } else {
            self.active.store(false, Ordering::Release);
            self.stop_queues();
        }
    }

    /// Returns whether the service-side FrameVsock frontend is active.
    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Returns the backend queues for one vCPU.
    pub(crate) fn queues(&self, vcpu_id: usize) -> Option<&VcpuQueues> {
        self.queues.get(vcpu_id)
    }

    /// Returns the fixed number of per-vCPU queue pairs.
    pub(crate) fn queue_count(&self) -> usize {
        self.queues.len()
    }

    /// Returns the ready-time FrameV ring count for this device.
    pub(crate) fn ring_count(&self) -> usize {
        self.queue_count().saturating_mul(2)
    }

    /// Returns whether the first queued packet forces an IRQ.
    pub(crate) fn irq_urgent_first_packet(&self) -> bool {
        self.irq_urgent_first_packet.load(Ordering::Relaxed)
    }

    /// Returns the device-local IRQ coalescing policy.
    pub(crate) fn irq_coalescing_config(&self) -> IrqCoalescingConfig {
        IrqCoalescingConfig::new(
            self.irq_batch_threshold.load(Ordering::Relaxed).max(1),
            self.irq_time_threshold_us.load(Ordering::Relaxed),
            self.irq_config_epoch.load(Ordering::Relaxed),
        )
    }

    /// Stops the device data path and drops queued backend packets.
    pub(crate) fn stop(&self) {
        self.set_active(false);
    }

    /// Resets volatile device state.
    pub(crate) fn reset(&self) {
        self.set_active(false);
    }

    fn start_queues(&self) {
        for queue in &self.queues {
            queue.start();
        }
    }

    fn stop_queues(&self) {
        self.clear_flow_affinity();
        for (vcpu_id, queue) in self.queues.iter().enumerate() {
            if let Some(queue_reserved_len) = queue.stop_and_clear() {
                notify_host_queue_drain_for_stop(self, vcpu_id, queue_reserved_len);
            }
        }
    }

    pub(crate) fn host_packet_handler(&self) -> Option<HostPacketHandler> {
        self.host_endpoint.packet_handler()
    }

    pub(crate) fn host_queue_drain_handler(&self) -> Option<HostQueueDrainHandler> {
        self.host_endpoint.queue_drain_handler()
    }

    pub(crate) fn set_host_packet_handler(&self, handler: HostPacketHandler) {
        self.host_endpoint.set_packet_handler(handler);
    }

    pub(crate) fn set_host_queue_drain_handler(&self, handler: HostQueueDrainHandler) {
        self.host_endpoint.set_queue_drain_handler(handler);
    }

    pub(crate) fn observe_submitted_packet_queue(
        &self,
        packet: &FrameVsockPacket,
        queue_id: usize,
    ) -> Result<usize, usize> {
        let key = FrameVsockFlowKey::from_packet(packet);
        self.flow_affinity
            .lock()
            .observe(key, queue_id)
            .map_err(|error| match error {
                framev_sock_common::FlowAffinityError::WrongQueue { expected, .. } => expected,
            })
    }

    pub(crate) fn select_outbound_packet_queue(
        &self,
        packet: &FrameVsockPacket,
        preferred_queue: usize,
    ) -> usize {
        let key = FrameVsockFlowKey::from_packet(packet);
        let mut affinity = self.flow_affinity.lock();
        if packet.operation() == VsockOp::Rst {
            return affinity.get(key).unwrap_or(preferred_queue);
        }
        affinity.bind_or_get(key, preferred_queue)
    }

    pub(crate) fn remove_packet_flow_key(&self, key: FrameVsockFlowKey) {
        self.flow_affinity.lock().remove(key);
    }

    fn clear_flow_affinity(&self) {
        self.flow_affinity.lock().clear();
    }
}

// The first FrameV Sock profile uses the simple notification policy: every
// published backend-to-frontend packet requests common IRQ delivery. The common
// device delivery path may still coalesce already-pending IRQ work without
// losing visible packets.
const DEFAULT_IRQ_BATCH_THRESHOLD: u32 = 1;
const DEFAULT_IRQ_TIME_THRESHOLD_US: u64 = 20;

fn current_time_ns() -> u64 {
    let freq = host_ostd::arch::tsc_freq();
    if freq == 0 {
        return 0;
    }
    let tsc = host_ostd::arch::read_tsc();
    ((tsc as u128) * 1_000_000_000u128 / freq as u128) as u64
}

// ============================================================================
// Host Handlers (registered by Host socket layer)
// ============================================================================

/// Initializes the RRef runtime used by host-side FrameV Sock carriers.
pub fn init_rref_runtime() {
    rref_registry::init();
}

/// Registers the host handler for service-submitted unified packets.
///
/// Called by the host socket layer during initialization.
pub fn register_host_packet_handler(handler: fn(RRef<FrameVsockPacket>)) {
    HOST_ENDPOINT.register_packet_handler(handler);
}

/// Registers the host handler for host-to-service TX queue drain notifications.
///
/// Called by the host socket layer during initialization.
pub fn register_host_queue_drain_handler(handler: fn(usize, usize)) {
    HOST_ENDPOINT.register_queue_drain_handler(handler);
}

fn service_packet_sock(src_cid: u64) -> Option<FrameVmSock> {
    cid_to_vm_id(src_cid)
        .and_then(|vm_id| sock_for_vm_id(vm_id).ok())
        .or_else(current_service_sock)
}

#[inline]
fn notify_host_queue_drain(
    sock: &FrameVmSock,
    vcpu_id: usize,
    queue_reserved_len_before_pop: usize,
) {
    if let Some(handler) = sock.device().host_queue_drain_handler() {
        handler(vcpu_id, queue_reserved_len_before_pop);
    }
}

fn notify_host_queue_drain_for_stop(
    device: &FrameVsockDevice,
    vcpu_id: usize,
    queue_reserved_len_before_pop: usize,
) {
    if let Some(handler) = device.host_queue_drain_handler() {
        handler(vcpu_id, queue_reserved_len_before_pop);
    }
}

// ============================================================================
// TX path: service to host.
// ============================================================================

/// Submits a unified FrameV Sock packet from the service to the host.
///
/// The queue id is transport state: it is learned for the flow and is not part
/// of the packet header.
fn submit_service_packet(
    queue_id: usize,
    packet: RRef<FrameVsockPacket>,
) -> Result<(), RRef<FrameVsockPacket>> {
    let header = packet.header();
    let source_sock = service_packet_sock(header.src_cid);
    if header.dst_cid != HOST_CID {
        return Err(packet);
    }

    let Some(sock) = source_sock.as_ref() else {
        return Err(packet);
    };
    let device = sock.device();
    if device
        .observe_submitted_packet_queue(&packet, queue_id)
        .is_err()
    {
        return Err(packet);
    }

    let Some(handler) = device.host_packet_handler() else {
        if packet.operation() == VsockOp::Request {
            return reject_service_request_with_rst(sock, queue_id, packet);
        }
        return Err(packet);
    };
    let removes_flow = packet.operation() == VsockOp::Rst;
    let flow_key = FrameVsockFlowKey::from_packet(&packet);
    let packet = match packet.try_transfer_to(DomainId::Host) {
        Ok(packet) => packet,
        Err(error) => return Err(error.into_rref()),
    };

    let _host_domain = enter_domain(DomainId::Host);
    handler(packet);
    if removes_flow {
        device.remove_packet_flow_key(flow_key);
    }
    Ok(())
}

fn reject_service_request_with_rst(
    sock: &FrameVmSock,
    preferred_queue: usize,
    packet: RRef<FrameVsockPacket>,
) -> Result<(), RRef<FrameVsockPacket>> {
    let header = packet.header();
    let rst = FrameVsockPacket::rst(
        FrameVsockAddr::new(header.dst_cid, header.dst_port),
        FrameVsockAddr::new(header.src_cid, header.src_port),
    );

    {
        let _host_domain = enter_domain(DomainId::Host);
        let rst = RRef::new_with_owner(rst, DomainId::Host);
        if send_to_guest_packet_for_sock(sock, preferred_queue, rst).is_err() {
            return Err(packet);
        }
    }

    match packet.try_transfer_to(DomainId::Host) {
        Ok(_packet) => Ok(()),
        Err(error) => Err(error.into_rref()),
    }
}

// ============================================================================
// RX path: host to service.
// ============================================================================

/// Sends a unified FrameV Sock packet from host to service.
///
/// The caller-provided vCPU is the first-flow queue policy. Established flows
/// are steered through their learned queue affinity.
fn send_to_guest_packet_for_sock(
    sock: &FrameVmSock,
    preferred_vcpu_id: usize,
    packet: RRef<FrameVsockPacket>,
) -> Result<(), RRef<FrameVsockPacket>> {
    let header = packet.header();
    let vm_id = sock.vm_id();
    if cid_to_vm_id(header.dst_cid) != Some(vm_id) {
        return Err(packet);
    }

    if !sock.vm.is_running() || !sock.is_active() {
        return Err(packet);
    }

    let device = sock.device();
    let vcpu_id = device.select_outbound_packet_queue(&packet, preferred_vcpu_id);
    let flow_key = FrameVsockFlowKey::from_packet(&packet);
    let queues = match sock.queues(vcpu_id) {
        Some(queues) => queues,
        None => {
            return Err(packet);
        }
    };

    if let Err(packet) = queues.push_packet_to_domain(packet, DomainId::Guest(vm_id)) {
        sock.notify_rx(vcpu_id);
        return Err(packet);
    }

    let now_ns = current_time_ns();
    queues.refresh_irq_strategy(device.irq_coalescing_config());
    let urgent_first_packet = device.irq_urgent_first_packet();
    let is_urgent = urgent_first_packet && queues.packet_queue_len() == 1;
    let should_inject_irq = queues.should_inject_irq(is_urgent, true, now_ns);
    if should_inject_irq {
        sock.notify_rx(vcpu_id);
    }

    if header.operation() == Some(VsockOp::Rst) {
        device.remove_packet_flow_key(flow_key);
    }

    Ok(())
}

/// Sends a unified FrameV Sock packet from host to service.
pub fn send_to_guest_packet(
    preferred_vcpu_id: usize,
    packet: RRef<FrameVsockPacket>,
) -> Result<(), RRef<FrameVsockPacket>> {
    let header = packet.header();
    let Some(vm_id) = cid_to_vm_id(header.dst_cid) else {
        return Err(packet);
    };
    let Ok(sock) = sock_for_vm_id(vm_id) else {
        return Err(packet);
    };

    sock.send_packet(preferred_vcpu_id, packet)
}

// ============================================================================
// Receive API.
// ============================================================================

/// Receives a unified FrameV Sock packet from the backend for a specific VM.
pub fn recv_packet_for_vm(vm_id: VmId, vcpu_id: usize) -> Option<RRef<FrameVsockPacket>> {
    sock_for_vm_id(vm_id).ok()?.recv_packet(vcpu_id)
}

/// Receives multiple unified FrameV Sock packets from the backend for a specific VM.
pub fn recv_packets_for_vm(
    vm_id: VmId,
    vcpu_id: usize,
    max_count: usize,
) -> Vec<RRef<FrameVsockPacket>> {
    sock_for_vm_id(vm_id)
        .map(|sock| sock.recv_packets(vcpu_id, max_count))
        .unwrap_or_default()
}

/// Receives a unified FrameV Sock packet from the current service VM.
fn recv_packet(vcpu_id: usize) -> Option<RRef<FrameVsockPacket>> {
    current_service_sock()?.recv_packet(vcpu_id)
}

/// Receives multiple unified FrameV Sock packets from the current service VM.
fn recv_packets(vcpu_id: usize, max_count: usize) -> Vec<RRef<FrameVsockPacket>> {
    current_service_sock()
        .map(|sock| sock.recv_packets(vcpu_id, max_count))
        .unwrap_or_default()
}

// ============================================================================
// Query API
// ============================================================================

/// Check if there are pending unified FrameV Sock packets for a specific VM.
pub fn has_pending_packet_for_vm(vm_id: VmId, vcpu_id: usize) -> bool {
    sock_for_vm_id(vm_id)
        .map(|sock| sock.has_pending_packet(vcpu_id))
        .unwrap_or(false)
}

/// Check if there are pending unified FrameV Sock packets for the current service VM.
fn has_pending_packet(vcpu_id: usize) -> bool {
    current_service_sock()
        .map(|sock| sock.has_pending_packet(vcpu_id))
        .unwrap_or(false)
}

// ============================================================================
// Utility
// ============================================================================

/// Get vCPU count for a specific VM.
#[inline]
pub fn get_vcpu_count_for_vm(vm_id: VmId) -> usize {
    sock_for_vm_id(vm_id)
        .map(|sock| sock.queue_count())
        .unwrap_or(0)
}

/// Gets the vCPU count for the FrameVM addressed by a `framev-sock` CID.
#[inline]
pub fn get_vcpu_count_for_cid(cid: u64) -> Option<usize> {
    cid_to_vm_id(cid)
        .map(vm::get_vcpu_count_for_vm)
        .filter(|vcpu_count| *vcpu_count != 0)
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn device_topology_uses_one_queue_pair_per_vcpu() {
        let device = FrameVsockDevice::new(3);

        assert_eq!(device.queue_count(), 3);
        assert_eq!(device.ring_count(), 6);
        assert!(device.queues(0).is_some());
        assert!(device.queues(1).is_some());
        assert!(device.queues(2).is_some());
        assert!(device.queues(3).is_none());
    }
}
