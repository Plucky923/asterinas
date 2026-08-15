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
//! Packets are routed through FrameVisor's CID registry, which records the
//! owning VM and device-claim generation.

#![deny(unsafe_code)]

mod cid;
mod queues;
mod ring;

pub use cid::SockConfiguration;
pub(crate) use cid::{CidReservation, route_for_cid};

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use aster_framevisor_exchangeable::{RRef, enter_vm};
use framev_sock_common::{
    FlowAffinityTable, FrameVsockAddr, FrameVsockFlowKey, FrameVsockPacket, FrameVsockSendError,
    HOST_CID, VsockOp,
};
use queues::QueuePushError;
pub(crate) use queues::VcpuQueues;

use crate::{
    rref_accounting,
    sync::{Once, SpinLock},
    task, vm,
    vm::VmId,
};

/// Host-control handle for one VM's `framev-sock` backend.
#[derive(Clone)]
pub(crate) struct FrameVmSock {
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
    pub(crate) fn vm_id(&self) -> VmId {
        self.vm.id()
    }

    pub(crate) fn set_active(&self, active: bool) -> bool {
        self.device().set_active(active)
    }

    /// Returns whether this VM's `framev-sock` frontend is active.
    pub(crate) fn is_active(&self) -> bool {
        self.device().is_active()
    }

    /// Returns the fixed number of queue pairs for this VM's `framev-sock`.
    pub(crate) fn queue_count(&self) -> usize {
        self.device().queue_count()
    }

    pub(crate) fn notify_reset(&self, vm_running: bool) -> crate::Result<()> {
        self.device().notify_reset(vm_running)
    }

    /// Sends a unified packet through this VM's `framev-sock` backend.
    fn send_packet(
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
        if queues.rearm_notification_if_drained() {
            let _ = self.device().notify_rx(self.vm.is_running(), vcpu_id);
        }
        if packet.is_some() {
            self.device()
                .notify_host_queue_drain(vcpu_id, queue_reserved_len_before_pop);
        }
        packet
    }
}

pub(crate) fn sock_for_vm_id(vm_id: VmId) -> crate::Result<FrameVmSock> {
    let vm = vm::get_vm_by_id(vm_id).ok_or(crate::Error::InvalidArgs)?;
    Ok(FrameVmSock { vm })
}

fn current_service_sock() -> Option<FrameVmSock> {
    task::current_frame_vm().map(|vm| FrameVmSock { vm })
}

/// Handler type for unified packets submitted by a service.
pub(crate) type HostPacketHandler = fn(RRef<FrameVsockPacket>);

/// Handler type for host-to-service TX queue drain notifications.
///
/// Called when a packet is popped from a host-to-service queue.
/// Arguments are (vcpu_id, queue_reserved_len_before_pop).
pub(crate) type HostQueueDrainHandler = fn(usize, usize);

/// A closed submission failure family that retains the unchanged packet.
enum SocketSendError {
    /// The packet source, owner, or queue selection is invalid.
    InvalidPacket(RRef<FrameVsockPacket>),
    /// The destination is denied, absent, or stale.
    DestinationUnavailable(RRef<FrameVsockPacket>),
    /// The selected receiver queue is full.
    ReceiverFull(RRef<FrameVsockPacket>),
    /// The sender or receiver stopped while the packet was submitted.
    Stopped(RRef<FrameVsockPacket>),
}

impl SocketSendError {
    fn into_parts(self) -> (FrameVsockSendError, RRef<FrameVsockPacket>) {
        match self {
            Self::InvalidPacket(packet) => (FrameVsockSendError::InvalidPacket, packet),
            Self::DestinationUnavailable(packet) => {
                (FrameVsockSendError::DestinationUnavailable, packet)
            }
            Self::ReceiverFull(packet) => (FrameVsockSendError::ReceiverFull, packet),
            Self::Stopped(packet) => (FrameVsockSendError::Stopped, packet),
        }
    }

    fn into_packet(self) -> RRef<FrameVsockPacket> {
        self.into_parts().1
    }
}

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
    pending_reset_generation: AtomicU64,
    last_reset_generation: AtomicU64,
    host_endpoint: HostEndpointBinding,
}

impl FrameVsockDevice {
    /// Creates inactive backend state for one required FrameVsock device.
    pub(crate) fn new(vcpu_count: usize) -> Self {
        Self {
            active: AtomicBool::new(false),
            queues: (0..vcpu_count).map(|_| VcpuQueues::new()).collect(),
            flow_affinity: SpinLock::new(FlowAffinityTable::new()),
            pending_reset_generation: AtomicU64::new(0),
            last_reset_generation: AtomicU64::new(0),
            host_endpoint: HOST_ENDPOINT.binding_for_new_device(),
        }
    }

    /// Sets whether the service-side FrameVsock frontend is active.
    pub(crate) fn set_active(&self, active: bool, generation: u64) -> bool {
        if active {
            if !self.active.swap(true, Ordering::AcqRel) {
                self.start_queues();
            }
            if generation > 1
                && self
                    .last_reset_generation
                    .swap(generation, Ordering::AcqRel)
                    != generation
            {
                self.pending_reset_generation
                    .store(generation, Ordering::Release);
                return true;
            }
        } else {
            self.active.store(false, Ordering::Release);
            self.pending_reset_generation.store(0, Ordering::Release);
            self.stop_queues();
        }
        false
    }

    /// Returns whether the service-side FrameVsock frontend is active.
    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Returns the backend queues for one vCPU.
    pub(crate) fn queues(&self, vcpu_id: usize) -> Option<&VcpuQueues> {
        self.queues.get(vcpu_id)
    }

    pub(crate) fn take_transport_reset(&self, generation: u64) -> Option<u64> {
        self.pending_reset_generation
            .compare_exchange(generation, 0, Ordering::AcqRel, Ordering::Acquire)
            .ok()
    }

    /// Returns the fixed number of per-vCPU queue pairs.
    pub(crate) fn queue_count(&self) -> usize {
        self.queues.len()
    }

    /// Returns the ready-time FrameV ring count for this device.
    pub(crate) fn ring_count(&self) -> usize {
        self.queue_count().saturating_mul(2)
    }

    /// Stops the device data path and drops queued backend packets.
    pub(crate) fn stop(&self) {
        let _ = self.set_active(false, 0);
    }

    /// Resets volatile device state.
    pub(crate) fn reset(&self) {
        let _ = self.set_active(false, 0);
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
                self.notify_host_queue_drain(vcpu_id, queue_reserved_len);
            }
        }
    }

    pub(crate) fn host_packet_handler(&self) -> Option<HostPacketHandler> {
        self.host_endpoint.packet_handler()
    }

    pub(crate) fn notify_host_queue_drain(
        &self,
        vcpu_id: usize,
        queue_reserved_len_before_pop: usize,
    ) {
        if let Some(handler) = self.host_endpoint.queue_drain_handler() {
            handler(vcpu_id, queue_reserved_len_before_pop);
        }
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

    pub(crate) fn has_packet_flow(&self, packet: &FrameVsockPacket) -> bool {
        self.flow_affinity
            .lock()
            .get(FrameVsockFlowKey::from_packet(packet))
            .is_some()
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

// ============================================================================
// Host Handlers (registered by Host socket layer)
// ============================================================================

/// Initializes the RRef runtime used by host-side FrameV Sock carriers.
pub fn init_rref_runtime() {
    rref_accounting::init();
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

fn service_packet_source_matches(sock: &FrameVmSock, src_cid: u64, owner: VmId) -> bool {
    let Some(route) = route_for_cid(src_cid) else {
        return false;
    };
    route.vm_id == sock.vm_id()
        && route.generation == sock.device().claimed_generation().unwrap_or(0)
        && owner == sock.vm_id()
}

// ============================================================================
// TX path: service to host.
// ============================================================================

/// Submits a unified FrameV Sock packet from the service to the host.
///
/// The queue id is transport state: it is learned for the flow and is not part
/// of the packet header.
fn submit_service_packet_inner(
    queue_id: usize,
    packet: RRef<FrameVsockPacket>,
) -> Result<(), SocketSendError> {
    let header = packet.header();
    let src_cid = header.src_cid;
    let dst_cid = header.dst_cid;
    let dst_port = header.dst_port;
    let operation = packet.operation();
    let Some(sock) = current_service_sock() else {
        return Err(SocketSendError::Stopped(packet));
    };
    if !service_packet_source_matches(&sock, src_cid, packet.owner()) {
        return Err(SocketSendError::InvalidPacket(packet));
    }
    let device = sock.device();
    if device
        .observe_submitted_packet_queue(&packet, queue_id)
        .is_err()
    {
        return Err(SocketSendError::InvalidPacket(packet));
    }
    if dst_cid == HOST_CID {
        let authorized_flow = device.has_packet_flow(&packet);
        if !authorized_flow
            && (operation != VsockOp::Request
                || !device
                    .configuration()
                    .allows_guest_connect_host_port(dst_port))
        {
            return Err(SocketSendError::DestinationUnavailable(packet));
        }
    } else {
        let Ok(peer_cid) = u32::try_from(header.dst_cid) else {
            return Err(SocketSendError::DestinationUnavailable(packet));
        };
        if !device.configuration().allows_peer(peer_cid) {
            return Err(SocketSendError::DestinationUnavailable(packet));
        }
        let Some(route) = route_for_cid(header.dst_cid) else {
            return Err(SocketSendError::DestinationUnavailable(packet));
        };
        let Ok(destination) = sock_for_vm_id(route.vm_id) else {
            return Err(SocketSendError::DestinationUnavailable(packet));
        };
        let preferred_queue =
            FrameVsockFlowKey::from_packet(&packet).preferred_queue(destination.queue_count());
        return enqueue_guest_packet_for_sock(&destination, preferred_queue, packet);
    }

    let Some(handler) = device.host_packet_handler() else {
        if operation == VsockOp::Request {
            return reject_service_request_with_rst(&sock, queue_id, packet)
                .map_err(SocketSendError::DestinationUnavailable);
        }
        return Err(SocketSendError::DestinationUnavailable(packet));
    };
    let removes_flow = packet.operation() == VsockOp::Rst;
    let flow_key = FrameVsockFlowKey::from_packet(&packet);
    let packet = match packet.try_transfer_to(VmId::Host) {
        Ok(packet) => packet,
        Err(error) => return Err(SocketSendError::InvalidPacket(error.into_rref())),
    };

    let _host_vm = enter_vm(VmId::Host);
    handler(packet);
    if removes_flow {
        device.remove_packet_flow_key(flow_key);
    }
    Ok(())
}

pub(crate) fn submit_service_packet(
    queue_id: usize,
    packet: RRef<FrameVsockPacket>,
) -> Result<(), (FrameVsockSendError, RRef<FrameVsockPacket>)> {
    submit_service_packet_inner(queue_id, packet).map_err(SocketSendError::into_parts)
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
        let _host_vm = enter_vm(VmId::Host);
        let rst = RRef::new_with_owner(rst, VmId::Host);
        if send_to_guest_packet_for_sock(sock, preferred_queue, rst).is_err() {
            return Err(packet);
        }
    }

    match packet.try_transfer_to(VmId::Host) {
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
    enqueue_guest_packet_for_sock(sock, preferred_vcpu_id, packet)
        .map_err(SocketSendError::into_packet)
}

fn enqueue_guest_packet_for_sock(
    sock: &FrameVmSock,
    preferred_vcpu_id: usize,
    packet: RRef<FrameVsockPacket>,
) -> Result<(), SocketSendError> {
    let header = packet.header();
    let dst_cid = header.dst_cid;
    let dst_port = header.dst_port;
    let operation = packet.operation();
    let vm_id = sock.vm_id();
    let Some(route) = route_for_cid(dst_cid) else {
        return Err(SocketSendError::DestinationUnavailable(packet));
    };
    if route.vm_id != vm_id || route.generation != sock.device().claimed_generation().unwrap_or(0) {
        return Err(SocketSendError::DestinationUnavailable(packet));
    }

    if packet.owner() == VmId::Host {
        if header.src_cid != HOST_CID {
            return Err(SocketSendError::InvalidPacket(packet));
        }
        let authorized_flow = sock.device().has_packet_flow(&packet);
        if !authorized_flow
            && (operation != VsockOp::Request
                || !sock
                    .device()
                    .configuration()
                    .allows_host_connect_guest_port(dst_port))
        {
            return Err(SocketSendError::DestinationUnavailable(packet));
        }
    }

    if !sock.vm.is_running() || !sock.is_active() {
        return Err(SocketSendError::Stopped(packet));
    }

    let device = sock.device();
    let vcpu_id = device.select_outbound_packet_queue(&packet, preferred_vcpu_id);
    let flow_key = FrameVsockFlowKey::from_packet(&packet);
    let queues = match sock.queues(vcpu_id) {
        Some(queues) => queues,
        None => return Err(SocketSendError::DestinationUnavailable(packet)),
    };

    let should_notify = match queues.push_packet_to_vm(packet, vm_id) {
        Ok(should_notify) => should_notify,
        Err(error) => {
            let _ = sock.device().notify_rx(sock.vm.is_running(), vcpu_id);
            return Err(match error {
                QueuePushError::InvalidOwner(packet) => SocketSendError::InvalidPacket(packet),
                QueuePushError::Full(packet) => SocketSendError::ReceiverFull(packet),
                QueuePushError::Stopped(packet) => SocketSendError::Stopped(packet),
            });
        }
    };

    if should_notify {
        let _ = device.notify_rx(sock.vm.is_running(), vcpu_id);
    }
    if operation == VsockOp::Rst {
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
    let Some(route) = route_for_cid(header.dst_cid) else {
        return Err(packet);
    };
    let Ok(sock) = sock_for_vm_id(route.vm_id) else {
        return Err(packet);
    };

    sock.send_packet(preferred_vcpu_id, packet)
}

// ============================================================================
// Receive API.
// ============================================================================

/// Receives a unified FrameV Sock packet from the backend for a specific VM.
pub(crate) fn recv_packet_for_vm(vm_id: VmId, vcpu_id: usize) -> Option<RRef<FrameVsockPacket>> {
    sock_for_vm_id(vm_id).ok()?.recv_packet(vcpu_id)
}

pub(crate) fn take_transport_reset() -> Option<u64> {
    let sock = current_service_sock()?;
    let generation = sock.device().claimed_generation()?;
    sock.device().take_transport_reset(generation)
}

// ============================================================================
// Utility
// ============================================================================

/// Gets the vCPU count for the FrameVM addressed by a `framev-sock` CID.
#[inline]
pub fn get_vcpu_count_for_cid(cid: u64) -> Option<usize> {
    route_for_cid(cid)
        .and_then(|route| vm::get_vm_by_id(route.vm_id))
        .map(|frame_vm| frame_vm.vcpu_count())
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

    #[ktest]
    fn restart_publishes_one_current_generation_reset() {
        let device = FrameVsockDevice::new(1);

        assert!(!device.set_active(true, 1));
        assert!(!device.set_active(true, 1));
        let _ = device.set_active(false, 0);
        assert!(device.set_active(true, 2));
        assert_eq!(device.take_transport_reset(1), None);
        assert_eq!(device.take_transport_reset(2), Some(2));
        assert_eq!(device.take_transport_reset(2), None);
    }
}
