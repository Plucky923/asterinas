// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;

use framev_pci_common::FrameVFunctionFamily;

use super::state::FunctionRuntime;
use crate::{
    Error, Result,
    pci::VirtualPciBus,
    vm::VmId,
    vsock::{CidReservation, FrameVsockDevice, SockConfiguration, VcpuQueues},
};

/// Typed host handle for one VM's FrameV Sock backend.
pub struct Sock {
    runtime: Arc<FunctionRuntime>,
    backend: FrameVsockDevice,
    cid_reservation: CidReservation,
    configuration: SockConfiguration,
    pci: Arc<VirtualPciBus>,
}

impl Sock {
    pub(super) fn new(
        runtime: Arc<FunctionRuntime>,
        vm_id: VmId,
        vcpu_count: usize,
        configuration: SockConfiguration,
        pci: Arc<VirtualPciBus>,
    ) -> Result<Self> {
        let cid_reservation = CidReservation::reserve(&configuration, vm_id)?;
        Ok(Self {
            runtime,
            backend: FrameVsockDevice::new(vcpu_count),
            cid_reservation,
            configuration,
            pci,
        })
    }

    pub(super) fn runtime(&self) -> &FunctionRuntime {
        &self.runtime
    }

    pub(crate) fn set_active(&self, active: bool) -> bool {
        self.backend.set_active(active, self.runtime.generation())
    }

    pub(crate) fn is_active(&self) -> bool {
        self.backend.is_active()
    }

    pub(crate) fn queues(&self, vcpu_id: usize) -> Option<&VcpuQueues> {
        self.backend.queues(vcpu_id)
    }

    pub(crate) fn take_transport_reset(&self, generation: u64) -> Option<u64> {
        self.backend.take_transport_reset(generation)
    }

    pub(crate) fn queue_count(&self) -> usize {
        self.backend.queue_count()
    }

    pub(crate) fn ring_count(&self) -> usize {
        self.backend.ring_count()
    }

    pub(crate) fn guest_cid(&self) -> u32 {
        self.cid_reservation.cid()
    }

    pub(crate) fn claimed_generation(&self) -> Option<u64> {
        self.runtime.claimed_generation()
    }

    pub(crate) fn configuration(&self) -> &SockConfiguration {
        &self.configuration
    }

    pub(crate) fn host_packet_handler(&self) -> Option<crate::vsock::HostPacketHandler> {
        self.backend.host_packet_handler()
    }

    pub(crate) fn notify_host_queue_drain(
        &self,
        vcpu_id: usize,
        queue_reserved_len_before_pop: usize,
    ) {
        self.backend
            .notify_host_queue_drain(vcpu_id, queue_reserved_len_before_pop);
    }

    pub(crate) fn notify_rx(&self, vm_running: bool, target_vcpu: usize) -> Result<()> {
        if !vm_running || target_vcpu >= self.queue_count() {
            return Err(Error::InvalidArgs);
        }

        let _call = self.runtime.enter_host()?;
        let generation = self.runtime.generation();
        self.pci
            .raise(FrameVFunctionFamily::Sock, target_vcpu as u16, generation)
            .map(|_| ())
    }

    pub(crate) fn notify_reset(&self, vm_running: bool) -> Result<()> {
        if !vm_running {
            return Err(Error::InvalidArgs);
        }

        let _call = self.runtime.enter_host()?;
        let generation = self.runtime.generation();
        let vector = u16::try_from(self.queue_count()).map_err(|_| Error::Overflow)?;
        self.pci
            .raise(FrameVFunctionFamily::Sock, vector, generation)
            .map(|_| ())
    }

    pub(crate) fn set_host_packet_handler(&self, handler: crate::vsock::HostPacketHandler) {
        self.backend.set_host_packet_handler(handler);
    }

    pub(crate) fn set_host_queue_drain_handler(
        &self,
        handler: crate::vsock::HostQueueDrainHandler,
    ) {
        self.backend.set_host_queue_drain_handler(handler);
    }

    pub(crate) fn observe_submitted_packet_queue(
        &self,
        packet: &framev_sock_common::FrameVsockPacket,
        queue_id: usize,
    ) -> Result<usize, usize> {
        self.backend
            .observe_submitted_packet_queue(packet, queue_id)
    }

    pub(crate) fn has_packet_flow(&self, packet: &framev_sock_common::FrameVsockPacket) -> bool {
        self.backend.has_packet_flow(packet)
    }

    pub(crate) fn select_outbound_packet_queue(
        &self,
        packet: &framev_sock_common::FrameVsockPacket,
        preferred_queue: usize,
    ) -> usize {
        self.backend
            .select_outbound_packet_queue(packet, preferred_queue)
    }

    pub(crate) fn remove_packet_flow_key(&self, key: framev_sock_common::FrameVsockFlowKey) {
        self.backend.remove_packet_flow_key(key);
    }

    pub(super) fn reset(&self) {
        self.backend.reset();
    }

    pub(super) fn validate_start(&self) -> Result<()> {
        if self.ring_count() == 0 {
            return Err(Error::InvalidArgs);
        }
        Ok(())
    }

    pub(super) fn publish_generation(&self) -> Result<()> {
        self.cid_reservation
            .set_generation(self.runtime.generation())
    }

    pub(super) fn stop(&self) {
        self.backend.stop();
    }

    pub(crate) fn release_cid(&self) {
        self.cid_reservation.release();
    }
}
