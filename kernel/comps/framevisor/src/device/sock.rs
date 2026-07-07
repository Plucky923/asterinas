// SPDX-License-Identifier: MPL-2.0

use framev_device::{
    CommonError, DeviceGeneration, DeviceStatus, FrameVDevice, FrameVDeviceError, FrameVDeviceInfo,
};

use super::state::CommonDevice;
use crate::vsock::{FrameVsockDevice, VcpuQueues};

/// Typed host handle for one VM's FrameV Sock backend.
pub struct Sock {
    common: CommonDevice,
    backend: FrameVsockDevice,
}

impl Sock {
    pub(super) fn new(info: FrameVDeviceInfo, vcpu_count: usize) -> Self {
        Self {
            common: CommonDevice::new(info),
            backend: FrameVsockDevice::new(vcpu_count),
        }
    }

    pub(crate) fn set_active(&self, active: bool) {
        self.backend.set_active(active);
    }

    pub(crate) fn is_active(&self) -> bool {
        self.backend.is_active()
    }

    pub(crate) fn queues(&self, vcpu_id: usize) -> Option<&VcpuQueues> {
        self.backend.queues(vcpu_id)
    }

    pub(crate) fn queue_count(&self) -> usize {
        self.backend.queue_count()
    }

    pub(crate) fn ring_count(&self) -> usize {
        self.backend.ring_count()
    }

    pub(crate) fn irq_urgent_first_packet(&self) -> bool {
        self.backend.irq_urgent_first_packet()
    }

    pub(crate) fn irq_coalescing_config(&self) -> crate::vsock::IrqCoalescingConfig {
        self.backend.irq_coalescing_config()
    }

    pub(crate) fn host_packet_handler(&self) -> Option<crate::vsock::HostPacketHandler> {
        self.backend.host_packet_handler()
    }

    pub(crate) fn host_queue_drain_handler(&self) -> Option<crate::vsock::HostQueueDrainHandler> {
        self.backend.host_queue_drain_handler()
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
        self.common.reset();
        self.backend.reset();
    }
}

impl FrameVDevice for Sock {
    fn info(&self) -> FrameVDeviceInfo {
        self.common.info()
    }

    fn status(&self) -> DeviceStatus {
        self.common.status()
    }

    fn generation(&self) -> DeviceGeneration {
        self.common.generation()
    }

    fn ensure_ready(&self) -> Result<DeviceGeneration, CommonError> {
        self.common.ensure_ready()
    }

    fn mark_ready(&self) -> framev_device::Result<()> {
        if self.ring_count() == 0 {
            return Err(FrameVDeviceError::InvalidLifecycleTransition);
        }
        self.common.mark_ready()
    }

    fn stop(&self) {
        self.common.stop();
        self.backend.stop();
    }

    fn begin_reset(&self) -> framev_device::Result<DeviceGeneration> {
        self.common.begin_reset()
    }

    fn reset_backend(&self) {
        self.backend.reset();
    }

    fn finish_reset(&self, generation: DeviceGeneration) -> framev_device::Result<()> {
        self.common.finish_reset(generation)
    }
}
