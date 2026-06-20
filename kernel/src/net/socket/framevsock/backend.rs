// SPDX-License-Identifier: MPL-2.0

//! Packet-carrier backend for host-side FrameVsock sockets.
//!
//! Socket state machines should stay aligned with `kernel/src/net/socket/vsock`.
//! The backend is the boundary where the carrier differs from virtio-vsock.

use aster_framevisor::vsock as framevisor_vsock;
use aster_framevisor_exchangeable::RRef;
use aster_framevsock::{ControlPacket, DataPacket};

trait VsockPacketBackend: Send + Sync {
    fn register_host_handlers(
        &self,
        data_handler: fn(RRef<DataPacket>),
        control_handler: fn(RRef<ControlPacket>),
        queue_drain_handler: fn(usize, usize),
    );

    fn vcpu_count(&self) -> usize;

    fn send_data(&self, vcpu_id: usize, packet: RRef<DataPacket>) -> Result<(), RRef<DataPacket>>;

    fn send_control(
        &self,
        vcpu_id: usize,
        packet: RRef<ControlPacket>,
    ) -> Result<(), RRef<ControlPacket>>;
}

struct FrameVisorVsockBackend;

impl VsockPacketBackend for FrameVisorVsockBackend {
    fn register_host_handlers(
        &self,
        data_handler: fn(RRef<DataPacket>),
        control_handler: fn(RRef<ControlPacket>),
        queue_drain_handler: fn(usize, usize),
    ) {
        framevisor_vsock::register_host_data_handler(data_handler);
        framevisor_vsock::register_host_control_handler(control_handler);
        framevisor_vsock::register_host_queue_drain_handler(queue_drain_handler);
    }

    fn vcpu_count(&self) -> usize {
        framevisor_vsock::get_vcpu_count()
    }

    fn send_data(&self, vcpu_id: usize, packet: RRef<DataPacket>) -> Result<(), RRef<DataPacket>> {
        framevisor_vsock::send_to_guest_data(vcpu_id, packet)
    }

    fn send_control(
        &self,
        vcpu_id: usize,
        packet: RRef<ControlPacket>,
    ) -> Result<(), RRef<ControlPacket>> {
        framevisor_vsock::send_to_guest_control(vcpu_id, packet)
    }
}

static BACKEND: FrameVisorVsockBackend = FrameVisorVsockBackend;

fn backend() -> &'static dyn VsockPacketBackend {
    &BACKEND
}

pub(in crate::net::socket::framevsock) fn register_host_handlers(
    data_handler: fn(RRef<DataPacket>),
    control_handler: fn(RRef<ControlPacket>),
    queue_drain_handler: fn(usize, usize),
) {
    backend().register_host_handlers(data_handler, control_handler, queue_drain_handler);
}

pub(in crate::net::socket::framevsock) fn vcpu_count() -> usize {
    backend().vcpu_count().max(1)
}

pub(in crate::net::socket::framevsock) fn send_data(
    vcpu_id: usize,
    packet: RRef<DataPacket>,
) -> Result<(), RRef<DataPacket>> {
    backend().send_data(vcpu_id, packet)
}

pub(in crate::net::socket::framevsock) fn send_control(
    vcpu_id: usize,
    packet: RRef<ControlPacket>,
) -> Result<(), RRef<ControlPacket>> {
    backend().send_control(vcpu_id, packet)
}
