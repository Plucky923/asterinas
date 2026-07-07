// SPDX-License-Identifier: MPL-2.0

//! Packet-carrier backend for host-side FrameVsock sockets.
//!
//! The host socket layer uses a single unified `FrameVsockPacket` carrier. The
//! packet semantics stay virtio-vsock compatible; this module only binds packet
//! ownership to the FrameVisor transport.

use aster_framevisor::vsock as framevisor_vsock;
use aster_framevisor_exchangeable::{DomainId, RRef};
use framev_sock_common::FrameVsockPacket;
use spin::Once;

/// Host-side carrier for one unified FrameV Sock packet.
pub(in crate::net::socket::framevsock) struct PacketCarrier {
    packet: RRef<FrameVsockPacket>,
}

impl PacketCarrier {
    /// Creates a carrier from an exchange-owned unified packet.
    pub(in crate::net::socket::framevsock) fn from_packet(packet: RRef<FrameVsockPacket>) -> Self {
        Self { packet }
    }

    /// Creates a host-owned carrier from an owned unified packet.
    pub(in crate::net::socket::framevsock) fn from_owned(packet: FrameVsockPacket) -> Self {
        Self::from_packet(RRef::new_with_owner(packet, DomainId::Host))
    }

    /// Returns the carried unified packet.
    pub(in crate::net::socket::framevsock) fn packet(&self) -> &FrameVsockPacket {
        &self.packet
    }

    /// Extracts the exchange-owned unified packet.
    pub(in crate::net::socket::framevsock) fn into_packet(self) -> RRef<FrameVsockPacket> {
        self.packet
    }
}

type PacketCarrierHandler = fn(PacketCarrier);

static PACKET_CARRIER_HANDLER: Once<PacketCarrierHandler> = Once::new();

trait VsockPacketBackend: Send + Sync {
    fn register_host_packet_handler(
        &self,
        packet_handler: PacketCarrierHandler,
        queue_drain_handler: fn(usize, usize),
    );

    fn vcpu_count_for_cid(&self, cid: u64) -> Option<usize>;

    fn send_packet(&self, vcpu_id: usize, packet: PacketCarrier) -> Result<(), PacketCarrier>;
}

struct FrameVisorVsockBackend;

fn dispatch_framevisor_packet(packet: RRef<FrameVsockPacket>) {
    if let Some(handler) = PACKET_CARRIER_HANDLER.get().copied() {
        handler(PacketCarrier::from_packet(packet));
    }
}

impl VsockPacketBackend for FrameVisorVsockBackend {
    fn register_host_packet_handler(
        &self,
        packet_handler: PacketCarrierHandler,
        queue_drain_handler: fn(usize, usize),
    ) {
        PACKET_CARRIER_HANDLER.call_once(|| packet_handler);
        framevisor_vsock::register_host_packet_handler(dispatch_framevisor_packet);
        framevisor_vsock::register_host_queue_drain_handler(queue_drain_handler);
    }

    fn vcpu_count_for_cid(&self, cid: u64) -> Option<usize> {
        framevisor_vsock::get_vcpu_count_for_cid(cid)
    }

    fn send_packet(&self, vcpu_id: usize, packet: PacketCarrier) -> Result<(), PacketCarrier> {
        framevisor_vsock::send_to_guest_packet(vcpu_id, packet.into_packet())
            .map_err(PacketCarrier::from_packet)
    }
}

static BACKEND: FrameVisorVsockBackend = FrameVisorVsockBackend;

fn backend() -> &'static dyn VsockPacketBackend {
    &BACKEND
}

pub(in crate::net::socket::framevsock) fn register_host_packet_handler(
    packet_handler: PacketCarrierHandler,
    queue_drain_handler: fn(usize, usize),
) {
    backend().register_host_packet_handler(packet_handler, queue_drain_handler);
}

pub(in crate::net::socket::framevsock) fn vcpu_count_for_cid(cid: u64) -> usize {
    backend().vcpu_count_for_cid(cid).unwrap_or(1).max(1)
}

pub(in crate::net::socket::framevsock) fn has_cid(cid: u64) -> bool {
    backend().vcpu_count_for_cid(cid).is_some()
}

pub(in crate::net::socket::framevsock) fn send_packet(
    vcpu_id: usize,
    packet: PacketCarrier,
) -> Result<(), PacketCarrier> {
    backend().send_packet(vcpu_id, packet)
}
