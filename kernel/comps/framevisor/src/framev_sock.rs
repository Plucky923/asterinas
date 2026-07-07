// SPDX-License-Identifier: MPL-2.0

//! Service-safe FrameV Sock transport facade.
//!
//! This module hides FrameVisor's `RRef` carrier from FrameVM code. Service
//! socket code exchanges owned `FrameVsockPacket` values; this facade wraps and
//! unwraps the internal move-only carrier at the dynamic boundary.

use aster_framevisor_exchangeable::{DomainId, RRef, enter_domain};
use framev_sock_common::{FrameVsockPacket, vm_id_to_cid};

use crate::{irq, rref_registry, task, vm, vsock};

/// Returns the current service VM ID.
pub fn current_vm_id() -> Option<vm::VmId> {
    task::current_frame_vcpu_id().map(|id| id.vm_id())
}

/// Returns the current service vCPU index.
pub fn current_vcpu_index() -> Option<usize> {
    task::current_frame_vcpu_id().map(|id| id.vcpu_index())
}

/// Returns the service-visible guest CID for this FrameV Sock frontend.
pub fn guest_cid() -> Option<u64> {
    current_vm_id().map(vm_id_to_cid)
}

/// Returns the number of FrameV Sock queue pairs visible to the current service.
pub fn queue_count() -> usize {
    current_vm_id()
        .map(vsock::get_vcpu_count_for_vm)
        .filter(|count| *count != 0)
        .unwrap_or(0)
}

/// Marks the service-side FrameV Sock transport active.
pub fn activate() {
    ensure_rref_runtime_initialized();
    let Some(vm_id) = current_vm_id() else {
        return;
    };

    if let Ok(sock) = vsock::sock_for_vm_id(vm_id) {
        sock.set_active(true);
    }
}

/// Returns whether the service-side FrameV Sock transport is active.
pub fn is_active() -> bool {
    current_vm_id()
        .and_then(|vm_id| vsock::sock_for_vm_id(vm_id).ok())
        .map(|sock| sock.is_active())
        .unwrap_or(false)
}

/// Installs the service-side backend-to-frontend RX callback.
pub fn install_rx_callback(callback: fn()) -> crate::Result<()> {
    let _vm_id = current_vm_id().ok_or(crate::Error::InvalidArgs)?;
    irq::register_persistent_handler(framev_sock_common::DEFAULT_IRQ_LINE, move || callback())
}

/// Marks the service-side FrameV Sock transport inactive.
pub fn deactivate() {
    if let Some(vm_id) = current_vm_id()
        && let Ok(sock) = vsock::sock_for_vm_id(vm_id)
    {
        sock.set_active(false);
    }
}

/// Returns whether the selected RX queue has pending packets.
pub fn has_pending_packet(queue_id: usize) -> bool {
    current_vm_id()
        .map(|vm_id| vsock::has_pending_packet_for_vm(vm_id, queue_id))
        .unwrap_or(false)
}

/// Submits one service-owned packet to the backend.
///
/// On failure, the original packet value is returned to the caller.
pub fn submit_packet(queue_id: usize, packet: FrameVsockPacket) -> Result<(), FrameVsockPacket> {
    ensure_rref_runtime_initialized();

    let Some(vm_id) = current_vm_id() else {
        return Err(packet);
    };

    let _guest_domain = enter_domain(DomainId::Guest(vm_id));
    let packet = RRef::new_with_owner(packet, DomainId::Guest(vm_id));
    match vsock::transport::submit_packet(queue_id, packet) {
        Ok(()) => Ok(()),
        Err(packet) => Err(return_packet_to_service(packet)),
    }
}

/// Receives one backend-owned packet from a service RX queue.
pub fn recv_packet(queue_id: usize) -> Option<FrameVsockPacket> {
    ensure_rref_runtime_initialized();

    let vm_id = current_vm_id()?;
    let _guest_domain = enter_domain(DomainId::Guest(vm_id));
    recv_packet_as_service(vm_id, queue_id)
}

fn ensure_rref_runtime_initialized() {
    rref_registry::init();
}

fn recv_packet_as_service(vm_id: vm::VmId, queue_id: usize) -> Option<FrameVsockPacket> {
    vsock::recv_packet_for_vm(vm_id, queue_id).map(return_packet_to_service)
}

fn return_packet_to_service(packet: RRef<FrameVsockPacket>) -> FrameVsockPacket {
    match packet.try_into_inner() {
        Ok(packet) => packet,
        Err(_) => {
            panic!("FrameV Sock facade must recover packets while executing as the guest owner")
        }
    }
}

#[cfg(ktest)]
mod tests {
    use framev_sock_common::{FrameVsockAddr, HOST_CID};
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn no_context_facade_has_no_default_vm() {
        assert_eq!(guest_cid(), None);
        assert_eq!(queue_count(), 0);
        assert!(!is_active());
        assert!(!has_pending_packet(0));
        assert!(recv_packet(0).is_none());
    }

    #[ktest]
    fn submit_without_context_does_not_infer_vm_from_packet_header() {
        let packet = FrameVsockPacket::request(
            FrameVsockAddr::new(vm_id_to_cid(7), 1024),
            FrameVsockAddr::new(HOST_CID, 2048),
            4096,
            0,
        );

        let returned = submit_packet(0, packet).unwrap_err();
        let header = returned.header();
        let src_cid = header.src_cid;

        assert_eq!(src_cid, vm_id_to_cid(7));
    }
}
