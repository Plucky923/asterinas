// SPDX-License-Identifier: MPL-2.0

//! Service-safe FrameV Sock transport facade.
//!
//! This module hides FrameVisor's `RRef` carrier from FrameVM code. Packets
//! crossing the dynamic boundary are copied into the receiving side's heap, so
//! neither side ever drops a `Vec` allocated by the other side.

use aster_framevisor_exchangeable::{RRef, enter_vm};
use framev_pci_common::FrameVFunctionFamily;
use framev_sock_common::{FrameVsockPacket, FrameVsockSendError};

use crate::{task, vm, vsock};

/// Returns the service-visible guest CID for this FrameV Sock frontend.
fn guest_cid() -> Option<u64> {
    task::current_frame_vm().map(|frame_vm| frame_vm.cid())
}

/// Returns the number of FrameV Sock queue pairs visible to the current service.
fn queue_count() -> usize {
    task::current_frame_vm()
        .map(|frame_vm| frame_vm.vcpu_count())
        .filter(|count| *count != 0)
        .unwrap_or(0)
}

/// Marks the service-side FrameV Sock transport active.
fn activate() {
    let Some(frame_vm) = task::current_frame_vm() else {
        return;
    };
    let vm_id = frame_vm.id();

    if let Ok(sock) = vsock::sock_for_vm_id(vm_id) {
        let should_notify_reset = sock.set_active(true);
        if should_notify_reset {
            let _ = sock.notify_reset(frame_vm.is_running());
        }
    }
}

/// Marks one claimed FrameV Sock transport active.
pub fn activate_claimed(claim: &crate::device::FunctionClaim) -> crate::Result<()> {
    let _call = claim.enter(FrameVFunctionFamily::Sock)?;
    activate();
    Ok(())
}

/// Returns whether the service-side FrameV Sock transport is active.
fn is_active() -> bool {
    task::current_frame_vm()
        .and_then(|frame_vm| vsock::sock_for_vm_id(frame_vm.id()).ok())
        .map(|sock| sock.is_active())
        .unwrap_or(false)
}

/// Returns whether one claimed FrameV Sock transport is active.
pub fn is_active_claimed(claim: &crate::device::FunctionClaim) -> crate::Result<bool> {
    let _call = claim.enter(FrameVFunctionFamily::Sock)?;
    Ok(is_active())
}

/// Returns the queue count for one claimed FrameV Sock transport.
pub fn queue_count_claimed(claim: &crate::device::FunctionClaim) -> crate::Result<usize> {
    let _call = claim.enter(FrameVFunctionFamily::Sock)?;
    Ok(queue_count())
}

/// Returns the guest CID for one claimed FrameV Sock transport.
pub fn guest_cid_claimed(claim: &crate::device::FunctionClaim) -> crate::Result<Option<u64>> {
    let _call = claim.enter(FrameVFunctionFamily::Sock)?;
    Ok(guest_cid())
}

/// Submits a copy of one service-owned packet to the backend.
fn submit_packet(queue_id: usize, packet: &FrameVsockPacket) -> Result<(), FrameVsockSendError> {
    let Some(frame_vm) = task::current_frame_vm() else {
        return Err(FrameVsockSendError::Stopped);
    };
    let vm_id = frame_vm.id();

    let _guest_vm = enter_vm(vm_id);
    // The service payload may have been allocated by the image-local Rust
    // provider. This Host-side copy is the only packet retained by the
    // exchange carrier; the borrowed service packet remains with its caller.
    let shared_packet = match packet.try_clone() {
        Some(packet_copy) => packet_copy,
        None => return Err(FrameVsockSendError::Stopped),
    };
    let packet = match RRef::try_new_with_owner_recoverable(shared_packet, vm_id) {
        Ok(packet) => packet,
        Err((_, _shared_packet)) => return Err(FrameVsockSendError::Stopped),
    };
    match vsock::submit_service_packet(queue_id, packet) {
        Ok(()) => Ok(()),
        Err((error, _packet)) => Err(error),
    }
}

/// Submits one packet through a claimed FrameV Sock function.
pub fn submit_packet_claimed(
    claim: &crate::device::FunctionClaim,
    queue_id: usize,
    packet: &FrameVsockPacket,
) -> Result<(), FrameVsockSendError> {
    let _call = match claim.enter(FrameVFunctionFamily::Sock) {
        Ok(call) => call,
        Err(error) => {
            crate::early_println!(
                "[framev-sock] submit claim rejected: claim_vm={:?}, current_frame_vcpu={:?}, error={:?}",
                claim.vm_id(),
                task::current_frame_vcpu_id(),
                error,
            );
            return Err(FrameVsockSendError::Stopped);
        }
    };
    submit_packet(queue_id, packet)
}

/// Receives one backend packet by copying it into the service's private heap.
fn recv_packet(
    queue_id: usize,
    copy_to_service: fn(&FrameVsockPacket) -> Option<FrameVsockPacket>,
) -> Option<FrameVsockPacket> {
    let vm_id = task::current_frame_vm()?.id();
    let _guest_vm = enter_vm(vm_id);
    recv_packet_as_service(vm_id, queue_id, copy_to_service)
}

/// Receives one packet through a claimed FrameV Sock function.
pub fn recv_packet_claimed(
    claim: &crate::device::FunctionClaim,
    queue_id: usize,
    copy_to_service: fn(&FrameVsockPacket) -> Option<FrameVsockPacket>,
) -> Option<FrameVsockPacket> {
    let _call = claim.enter(FrameVFunctionFamily::Sock).ok()?;
    recv_packet(queue_id, copy_to_service)
}

/// Takes one transport-reset event for the current claimed function.
pub fn take_transport_reset_claimed(
    claim: &crate::device::FunctionClaim,
) -> crate::Result<Option<u64>> {
    let _call = claim.enter(FrameVFunctionFamily::Sock)?;
    Ok(vsock::take_transport_reset())
}

fn recv_packet_as_service(
    vm_id: vm::VmId,
    queue_id: usize,
    copy_to_service: fn(&FrameVsockPacket) -> Option<FrameVsockPacket>,
) -> Option<FrameVsockPacket> {
    let packet = vsock::recv_packet_for_vm(vm_id, queue_id)?;
    copy_to_service(packet.get())
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
        assert!(recv_packet(0, FrameVsockPacket::try_clone).is_none());
    }

    #[ktest]
    fn submit_without_context_does_not_infer_vm_from_packet_header() {
        let packet = FrameVsockPacket::request(
            FrameVsockAddr::new(10, 1024),
            FrameVsockAddr::new(HOST_CID, 2048),
            4096,
            0,
        );

        let error = submit_packet(0, &packet).unwrap_err();
        let header = packet.header();
        let src_cid = header.src_cid;

        assert_eq!(error, FrameVsockSendError::Stopped);
        assert_eq!(src_cid, 10);
    }
}
