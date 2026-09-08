// SPDX-License-Identifier: MPL-2.0

//! Service-safe FrameV-net transport facade.
//!
//! The FrameVM service accesses one FrameV-net function only through its
//! generation-scoped PCI claim. The Host owns endpoint I/O and receive-buffer
//! state, while this module carries only validated borrowed frames and owned
//! receive storage across the service boundary.

use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use framev_net_common::{
    BufferDropGuard, FrameVNetConfig, FrameVNetError, FrameVNetReceiveStatus, OwnedNetworkBuffer,
};
use framev_pci_common::FrameVFunctionFamily;

use crate::{
    Error, Result,
    device::{FunctionClaim, Net},
    sync::{Once, SpinLock},
    task, vm,
};

static NEXT_HOST_BUFFER_CHARGE: AtomicUsize = AtomicUsize::new(1);
static HOST_BUFFER_CHARGES: Once<SpinLock<BTreeMap<usize, HostBufferCharge>>> = Once::new();

struct HostBufferCharge {
    vm_id: vm::VmId,
    buffer_address: usize,
    _charge: vm::MemoryCharge,
}

fn host_buffer_charges() -> &'static SpinLock<BTreeMap<usize, HostBufferCharge>> {
    HOST_BUFFER_CHARGES.call_once(|| SpinLock::new(BTreeMap::new()))
}

fn retain_host_buffer_charge(
    vm_id: vm::VmId,
    buffer_address: usize,
    charge: vm::MemoryCharge,
) -> BufferDropGuard {
    // Keep the registry key independent of the allocation address. The
    // address can be reused between the storage reclaimer and the guard's
    // release callback, while the token remains unique to this charge.
    let token = NEXT_HOST_BUFFER_CHARGE.fetch_add(1, Ordering::Relaxed);
    host_buffer_charges().lock().insert(
        token,
        HostBufferCharge {
            vm_id,
            buffer_address,
            _charge: charge,
        },
    );
    BufferDropGuard::new(token, release_host_buffer_charge)
}

fn release_host_buffer_charge(token: usize) {
    let _ = host_buffer_charges().lock().remove(&token);
}

fn is_registered_host_buffer(vm_id: vm::VmId, receive_buffer: &OwnedNetworkBuffer) -> bool {
    let buffer_address = receive_buffer.as_bytes().as_ptr() as usize;
    let Some(token) = receive_buffer.token_if_released_by(release_host_buffer_charge) else {
        return false;
    };
    host_buffer_charges()
        .lock()
        .get(&token)
        .is_some_and(|record| record.vm_id == vm_id && record.buffer_address == buffer_address)
}

/// Returns the current service VM's immutable FrameV-net configuration.
pub fn current_net_config(claim: &FunctionClaim) -> Result<FrameVNetConfig> {
    let _call = claim.enter(FrameVFunctionFamily::Net)?;
    with_current_net(|net| Ok(net.config()))
}

/// Sends one borrowed Ethernet frame through the claimed FrameV-net function.
pub fn send_claimed(
    claim: &FunctionClaim,
    ethernet_frame: &[u8],
) -> Result<core::result::Result<(), FrameVNetError>> {
    let _call = claim.enter(FrameVFunctionFamily::Net)?;
    with_current_net(|net| Ok(net.send(ethernet_frame)))
}

/// Posts one owned receive buffer through the claimed FrameV-net function.
///
/// Only a buffer allocated by [`allocate_receive_buffer_claimed`] may be
/// retained by Host. A service-created buffer is returned unchanged so its
/// creating image remains responsible for reclamation.
pub fn post_receive_buffer_claimed(
    claim: &FunctionClaim,
    receive_buffer: OwnedNetworkBuffer,
) -> core::result::Result<
    core::result::Result<(), (FrameVNetError, OwnedNetworkBuffer)>,
    (Error, OwnedNetworkBuffer),
> {
    let _call = match claim.enter(FrameVFunctionFamily::Net) {
        Ok(call) => call,
        Err(error) => return Err((error, receive_buffer)),
    };
    let frame_vcpu_id = match task::current_frame_vcpu_id() {
        Some(frame_vcpu_id) => frame_vcpu_id,
        None => return Err((Error::InvalidArgs, receive_buffer)),
    };
    let Some(vm) = vm::get_vm_by_id(frame_vcpu_id.vm_id()) else {
        return Err((Error::InvalidArgs, receive_buffer));
    };
    let Some(net) = vm.devices().net() else {
        return Err((Error::InvalidArgs, receive_buffer));
    };

    if !is_registered_host_buffer(frame_vcpu_id.vm_id(), &receive_buffer) {
        return Ok(Err((
            FrameVNetError::ReceiveBufferNotHostOwned,
            receive_buffer,
        )));
    }

    Ok(net.post_receive_buffer(receive_buffer))
}

/// Allocates one Host-owned receive buffer for the current FrameV-net.
///
/// The returned storage may be retained by Host after this call returns and
/// may later move back to the service without a bridge copy. Its reclamation
/// capability remains bound to Host, and its memory charge is released when
/// the buffer is finally dropped.
pub fn allocate_receive_buffer_claimed(claim: &FunctionClaim) -> Result<OwnedNetworkBuffer> {
    let _call = claim.enter(FrameVFunctionFamily::Net)?;
    let frame_vcpu_id = task::current_frame_vcpu_id().ok_or(Error::InvalidArgs)?;
    let vm = vm::get_vm_by_id(frame_vcpu_id.vm_id()).ok_or(Error::InvalidArgs)?;
    let net = vm.devices().net().ok_or(Error::InvalidArgs)?;
    let buffer_len = net.config().maximum_frame_bytes() as usize;

    let host_charge = vm.memory().charge_host(buffer_len)?;
    let mut host_storage = Vec::new();
    if host_storage.try_reserve_exact(buffer_len).is_err() {
        drop(host_charge);
        return Err(Error::NoMemory);
    }
    host_storage.resize(buffer_len, 0);

    let host_storage = host_storage.into_boxed_slice();
    let buffer_address = host_storage.as_ptr() as usize;
    let drop_guard = retain_host_buffer_charge(frame_vcpu_id.vm_id(), buffer_address, host_charge);
    Ok(OwnedNetworkBuffer::from_boxed_slice_with_drop_guard(
        host_storage,
        drop_guard,
    ))
}

/// Polls one datagram and raises the receive vector after publication.
pub fn poll_receive_claimed(claim: &FunctionClaim) -> Result<FrameVNetReceiveStatus> {
    let _call = claim.enter(FrameVFunctionFamily::Net)?;
    with_current_net(Net::poll_receive_and_notify)
}

/// Takes one completed receive buffer from the claimed FrameV-net function.
pub fn take_completed_buffer_claimed(
    claim: &FunctionClaim,
) -> Result<Option<(OwnedNetworkBuffer, usize)>> {
    let _call = claim.enter(FrameVFunctionFamily::Net)?;
    with_current_net(|net| Ok(net.take_completed_frame().map(|frame| frame.into_parts())))
}

/// Returns whether a received FrameV-net buffer is ready for the claimed frontend.
pub fn has_completed_buffer_claimed(claim: &FunctionClaim) -> Result<bool> {
    let _call = claim.enter(FrameVFunctionFamily::Net)?;
    with_current_net(|net| Ok(net.has_completed_frame()))
}

/// Returns whether the claimed FrameV-net endpoint is permanently unavailable.
pub fn is_endpoint_lost_claimed(claim: &FunctionClaim) -> Result<bool> {
    let _call = claim.enter(FrameVFunctionFamily::Net)?;
    with_current_net(|net| Ok(net.is_endpoint_lost()))
}

/// Takes one receive buffer reclaimed after endpoint loss.
pub fn take_reclaimed_buffer_claimed(claim: &FunctionClaim) -> Result<Option<OwnedNetworkBuffer>> {
    let _call = claim.enter(FrameVFunctionFamily::Net)?;
    with_current_net(|net| Ok(net.take_reclaimed_buffer()))
}

fn with_current_net<T>(f: impl FnOnce(&Net) -> Result<T>) -> Result<T> {
    let frame_vcpu_id = task::current_frame_vcpu_id().ok_or(Error::InvalidArgs)?;
    let vm = vm::get_vm_by_id(frame_vcpu_id.vm_id()).ok_or(Error::InvalidArgs)?;
    let net = vm.devices().net().ok_or(Error::InvalidArgs)?;
    f(net)
}
