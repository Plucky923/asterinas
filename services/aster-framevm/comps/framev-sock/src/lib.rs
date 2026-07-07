// SPDX-License-Identifier: MPL-2.0

//! FrameV socket frontend provider for the FrameVM service.

#![no_std]
#![deny(unsafe_code)]

use component::{ComponentInitError, init_component};
use framev_bus::FrameVBusError;
use framev_sock_common::FrameVsockPacket;

#[init_component(kthread)]
fn init() -> Result<(), ComponentInitError> {
    init_for_framevm_component_profile()
}

/// Initializes the FrameV socket frontend in the FrameVM component profile.
pub fn init_for_framevm_component_profile() -> Result<(), ComponentInitError> {
    Ok(())
}

/// Marks the default `framev-sock` transport active.
pub fn activate() -> Result<(), FrameVBusError> {
    framev_bus::sock()?.activate();
    Ok(())
}

/// Installs the RX notification callback for the default `framev-sock` device.
pub fn install_rx_callback(callback: fn()) -> Result<(), FrameVBusError> {
    framev_bus::sock()?.install_rx_callback(callback)
}

/// Returns whether the default `framev-sock` transport is active.
pub fn is_active() -> bool {
    framev_bus::sock().is_ok_and(|sock| sock.is_active())
}

/// Returns the number of visible `framev-sock` queue pairs.
pub fn queue_count() -> usize {
    framev_bus::sock()
        .map(|sock| sock.queue_count())
        .unwrap_or_default()
}

/// Returns the current service vCPU index.
pub fn current_vcpu_index() -> Option<usize> {
    framev_bus::sock()
        .ok()
        .and_then(|sock| sock.current_vcpu_index())
}

/// Returns the service-visible guest CID.
pub fn guest_cid() -> Option<u64> {
    framev_bus::sock().ok().and_then(|sock| sock.guest_cid())
}

/// Submits one packet through the default `framev-sock` transport.
pub fn submit_packet(queue_id: usize, packet: FrameVsockPacket) -> Result<(), FrameVsockPacket> {
    let Ok(sock) = framev_bus::sock() else {
        return Err(packet);
    };
    sock.submit_packet(queue_id, packet)
}

/// Receives one packet from a default `framev-sock` queue.
pub fn recv_packet(queue_id: usize) -> Option<FrameVsockPacket> {
    framev_bus::sock()
        .ok()
        .and_then(|sock| sock.recv_packet(queue_id))
}
