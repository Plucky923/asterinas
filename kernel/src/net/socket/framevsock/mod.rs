// SPDX-License-Identifier: MPL-2.0

//! Host-side AF_VSOCK sockets backed by the FrameVisor packet carrier.
//!
//! FrameVsock deliberately follows the ordinary virtio-vsock socket layout in
//! `crate::net::socket::vsock`: address conversion, stream socket states,
//! listener lookup, connection lookup, shutdown, credit accounting, and polling
//! stay in the socket/transport layers. The backend is the only carrier-specific
//! boundary; it moves `RRef` packets through FrameVisor queues and must not grow
//! Linux socket or syscall semantics.
//!
//! # Architecture
//!
//! - RX from service: FrameVisor delivers service-owned packets to the host
//!   handler registered by this module.
//! - TX to service: the socket/transport layer builds protocol packets and hands
//!   them to the backend for queue delivery.
//!
//! # Zero-Copy Design
//!
//! - Data packets are passed by `RRef` ownership.
//! - Control packets use the same backend carrier, but are handled by the
//!   transport state machine.
//! - User memory is copied only at the normal socket syscall boundary.

use aster_framevisor_exchangeable::RRef;
use aster_framevsock::{ControlPacket, DataPacket};
use spin::Once;

use crate::prelude::*;

pub mod addr;
mod backend;
pub mod stream;
pub(in crate::net::socket::framevsock) mod transport;

pub use stream::socket::FrameVsockStreamSocket;
use transport::FrameVsockSpace;

pub(in crate::net::socket::framevsock) static FRAME_VSOCK_GLOBAL: Once<Arc<FrameVsockSpace>> =
    Once::new();

/// Data packet handler callback for Guest -> Host data packets
/// Zero-copy: packet ownership is transferred to the connected socket
fn handle_guest_data_packet(packet: RRef<DataPacket>) {
    // Dispatch packet to FrameVsockSpace (zero-copy: ownership transfer)
    if let Some(space) = FRAME_VSOCK_GLOBAL.get() {
        let _ = space.on_data_packet_received(packet);
    }
}

/// Control packet handler callback for Guest -> Host control packets
fn handle_guest_control_packet(packet: RRef<ControlPacket>) {
    // Dispatch packet to FrameVsockSpace
    if let Some(space) = FRAME_VSOCK_GLOBAL.get() {
        let _ = space.on_control_packet_received(packet);
    }
}

/// Host->Guest TX queue drain callback.
///
/// Called by FrameVisor when Guest pops a data packet from backend queue.
fn handle_host_queue_drain(vcpu_id: usize, queue_reserved_len_before_pop: usize) {
    if let Some(space) = FRAME_VSOCK_GLOBAL.get() {
        space.notify_tx_queue_drained(vcpu_id, queue_reserved_len_before_pop);
    }
}

/// Initialize the FrameVsock subsystem.
///
/// This function registers the host-side handlers for processing packets sent from FrameVM.
pub(in crate::net) fn init() {
    info!("[FrameVsock] Initializing FrameVsock subsystem...");

    // Initialize global space
    FRAME_VSOCK_GLOBAL.call_once(|| Arc::new(FrameVsockSpace::new()));

    // Register the packet handlers for Guest -> Host packets
    backend::register_host_handlers(
        handle_guest_data_packet,
        handle_guest_control_packet,
        handle_host_queue_drain,
    );

    info!("[FrameVsock] FrameVsock subsystem initialized successfully");
}
