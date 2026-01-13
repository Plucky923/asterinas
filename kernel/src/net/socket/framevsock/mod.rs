// SPDX-License-Identifier: MPL-2.0

//! FrameVsock module for communication between FrameVM (Guest) and Kernel (Host).
//!
//! This module provides initialization and management for FrameVsock, which enables
//! zero-copy communication between FrameVM and the kernel.
//!
//! # Architecture
//! - TX (Guest -> Host): Guest calls FrameVisor's submit_packet(), which calls our packet handler
//! - RX (Host -> Guest): Host calls FrameVisor's deliver_packet() to send to Guest
//!
//! # Zero-Copy Design
//! - Data packets are passed by RRef ownership (zero-copy)
//! - Control packets are processed inline
//! - The only copy happens at syscall boundary (user-space ↔ kernel-space)

use alloc::sync::Arc;

use aster_framevisor::vsock as framevisor_vsock;
use aster_framevisor_exchangeable::RRef;
use aster_framevsock::{ControlPacket, DataPacket};
use log::info;
use spin::Once;

pub mod addr;
pub mod common;
pub mod stream;

use common::FrameVsockSpace;
pub use stream::socket::FrameVsockStreamSocket;

pub static FRAME_VSOCK_GLOBAL: Once<Arc<FrameVsockSpace>> = Once::new();

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

/// Initialize the FrameVsock subsystem.
///
/// This function registers the host-side handlers for processing packets sent from FrameVM.
pub(in crate::net) fn init() {
    info!("[FrameVsock] Initializing FrameVsock subsystem...");

    // Initialize FrameVisor vsock backend
    framevisor_vsock::init();

    // Initialize global space
    FRAME_VSOCK_GLOBAL.call_once(|| Arc::new(FrameVsockSpace::new()));

    // Register the packet handlers for Guest -> Host packets
    framevisor_vsock::register_data_packet_handler(handle_guest_data_packet);
    framevisor_vsock::register_control_packet_handler(handle_guest_control_packet);

    info!("[FrameVsock] FrameVsock subsystem initialized successfully");
}
