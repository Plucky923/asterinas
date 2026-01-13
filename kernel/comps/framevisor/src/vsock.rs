// SPDX-License-Identifier: MPL-2.0

//! FrameVisor Vsock backend
//!
//! This module provides the Host-side vsock functionality:
//! - Receives packets from Guest via `submit_packet()`
//! - Sends packets to Guest via `deliver_packet()`
//!
//! # Architecture (IHT-Only)
//!
//! All packets from Host to Guest go through the IHT (Interrupt Handler Task):
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    IHT-Only Architecture                     │
//! │                                                              │
//! │   Host Thread                                                │
//! │       │                                                      │
//! │       │ deliver_data_packet() / deliver_control_packet()     │
//! │       ▼                                                      │
//! │   ┌─────────────────────────────────────────────────────┐   │
//! │   │  Queue to Per-vCPU Context + Wake IHT               │   │
//! │   │  - All packets queued to Per-vCPU queue             │   │
//! │   │  - IHT woken to process packets                     │   │
//! │   └───────────────────────┬─────────────────────────────┘   │
//! │                           │                                  │
//! │                           ▼                                  │
//! │   ┌─────────────────────────────────────────────────────┐   │
//! │   │  IHT Task (RT Priority)                              │   │
//! │   │  - Processes packets from Per-vCPU queue            │   │
//! │   │  - Dispatches to Guest sockets via registered       │   │
//! │   │    GUEST_DATA_HANDLER / GUEST_CONTROL_HANDLER       │   │
//! │   └─────────────────────────────────────────────────────┘   │
//! │                                                              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Zero-Copy Design
//! - All packets are transferred via RRef for zero-copy
//! - The only copy happens at syscall boundary (user-space ↔ kernel-space)

#![deny(unsafe_code)]

use core::sync::atomic::{AtomicBool, Ordering};

use aster_framevisor_exchangeable::{DomainId, RRef};
use aster_framevsock::{ControlPacket, DataPacket, HOST_CID, VMADDR_CID_GUEST};
use spin::Once;

use crate::iht::{self, IHT_MANAGER};

/// Callback type for handling data packets received from Guest
/// DataPacket is used for RW operations with payload
pub type DataPacketHandler = fn(RRef<DataPacket>);

/// Callback type for handling control packets received from Guest
/// ControlPacket is used for connection management (Request, Response, Rst, Shutdown, etc.)
pub type ControlPacketHandler = fn(RRef<ControlPacket>);

/// Callback type for dispatching data packets to Guest sockets
/// Called by IHT to deliver packets to the appropriate Guest socket
/// Returns true if packet was successfully dispatched, false otherwise
pub type GuestDataHandler = fn(RRef<DataPacket>) -> bool;

/// Callback type for dispatching control packets to Guest sockets
/// Called by IHT to deliver packets to the appropriate Guest socket
/// Returns true if packet was successfully dispatched, false otherwise
pub type GuestControlHandler = fn(RRef<ControlPacket>) -> bool;

// ========== Global State ==========

/// Registered data packet handler from Host
static DATA_PACKET_HANDLER: Once<DataPacketHandler> = Once::new();

/// Registered control packet handler from Host
static CONTROL_PACKET_HANDLER: Once<ControlPacketHandler> = Once::new();

/// Registered Guest data packet handler (called by IHT to dispatch to Guest sockets)
static GUEST_DATA_HANDLER: Once<GuestDataHandler> = Once::new();

/// Registered Guest control packet handler (called by IHT to dispatch to Guest sockets)
static GUEST_CONTROL_HANDLER: Once<GuestControlHandler> = Once::new();

/// Flag indicating if Guest vsock subsystem is active
/// When false, direct dispatch and packet delivery are disabled
static GUEST_VSOCK_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Initialize vsock backend
pub fn init() {
    // Nothing to initialize here - IHT manager handles queue initialization
}

/// Initialize per-vCPU queues (delegates to IHT manager)
pub fn init_vcpu_queue(vcpu_count: usize) {
    // IHT manager now owns the per-vCPU queues
    iht::init_iht_manager(vcpu_count);
}

/// Register data packet handler from Host kernel
/// This handler is called when Guest sends a data packet (RW operation)
pub fn register_data_packet_handler(handler: DataPacketHandler) {
    DATA_PACKET_HANDLER.call_once(|| handler);
}

/// Register control packet handler from Host kernel
/// This handler is called when Guest sends a control packet
pub fn register_control_packet_handler(handler: ControlPacketHandler) {
    CONTROL_PACKET_HANDLER.call_once(|| handler);
}

/// Register Guest data packet handler (for IHT to dispatch to Guest sockets)
/// This handler is called by IHT when processing data packets from the queue
#[ostd::ensure_stack(4096)]
pub fn register_guest_data_handler(handler: GuestDataHandler) {
    GUEST_DATA_HANDLER.call_once(|| handler);
}

/// Register Guest control packet handler (for IHT to dispatch to Guest sockets)
/// This handler is called by IHT when processing control packets from the queue
#[ostd::ensure_stack(4096)]
pub fn register_guest_control_handler(handler: GuestControlHandler) {
    GUEST_CONTROL_HANDLER.call_once(|| handler);
}

/// Set the Guest vsock active state
/// Called by Guest when vsock is initialized/shutdown
#[ostd::ensure_stack(4096)]
pub fn set_guest_vsock_active(active: bool) {
    GUEST_VSOCK_ACTIVE.store(active, Ordering::Release);
}

/// Check if Guest vsock subsystem is active
pub fn is_guest_vsock_active() -> bool {
    GUEST_VSOCK_ACTIVE.load(Ordering::Acquire)
}

// Helper functions for invoke_direct_dispatch removed as they are no longer used


// ========== TX Path: Guest -> Host ==========

/// Submit a data packet from Guest to Host
/// This is the entry point for Guest TX data operations
///
/// # Ownership Transfer
/// The packet ownership is transferred from Guest (FrameVM) to Host.
#[ostd::ensure_stack(4096)]
pub fn submit_data_packet(packet: RRef<DataPacket>) {
    // Validate packet destination
    if packet.header.dst_cid != HOST_CID {
        // Packet not destined for Host, drop it
        return;
    }

    // Transfer ownership from Guest to Host
    let packet = packet.transfer_to(DomainId::Host);

    // Dispatch to registered handler
    if let Some(h) = DATA_PACKET_HANDLER.get() {
        h(packet);
    }
}

/// Submit a control packet from Guest to Host
/// This is the entry point for Guest TX control operations
///
/// # Ownership Transfer
/// The packet ownership is transferred from Guest (FrameVM) to Host.
#[ostd::ensure_stack(4096)]
pub fn submit_control_packet(packet: RRef<ControlPacket>) {
    // Validate packet destination
    if packet.header.dst_cid != HOST_CID {
        // Packet not destined for Host, drop it
        return;
    }

    // Transfer ownership from Guest to Host
    let packet = packet.transfer_to(DomainId::Host);

    // Dispatch to registered handler
    if let Some(h) = CONTROL_PACKET_HANDLER.get() {
        h(packet);
    }
}

// ========== RX Path: Host -> Guest ==========

/// Default Guest FrameVM ID (used when specific VM ID is not known)
const DEFAULT_GUEST_VM_ID: u32 = 0;

/// Deliver a data packet from Host to Guest
///
/// # Delivery Strategy
/// **IHT Queue Only (L2)**: Queue to IHT for processing
/// - IHT processes from the shared Per-vCPU queue
/// - Wakes IHT task to process
/// - Direct Dispatch is intentionally bypassed to ensure IHT context execution
///
/// # Ownership Transfer
/// The packet ownership is transferred from Host to Guest (FrameVM).
pub fn deliver_data_packet(vcpu_id: usize, packet: RRef<DataPacket>) -> Result<(), ()> {
    // Validate packet destination
    if packet.header.dst_cid != VMADDR_CID_GUEST {
        return Err(());
    }

    // Check if Guest vsock is active
    if !GUEST_VSOCK_ACTIVE.load(Ordering::Acquire) {
        return Err(());
    }

    // Transfer ownership from Host to Guest
    let packet = packet.transfer_to(DomainId::FrameVM(DEFAULT_GUEST_VM_ID));

    // Queue to IHT for processing
    // Note: We skip direct dispatch to ensure all packets are processed
    // in the IHT context, providing consistent accounting and scheduling.
    match iht::deliver_data_to_vcpu(vcpu_id, packet) {
        Ok(()) => Ok(()),
        Err(_rejected) => Err(()),
    }
}

/// Deliver a control packet from Host to Guest
///
/// Control packets are always important (connection management).
/// They are queued to the IHT control queue which has higher priority.
///
/// # Ownership Transfer
/// The packet ownership is transferred from Host to Guest (FrameVM).
pub fn deliver_control_packet(vcpu_id: usize, packet: RRef<ControlPacket>) -> Result<(), ()> {
    // Validate packet destination
    if packet.header.dst_cid != VMADDR_CID_GUEST {
        return Err(());
    }

    // Check if Guest vsock is active
    if !GUEST_VSOCK_ACTIVE.load(Ordering::Acquire) {
        return Err(());
    }

    // Transfer ownership from Host to Guest
    let packet = packet.transfer_to(DomainId::FrameVM(DEFAULT_GUEST_VM_ID));

    // Queue to IHT for processing
    match iht::deliver_control_to_vcpu(vcpu_id, packet) {
        Ok(()) => Ok(()),
        Err(_rejected) => Err(()),
    }
}

// ========== Guest-side packet dispatch (called by IHT) ==========

/// Dispatch a data packet to the appropriate Guest socket
/// Called by IHT when processing packets from the queue
pub fn dispatch_data_packet_to_guest(packet: RRef<DataPacket>) {
    if let Some(handler) = GUEST_DATA_HANDLER.get() {
        let _ = handler(packet);
    }
    // If no handler registered, packet is dropped
}

/// Dispatch a control packet to the appropriate Guest socket
/// Called by IHT when processing packets from the queue
pub fn dispatch_control_packet_to_guest(packet: RRef<ControlPacket>) {
    if let Some(handler) = GUEST_CONTROL_HANDLER.get() {
        let _ = handler(packet);
    }
    // If no handler registered, packet is dropped
}

/// Get the number of vCPUs configured (lock-free)
#[inline]
pub fn get_vcpu_count() -> usize {
    iht::get_vcpu_count()
}
