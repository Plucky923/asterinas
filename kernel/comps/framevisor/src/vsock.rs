// SPDX-License-Identifier: MPL-2.0

//! FrameVisor Vsock backend
//!
//! This module provides the Host-side vsock functionality:
//! - Receives packets from Guest via `submit_packet()`
//! - Sends packets to Guest via `deliver_packet()`
//!
//! # Architecture
//! - TX (Guest -> Host): Guest calls `submit_packet()`, which dispatches to Host's socket handler
//! - RX (Host -> Guest): Host calls `deliver_packet()`, which pushes to Guest's RxQueue
//!
//! # Zero-Copy Design
//! - All packets are transferred via RRef for zero-copy
//! - DataPacket is used for all packet types (control packets have empty data)
//! - The only copy happens at syscall boundary (user-space ↔ kernel-space)

#![deny(unsafe_code)]

use alloc::{collections::VecDeque, vec::Vec};

use aster_framevisor_exchangeable::RRef;
use aster_framevsock::{ControlPacket, DataPacket, HOST_CID, VMADDR_CID_GUEST};
use spin::{Mutex, Once};

use crate::irq::inject_vsock_rx_interrupt;

/// Callback type for handling data packets received from Guest
/// DataPacket is used for RW operations with payload
pub type DataPacketHandler = fn(RRef<DataPacket>);

/// Callback type for handling control packets received from Guest
/// ControlPacket is used for connection management (Request, Response, Rst, Shutdown, etc.)
pub type ControlPacketHandler = fn(RRef<ControlPacket>);

/// Per-vCPU RX queue for delivering data packets to Guest
static GUEST_DATA_RX_QUEUES: Once<Mutex<Vec<VecDeque<RRef<DataPacket>>>>> = Once::new();

/// Per-vCPU RX queue for delivering control packets to Guest
static GUEST_CONTROL_RX_QUEUES: Once<Mutex<Vec<VecDeque<RRef<ControlPacket>>>>> = Once::new();

/// Registered data packet handler from Host
static DATA_PACKET_HANDLER: Once<Mutex<Option<DataPacketHandler>>> = Once::new();

/// Registered control packet handler from Host
static CONTROL_PACKET_HANDLER: Once<Mutex<Option<ControlPacketHandler>>> = Once::new();

/// Initialize vsock backend
pub fn init() {
    GUEST_DATA_RX_QUEUES.call_once(|| Mutex::new(Vec::new()));
    GUEST_CONTROL_RX_QUEUES.call_once(|| Mutex::new(Vec::new()));
    DATA_PACKET_HANDLER.call_once(|| Mutex::new(None));
    CONTROL_PACKET_HANDLER.call_once(|| Mutex::new(None));
}

/// Initialize per-vCPU RX queues
pub fn init_vcpu_queue(vcpu_count: usize) {
    {
        let mut queues = GUEST_DATA_RX_QUEUES
            .get()
            .expect("vsock not initialized")
            .lock();
        queues.clear();
        for _ in 0..vcpu_count {
            queues.push(VecDeque::new());
        }
    }
    {
        let mut queues = GUEST_CONTROL_RX_QUEUES
            .get()
            .expect("vsock not initialized")
            .lock();
        queues.clear();
        for _ in 0..vcpu_count {
            queues.push(VecDeque::new());
        }
    }
}

/// Register data packet handler from Host kernel
/// This handler is called when Guest sends a data packet (RW operation)
pub fn register_data_packet_handler(handler: DataPacketHandler) {
    let mut h = DATA_PACKET_HANDLER
        .get()
        .expect("vsock not initialized")
        .lock();
    *h = Some(handler);
}

/// Register control packet handler from Host kernel
/// This handler is called when Guest sends a control packet
pub fn register_control_packet_handler(handler: ControlPacketHandler) {
    let mut h = CONTROL_PACKET_HANDLER
        .get()
        .expect("vsock not initialized")
        .lock();
    *h = Some(handler);
}

// ========== TX Path: Guest -> Host ==========

/// Submit a data packet from Guest to Host
/// This is the entry point for Guest TX data operations
pub fn submit_data_packet(packet: RRef<DataPacket>) {
    // Validate packet destination
    if packet.header.dst_cid != HOST_CID {
        // Packet not destined for Host, drop it
        return;
    }

    // Dispatch to registered handler
    let handler = DATA_PACKET_HANDLER
        .get()
        .expect("vsock not initialized")
        .lock();
    if let Some(h) = *handler {
        h(packet);
    }
}

/// Submit a control packet from Guest to Host
/// This is the entry point for Guest TX control operations
pub fn submit_control_packet(packet: RRef<ControlPacket>) {
    // Validate packet destination
    if packet.header.dst_cid != HOST_CID {
        // Packet not destined for Host, drop it
        return;
    }

    // Dispatch to registered handler
    let handler = CONTROL_PACKET_HANDLER
        .get()
        .expect("vsock not initialized")
        .lock();
    if let Some(h) = *handler {
        h(packet);
    }
}

// ========== RX Path: Host -> Guest ==========

/// Deliver a data packet from Host to Guest
/// This is called by Host kernel to send data to Guest
pub fn deliver_data_packet(vcpu_id: usize, packet: RRef<DataPacket>) -> Result<(), ()> {
    // Validate packet destination
    if packet.header.dst_cid != VMADDR_CID_GUEST {
        return Err(());
    }

    let mut queues = GUEST_DATA_RX_QUEUES
        .get()
        .expect("vsock not initialized")
        .lock();
    if vcpu_id >= queues.len() {
        return Err(());
    }

    queues[vcpu_id].push_back(packet);
    drop(queues); // Release lock before injecting interrupt

    // Inject virtual interrupt to notify Guest
    inject_vsock_rx_interrupt();

    Ok(())
}

/// Deliver a control packet from Host to Guest
/// This is called by Host kernel to send control messages to Guest
pub fn deliver_control_packet(vcpu_id: usize, packet: RRef<ControlPacket>) -> Result<(), ()> {
    // Validate packet destination
    if packet.header.dst_cid != VMADDR_CID_GUEST {
        return Err(());
    }

    let mut queues = GUEST_CONTROL_RX_QUEUES
        .get()
        .expect("vsock not initialized")
        .lock();
    if vcpu_id >= queues.len() {
        return Err(());
    }

    queues[vcpu_id].push_back(packet);
    drop(queues); // Release lock before injecting interrupt

    // Inject virtual interrupt to notify Guest
    inject_vsock_rx_interrupt();

    Ok(())
}

/// Pop a data packet from Guest's RX queue
/// Called by Guest's interrupt handler
pub fn pop_guest_data_packet(vcpu_id: usize) -> Option<RRef<DataPacket>> {
    let mut queues = GUEST_DATA_RX_QUEUES
        .get()
        .expect("vsock not initialized")
        .lock();
    if vcpu_id >= queues.len() {
        return None;
    }
    queues[vcpu_id].pop_front()
}

/// Pop a control packet from Guest's RX queue
/// Called by Guest's interrupt handler
pub fn pop_guest_control_packet(vcpu_id: usize) -> Option<RRef<ControlPacket>> {
    let mut queues = GUEST_CONTROL_RX_QUEUES
        .get()
        .expect("vsock not initialized")
        .lock();
    if vcpu_id >= queues.len() {
        return None;
    }
    queues[vcpu_id].pop_front()
}

/// Check if Guest has pending data packets
pub fn guest_has_pending_data(vcpu_id: usize) -> bool {
    let queues = GUEST_DATA_RX_QUEUES
        .get()
        .expect("vsock not initialized")
        .lock();
    if vcpu_id >= queues.len() {
        return false;
    }
    !queues[vcpu_id].is_empty()
}

/// Check if Guest has pending control packets
pub fn guest_has_pending_control(vcpu_id: usize) -> bool {
    let queues = GUEST_CONTROL_RX_QUEUES
        .get()
        .expect("vsock not initialized")
        .lock();
    if vcpu_id >= queues.len() {
        return false;
    }
    !queues[vcpu_id].is_empty()
}

/// Check if Guest has any pending packets (data or control)
pub fn guest_has_pending(vcpu_id: usize) -> bool {
    guest_has_pending_data(vcpu_id) || guest_has_pending_control(vcpu_id)
}

/// Get the number of vCPUs configured
pub fn get_vcpu_count() -> usize {
    let queues = GUEST_DATA_RX_QUEUES.get();
    match queues {
        Some(q) => q.lock().len(),
        None => 1, // Default to 1 if not initialized
    }
}
