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
//!
//! # Interrupt Coalescing
//! - `GUEST_RX_PROCESSING` flag tracks if Guest is currently processing RX queues
//! - If Guest is processing, Host skips interrupt injection
//! - This reduces interrupt overhead during high throughput

#![deny(unsafe_code)]

use alloc::{collections::VecDeque, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use aster_framevisor_exchangeable::{DomainId, RRef};
use aster_framevsock::{ControlPacket, DataPacket, HOST_CID, VMADDR_CID_GUEST};
use spin::{Mutex, Once};

use crate::{iht::IHT_MANAGER, irq::inject_vsock_rx_interrupt};

/// Callback type for handling data packets received from Guest
/// DataPacket is used for RW operations with payload
pub type DataPacketHandler = fn(RRef<DataPacket>);

/// Callback type for handling control packets received from Guest
/// ControlPacket is used for connection management (Request, Response, Rst, Shutdown, etc.)
pub type ControlPacketHandler = fn(RRef<ControlPacket>);

/// Callback type for direct dispatch of data packets to Guest
/// Returns true if packet was successfully dispatched, false otherwise
pub type DirectDispatchHandler = fn(RRef<DataPacket>) -> bool;

/// Per-vCPU RX queue for delivering data packets to Guest
static GUEST_DATA_RX_QUEUES: Once<Mutex<Vec<VecDeque<RRef<DataPacket>>>>> = Once::new();

/// Per-vCPU RX queue for delivering control packets to Guest
static GUEST_CONTROL_RX_QUEUES: Once<Mutex<Vec<VecDeque<RRef<ControlPacket>>>>> = Once::new();

/// Registered data packet handler from Host
static DATA_PACKET_HANDLER: Once<DataPacketHandler> = Once::new();

/// Registered control packet handler from Host
static CONTROL_PACKET_HANDLER: Once<ControlPacketHandler> = Once::new();

/// Registered direct dispatch handler from Guest
static DIRECT_DISPATCH_HANDLER: Once<DirectDispatchHandler> = Once::new();

/// Flag indicating if Guest is currently processing RX packets
/// Used for interrupt coalescing
static GUEST_RX_PROCESSING: AtomicBool = AtomicBool::new(false);

/// Flag indicating if Guest vsock subsystem is active
/// When false, direct dispatch and IRQ injection are disabled
static GUEST_VSOCK_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Initialize vsock backend
pub fn init() {
    GUEST_DATA_RX_QUEUES.call_once(|| Mutex::new(Vec::new()));
    GUEST_CONTROL_RX_QUEUES.call_once(|| Mutex::new(Vec::new()));
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
    DATA_PACKET_HANDLER.call_once(|| handler);
}

/// Register control packet handler from Host kernel
/// This handler is called when Guest sends a control packet
pub fn register_control_packet_handler(handler: ControlPacketHandler) {
    CONTROL_PACKET_HANDLER.call_once(|| handler);
}

/// Register direct dispatch handler from Guest
/// This handler is called when Host sends a data packet to Guest
#[ostd::ensure_stack(4096)]
pub fn register_direct_dispatch_handler(handler: DirectDispatchHandler) {
    DIRECT_DISPATCH_HANDLER.call_once(|| handler);
}

/// Set the Guest RX processing state
/// Called by Guest to suppress interrupts
#[ostd::ensure_stack(4096)]
pub fn set_guest_rx_processing(processing: bool) {
    GUEST_RX_PROCESSING.store(processing, Ordering::Release);
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

/// Helper to invoke the direct dispatch handler from IHT
pub fn invoke_direct_dispatch(packet: RRef<DataPacket>) -> bool {
    if let Some(handler) = DIRECT_DISPATCH_HANDLER.get() {
        handler(packet)
    } else {
        false
    }
}

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
/// This is called by Host kernel to send data to Guest
///
/// # Ownership Transfer
/// The packet ownership is transferred from Host to Guest (FrameVM).
pub fn deliver_data_packet(vcpu_id: usize, packet: RRef<DataPacket>) -> Result<(), ()> {
    // Validate packet destination
    if packet.header.dst_cid != VMADDR_CID_GUEST {
        return Err(());
    }

    // Check if Guest vsock is active before any Guest-side operations
    if !GUEST_VSOCK_ACTIVE.load(Ordering::Acquire) {
        return Err(());
    }

    // Transfer ownership from Host to Guest
    let packet = packet.transfer_to(DomainId::FrameVM(DEFAULT_GUEST_VM_ID));

    // Use IHT if initialized
    if let Some(manager) = IHT_MANAGER.get() {
        if let Some(ctx) = manager.get_context(vcpu_id) {
            ctx.packet_queue.lock().push_back(packet);
            ctx.wait_queue.wake_one();
            return Ok(());
        }
    }

    // Try direct dispatch first (only if Guest is active)
    if let Some(handler) = DIRECT_DISPATCH_HANDLER.get() {
        if handler(packet) {
            return Ok(());
        } else {
            return Err(());
        }
    }

    Err(())
}

/// Deliver a control packet from Host to Guest
/// This is called by Host kernel to send control messages to Guest
///
/// # Ownership Transfer
/// The packet ownership is transferred from Host to Guest (FrameVM).
pub fn deliver_control_packet(vcpu_id: usize, packet: RRef<ControlPacket>) -> Result<(), ()> {
    // Validate packet destination
    if packet.header.dst_cid != VMADDR_CID_GUEST {
        return Err(());
    }

    // Check if Guest vsock is active before any Guest-side operations
    if !GUEST_VSOCK_ACTIVE.load(Ordering::Acquire) {
        // Guest not active, cannot deliver packet
        return Err(());
    }

    // Transfer ownership from Host to Guest
    let packet = packet.transfer_to(DomainId::FrameVM(DEFAULT_GUEST_VM_ID));

    let mut queues = GUEST_CONTROL_RX_QUEUES
        .get()
        .expect("vsock not initialized")
        .lock();
    if vcpu_id >= queues.len() {
        return Err(());
    }

    queues[vcpu_id].push_back(packet);
    drop(queues); // Release lock before injecting interrupt

    // Check if Guest is already processing RX queue
    if !GUEST_RX_PROCESSING.load(Ordering::Acquire) {
        inject_vsock_rx_interrupt();
    }

    Ok(())
}

/// Pop a data packet from Guest's RX queue
/// Called by Guest's interrupt handler
#[ostd::ensure_stack(4096)]
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
#[ostd::ensure_stack(4096)]
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
#[ostd::ensure_stack(4096)]
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
#[ostd::ensure_stack(4096)]
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
#[ostd::ensure_stack(4096)]
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
