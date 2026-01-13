// SPDX-License-Identifier: MPL-2.0

//! FrameVsock module for FrameVM (Guest side)
//!
//! Provides vsock socket for communication between FrameVM and Kernel.
//!
//! # Architecture
//! - TX: Guest synchronously calls `submit_data_packet()` or `submit_control_packet()`
//! - RX: Host pushes to RxQueue, Guest reads in interrupt handler
//!
//! # Zero-Copy Design
//! - Packets are transferred via RRef<DataPacket> or RRef<ControlPacket>
//! - The only copy happens at syscall boundary (user-space ↔ kernel-space)

#![deny(unsafe_code)]

pub mod addr;
pub mod socket;

use alloc::{collections::BTreeMap, sync::Arc};

use aster_framevisor::irq::{IrqLine, FRAMEVSOCK_IRQ_NUM};
use aster_framevsock::{create_rst, ControlPacket, DataPacket, VsockOp};
use exchangeable::RRef;
pub use socket::FrameVsockSocket;
use spin::{Mutex, Once, RwLock};

use crate::error::{Errno, Error, Result};

/// Vsock IRQ line for RX notifications
static VSOCK_IRQ: Once<IrqLine> = Once::new();

/// Global socket table: fd -> socket
static SOCKET_TABLE: Once<Mutex<SocketTable>> = Once::new();

/// Port to socket mapping for fast lookup (used for listening sockets)
static PORT_INDEX: Once<RwLock<BTreeMap<u32, Arc<FrameVsockSocket>>>> = Once::new();

/// Connection ID for connected sockets: (local_port, peer_cid, peer_port)
pub type ConnectionId = (u32, u64, u32);

/// Connection index for connected sockets (used for data packet routing)
/// Key: (local_port, peer_cid, peer_port)
static CONNECTION_INDEX: Once<RwLock<BTreeMap<ConnectionId, Arc<FrameVsockSocket>>>> = Once::new();

/// Cache for the last accessed connection to speed up data plane lookups
/// This avoids BTreeMap O(log n) lookup and RwLock overhead for the hot path
static LAST_CONNECTION_CACHE: Once<Mutex<Option<(ConnectionId, Arc<FrameVsockSocket>)>>> =
    Once::new();

struct SocketTable {
    sockets: BTreeMap<i32, Arc<FrameVsockSocket>>,
    next_fd: i32,
}

impl SocketTable {
    fn new() -> Self {
        Self {
            sockets: BTreeMap::new(),
            next_fd: 3, // 0,1,2 reserved for stdio
        }
    }
}

/// Initialize vsock subsystem
pub fn init() {
    SOCKET_TABLE.call_once(|| Mutex::new(SocketTable::new()));
    PORT_INDEX.call_once(|| RwLock::new(BTreeMap::new()));
    CONNECTION_INDEX.call_once(|| RwLock::new(BTreeMap::new()));
    LAST_CONNECTION_CACHE.call_once(|| Mutex::new(None));

    // Register direct dispatch handler for zero-copy RX
    aster_framevisor::vsock::register_direct_dispatch_handler(direct_dispatch_handler);

    // Register vsock IRQ callback for RX notifications
    VSOCK_IRQ.call_once(|| {
        let mut irq =
            IrqLine::alloc_specific(FRAMEVSOCK_IRQ_NUM).expect("Failed to allocate vsock IRQ");

        // Register fast path handler
        aster_framevisor::irq::register_framevsock_handler(|| process_rx_packets());

        irq.on_active(|_trap_frame| {
            // IRQ callback: process pending RX packets from FrameVisor
            process_rx_packets();
        });
        irq
    });

    // Mark Guest vsock as active
    aster_framevisor::vsock::set_guest_vsock_active(true);
}

/// Shutdown vsock subsystem
/// Should be called when the Guest is about to exit
pub fn shutdown() {
    // Mark Guest vsock as inactive to prevent Host from calling Guest callbacks
    aster_framevisor::vsock::set_guest_vsock_active(false);
}

fn socket_table() -> &'static Mutex<SocketTable> {
    SOCKET_TABLE.get().expect("vsock not initialized")
}

fn port_index() -> &'static RwLock<BTreeMap<u32, Arc<FrameVsockSocket>>> {
    PORT_INDEX.get().expect("port index not initialized")
}

fn connection_index() -> &'static RwLock<BTreeMap<ConnectionId, Arc<FrameVsockSocket>>> {
    CONNECTION_INDEX
        .get()
        .expect("connection index not initialized")
}

fn last_connection_cache() -> &'static Mutex<Option<(ConnectionId, Arc<FrameVsockSocket>)>> {
    LAST_CONNECTION_CACHE.get().expect("cache not initialized")
}

/// Allocate fd for a new socket
pub fn alloc_fd(socket: Arc<FrameVsockSocket>) -> i32 {
    let mut table = socket_table().lock();
    let fd = table.next_fd;
    table.next_fd += 1;
    table.sockets.insert(fd, socket);
    fd
}

/// Get socket by fd
pub fn get_socket(fd: i32) -> Result<Arc<FrameVsockSocket>> {
    let table = socket_table().lock();
    table
        .sockets
        .get(&fd)
        .cloned()
        .ok_or_else(|| Error::new(Errno::EBADF))
}

/// Remove socket by fd
pub fn remove_socket(fd: i32) -> Result<Arc<FrameVsockSocket>> {
    let mut table = socket_table().lock();
    table
        .sockets
        .remove(&fd)
        .ok_or_else(|| Error::new(Errno::EBADF))
}

/// Register socket's port in the port index for fast lookup
pub fn register_port(port: u32, socket: Arc<FrameVsockSocket>) {
    let mut index = port_index().write();
    index.insert(port, socket);
}

/// Unregister socket's port from the port index
pub fn unregister_port(port: u32) {
    let mut index = port_index().write();
    index.remove(&port);
}

/// Get socket by port (O(log n) lookup)
/// Used for listening sockets and control packets
pub fn get_socket_by_port(port: u32) -> Option<Arc<FrameVsockSocket>> {
    let index = port_index().read();
    index.get(&port).cloned()
}

/// Register a connected socket in the connection index
/// Key: (local_port, peer_cid, peer_port)
pub fn register_connection(
    local_port: u32,
    peer_cid: u64,
    peer_port: u32,
    socket: Arc<FrameVsockSocket>,
) {
    let mut index = connection_index().write();
    index.insert((local_port, peer_cid, peer_port), socket);
}

/// Unregister a connected socket from the connection index
pub fn unregister_connection(local_port: u32, peer_cid: u64, peer_port: u32) {
    let id = (local_port, peer_cid, peer_port);
    let mut index = connection_index().write();
    index.remove(&id);

    // Invalidate cache if needed
    let mut cache = last_connection_cache().lock();
    if let Some((cached_id, _)) = &*cache {
        if *cached_id == id {
            *cache = None;
        }
    }
}

/// Get socket by connection ID (O(1) cached or O(log n) lookup)
/// Used for connected sockets and data packets
pub fn get_socket_by_connection(
    local_port: u32,
    peer_cid: u64,
    peer_port: u32,
) -> Option<Arc<FrameVsockSocket>> {
    let id = (local_port, peer_cid, peer_port);

    // Fast path: Check cache
    {
        let cache = last_connection_cache().lock();
        if let Some((cached_id, socket)) = &*cache {
            if *cached_id == id {
                return Some(socket.clone());
            }
        }
    }

    // Slow path: Check index
    let index = connection_index().read();
    if let Some(socket) = index.get(&id).cloned() {
        // Update cache
        *last_connection_cache().lock() = Some((id, socket.clone()));
        return Some(socket);
    }
    None
}

// ========== TX Path: Guest -> Host ==========

/// Submit a data packet to the host (synchronous call)
/// This is called by socket operations to send data to Host
pub fn submit_data_packet(packet: RRef<DataPacket>) -> Result<()> {
    aster_framevisor::vsock::submit_data_packet(packet);
    Ok(())
}

/// Submit a control packet to the host (synchronous call)
/// This is called by socket operations to send control messages to Host
pub fn submit_control_packet(packet: RRef<ControlPacket>) -> Result<()> {
    aster_framevisor::vsock::submit_control_packet(packet);
    Ok(())
}

/// Direct dispatch handler for data packets
/// Called by Host directly to deliver packet to socket
fn direct_dispatch_handler(packet: RRef<DataPacket>) -> bool {
    let dst_port = packet.header.dst_port;
    let src_cid = packet.header.src_cid;
    let src_port = packet.header.src_port;

    // Look up by connection ID (connected socket)
    if let Some(socket) = get_socket_by_connection(dst_port, src_cid, src_port) {
        socket.on_data_packet_received(packet);
        true
    } else if let Some(socket) = get_socket_by_port(dst_port) {
        // Fallback to port index
        socket.on_data_packet_received(packet);
        true
    } else {
        // No socket found
        false
    }
}

// ========== RX Path: Host -> Guest ==========

/// Process received packets (called from interrupt handler or polling)
///
/// This function fetches packets from FrameVisor's queues (where Host pushes them),
/// then dispatches each packet to the appropriate socket.
///
/// # Architecture
/// Host calls `deliver_control_packet()` / `deliver_data_packet()` which push to
/// FrameVisor's GUEST_*_RX_QUEUES. This function pops from those queues and
/// dispatches to the correct socket.
///
/// # Routing Strategy
/// - Control packets: Look up by destination port (for listening sockets)
/// - Data packets: Look up by connection ID first, then fall back to port
///
/// # Interrupt Coalescing
/// Sets `GUEST_RX_PROCESSING` to suppress interrupts while processing.
pub fn process_rx_packets() {
    // For single vCPU setup, use vCPU 0
    let vcpu_id = 0;

    aster_framevisor::vsock::set_guest_rx_processing(true);

    loop {
        // Fetch and process control packets from FrameVisor first
        // (connection management takes priority)
        while let Some(packet) = aster_framevisor::vsock::pop_guest_control_packet(vcpu_id) {
            let dst_port = packet.header.dst_port;
            let dst_cid = packet.header.dst_cid;
            let src_cid = packet.header.src_cid;
            let src_port = packet.header.src_port;
            let op = packet.operation();

            // For control packets, first try connection index (for connected sockets),
            // then fall back to port index (for listening sockets)
            if let Some(socket) = get_socket_by_connection(dst_port, src_cid, src_port) {
                socket.on_control_packet_received(packet);
            } else if let Some(socket) = get_socket_by_port(dst_port) {
                socket.on_control_packet_received(packet);
            } else {
                // No socket found - if this is a Request, send RST back
                if op == VsockOp::Request {
                    let rst = create_rst(dst_cid, dst_port, src_cid, src_port);
                    let _ = submit_control_packet(rst);
                }
                // Other control packets without a socket are silently dropped
            }
        }

        // Then fetch and process data packets from FrameVisor
        while let Some(packet) = aster_framevisor::vsock::pop_guest_data_packet(vcpu_id) {
            let dst_port = packet.header.dst_port;
            let src_cid = packet.header.src_cid;
            let src_port = packet.header.src_port;

            // For data packets, look up by connection ID (connected socket)
            // Fall back to port index if not found
            if let Some(socket) = get_socket_by_connection(dst_port, src_cid, src_port) {
                socket.on_data_packet_received(packet);
            } else if let Some(socket) = get_socket_by_port(dst_port) {
                socket.on_data_packet_received(packet);
            }
            // If no socket found, data packet is silently dropped
        }

        // Clear flag to allow new interrupts
        aster_framevisor::vsock::set_guest_rx_processing(false);

        // Check if new packets arrived while we were clearing the flag
        // If so, loop again (and re-enable flag)
        if !aster_framevisor::vsock::guest_has_pending(vcpu_id) {
            break;
        }

        // Re-enable flag for next iteration
        aster_framevisor::vsock::set_guest_rx_processing(true);
    }
}
