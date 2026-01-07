// SPDX-License-Identifier: MPL-2.0

//! FrameVsock - Zero-copy vsock communication between FrameVM and FrameVisor
//!
//! # Architecture
//!
//! ## TX Path (Guest → Host): Synchronous
//! - Guest directly calls Host's `submit_packet()` function
//! - No send queue needed - immediate function call semantics
//!
//! ## RX Path (Host → Guest): Asynchronous
//! - Host pushes packets to per-vCPU `RxQueue`
//! - Host injects virtual interrupt to notify Guest
//! - Guest reads from `RxQueue` in interrupt handler
//!
//! ## Data Transfer
//! - All data passes via `RRef<FrameVsockBuffer<T>>` for zero-copy
//! - No shared memory required
//! - Only ONE copy happens: at syscall boundary (user-space ↔ kernel-space)
//!
//! # Generic Buffer Design
//!
//! `FrameVsockBuffer<T>` is generic over the payload type:
//! - `FrameVsockBuffer<()>` (ControlPacket): For control messages without data
//! - `FrameVsockBuffer<Vec<u8>>` (DataPacket): For data transfer with dynamic payload

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::{collections::VecDeque, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use exchangeable::{Exchangeable, RRef};
use spin::Mutex;

/// The vSocket equivalent of INADDR_ANY.
pub const VMADDR_CID_ANY: u64 = u64::MAX;
/// Use this as the destination CID in an address when referring to the local communication (loopback).
pub const VMADDR_CID_LOCAL: u64 = 1;
/// Use this as the destination CID in an address when referring to the host (any process other than the hypervisor).
pub const HOST_CID: u64 = 2;
pub const VMADDR_CID_HOST: u64 = 2;
/// Guest (FrameVM) CID
pub const VMADDR_CID_GUEST: u64 = 3;
/// Bind to any available port.
pub const VMADDR_PORT_ANY: u32 = u32::MAX;

/// FrameVsock socket address
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameVsockAddr {
    pub cid: u64,
    pub port: u32,
}

impl FrameVsockAddr {
    pub const fn new(cid: u64, port: u32) -> Self {
        Self { cid, port }
    }

    pub const fn any() -> Self {
        Self {
            cid: VMADDR_CID_ANY,
            port: VMADDR_PORT_ANY,
        }
    }
}

impl From<FrameVsockHeader> for FrameVsockAddr {
    fn from(value: FrameVsockHeader) -> Self {
        FrameVsockAddr {
            cid: value.src_cid,
            port: value.src_port,
        }
    }
}

/// Vsock operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum VsockOp {
    Invalid = 0,
    Request = 1,       // Connection request (connect)
    Response = 2,      // Connection response (accept)
    Rst = 3,           // Reset connection
    Shutdown = 4,      // Shutdown connection
    Rw = 5,            // Read/Write data
    CreditUpdate = 6,  // Credit update for flow control
    CreditRequest = 7, // Credit request
}

impl From<u16> for VsockOp {
    fn from(val: u16) -> Self {
        match val {
            1 => VsockOp::Request,
            2 => VsockOp::Response,
            3 => VsockOp::Rst,
            4 => VsockOp::Shutdown,
            5 => VsockOp::Rw,
            6 => VsockOp::CreditUpdate,
            7 => VsockOp::CreditRequest,
            _ => VsockOp::Invalid,
        }
    }
}

/// Shutdown flags
pub const SHUTDOWN_FLAG_SEND: u32 = 1;
pub const SHUTDOWN_FLAG_RECV: u32 = 2;
pub const SHUTDOWN_FLAG_BOTH: u32 = SHUTDOWN_FLAG_SEND | SHUTDOWN_FLAG_RECV;

/// FrameVsock Buffer Header - Common header for all packets
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FrameVsockHeader {
    pub src_cid: u64,
    pub dst_cid: u64,
    pub src_port: u32,
    pub dst_port: u32,
    pub op: u16,
    pub flags: u16,
    pub buf_alloc: u32, // Buffer space allocated by sender
    pub fwd_cnt: u32,   // Forward count for flow control
}

impl FrameVsockHeader {
    pub const fn new() -> Self {
        Self {
            src_cid: 0,
            dst_cid: 0,
            src_port: 0,
            dst_port: 0,
            op: 0,
            flags: 0,
            buf_alloc: 0,
            fwd_cnt: 0,
        }
    }

    pub fn with_addrs(
        src_cid: u64,
        dst_cid: u64,
        src_port: u32,
        dst_port: u32,
        op: VsockOp,
    ) -> Self {
        Self {
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            op: op as u16,
            flags: 0,
            buf_alloc: 0,
            fwd_cnt: 0,
        }
    }

    /// Get the operation type
    pub fn operation(&self) -> VsockOp {
        VsockOp::from(self.op)
    }

    /// Set operation type
    pub fn set_operation(&mut self, op: VsockOp) {
        self.op = op as u16;
    }

    /// Create a response header with swapped src/dst
    pub fn create_response_header(&self, op: VsockOp) -> Self {
        Self {
            src_cid: self.dst_cid,
            dst_cid: self.src_cid,
            src_port: self.dst_port,
            dst_port: self.src_port,
            op: op as u16,
            flags: 0,
            buf_alloc: 0,
            fwd_cnt: 0,
        }
    }
}

impl Exchangeable for FrameVsockHeader {}

/// Generic FrameVsock Buffer for zero-copy data transfer
///
/// # Type Parameter
/// - `T = ()`: Control packet with no data payload
/// - `T = Vec<u8>`: Data packet with dynamically-sized payload
///
/// # Zero-Copy Design
/// The buffer owns its data. When transferred via RRef, ownership moves
/// without copying the underlying data.
#[repr(C)]
pub struct FrameVsockBuffer<T: Exchangeable = ()> {
    /// Packet header
    pub header: FrameVsockHeader,
    /// Payload data (generic)
    pub data: T,
}

/// Type alias for control packets (no data payload)
pub type ControlPacket = FrameVsockBuffer<()>;

/// Type alias for data packets (with Vec<u8> payload)
pub type DataPacket = FrameVsockBuffer<Vec<u8>>;

impl<T: Exchangeable> FrameVsockBuffer<T> {
    /// Get the operation type
    pub fn operation(&self) -> VsockOp {
        self.header.operation()
    }

    /// Set operation type
    pub fn set_operation(&mut self, op: VsockOp) {
        self.header.set_operation(op);
    }

    /// Get source CID
    pub fn src_cid(&self) -> u64 {
        self.header.src_cid
    }

    /// Get destination CID
    pub fn dst_cid(&self) -> u64 {
        self.header.dst_cid
    }

    /// Get source port
    pub fn src_port(&self) -> u32 {
        self.header.src_port
    }

    /// Get destination port
    pub fn dst_port(&self) -> u32 {
        self.header.dst_port
    }

    /// Get buffer allocation
    pub fn buf_alloc(&self) -> u32 {
        self.header.buf_alloc
    }

    /// Get forward count
    pub fn fwd_cnt(&self) -> u32 {
        self.header.fwd_cnt
    }

    /// Get flags
    pub fn flags(&self) -> u16 {
        self.header.flags
    }
}

// Control packet (no data) implementations
impl FrameVsockBuffer<()> {
    /// Create a new empty control packet
    pub const fn new() -> Self {
        Self {
            header: FrameVsockHeader::new(),
            data: (),
        }
    }

    /// Create a control packet with header
    pub fn with_header(
        src_cid: u64,
        dst_cid: u64,
        src_port: u32,
        dst_port: u32,
        op: VsockOp,
    ) -> Self {
        Self {
            header: FrameVsockHeader::with_addrs(src_cid, dst_cid, src_port, dst_port, op),
            data: (),
        }
    }

    /// Create a response packet with swapped addresses
    pub fn create_response(&self, op: VsockOp) -> Self {
        Self {
            header: self.header.create_response_header(op),
            data: (),
        }
    }

    /// Convert to a data packet by adding payload
    pub fn with_data(self, data: Vec<u8>) -> DataPacket {
        FrameVsockBuffer {
            header: self.header,
            data,
        }
    }
}

impl Default for FrameVsockBuffer<()> {
    fn default() -> Self {
        Self::new()
    }
}

// Data packet (Vec<u8>) implementations
impl FrameVsockBuffer<Vec<u8>> {
    /// Create a new data packet with empty data
    pub fn new_data() -> Self {
        Self {
            header: FrameVsockHeader::new(),
            data: Vec::new(),
        }
    }

    /// Create a data packet with header and data
    pub fn with_header_and_data(
        src_cid: u64,
        dst_cid: u64,
        src_port: u32,
        dst_port: u32,
        op: VsockOp,
        data: Vec<u8>,
    ) -> Self {
        Self {
            header: FrameVsockHeader::with_addrs(src_cid, dst_cid, src_port, dst_port, op),
            data,
        }
    }

    /// Create a data packet for RW operation
    pub fn new_rw(src_cid: u64, dst_cid: u64, src_port: u32, dst_port: u32, data: Vec<u8>) -> Self {
        Self::with_header_and_data(src_cid, dst_cid, src_port, dst_port, VsockOp::Rw, data)
    }

    /// Get payload slice
    pub fn payload(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable payload slice
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get payload length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if payload is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Take ownership of the data
    pub fn take_data(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.data)
    }

    /// Create a response packet with swapped addresses
    pub fn create_response(&self, op: VsockOp) -> ControlPacket {
        ControlPacket {
            header: self.header.create_response_header(op),
            data: (),
        }
    }

    /// Create a response data packet with swapped addresses and new data
    pub fn create_data_response(&self, op: VsockOp, data: Vec<u8>) -> DataPacket {
        DataPacket {
            header: self.header.create_response_header(op),
            data,
        }
    }

    /// Consume partial data and return remaining as a new packet (for partial reads)
    pub fn consume_partial(mut self, bytes: usize) -> Option<Self> {
        if bytes >= self.data.len() {
            None // Fully consumed
        } else {
            // Split the data
            let remaining = self.data.split_off(bytes);
            Some(Self {
                header: self.header,
                data: remaining,
            })
        }
    }
}

impl Default for FrameVsockBuffer<Vec<u8>> {
    fn default() -> Self {
        Self::new_data()
    }
}

// Implement Exchangeable for FrameVsockBuffer<T>
impl Exchangeable for FrameVsockBuffer<()> {}
impl Exchangeable for FrameVsockBuffer<Vec<u8>> {}

/// Connection identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId {
    pub local_addr: FrameVsockAddr,
    pub peer_addr: FrameVsockAddr,
}

impl ConnectionId {
    pub fn new(local_cid: u64, local_port: u32, peer_cid: u64, peer_port: u32) -> Self {
        Self {
            local_addr: FrameVsockAddr::new(local_cid, local_port),
            peer_addr: FrameVsockAddr::new(peer_cid, peer_port),
        }
    }

    pub fn from_addrs(local_addr: FrameVsockAddr, peer_addr: FrameVsockAddr) -> Self {
        Self {
            local_addr,
            peer_addr,
        }
    }

    /// Create from buffer header, treating local as destination
    pub fn from_header_as_local(header: &FrameVsockHeader) -> Self {
        Self {
            local_addr: FrameVsockAddr::new(header.dst_cid, header.dst_port),
            peer_addr: FrameVsockAddr::new(header.src_cid, header.src_port),
        }
    }

    /// Create from buffer header, treating local as source
    pub fn from_header_as_peer(header: &FrameVsockHeader) -> Self {
        Self {
            local_addr: FrameVsockAddr::new(header.src_cid, header.src_port),
            peer_addr: FrameVsockAddr::new(header.dst_cid, header.dst_port),
        }
    }

    /// Create from a FrameVsockBuffer, treating local as destination
    pub fn from_buffer_as_local<T: Exchangeable>(buf: &FrameVsockBuffer<T>) -> Self {
        Self::from_header_as_local(&buf.header)
    }

    /// Create from a FrameVsockBuffer, treating local as source
    pub fn from_buffer_as_peer<T: Exchangeable>(buf: &FrameVsockBuffer<T>) -> Self {
        Self::from_header_as_peer(&buf.header)
    }
}

/// Simple packet queue for buffering data packets
pub struct DataPacketQueue {
    queue: Mutex<VecDeque<RRef<DataPacket>>>,
    capacity: usize,
}

impl DataPacketQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    pub fn push(&self, packet: RRef<DataPacket>) -> Result<(), RRef<DataPacket>> {
        let mut queue = self.queue.lock();
        if queue.len() >= self.capacity {
            return Err(packet);
        }
        queue.push_back(packet);
        Ok(())
    }

    pub fn pop(&self) -> Option<RRef<DataPacket>> {
        self.queue.lock().pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.lock().is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.queue.lock().len() >= self.capacity
    }
}

/// FrameVsock Channel - Bidirectional communication channel
///
/// This is the core communication mechanism:
/// - Guest sends to Host via `guest_to_host` queue
/// - Host sends to Guest via `host_to_guest` queue
/// - Both sides use RRef<DataPacket> for zero-copy transfer
pub struct FrameVsockChannel {
    /// Queue for Guest -> Host packets
    guest_to_host: DataPacketQueue,
    /// Queue for Host -> Guest packets  
    host_to_guest: DataPacketQueue,
    /// Channel is active
    active: AtomicBool,
    /// Next sequence number for Guest
    guest_seq: AtomicU32,
    /// Next sequence number for Host
    host_seq: AtomicU32,
}

impl FrameVsockChannel {
    pub const DEFAULT_QUEUE_SIZE: usize = 64;

    pub fn new() -> Self {
        Self {
            guest_to_host: DataPacketQueue::new(Self::DEFAULT_QUEUE_SIZE),
            host_to_guest: DataPacketQueue::new(Self::DEFAULT_QUEUE_SIZE),
            active: AtomicBool::new(true),
            guest_seq: AtomicU32::new(0),
            host_seq: AtomicU32::new(0),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            guest_to_host: DataPacketQueue::new(capacity),
            host_to_guest: DataPacketQueue::new(capacity),
            active: AtomicBool::new(true),
            guest_seq: AtomicU32::new(0),
            host_seq: AtomicU32::new(0),
        }
    }

    /// Check if channel is active
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Deactivate the channel
    pub fn deactivate(&self) {
        self.active.store(false, Ordering::SeqCst);
    }

    // ========== Guest-side operations ==========

    /// Guest sends a packet to Host
    pub fn guest_send(&self, packet: RRef<DataPacket>) -> Result<(), RRef<DataPacket>> {
        if !self.is_active() {
            return Err(packet);
        }
        self.guest_seq.fetch_add(1, Ordering::SeqCst);
        self.guest_to_host.push(packet)
    }

    /// Guest receives a packet from Host
    pub fn guest_recv(&self) -> Option<RRef<DataPacket>> {
        self.host_to_guest.pop()
    }

    /// Check if Guest has pending packets to receive
    pub fn guest_has_pending(&self) -> bool {
        !self.host_to_guest.is_empty()
    }

    /// Check if Guest can send (not full)
    pub fn guest_can_send(&self) -> bool {
        !self.guest_to_host.is_full() && self.is_active()
    }

    // ========== Host-side operations ==========

    /// Host sends a packet to Guest
    pub fn host_send(&self, packet: RRef<DataPacket>) -> Result<(), RRef<DataPacket>> {
        if !self.is_active() {
            return Err(packet);
        }
        self.host_seq.fetch_add(1, Ordering::SeqCst);
        self.host_to_guest.push(packet)
    }

    /// Host receives a packet from Guest
    pub fn host_recv(&self) -> Option<RRef<DataPacket>> {
        self.guest_to_host.pop()
    }

    /// Check if Host has pending packets to receive
    pub fn host_has_pending(&self) -> bool {
        !self.guest_to_host.is_empty()
    }

    /// Check if Host can send (not full)
    pub fn host_can_send(&self) -> bool {
        !self.host_to_guest.is_full() && self.is_active()
    }

    // ========== Statistics ==========

    pub fn guest_send_count(&self) -> u32 {
        self.guest_seq.load(Ordering::SeqCst)
    }

    pub fn host_send_count(&self) -> u32 {
        self.host_seq.load(Ordering::SeqCst)
    }
}

impl Default for FrameVsockChannel {
    fn default() -> Self {
        Self::new()
    }
}

// ========== Helper functions for creating packets ==========

/// Create a connection request (control packet)
pub fn create_request(
    src_cid: u64,
    src_port: u32,
    dst_cid: u64,
    dst_port: u32,
) -> RRef<ControlPacket> {
    RRef::new(ControlPacket::with_header(
        src_cid,
        dst_cid,
        src_port,
        dst_port,
        VsockOp::Request,
    ))
}

/// Create a connection response (control packet)
pub fn create_response(
    src_cid: u64,
    src_port: u32,
    dst_cid: u64,
    dst_port: u32,
) -> RRef<ControlPacket> {
    RRef::new(ControlPacket::with_header(
        src_cid,
        dst_cid,
        src_port,
        dst_port,
        VsockOp::Response,
    ))
}

/// Create a reset packet (control packet)
pub fn create_rst(src_cid: u64, src_port: u32, dst_cid: u64, dst_port: u32) -> RRef<ControlPacket> {
    RRef::new(ControlPacket::with_header(
        src_cid,
        dst_cid,
        src_port,
        dst_port,
        VsockOp::Rst,
    ))
}

/// Create a shutdown packet (control packet with flags)
pub fn create_shutdown(
    src_cid: u64,
    src_port: u32,
    dst_cid: u64,
    dst_port: u32,
    flags: u32,
) -> RRef<ControlPacket> {
    let mut packet =
        ControlPacket::with_header(src_cid, dst_cid, src_port, dst_port, VsockOp::Shutdown);
    packet.header.flags = flags as u16;
    RRef::new(packet)
}

/// Create a credit update packet (control packet with credit info)
pub fn create_credit_update(
    src_cid: u64,
    src_port: u32,
    dst_cid: u64,
    dst_port: u32,
    buf_alloc: u32,
    fwd_cnt: u32,
) -> RRef<ControlPacket> {
    let mut packet =
        ControlPacket::with_header(src_cid, dst_cid, src_port, dst_port, VsockOp::CreditUpdate);
    packet.header.buf_alloc = buf_alloc;
    packet.header.fwd_cnt = fwd_cnt;
    RRef::new(packet)
}

/// Create a credit request packet (control packet)
pub fn create_credit_request(
    src_cid: u64,
    src_port: u32,
    dst_cid: u64,
    dst_port: u32,
) -> RRef<ControlPacket> {
    RRef::new(ControlPacket::with_header(
        src_cid,
        dst_cid,
        src_port,
        dst_port,
        VsockOp::CreditRequest,
    ))
}

/// Create a data packet with payload
pub fn create_data_packet(
    src_cid: u64,
    src_port: u32,
    dst_cid: u64,
    dst_port: u32,
    data: Vec<u8>,
) -> RRef<DataPacket> {
    RRef::new(DataPacket::new_rw(
        src_cid, dst_cid, src_port, dst_port, data,
    ))
}

/// Create a data packet with credit info
pub fn create_data_packet_with_credit(
    src_cid: u64,
    src_port: u32,
    dst_cid: u64,
    dst_port: u32,
    data: Vec<u8>,
    buf_alloc: u32,
    fwd_cnt: u32,
) -> RRef<DataPacket> {
    let mut packet = DataPacket::new_rw(src_cid, dst_cid, src_port, dst_port, data);
    packet.header.buf_alloc = buf_alloc;
    packet.header.fwd_cnt = fwd_cnt;
    RRef::new(packet)
}