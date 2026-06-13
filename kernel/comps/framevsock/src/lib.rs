// SPDX-License-Identifier: MPL-2.0

//! Shared FrameVsock protocol types and runtime helpers.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

pub mod notify;
pub mod ring;
pub mod trace;
pub mod tuning;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use exchangeable::{Exchangeable, RRef};

/// The vSocket equivalent of INADDR_ANY.
pub const VMADDR_CID_ANY: u64 = u64::MAX;
/// Use this as the destination CID in an address when referring to the local communication (loopback).
pub const VMADDR_CID_LOCAL: u64 = 1;
/// Use this as the destination CID in an address when referring to the host (any process other than the hypervisor).
pub const HOST_CID: u64 = 2;
pub const VMADDR_CID_HOST: u64 = 2;
/// Guest (FrameVM) CID
pub const VMADDR_CID_GUEST: u64 = 3;
/// Base CID for guest VMs (VMs get CID = BASE + vm_id)
pub const GUEST_CID_BASE: u64 = VMADDR_CID_GUEST;
/// Bind to any available port.
pub const VMADDR_PORT_ANY: u32 = u32::MAX;

// ========== CID / VM ID Conversion ==========

/// Check if CID represents a guest VM.
#[inline]
pub const fn is_guest_cid(cid: u64) -> bool {
    cid >= GUEST_CID_BASE
}

/// Convert CID to VM ID (returns None if CID is not a guest CID).
#[inline]
pub const fn cid_to_vm_id(cid: u64) -> Option<u32> {
    if cid >= GUEST_CID_BASE {
        Some((cid - GUEST_CID_BASE) as u32)
    } else {
        None
    }
}

/// Convert VM ID to CID.
#[inline]
pub const fn vm_id_to_cid(vm_id: u32) -> u64 {
    (vm_id as u64) + GUEST_CID_BASE
}

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

/// Zero-copy data buffer with offset tracking.
///
/// This structure avoids O(N²) copy overhead when doing partial reads.
/// Instead of using `Vec::split_off` which copies remaining data,
/// we track the consumed offset and only return a slice view.
#[derive(Clone, Default)]
pub struct DataBuffer {
    data: Vec<u8>,
    offset: usize,
}

impl DataBuffer {
    /// Create a new DataBuffer from a Vec.
    #[inline]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, offset: 0 }
    }

    /// Create an empty DataBuffer.
    #[inline]
    pub fn empty() -> Self {
        Self {
            data: Vec::new(),
            offset: 0,
        }
    }

    /// Get the remaining payload slice (after offset).
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data[self.offset..]
    }

    /// Get mutable remaining payload slice.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[self.offset..]
    }

    /// Get the remaining length (total - consumed).
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    /// Check if all data has been consumed.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    /// Consume `bytes` from the front. Returns true if data remains.
    ///
    /// This is O(1) - just advances the offset pointer.
    #[inline]
    pub fn consume(&mut self, bytes: usize) -> bool {
        self.offset = (self.offset + bytes).min(self.data.len());
        !self.is_empty()
    }

    /// Take ownership of the underlying Vec, consuming self.
    ///
    /// Returns data from current offset onwards.
    ///
    /// # Performance
    /// - If offset == 0: O(1) - direct ownership transfer
    /// - If offset > 0: O(n) copy is unavoidable for Vec ownership
    ///
    /// For zero-copy access, prefer using `as_slice()` when possible.
    #[inline]
    pub fn take(self) -> Vec<u8> {
        if self.offset == 0 {
            self.data
        } else {
            // When offset > 0, we must copy to return owned Vec
            // This is unavoidable if caller needs Vec<u8> ownership
            self.data[self.offset..].to_vec()
        }
    }

    /// Take the remaining data as a new DataBuffer without copying.
    ///
    /// This is more efficient than `take()` when you don't need a `Vec<u8>`,
    /// as it avoids the O(n) copy for partial reads.
    ///
    /// # Performance
    /// O(1) - just moves ownership, no data copying.
    #[inline]
    pub fn take_buffer(self) -> Self {
        // Just return self - the offset is already tracked
        self
    }

    /// Consume self and return the underlying data, resetting offset.
    ///
    /// This drains the front bytes that were consumed, returning
    /// a new Vec containing only the remaining data.
    ///
    /// # Performance
    /// - If offset == 0: O(1)
    /// - If offset > 0: O(n) where n = remaining bytes
    #[inline]
    pub fn into_remaining(mut self) -> Vec<u8> {
        if self.offset == 0 {
            self.data
        } else {
            // drain(..offset) removes consumed bytes, leaving remaining
            self.data.drain(..self.offset);
            self.data
        }
    }

    /// Get the current offset (for debugging/stats).
    #[inline]
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Try to extend the buffer with new data (no reallocation).
    ///
    /// Returns `Ok(())` on success. If there is a non-zero offset (partial read
    /// in progress) or there is not enough spare capacity, returns `Err(data)`
    /// so the caller can fall back without data loss.
    #[inline]
    pub fn try_extend(&mut self, mut data: Vec<u8>) -> Result<(), Vec<u8>> {
        if self.offset != 0 {
            return Err(data);
        }
        let available = self.data.capacity().saturating_sub(self.data.len());
        if available < data.len() {
            return Err(data);
        }
        self.data.append(&mut data);
        Ok(())
    }
}

impl Exchangeable for DataBuffer {}

/// Generic FrameVsock Buffer for zero-copy data transfer
///
/// # Type Parameter
/// - `T = ()`: Control packet with no data payload
/// - `T = DataBuffer`: Data packet with zero-copy partial read support
///
/// # Zero-Copy Design
/// The buffer owns its data. When transferred via RRef, ownership moves
/// without copying the underlying data. Partial reads use offset tracking
/// instead of data copying.
#[repr(C)]
pub struct FrameVsockBuffer<T: Exchangeable = ()> {
    /// Packet header
    pub header: FrameVsockHeader,
    /// Payload data (generic)
    pub data: T,
}

/// Type alias for control packets (no data payload)
pub type ControlPacket = FrameVsockBuffer<()>;

/// Type alias for data packets (with zero-copy DataBuffer payload)
pub type DataPacket = FrameVsockBuffer<DataBuffer>;

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
            data: DataBuffer::new(data),
        }
    }
}

impl Default for FrameVsockBuffer<()> {
    fn default() -> Self {
        Self::new()
    }
}

// Data packet (DataBuffer) implementations - zero-copy optimized
impl FrameVsockBuffer<DataBuffer> {
    /// Create a new data packet with empty data
    pub fn new_data() -> Self {
        Self {
            header: FrameVsockHeader::new(),
            data: DataBuffer::empty(),
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
            data: DataBuffer::new(data),
        }
    }

    /// Create a data packet for RW operation
    pub fn new_rw(src_cid: u64, dst_cid: u64, src_port: u32, dst_port: u32, data: Vec<u8>) -> Self {
        Self::with_header_and_data(src_cid, dst_cid, src_port, dst_port, VsockOp::Rw, data)
    }

    /// Get payload slice (remaining data after offset)
    #[inline]
    pub fn payload(&self) -> &[u8] {
        self.data.as_slice()
    }

    /// Get mutable payload slice
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        self.data.as_mut_slice()
    }

    /// Get payload length (remaining after consumed bytes)
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if payload is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Take ownership of the remaining data
    pub fn take_data(self) -> Vec<u8> {
        self.data.take()
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
            data: DataBuffer::new(data),
        }
    }

    /// Consume partial data - O(1) operation, no copying!
    ///
    /// This is the key optimization: instead of using `Vec::split_off` which
    /// copies O(N) bytes for each partial read, we just advance an offset.
    ///
    /// Returns `Some(self)` if data remains after consuming, `None` if fully consumed.
    #[inline]
    pub fn consume_partial(mut self, bytes: usize) -> Option<Self> {
        if self.data.consume(bytes) {
            Some(self)
        } else {
            None // Fully consumed
        }
    }
}

impl Default for FrameVsockBuffer<DataBuffer> {
    fn default() -> Self {
        Self::new_data()
    }
}

// Implement Exchangeable for FrameVsockBuffer<T>
impl Exchangeable for FrameVsockBuffer<()> {}
impl Exchangeable for FrameVsockBuffer<DataBuffer> {}

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

// ========== Flow Control Configuration ==========

/// Flow control configuration for FrameVsock connections.
///
/// This module provides tunable parameters for optimizing throughput and latency.
/// The default values are chosen to balance between small packet scenarios (64B)
/// and large bulk transfers (1MB+).
///
/// # Design Philosophy (Linux-style)
///
/// Unlike the previous packet-count-based approach, we now use a buffer-percentage
/// approach similar to Linux virtio-vsock:
/// - Credit updates are sent when free space drops below a threshold
/// - This naturally handles both small and large packets efficiently
/// - Large packets no longer trigger excessive credit updates
pub mod flow_control {
    /// Default buffer allocation advertised to peer.
    ///
    /// This is the receive window size. Larger values allow more in-flight data
    /// but consume more memory. Should be >= MAX_PENDING_PACKETS * avg_packet_size.
    ///
    /// Set to 4MB to allow more outstanding data and reduce credit update frequency.
    pub const DEFAULT_BUF_ALLOC: u32 = 4 * 1024 * 1024; // 4MB

    /// Maximum pending packets per connection.
    ///
    /// With DEFAULT_BUF_ALLOC=4MB and 64B packets, we need at least 65536 slots.
    pub const MIN_PKT_BUF_SIZE: u32 = 64; // 64B
    pub const MAX_PENDING_PACKETS: usize = (DEFAULT_BUF_ALLOC / MIN_PKT_BUF_SIZE) as usize;

    /// Maximum single packet size (same as Linux VIRTIO_VSOCK_MAX_PKT_BUF_SIZE).
    ///
    /// Used for credit update threshold calculations.
    pub const MAX_PKT_BUF_SIZE: u32 = 64 * 1024; // 64KB

    /// Minimum credit update threshold.
    ///
    /// For very small packets, we want frequent updates to avoid sender stalls.
    pub const MIN_CREDIT_UPDATE_THRESHOLD: u32 = 4 * 1024; // 4KB

    /// Maximum credit update threshold.
    ///
    /// For large packets, we use buffer-percentage based updates.
    /// Set to 512KB (12.5% of DEFAULT_BUF_ALLOC) to balance credit update
    /// frequency vs overhead. Lower values improve multi-connection fairness
    /// by replenishing sender credit faster, at the cost of slightly more
    /// control packets (~1.5μs each, negligible vs data throughput).
    pub const MAX_CREDIT_UPDATE_THRESHOLD: u32 = 512 * 1024; // 512KB

    /// Calculate adaptive credit update threshold based on actual buffer allocation.
    ///
    /// This is the preferred function when you have the actual buf_alloc value.
    #[inline]
    pub const fn adaptive_threshold_for_buf(buf_alloc: u32) -> u32 {
        // Use 25% of buffer allocation as threshold
        let threshold = buf_alloc / 4;
        if threshold < MIN_CREDIT_UPDATE_THRESHOLD {
            MIN_CREDIT_UPDATE_THRESHOLD
        } else if threshold > MAX_CREDIT_UPDATE_THRESHOLD {
            MAX_CREDIT_UPDATE_THRESHOLD
        } else {
            threshold
        }
    }

    /// Fast threshold for low-latency scenarios.
    ///
    /// Used when we detect the sender might be stalled (credit near zero).
    pub const URGENT_CREDIT_UPDATE_THRESHOLD: u32 = 4 * 1024; // 4KB

    /// Credit watermark: when available credit drops below this percentage
    /// of buf_alloc, receiver should proactively send credit update.
    ///
    /// 25% means: if we've consumed 75% of the window, send update early.
    pub const LOW_CREDIT_WATERMARK_PERCENT: u32 = 25;

    /// Calculate low credit watermark value.
    #[inline]
    pub const fn low_credit_watermark(buf_alloc: u32) -> u32 {
        buf_alloc / 4 // 25%
    }

    /// Check if credit update should be sent (Linux-style).
    ///
    /// This function implements the Linux virtio-vsock credit update logic:
    /// 1. Send update if free space < MAX_PKT_BUF_SIZE (receiver almost full)
    /// 2. Send update if consumed since last update >= threshold
    ///
    /// # Arguments
    /// * `buf_alloc` - Total buffer allocation
    /// * `buf_used` - Currently used buffer space
    /// * `fwd_cnt` - Current forward count
    /// * `last_fwd_cnt` - Forward count at last credit update
    #[inline]
    pub const fn should_send_credit_update(
        buf_alloc: u32,
        buf_used: u32,
        fwd_cnt: u32,
        last_fwd_cnt: u32,
    ) -> bool {
        let free_space = buf_alloc.saturating_sub(buf_used);
        let consumed_since_last = fwd_cnt.wrapping_sub(last_fwd_cnt);
        let threshold = adaptive_threshold_for_buf(buf_alloc);

        // Linux-style: update when free space is low OR when we've consumed enough
        free_space <= MAX_PKT_BUF_SIZE || consumed_since_last >= threshold
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

/// Create a connection request with credit info (control packet)
pub fn create_request_with_credit(
    src_cid: u64,
    src_port: u32,
    dst_cid: u64,
    dst_port: u32,
    buf_alloc: u32,
    fwd_cnt: u32,
) -> RRef<ControlPacket> {
    let mut packet =
        ControlPacket::with_header(src_cid, dst_cid, src_port, dst_port, VsockOp::Request);
    packet.header.buf_alloc = buf_alloc;
    packet.header.fwd_cnt = fwd_cnt;
    RRef::new(packet)
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

/// Create a connection response with credit info (control packet)
pub fn create_response_with_credit(
    src_cid: u64,
    src_port: u32,
    dst_cid: u64,
    dst_port: u32,
    buf_alloc: u32,
    fwd_cnt: u32,
) -> RRef<ControlPacket> {
    let mut packet =
        ControlPacket::with_header(src_cid, dst_cid, src_port, dst_port, VsockOp::Response);
    packet.header.buf_alloc = buf_alloc;
    packet.header.fwd_cnt = fwd_cnt;
    RRef::new(packet)
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
