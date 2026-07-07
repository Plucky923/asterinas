// SPDX-License-Identifier: MPL-2.0

//! Shared FrameVsock protocol types and runtime helpers.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::{collections::BTreeMap, vec::Vec};
use core::fmt;

use exchangeable::Exchangeable;
use framev_device::{FrameVDeviceId, FrameVDeviceInfo, FrameVDeviceType, IrqLine, well_known};

/// The default `framev-sock` device ID.
pub const DEFAULT_DEVICE_ID: FrameVDeviceId = well_known::DEFAULT_SOCK_DEVICE_ID;

/// The default `framev-sock` software IRQ line.
pub const DEFAULT_IRQ_LINE: IrqLine = IrqLine::new(2);

/// Returns the default `framev-sock` device metadata.
pub const fn default_device_info() -> FrameVDeviceInfo {
    FrameVDeviceInfo::new(DEFAULT_DEVICE_ID, FrameVDeviceType::Sock, DEFAULT_IRQ_LINE)
}

/// The vSocket equivalent of INADDR_ANY.
pub const VMADDR_CID_ANY: u64 = u64::MAX;
/// Use this as the destination CID in an address when referring to the local
/// communication (loopback).
pub const VMADDR_CID_LOCAL: u64 = 1;
/// Use this as the destination CID in an address when referring to the host
/// (any process other than the hypervisor).
pub const HOST_CID: u64 = 2;
pub const VMADDR_CID_HOST: u64 = 2;
/// Default guest CID used by the first service instance.
pub const VMADDR_CID_GUEST: u64 = 3;

/// Base CID used by the backend to route service guests.
pub const GUEST_CID_BASE: u64 = VMADDR_CID_GUEST;
/// Bind to any available port.
pub const VMADDR_PORT_ANY: u32 = u32::MAX;

/// The virtio-vsock stream packet type value.
pub const VSOCK_TYPE_STREAM: u16 = 1;

/// Maximum payload bytes in one FrameV Sock `Rw` packet.
pub const MAX_PACKET_PAYLOAD_LEN: usize = 64 * 1024;

// ========== CID / VM ID Conversion ==========

/// Checks if a CID is routed to a service guest.
#[inline]
pub const fn is_guest_cid(cid: u64) -> bool {
    cid >= GUEST_CID_BASE && cid - GUEST_CID_BASE <= u32::MAX as u64
}

/// Converts a guest CID to the backend VM ID.
#[inline]
pub const fn cid_to_vm_id(cid: u64) -> Option<u32> {
    if is_guest_cid(cid) {
        Some((cid - GUEST_CID_BASE) as u32)
    } else {
        None
    }
}

/// Converts a backend VM ID to its guest CID.
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

/// Canonical endpoint-pair key used for FrameV Sock flow affinity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct FrameVsockFlowKey {
    first: FrameVsockAddr,
    second: FrameVsockAddr,
}

impl FrameVsockFlowKey {
    /// Creates a canonical key by sorting two endpoints.
    pub const fn new(a: FrameVsockAddr, b: FrameVsockAddr) -> Self {
        if Self::addr_le(a, b) {
            Self {
                first: a,
                second: b,
            }
        } else {
            Self {
                first: b,
                second: a,
            }
        }
    }

    /// Creates a canonical key from a packet header.
    pub const fn from_header(header: &FrameVsockHdr) -> Self {
        Self::new(header.src_addr(), header.dst_addr())
    }

    /// Creates a canonical key from a validated packet.
    pub const fn from_packet(packet: &FrameVsockPacket) -> Self {
        Self::new(packet.src_addr(), packet.dst_addr())
    }

    /// Returns the first canonical endpoint.
    pub const fn first(&self) -> FrameVsockAddr {
        self.first
    }

    /// Returns the second canonical endpoint.
    pub const fn second(&self) -> FrameVsockAddr {
        self.second
    }

    const fn addr_le(a: FrameVsockAddr, b: FrameVsockAddr) -> bool {
        a.cid < b.cid || (a.cid == b.cid && a.port <= b.port)
    }
}

/// Flow-affinity error returned when packet queue placement violates state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowAffinityError {
    /// The packet arrived on a queue different from the bound queue.
    WrongQueue { expected: usize, actual: usize },
}

/// Local flow-to-queue affinity table.
#[derive(Debug, Default)]
pub struct FlowAffinityTable {
    entries: BTreeMap<FrameVsockFlowKey, usize>,
}

impl FlowAffinityTable {
    /// Creates an empty affinity table.
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Returns the queue bound to a flow.
    pub fn get(&self, key: FrameVsockFlowKey) -> Option<usize> {
        self.entries.get(&key).copied()
    }

    /// Observes an unbound or already-bound flow on `queue_id`.
    ///
    /// The first observation establishes affinity. Later observations must use
    /// the same queue until the flow is removed.
    pub fn observe(
        &mut self,
        key: FrameVsockFlowKey,
        queue_id: usize,
    ) -> Result<usize, FlowAffinityError> {
        match self.entries.get(&key).copied() {
            Some(bound_queue_id) if bound_queue_id == queue_id => Ok(bound_queue_id),
            Some(bound_queue_id) => Err(FlowAffinityError::WrongQueue {
                expected: bound_queue_id,
                actual: queue_id,
            }),
            None => {
                self.entries.insert(key, queue_id);
                Ok(queue_id)
            }
        }
    }

    /// Selects a queue for local transmit and binds the flow if needed.
    pub fn bind_or_get(&mut self, key: FrameVsockFlowKey, queue_id: usize) -> usize {
        *self.entries.entry(key).or_insert(queue_id)
    }

    /// Removes affinity for a closed or reset flow.
    pub fn remove(&mut self, key: FrameVsockFlowKey) -> Option<usize> {
        self.entries.remove(&key)
    }

    /// Clears all affinity entries during transport reset or stop.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns the number of tracked flows.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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

impl VsockOp {
    /// Decodes a raw operation value.
    pub const fn decode(val: u16) -> Option<Self> {
        match val {
            1 => Some(VsockOp::Request),
            2 => Some(VsockOp::Response),
            3 => Some(VsockOp::Rst),
            4 => Some(VsockOp::Shutdown),
            5 => Some(VsockOp::Rw),
            6 => Some(VsockOp::CreditUpdate),
            7 => Some(VsockOp::CreditRequest),
            _ => None,
        }
    }

    /// Returns whether this is a valid encoded packet operation.
    pub const fn is_valid(self) -> bool {
        !matches!(self, VsockOp::Invalid)
    }
}

/// Shutdown flags
pub const SHUTDOWN_FLAG_RECV: u32 = 1;
pub const SHUTDOWN_FLAG_SEND: u32 = 2;
pub const SHUTDOWN_FLAG_BOTH: u32 = SHUTDOWN_FLAG_SEND | SHUTDOWN_FLAG_RECV;

/// FrameV Sock packet header aligned with the virtio-vsock wire header.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct FrameVsockHdr {
    /// The source CID.
    pub src_cid: u64,
    /// The destination CID.
    pub dst_cid: u64,
    /// The source port.
    pub src_port: u32,
    /// The destination port.
    pub dst_port: u32,
    /// The payload length in bytes.
    pub len: u32,
    /// The encoded vsock packet type.
    pub type_: u16,
    /// The encoded [`VsockOp`].
    pub op: u16,
    /// Stores operation-specific flags.
    pub flags: u32,
    /// The sender's advertised receive buffer size.
    pub buf_alloc: u32,
    /// The sender's forwarded-byte counter.
    pub fwd_cnt: u32,
}

impl FrameVsockHdr {
    /// Creates a stream-type FrameV Sock header.
    #[expect(
        clippy::too_many_arguments,
        reason = "the header fields mirror the virtio-vsock packet header"
    )]
    pub const fn new(
        src: FrameVsockAddr,
        dst: FrameVsockAddr,
        len: u32,
        op: VsockOp,
        flags: u32,
        buf_alloc: u32,
        fwd_cnt: u32,
    ) -> Self {
        Self {
            src_cid: src.cid,
            dst_cid: dst.cid,
            src_port: src.port,
            dst_port: dst.port,
            len,
            type_: VSOCK_TYPE_STREAM,
            op: op as u16,
            flags,
            buf_alloc,
            fwd_cnt,
        }
    }

    /// Decodes and returns the packet operation.
    pub const fn operation(&self) -> Option<VsockOp> {
        VsockOp::decode(self.op)
    }

    /// Returns the source endpoint.
    pub const fn src_addr(&self) -> FrameVsockAddr {
        FrameVsockAddr::new(self.src_cid, self.src_port)
    }

    /// Returns the destination endpoint.
    pub const fn dst_addr(&self) -> FrameVsockAddr {
        FrameVsockAddr::new(self.dst_cid, self.dst_port)
    }

    /// Creates a response header with swapped endpoints.
    pub const fn create_response_header(&self, op: VsockOp, len: u32) -> Self {
        Self {
            src_cid: self.dst_cid,
            dst_cid: self.src_cid,
            src_port: self.dst_port,
            dst_port: self.src_port,
            len,
            type_: VSOCK_TYPE_STREAM,
            op: op as u16,
            flags: 0,
            buf_alloc: 0,
            fwd_cnt: 0,
        }
    }
}

impl fmt::Debug for FrameVsockHdr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let src_cid = self.src_cid;
        let dst_cid = self.dst_cid;
        let src_port = self.src_port;
        let dst_port = self.dst_port;
        let len = self.len;
        let type_ = self.type_;
        let op = self.op;
        let flags = self.flags;
        let buf_alloc = self.buf_alloc;
        let fwd_cnt = self.fwd_cnt;

        formatter
            .debug_struct("FrameVsockHdr")
            .field("src_cid", &src_cid)
            .field("dst_cid", &dst_cid)
            .field("src_port", &src_port)
            .field("dst_port", &dst_port)
            .field("len", &len)
            .field("type_", &type_)
            .field("op", &op)
            .field("flags", &flags)
            .field("buf_alloc", &buf_alloc)
            .field("fwd_cnt", &fwd_cnt)
            .finish()
    }
}

impl Exchangeable for FrameVsockHdr {}

/// Error returned when packet parts do not form a valid FrameV Sock packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVsockPacketError {
    /// The header does not encode stream packet type.
    InvalidType,
    /// The header does not encode a valid packet operation.
    InvalidOperation,
    /// Header length and payload length differ.
    LengthMismatch,
    /// A control packet carries payload bytes.
    ControlPayloadNotEmpty,
    /// An `Rw` packet has no payload bytes.
    EmptyRwPayload,
    /// An `Rw` packet exceeds the first-profile payload size.
    PayloadTooLarge,
}

/// A validated FrameV Sock packet.
#[derive(Debug)]
pub struct FrameVsockPacket {
    header: FrameVsockHdr,
    payload: Vec<u8>,
}

impl FrameVsockPacket {
    /// Creates a packet from header and payload after validating invariants.
    pub fn try_from_parts(
        header: FrameVsockHdr,
        payload: Vec<u8>,
    ) -> Result<Self, FrameVsockPacketError> {
        Self::validate(&header, payload.len())?;

        Ok(Self { header, payload })
    }

    /// Creates a connection request packet.
    pub fn request(src: FrameVsockAddr, dst: FrameVsockAddr, buf_alloc: u32, fwd_cnt: u32) -> Self {
        Self::control(src, dst, VsockOp::Request, 0, buf_alloc, fwd_cnt)
    }

    /// Creates a connection response packet.
    pub fn response(
        src: FrameVsockAddr,
        dst: FrameVsockAddr,
        buf_alloc: u32,
        fwd_cnt: u32,
    ) -> Self {
        Self::control(src, dst, VsockOp::Response, 0, buf_alloc, fwd_cnt)
    }

    /// Creates a reset packet.
    pub fn rst(src: FrameVsockAddr, dst: FrameVsockAddr) -> Self {
        Self::control(src, dst, VsockOp::Rst, 0, 0, 0)
    }

    /// Creates a shutdown packet.
    pub fn shutdown(src: FrameVsockAddr, dst: FrameVsockAddr, flags: u32) -> Self {
        Self::control(src, dst, VsockOp::Shutdown, flags, 0, 0)
    }

    /// Creates a credit update packet.
    pub fn credit_update(
        src: FrameVsockAddr,
        dst: FrameVsockAddr,
        buf_alloc: u32,
        fwd_cnt: u32,
    ) -> Self {
        Self::control(src, dst, VsockOp::CreditUpdate, 0, buf_alloc, fwd_cnt)
    }

    /// Creates a credit request packet.
    pub fn credit_request(src: FrameVsockAddr, dst: FrameVsockAddr) -> Self {
        Self::control(src, dst, VsockOp::CreditRequest, 0, 0, 0)
    }

    /// Creates a credit request packet with piggybacked credit state.
    pub fn credit_request_with_credit(
        src: FrameVsockAddr,
        dst: FrameVsockAddr,
        buf_alloc: u32,
        fwd_cnt: u32,
    ) -> Self {
        Self::control(src, dst, VsockOp::CreditRequest, 0, buf_alloc, fwd_cnt)
    }

    /// Creates an `Rw` packet.
    pub fn rw(
        src: FrameVsockAddr,
        dst: FrameVsockAddr,
        payload: Vec<u8>,
        buf_alloc: u32,
        fwd_cnt: u32,
    ) -> Result<Self, FrameVsockPacketError> {
        let len = payload.len();
        if len == 0 {
            return Err(FrameVsockPacketError::EmptyRwPayload);
        }
        if len > MAX_PACKET_PAYLOAD_LEN {
            return Err(FrameVsockPacketError::PayloadTooLarge);
        }

        let header = FrameVsockHdr::new(src, dst, len as u32, VsockOp::Rw, 0, buf_alloc, fwd_cnt);
        Ok(Self { header, payload })
    }

    /// Returns a zero-byte send result without creating an `Rw` packet.
    pub const fn zero_len_send_result() -> usize {
        0
    }

    /// Returns a copy of the packet header.
    pub const fn header(&self) -> FrameVsockHdr {
        self.header
    }

    /// Returns the decoded packet operation.
    pub const fn operation(&self) -> VsockOp {
        // This fallback is unreachable for values created by public packet constructors.
        match self.header.operation() {
            Some(op) => op,
            None => VsockOp::Invalid,
        }
    }

    /// Returns the payload bytes.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consumes the packet and returns the owned payload.
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    /// Returns the source endpoint.
    pub const fn src_addr(&self) -> FrameVsockAddr {
        self.header.src_addr()
    }

    /// Returns the destination endpoint.
    pub const fn dst_addr(&self) -> FrameVsockAddr {
        self.header.dst_addr()
    }

    fn control(
        src: FrameVsockAddr,
        dst: FrameVsockAddr,
        op: VsockOp,
        flags: u32,
        buf_alloc: u32,
        fwd_cnt: u32,
    ) -> Self {
        Self {
            header: FrameVsockHdr::new(src, dst, 0, op, flags, buf_alloc, fwd_cnt),
            payload: Vec::new(),
        }
    }

    fn validate(header: &FrameVsockHdr, payload_len: usize) -> Result<(), FrameVsockPacketError> {
        if header.type_ != VSOCK_TYPE_STREAM {
            return Err(FrameVsockPacketError::InvalidType);
        }

        let Some(op) = header.operation() else {
            return Err(FrameVsockPacketError::InvalidOperation);
        };

        if header.len as usize != payload_len {
            return Err(FrameVsockPacketError::LengthMismatch);
        }

        if op == VsockOp::Rw {
            if payload_len == 0 {
                return Err(FrameVsockPacketError::EmptyRwPayload);
            }
            if payload_len > MAX_PACKET_PAYLOAD_LEN {
                return Err(FrameVsockPacketError::PayloadTooLarge);
            }
        } else if payload_len != 0 {
            return Err(FrameVsockPacketError::ControlPayloadNotEmpty);
        }

        Ok(())
    }
}

impl Exchangeable for FrameVsockPacket {}

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

    /// Calculates sendable peer credit using virtio-vsock wrapping counters.
    #[inline]
    pub const fn available_peer_credit(
        tx_cnt: u32,
        peer_buf_alloc: u32,
        peer_fwd_cnt: u32,
    ) -> usize {
        let used = tx_cnt.wrapping_sub(peer_fwd_cnt);
        peer_buf_alloc.saturating_sub(used) as usize
    }

    /// Advances the local forwarded-byte counter after socket receive consumption.
    #[inline]
    pub const fn advance_fwd_cnt(fwd_cnt: u32, consumed_bytes: usize) -> u32 {
        fwd_cnt.wrapping_add(consumed_bytes as u32)
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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    fn src_addr() -> FrameVsockAddr {
        FrameVsockAddr::new(3, 1024)
    }

    fn dst_addr() -> FrameVsockAddr {
        FrameVsockAddr::new(HOST_CID, 2048)
    }

    #[test]
    fn constants_match_virtio_vsock_values() {
        assert_eq!(VSOCK_TYPE_STREAM, 1);
        assert_eq!(VsockOp::Request as u16, 1);
        assert_eq!(VsockOp::Response as u16, 2);
        assert_eq!(VsockOp::Rst as u16, 3);
        assert_eq!(VsockOp::Shutdown as u16, 4);
        assert_eq!(VsockOp::Rw as u16, 5);
        assert_eq!(VsockOp::CreditUpdate as u16, 6);
        assert_eq!(VsockOp::CreditRequest as u16, 7);
        assert_eq!(SHUTDOWN_FLAG_RECV, 1);
        assert_eq!(SHUTDOWN_FLAG_SEND, 2);
    }

    #[test]
    fn default_metadata_matches_sock_device() {
        let info = default_device_info();

        assert_eq!(info.id, DEFAULT_DEVICE_ID);
        assert_eq!(info.device_type, FrameVDeviceType::Sock);
        assert_eq!(info.irq_line, DEFAULT_IRQ_LINE);
    }

    #[test]
    fn only_stream_packet_operations_are_decoded() {
        for value in 1..=7 {
            assert!(VsockOp::decode(value).is_some());
        }

        assert_eq!(VsockOp::decode(0), None);
        assert_eq!(VsockOp::decode(8), None);
        assert_eq!(VsockOp::decode(u16::MAX), None);
    }

    #[test]
    fn header_matches_virtio_vsock_wire_size() {
        assert_eq!(size_of::<FrameVsockHdr>(), 44);
    }

    #[test]
    fn queue_id_is_not_encoded_in_header() {
        let header = FrameVsockHdr::new(src_addr(), dst_addr(), 0, VsockOp::Request, 0, 4096, 0);

        let len = header.len;
        let type_ = header.type_;
        let op = header.op;

        assert_eq!(size_of::<FrameVsockHdr>(), 44);
        assert_eq!(len, 0);
        assert_eq!(type_, VSOCK_TYPE_STREAM);
        assert_eq!(op, VsockOp::Request as u16);
    }

    #[test]
    fn request_constructor_creates_header_only_packet() {
        let packet = FrameVsockPacket::request(src_addr(), dst_addr(), 4096, 7);
        let header = packet.header();

        let src_cid = header.src_cid;
        let dst_cid = header.dst_cid;
        let src_port = header.src_port;
        let dst_port = header.dst_port;
        let len = header.len;
        let type_ = header.type_;
        let op = header.op;
        let flags = header.flags;
        let buf_alloc = header.buf_alloc;
        let fwd_cnt = header.fwd_cnt;

        assert_eq!(src_cid, 3);
        assert_eq!(dst_cid, HOST_CID);
        assert_eq!(src_port, 1024);
        assert_eq!(dst_port, 2048);
        assert_eq!(len, 0);
        assert_eq!(type_, VSOCK_TYPE_STREAM);
        assert_eq!(op, VsockOp::Request as u16);
        assert_eq!(flags, 0);
        assert_eq!(buf_alloc, 4096);
        assert_eq!(fwd_cnt, 7);
        assert!(packet.payload().is_empty());
    }

    #[test]
    fn rw_constructor_validates_payload_length() {
        assert_eq!(
            FrameVsockPacket::rw(src_addr(), dst_addr(), Vec::new(), 4096, 0).unwrap_err(),
            FrameVsockPacketError::EmptyRwPayload
        );

        let payload = vec![0; MAX_PACKET_PAYLOAD_LEN + 1];
        assert_eq!(
            FrameVsockPacket::rw(src_addr(), dst_addr(), payload, 4096, 0).unwrap_err(),
            FrameVsockPacketError::PayloadTooLarge
        );

        let payload = Vec::from([1, 2, 3]);
        let packet =
            FrameVsockPacket::rw(src_addr(), dst_addr(), payload.clone(), 4096, 11).unwrap();
        let header = packet.header();
        let len = header.len;
        let op = header.op;
        let buf_alloc = header.buf_alloc;
        let fwd_cnt = header.fwd_cnt;

        assert_eq!(len, payload.len() as u32);
        assert_eq!(op, VsockOp::Rw as u16);
        assert_eq!(buf_alloc, 4096);
        assert_eq!(fwd_cnt, 11);
        assert_eq!(packet.payload(), payload.as_slice());
    }

    #[test]
    fn checked_parts_reject_invalid_packets() {
        let valid_control =
            FrameVsockHdr::new(src_addr(), dst_addr(), 0, VsockOp::CreditUpdate, 0, 4096, 0);
        assert!(FrameVsockPacket::try_from_parts(valid_control, Vec::new()).is_ok());

        let invalid_type = FrameVsockHdr {
            type_: 0,
            ..valid_control
        };
        assert_eq!(
            FrameVsockPacket::try_from_parts(invalid_type, Vec::new()).unwrap_err(),
            FrameVsockPacketError::InvalidType
        );

        let invalid_op = FrameVsockHdr {
            op: 0,
            ..valid_control
        };
        assert_eq!(
            FrameVsockPacket::try_from_parts(invalid_op, Vec::new()).unwrap_err(),
            FrameVsockPacketError::InvalidOperation
        );

        let wrong_len = FrameVsockHdr {
            len: 1,
            ..valid_control
        };
        assert_eq!(
            FrameVsockPacket::try_from_parts(wrong_len, Vec::new()).unwrap_err(),
            FrameVsockPacketError::LengthMismatch
        );

        assert_eq!(
            FrameVsockPacket::try_from_parts(valid_control, Vec::from([1])).unwrap_err(),
            FrameVsockPacketError::LengthMismatch
        );

        let control_with_payload_len =
            FrameVsockHdr::new(src_addr(), dst_addr(), 1, VsockOp::CreditUpdate, 0, 4096, 0);
        assert_eq!(
            FrameVsockPacket::try_from_parts(control_with_payload_len, Vec::from([1])).unwrap_err(),
            FrameVsockPacketError::ControlPayloadNotEmpty
        );
    }

    #[test]
    fn zero_length_send_does_not_create_packet() {
        assert_eq!(FrameVsockPacket::zero_len_send_result(), 0);
    }

    #[test]
    fn flow_key_is_canonical_across_directions() {
        let forward = FrameVsockFlowKey::new(src_addr(), dst_addr());
        let reverse = FrameVsockFlowKey::new(dst_addr(), src_addr());

        assert_eq!(forward, reverse);
        assert_eq!(forward.first(), dst_addr());
        assert_eq!(forward.second(), src_addr());
    }

    #[test]
    fn flow_affinity_table_learns_and_reuses_queue() {
        let mut table = FlowAffinityTable::new();
        let key = FrameVsockFlowKey::new(src_addr(), dst_addr());

        assert_eq!(table.observe(key, 3), Ok(3));
        assert_eq!(table.get(key), Some(3));
        assert_eq!(table.observe(key, 3), Ok(3));
        assert_eq!(table.bind_or_get(key, 7), 3);
    }

    #[test]
    fn flow_affinity_table_rejects_wrong_queue() {
        let mut table = FlowAffinityTable::new();
        let key = FrameVsockFlowKey::new(src_addr(), dst_addr());

        assert_eq!(table.observe(key, 2), Ok(2));
        assert_eq!(
            table.observe(key, 4),
            Err(FlowAffinityError::WrongQueue {
                expected: 2,
                actual: 4
            })
        );
    }

    #[test]
    fn flow_affinity_table_removes_and_rebinds_flow() {
        let mut table = FlowAffinityTable::new();
        let key = FrameVsockFlowKey::new(src_addr(), dst_addr());

        assert_eq!(table.observe(key, 1), Ok(1));
        assert_eq!(table.remove(key), Some(1));
        assert!(table.is_empty());
        assert_eq!(table.observe(key, 5), Ok(5));

        table.clear();
        assert!(table.is_empty());
    }

    #[test]
    fn credit_helpers_match_virtio_vsock_wrapping_semantics() {
        use crate::flow_control::{advance_fwd_cnt, available_peer_credit};

        assert_eq!(available_peer_credit(1024, 4096, 512), 3584);
        assert_eq!(available_peer_credit(4096, 1024, 0), 0);
        assert_eq!(
            available_peer_credit(8, 64, u32::MAX - 7),
            48,
            "wrapping tx_cnt - peer_fwd_cnt should count 16 bytes used"
        );

        assert_eq!(advance_fwd_cnt(7, 9), 16);
        assert_eq!(advance_fwd_cnt(u32::MAX - 3, 8), 4);
    }

    #[test]
    fn packet_constructors_carry_credit_fields() {
        let src = FrameVsockAddr::new(3, 1024);
        let dst = FrameVsockAddr::new(HOST_CID, 2048);

        let request = FrameVsockPacket::request(src, dst, 8192, 11);
        let request_header = request.header();
        let request_buf_alloc = request_header.buf_alloc;
        let request_fwd_cnt = request_header.fwd_cnt;
        assert_eq!(request_buf_alloc, 8192);
        assert_eq!(request_fwd_cnt, 11);

        let response = FrameVsockPacket::response(dst, src, 4096, 17);
        let response_header = response.header();
        let response_buf_alloc = response_header.buf_alloc;
        let response_fwd_cnt = response_header.fwd_cnt;
        assert_eq!(response_buf_alloc, 4096);
        assert_eq!(response_fwd_cnt, 17);

        let data = FrameVsockPacket::rw(src, dst, Vec::from([1, 2, 3]), 1024, 23).unwrap();
        let data_header = data.header();
        let data_buf_alloc = data_header.buf_alloc;
        let data_fwd_cnt = data_header.fwd_cnt;
        assert_eq!(data_buf_alloc, 1024);
        assert_eq!(data_fwd_cnt, 23);

        let credit_update = FrameVsockPacket::credit_update(src, dst, 2048, 29);
        let credit_update_header = credit_update.header();
        let credit_update_buf_alloc = credit_update_header.buf_alloc;
        let credit_update_fwd_cnt = credit_update_header.fwd_cnt;
        assert_eq!(credit_update_buf_alloc, 2048);
        assert_eq!(credit_update_fwd_cnt, 29);
    }

    #[test]
    fn unified_packet_types_are_exchangeable() {
        use exchangeable::RRef;

        fn assert_exchangeable<T: Exchangeable>() {}

        assert_exchangeable::<FrameVsockHdr>();
        assert_exchangeable::<FrameVsockPacket>();
        assert_exchangeable::<RRef<FrameVsockPacket>>();
    }
}
