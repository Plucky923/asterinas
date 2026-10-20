// SPDX-License-Identifier: MPL-2.0

//! Exclusive whole-buffer grants across image boundaries.
//!
//! Local accessors borrow their owning wrapper. Handoff and submission consume
//! that wrapper; rejection returns it. No frame, mapping, identifier constructor,
//! or writable backing handle is exposed to image callers.

#[cfg(feature = "kernelet-host")]
mod host;
#[cfg(feature = "kernelet-host")]
pub use host::{BackendBuffer, IoRequest};
#[cfg(feature = "kernelet-host")]
pub use host::{HostLocalEndpoint, HostLocalGrant, HostSendCredit};
#[cfg(feature = "kernelet-host")]
pub(crate) use host::{Participant, dispatch_device, dispatch_net_exchange};

#[cfg(feature = "kernelet")]
mod image;
#[cfg(feature = "kernelet")]
pub use image::{Buffer, PendingIo, ReadBuffer, ReadWriteBuffer, Received};
#[cfg(feature = "kernelet")]
pub use image::{
    SharedNetTransport, ZeroCopyBlock, ZeroCopyDatagram, ZeroCopyDatagramSocket, ZeroCopyNet,
};

/// Maximum whole-buffer datagram payload on shared-buffer network links.
pub const MAX_DATAGRAM_PAYLOAD: usize = 65_535;

/// Access granted to the receiving owner of a whole buffer.
#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantAccess {
    /// Permits payload reads only.
    ReadOnly = 0,
    /// Permits exclusive reads and writes.
    ReadWrite = 1,
}

/// The physical device's permitted access to a submitted payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAccess {
    /// A disk write or transmit reads the payload.
    Read,
    /// A disk read or receive writes the payload.
    Write,
}

/// Startup-selected Ethernet device using whole-buffer grant handoffs.
#[derive(Clone, Copy, Debug)]
pub struct SharedNetInfo {
    /// Host-authorized private NIC connection.
    pub connection: u64,
    /// Ethernet hardware address.
    pub mac: [u8; 6],
    /// Maximum Ethernet bytes, including link header and excluding FCS.
    pub max_frame: usize,
    /// Virtual interrupt line for data and recycled-buffer notifications.
    pub irq: u8,
}

/// Validated metadata preceding an Ethernet frame in an exclusive grant.
/// A delivery with zero useful payload returns an empty reusable allocation.
#[derive(Clone, Copy, Debug)]
pub struct SharedNetHeader {
    /// Versioned magic plus the optional native-packet copy flag.
    flags: u32,
    /// First Ethernet byte, counted from the allocation start.
    frame_offset: u32,
    /// Number of Ethernet bytes, including its link header.
    frame_len: u32,
}

impl SharedNetHeader {
    /// Returns the first Ethernet byte relative to the allocation.
    pub fn frame_offset(&self) -> usize {
        self.frame_offset as usize
    }

    /// Returns the number of Ethernet bytes, including the link header.
    pub fn frame_len(&self) -> usize {
        self.frame_len as usize
    }

    /// Fixed wire metadata length.
    pub const SIZE: usize = 12;
    /// Protocol identity and version; low bit reports a payload copy.
    pub const MAGIC: u32 = 0x534e_0100;
    /// The Image converted an ordinary native packet by copying its payload.
    pub const COPIED: u32 = 1;
    /// Maximum Ethernet frame, excluding FCS.
    pub const MAX_FRAME: usize = 1514;

    /// Constructs bounded metadata; allocation and payload bounds are checked by receipt.
    pub fn new(offset: usize, len: usize, copied: bool) -> Option<Self> {
        if offset < Self::SIZE || !(14..=Self::MAX_FRAME).contains(&len) {
            return None;
        }
        Some(Self {
            flags: Self::MAGIC | u32::from(copied),
            frame_offset: offset.try_into().ok()?,
            frame_len: len as u32,
        })
    }

    /// Encodes scalar metadata without borrowing or copying Ethernet bytes.
    pub fn encode(self) -> [u8; Self::SIZE] {
        let mut bytes = [0; Self::SIZE];
        bytes[..4].copy_from_slice(&self.flags.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.frame_offset.to_le_bytes());
        bytes[8..].copy_from_slice(&self.frame_len.to_le_bytes());
        bytes
    }

    /// Rejects unknown versions, flags, and impossible frame lengths.
    pub fn decode(bytes: [u8; Self::SIZE]) -> Option<Self> {
        let header = Self {
            flags: u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            frame_offset: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            frame_len: u32::from_le_bytes(bytes[8..].try_into().unwrap()),
        };
        if header.flags & !Self::COPIED != Self::MAGIC {
            return None;
        }
        Self::new(
            header.frame_offset as usize,
            header.frame_len as usize,
            header.copied(),
        )
    }

    /// Reports the explicitly recorded native-packet conversion.
    pub fn copied(self) -> bool {
        self.flags & Self::COPIED != 0
    }
}

/// A Host-authorized network link, separate from copying VirtIO devices.
#[derive(Clone, Copy, Debug)]
pub struct ZeroCopyNetInfo {
    /// Opaque connection identity, assigned while both participants are live.
    pub connection: u64,
    /// Maximum useful bytes in a datagram, excluding allocation padding.
    pub max_payload: usize,
}

/// Immutable properties of a separately attached zero-copy block device.
#[derive(Clone, Copy, Debug)]
pub struct ZeroCopyBlockInfo {
    /// Device size in bytes.
    pub capacity_bytes: u64,
    /// Whether disk writes are forbidden.
    pub read_only: bool,
}

impl ZeroCopyBlockInfo {
    /// Checks transfer bounds and direction before ending a local grant.
    pub(crate) fn permits(&self, offset: u64, len: usize, access: DeviceAccess) -> bool {
        use super::abi::buffer::{BLOCK_ALIGNMENT, MAX_CAPACITY};

        len != 0
            && len <= MAX_CAPACITY
            && len.is_multiple_of(BLOCK_ALIGNMENT)
            && offset.is_multiple_of(BLOCK_ALIGNMENT as u64)
            && offset
                .checked_add(len as u64)
                .is_some_and(|end| end <= self.capacity_bytes)
            && (!self.read_only || access == DeviceAccess::Write)
    }
}
