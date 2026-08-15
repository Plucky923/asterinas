// SPDX-License-Identifier: MPL-2.0

//! FrameV PCI family configuration encoders and decoders.

use framev_blk_common::{FRAMEV_BLK_MAX_EXTENTS, FRAMEV_BLK_SECTOR_SIZE};
use framev_console_common::{MAX_INPUT_CHUNK_BYTES, QUEUED_INPUT_CAPACITY_BYTES};
use framev_net_common::{
    FRAMEV_NET_MAX_ETHERNET_FRAME_BYTES, FRAMEV_NET_MTU, FrameVNetConfig, FrameVNetConfigError,
};
use framev_rng_common::MAX_FILL_BYTES;

/// An invalid FrameV PCI family configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// A required numeric field is zero.
    ZeroValue,
    /// A numeric field is outside the accepted range.
    InvalidValue,
    /// A reserved byte is nonzero.
    ReservedNotZero,
    /// An encoded flag is unknown.
    UnknownFlags,
    /// A fixed revision-1 value does not match.
    InvalidFixedValue,
    /// An Ethernet address is zero or multicast.
    InvalidMacAddress,
}

fn reserved_is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Console function configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleConfig {
    /// Maximum bytes accepted by one input pull.
    pub max_input_chunk_bytes: u32,
    /// Maximum bytes queued for input.
    pub queued_input_capacity_bytes: u32,
}

impl ConsoleConfig {
    /// Encodes the exact revision-1 layout.
    pub fn encode(self) -> Result<[u8; 0x10], ConfigError> {
        if self.max_input_chunk_bytes == 0 || self.queued_input_capacity_bytes == 0 {
            return Err(ConfigError::ZeroValue);
        }
        if usize::try_from(self.max_input_chunk_bytes)
            .map_or(true, |value| value > MAX_INPUT_CHUNK_BYTES)
            || usize::try_from(self.queued_input_capacity_bytes)
                .map_or(true, |value| value > QUEUED_INPUT_CAPACITY_BYTES)
        {
            return Err(ConfigError::InvalidFixedValue);
        }
        let mut bytes = [0; 0x10];
        bytes[0..4].copy_from_slice(&self.max_input_chunk_bytes.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.queued_input_capacity_bytes.to_le_bytes());
        Ok(bytes)
    }

    /// Decodes and validates the exact revision-1 layout.
    pub fn decode(bytes: [u8; 0x10]) -> Result<Self, ConfigError> {
        if !reserved_is_zero(&bytes[8..]) {
            return Err(ConfigError::ReservedNotZero);
        }
        let config = Self {
            max_input_chunk_bytes: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            queued_input_capacity_bytes: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
        };
        config.encode()?;
        Ok(config)
    }
}

/// Entropy function configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RngConfig {
    /// Maximum bytes accepted by one fill call.
    pub max_fill_bytes: u32,
}

impl RngConfig {
    /// Encodes the exact revision-1 layout.
    pub fn encode(self) -> Result<[u8; 0x10], ConfigError> {
        if self.max_fill_bytes == 0 {
            return Err(ConfigError::ZeroValue);
        }
        if usize::try_from(self.max_fill_bytes).map_or(true, |value| value > MAX_FILL_BYTES) {
            return Err(ConfigError::InvalidFixedValue);
        }
        let mut bytes = [0; 0x10];
        bytes[0..4].copy_from_slice(&self.max_fill_bytes.to_le_bytes());
        Ok(bytes)
    }

    /// Decodes and validates the exact revision-1 layout.
    pub fn decode(bytes: [u8; 0x10]) -> Result<Self, ConfigError> {
        if !reserved_is_zero(&bytes[4..]) {
            return Err(ConfigError::ReservedNotZero);
        }
        let config = Self {
            max_fill_bytes: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        };
        config.encode()?;
        Ok(config)
    }
}

/// Block configuration flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockConfigFlags(u16);

impl BlockConfigFlags {
    /// No optional behavior is enabled.
    pub const EMPTY: Self = Self(0);
    /// The backend rejects writes.
    pub const READ_ONLY: Self = Self(1);

    /// Decodes known revision-1 flags.
    pub const fn from_bits(bits: u16) -> Result<Self, ConfigError> {
        if bits & !Self::READ_ONLY.0 != 0 {
            return Err(ConfigError::UnknownFlags);
        }
        Ok(Self(bits))
    }

    /// Returns the encoded bits.
    pub const fn bits(self) -> u16 {
        self.0
    }
}

/// Block function configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockConfig {
    /// Capacity in logical sectors.
    pub capacity_sectors: u64,
    /// Logical sector size in bytes.
    pub sector_size_bytes: u32,
    /// Maximum scatter/gather segment count.
    pub max_segments: u16,
    /// Immutable access flags.
    pub flags: BlockConfigFlags,
}

impl BlockConfig {
    /// Encodes the exact revision-1 layout.
    pub fn encode(self) -> Result<[u8; 0x20], ConfigError> {
        if self.capacity_sectors == 0 || self.max_segments == 0 {
            return Err(ConfigError::ZeroValue);
        }
        if self.sector_size_bytes != FRAMEV_BLK_SECTOR_SIZE as u32
            || self.max_segments != FRAMEV_BLK_MAX_EXTENTS as u16
        {
            return Err(ConfigError::InvalidFixedValue);
        }
        BlockConfigFlags::from_bits(self.flags.bits())?;
        let mut bytes = [0; 0x20];
        bytes[0..8].copy_from_slice(&self.capacity_sectors.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.sector_size_bytes.to_le_bytes());
        bytes[12..14].copy_from_slice(&self.max_segments.to_le_bytes());
        bytes[14..16].copy_from_slice(&self.flags.bits().to_le_bytes());
        Ok(bytes)
    }

    /// Decodes and validates the exact revision-1 layout.
    pub fn decode(bytes: [u8; 0x20]) -> Result<Self, ConfigError> {
        if !reserved_is_zero(&bytes[0x10..]) {
            return Err(ConfigError::ReservedNotZero);
        }
        let config = Self {
            capacity_sectors: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            sector_size_bytes: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            max_segments: u16::from_le_bytes(bytes[12..14].try_into().unwrap()),
            flags: BlockConfigFlags::from_bits(u16::from_le_bytes(
                bytes[14..16].try_into().unwrap(),
            ))?,
        };
        config.encode()?;
        Ok(config)
    }
}

/// Socket function configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SockConfig {
    /// Guest socket CID.
    pub guest_cid: u32,
    /// Number of per-vCPU receive queues and vectors.
    pub receive_queue_count: u16,
    /// Number of device-state event vectors.
    pub state_vector_count: u16,
    /// Maximum encoded packet bytes.
    pub max_packet_bytes: u32,
    /// Capacity of each receive queue.
    pub receive_queue_capacity: u32,
}

impl SockConfig {
    /// Maximum vCPU and receive-queue count in revision 1.
    pub const MAX_RECEIVE_QUEUES: u16 = 4;

    /// Encodes the exact revision-1 layout.
    pub fn encode(self) -> Result<[u8; 0x20], ConfigError> {
        if self.guest_cid == 0
            || self.receive_queue_count == 0
            || self.max_packet_bytes == 0
            || self.receive_queue_capacity == 0
        {
            return Err(ConfigError::ZeroValue);
        }
        if self.receive_queue_count > Self::MAX_RECEIVE_QUEUES || self.state_vector_count != 1 {
            return Err(ConfigError::InvalidValue);
        }
        let mut bytes = [0; 0x20];
        bytes[0..4].copy_from_slice(&self.guest_cid.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.receive_queue_count.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.state_vector_count.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.max_packet_bytes.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.receive_queue_capacity.to_le_bytes());
        Ok(bytes)
    }

    /// Decodes and validates the exact revision-1 layout.
    pub fn decode(bytes: [u8; 0x20]) -> Result<Self, ConfigError> {
        if !reserved_is_zero(&bytes[0x10..]) {
            return Err(ConfigError::ReservedNotZero);
        }
        let config = Self {
            guest_cid: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            receive_queue_count: u16::from_le_bytes(bytes[4..6].try_into().unwrap()),
            state_vector_count: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
            max_packet_bytes: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            receive_queue_capacity: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        };
        config.encode()?;
        Ok(config)
    }
}

/// Ethernet function configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetConfig {
    /// Immutable Ethernet address.
    pub mac_address: [u8; 6],
    /// Ethernet MTU, fixed to 1500 in revision 1.
    pub mtu: u16,
    /// Maximum complete Ethernet frame bytes.
    pub max_frame_bytes: u32,
    /// Maximum posted receive buffers.
    pub max_posted_receive_buffers: u32,
}

impl NetConfig {
    /// Revision-1 Ethernet MTU.
    pub const MTU: u16 = FRAMEV_NET_MTU;

    /// Revision-1 maximum untagged Ethernet frame length.
    pub const MAX_FRAME_BYTES: u32 = FRAMEV_NET_MAX_ETHERNET_FRAME_BYTES;

    /// Encodes the exact revision-1 layout.
    pub fn encode(self) -> Result<[u8; 0x10], ConfigError> {
        self.validate()?;
        let mut bytes = [0; 0x10];
        bytes[0..6].copy_from_slice(&self.mac_address);
        bytes[6..8].copy_from_slice(&self.mtu.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.max_frame_bytes.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.max_posted_receive_buffers.to_le_bytes());
        Ok(bytes)
    }

    /// Decodes and validates the exact revision-1 layout.
    pub fn decode(bytes: [u8; 0x10]) -> Result<Self, ConfigError> {
        let config = Self {
            mac_address: bytes[0..6].try_into().unwrap(),
            mtu: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
            max_frame_bytes: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            max_posted_receive_buffers: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        };
        config.encode()?;
        Ok(config)
    }

    fn validate(self) -> Result<(), ConfigError> {
        FrameVNetConfig::new(
            self.mac_address,
            self.mtu,
            self.max_frame_bytes,
            self.max_posted_receive_buffers,
        )
        .map(|_| ())
        .map_err(|error| match error {
            FrameVNetConfigError::InvalidMaximumFrameBytes(_)
            | FrameVNetConfigError::InvalidMtu(_) => ConfigError::InvalidFixedValue,
            FrameVNetConfigError::MulticastMacAddress | FrameVNetConfigError::ZeroMacAddress => {
                ConfigError::InvalidMacAddress
            }
            FrameVNetConfigError::ZeroReceiveBufferCapacity => ConfigError::ZeroValue,
        })
    }
}
