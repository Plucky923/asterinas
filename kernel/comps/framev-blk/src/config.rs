// SPDX-License-Identifier: MPL-2.0

//! FrameV-blk v1 configuration.

use crate::metadata::FRAMEV_BLK_SECTOR_SIZE;

/// FrameV-blk configuration flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameVBlkConfigFlags(u32);

impl FrameVBlkConfigFlags {
    /// The device rejects write requests.
    pub const READONLY: u32 = 1 << 0;

    /// The device supports flush requests.
    pub const FLUSH: u32 = 1 << 1;

    const KNOWN: u32 = Self::READONLY | Self::FLUSH;

    /// Creates validated config flags.
    pub const fn new(raw: u32) -> Result<Self, FrameVBlkConfigError> {
        if raw & !Self::KNOWN != 0 {
            return Err(FrameVBlkConfigError::UnknownFlags(raw & !Self::KNOWN));
        }
        Ok(Self(raw))
    }

    /// Returns raw flag bits.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Returns whether the device is readonly.
    pub const fn readonly(self) -> bool {
        self.0 & Self::READONLY != 0
    }

    /// Returns whether the device supports flush.
    pub const fn flush_supported(self) -> bool {
        self.0 & Self::FLUSH != 0
    }
}

/// A validated FrameV-blk v1 configuration.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameVBlkConfig {
    capacity_sectors: u64,
    logical_block_size: u32,
    flags: u32,
}

impl FrameVBlkConfig {
    /// Creates a validated FrameV-blk configuration.
    pub const fn new(
        capacity_sectors: u64,
        logical_block_size: u32,
        flags: u32,
    ) -> Result<Self, FrameVBlkConfigError> {
        if capacity_sectors == 0 {
            return Err(FrameVBlkConfigError::ZeroCapacity);
        }
        if logical_block_size != FRAMEV_BLK_SECTOR_SIZE as u32 {
            return Err(FrameVBlkConfigError::InvalidLogicalBlockSize(
                logical_block_size,
            ));
        }
        let flags = match FrameVBlkConfigFlags::new(flags) {
            Ok(flags) => flags,
            Err(err) => return Err(err),
        };
        Ok(Self {
            capacity_sectors,
            logical_block_size,
            flags: flags.raw(),
        })
    }

    /// Returns capacity in 512-byte sectors.
    pub const fn capacity_sectors(self) -> u64 {
        self.capacity_sectors
    }

    /// Returns the logical block size in bytes.
    pub const fn logical_block_size(self) -> u32 {
        self.logical_block_size
    }

    /// Returns validated config flags.
    pub const fn flags(self) -> FrameVBlkConfigFlags {
        // SAFETY BY CONSTRUCTION: `FrameVBlkConfig` is created only after flag validation.
        FrameVBlkConfigFlags(self.flags)
    }
}

/// FrameV-blk configuration validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVBlkConfigError {
    InvalidLogicalBlockSize(u32),
    UnknownFlags(u32),
    ZeroCapacity,
}
