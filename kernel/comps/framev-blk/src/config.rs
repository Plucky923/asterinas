// SPDX-License-Identifier: MPL-2.0

//! FrameV-blk configuration.

use core::ops::{BitOr, BitOrAssign};

use crate::FRAMEV_BLK_SECTOR_SIZE;

/// FrameV-blk configuration flags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameVBlkConfigFlags(u32);

impl FrameVBlkConfigFlags {
    /// No optional behavior is enabled.
    pub const EMPTY: Self = Self(0);
    /// The device rejects write requests.
    pub const READONLY: Self = Self(1 << 0);

    /// The device supports flush requests.
    pub const FLUSH: Self = Self(1 << 1);

    const KNOWN: u32 = Self::READONLY.0 | Self::FLUSH.0;

    /// Creates validated config flags.
    pub const fn new(raw: u32) -> Result<Self, FrameVBlkConfigError> {
        if raw & !Self::KNOWN != 0 {
            return Err(FrameVBlkConfigError::UnknownFlags(raw & !Self::KNOWN));
        }
        Ok(Self(raw))
    }

    /// Returns the raw bits for the wire/configuration boundary.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns whether the device is readonly.
    pub const fn readonly(self) -> bool {
        self.0 & Self::READONLY.0 != 0
    }
}

impl BitOr for FrameVBlkConfigFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for FrameVBlkConfigFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// A validated FrameV-blk configuration.
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
        flags: FrameVBlkConfigFlags,
    ) -> Result<Self, FrameVBlkConfigError> {
        if capacity_sectors == 0 {
            return Err(FrameVBlkConfigError::ZeroCapacity);
        }
        if logical_block_size != FRAMEV_BLK_SECTOR_SIZE as u32 {
            return Err(FrameVBlkConfigError::InvalidLogicalBlockSize(
                logical_block_size,
            ));
        }
        Ok(Self {
            capacity_sectors,
            logical_block_size,
            flags: flags.0,
        })
    }

    /// Creates a validated configuration from raw wire flags.
    pub const fn from_bits(
        capacity_sectors: u64,
        logical_block_size: u32,
        flags: u32,
    ) -> Result<Self, FrameVBlkConfigError> {
        let flags = match FrameVBlkConfigFlags::new(flags) {
            Ok(flags) => flags,
            Err(err) => return Err(err),
        };
        Self::new(capacity_sectors, logical_block_size, flags)
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
