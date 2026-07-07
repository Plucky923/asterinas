// SPDX-License-Identifier: MPL-2.0

//! FrameV-blk device metadata.

use framev_device::{FrameVDeviceId, FrameVDeviceInfo, FrameVDeviceType, IrqLine, well_known};

/// The fixed FrameV-blk sector size in bytes.
pub const FRAMEV_BLK_SECTOR_SIZE: u64 = 512;

/// The fixed v1 queue count.
pub const FRAMEV_BLK_QUEUE_COUNT: u16 = 1;

/// The default `framev-blk` device ID.
pub const DEFAULT_DEVICE_ID: FrameVDeviceId = well_known::DEFAULT_BLOCK_DEVICE_ID;

/// The default `framev-blk` software IRQ line.
pub const DEFAULT_IRQ_LINE: IrqLine = IrqLine::new(4);

/// Returns the default `framev-blk` device metadata.
pub const fn default_device_info() -> FrameVDeviceInfo {
    FrameVDeviceInfo::new(DEFAULT_DEVICE_ID, FrameVDeviceType::Block, DEFAULT_IRQ_LINE)
}

/// FrameV-blk v1 metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameVBlkDeviceMetadata {
    capacity_sectors: u64,
    logical_block_size: u32,
    queue_count: u16,
}

impl FrameVBlkDeviceMetadata {
    /// Creates FrameV-blk metadata.
    pub const fn new(capacity_sectors: u64) -> Self {
        Self {
            capacity_sectors,
            logical_block_size: FRAMEV_BLK_SECTOR_SIZE as u32,
            queue_count: FRAMEV_BLK_QUEUE_COUNT,
        }
    }

    /// Returns capacity in 512-byte sectors.
    pub const fn capacity_sectors(self) -> u64 {
        self.capacity_sectors
    }

    /// Returns the logical block size in bytes.
    pub const fn logical_block_size(self) -> u32 {
        self.logical_block_size
    }

    /// Returns the number of request queues.
    pub const fn queue_count(self) -> u16 {
        self.queue_count
    }
}
