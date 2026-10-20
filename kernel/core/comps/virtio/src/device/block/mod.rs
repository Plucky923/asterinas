// SPDX-License-Identifier: MPL-2.0

pub mod device;

use core::mem::offset_of;

use aster_util::safe_ptr::SafePtr;
use bitflags::bitflags;
use int_to_c_enum::TryFromInt;
use ostd_pod::FromZeros;

use crate::transport::{ConfigGeneration, ConfigManager, VirtioTransport};

pub const DEVICE_NAME: &str = "Virtio-Block";

bitflags! {
    /// features for virtio block device
    struct BlockFeatures : u64 {
        const BARRIER       = 1 << 0;
        const SIZE_MAX      = 1 << 1;
        const SEG_MAX       = 1 << 2;
        const GEOMETRY      = 1 << 4;
        const RO            = 1 << 5;
        const BLK_SIZE      = 1 << 6;
        const SCSI          = 1 << 7;
        const FLUSH         = 1 << 9;
        const TOPOLOGY      = 1 << 10;
        const CONFIG_WCE    = 1 << 11;
        const MQ            = 1 << 12;
        const DISCARD       = 1 << 13;
        const WRITE_ZEROES  = 1 << 14;

        const ALL_SUPPORTED = Self::BLK_SIZE.bits() | Self::FLUSH.bits();
    }
}

impl BlockFeatures {
    pub(super) fn negotiated_with_device(device_features: u64) -> Self {
        BlockFeatures::from_bits_truncate(device_features) & Self::ALL_SUPPORTED
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, TryFromInt)]
enum ReqType {
    In = 0,
    Out = 1,
    Flush = 4,
    GetId = 8,
    Discard = 11,
    WriteZeroes = 13,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, TryFromInt)]
enum RespStatus {
    /// Ok.
    Ok = 0,
    /// IoErr.
    IoErr = 1,
    /// Unsupported yet.
    Unsupported = 2,
    /// Not ready.
    _NotReady = 3,
}

#[padding_struct]
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct VirtioBlockConfig {
    /// The number of 512-byte sectors.
    capacity: u64,
    /// The maximum segment size.
    size_max: u32,
    /// The maximum number of segments.
    seg_max: u32,
    /// The geometry of the device.
    geometry: VirtioBlockGeometry,
    /// The block size. If `logical_block_size` is not given in qemu cmdline,
    /// `blk_size` will be set to sector size (512 bytes) by default.
    blk_size: u32,
    /// The topology of the device.
    topology: VirtioBlockTopology,
    /// Writeback mode.
    writeback: u8,
    unused0: u8,
    /// The number of virtqueues.
    num_queues: u16,
    /// The maximum discard sectors for one segment.
    max_discard_sectors: u32,
    /// The maximum number of discard segments in a discard command.
    max_discard_seg: u32,
    /// Discard commands must be aligned to this number of sectors.
    discard_sector_alignment: u32,
    /// The maximum number of write zeroes sectors in one segment.
    max_write_zeroes_sectors: u32,
    /// The maximum number of segments in a write zeroes command.
    max_write_zeroes_seg: u32,
    /// Set if a write zeroes command may result in the
    /// deallocation of one or more of the sectors.
    write_zeros_may_unmap: u8,
    unused1: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct VirtioBlockGeometry {
    cylinders: u16,
    heads: u8,
    sectors: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Pod)]
struct VirtioBlockTopology {
    /// Exponent for physical block per logical block.
    physical_block_exp: u8,
    /// Alignment offset in logical blocks.
    alignment_offset: u8,
    /// Minimum I/O size without performance penalty in logical blocks.
    min_io_size: u16,
    /// Optimal sustained I/O size in logical blocks.
    opt_io_size: u32,
}

impl VirtioBlockConfig {
    pub(self) fn new_manager(transport: &dyn VirtioTransport) -> BlockConfigManager {
        let safe_ptr = transport
            .device_config_mem()
            .map(|mem| SafePtr::new(mem, 0));
        let bar_space = transport.device_config_bar();

        BlockConfigManager {
            registers: ConfigManager::new(safe_ptr, bar_space),
            generation: transport.device_config_generation(),
        }
    }

    pub(self) const fn sector_size() -> usize {
        aster_block::SECTOR_SIZE
    }
}

#[derive(Debug)]
struct BlockConfigManager {
    registers: ConfigManager<VirtioBlockConfig>,
    generation: Option<ConfigGeneration>,
}

impl BlockConfigManager {
    pub(self) fn read_config(&self) -> VirtioBlockConfig {
        let mut blk_config = VirtioBlockConfig::new_zeroed();
        // Only following fields are defined in legacy interface.
        blk_config.capacity = self.capacity_sectors() as u64;
        blk_config.size_max = self
            .registers
            .read_once::<u32>(offset_of!(VirtioBlockConfig, size_max))
            .unwrap();
        blk_config.seg_max = self
            .registers
            .read_once::<u32>(offset_of!(VirtioBlockConfig, seg_max))
            .unwrap();
        blk_config.geometry.cylinders = self
            .registers
            .read_once::<u16>(
                offset_of!(VirtioBlockConfig, geometry)
                    + offset_of!(VirtioBlockGeometry, cylinders),
            )
            .unwrap();
        blk_config.geometry.heads = self
            .registers
            .read_once::<u8>(
                offset_of!(VirtioBlockConfig, geometry) + offset_of!(VirtioBlockGeometry, heads),
            )
            .unwrap();
        blk_config.geometry.sectors = self
            .registers
            .read_once::<u8>(
                offset_of!(VirtioBlockConfig, geometry) + offset_of!(VirtioBlockGeometry, sectors),
            )
            .unwrap();
        blk_config.blk_size = self
            .registers
            .read_once::<u32>(offset_of!(VirtioBlockConfig, blk_size))
            .unwrap();

        if self.registers.is_modern() {
            // TODO: read more field if modern interface exists.
        }

        blk_config
    }

    pub(self) fn block_size(&self) -> usize {
        self.registers
            .read_once::<u32>(offset_of!(VirtioBlockConfig, blk_size))
            .unwrap() as usize
    }

    pub(self) fn capacity_sectors(&self) -> usize {
        read_config_consistently(
            || {
                self.generation
                    .as_ref()
                    .map(|generation| generation.read().unwrap())
            },
            || {
                let cap_low = self
                    .registers
                    .read_once::<u32>(offset_of!(VirtioBlockConfig, capacity))
                    .unwrap() as usize;
                let cap_high = self
                    .registers
                    .read_once::<u32>(offset_of!(VirtioBlockConfig, capacity) + 4)
                    .unwrap() as usize;
                (cap_high << 32) | cap_low
            },
        )
    }
}

/// Reads one device configuration snapshot, retrying a concurrent update.
fn read_config_consistently<T: PartialEq>(
    mut generation_fn: impl FnMut() -> Option<u32>,
    mut read_fn: impl FnMut() -> T,
) -> T {
    loop {
        let before = generation_fn();
        let value = read_fn();
        // Modern transports have a generation register. Legacy capacity
        // fields instead require two consecutive reads with equal values.
        let consistent = match before {
            Some(generation) => generation_fn() == Some(generation),
            None => value == read_fn(),
        };
        if consistent {
            return value;
        }
    }
}

#[cfg(ktest)]
mod tests {
    use core::cell::Cell;

    use ostd::prelude::*;

    use super::*;

    #[ktest]
    fn block_capacity_retries_a_split_read_when_generation_changes() {
        let capacity = Cell::new(0xffff_fff0u64);
        let generation = Cell::new(1u32);
        let reads = Cell::new(0);
        let result = read_config_consistently(
            || Some(generation.get()),
            || {
                let low = capacity.get() as u32 as u64;
                if reads.get() == 0 {
                    capacity.set(0x1_0000_0010);
                    generation.set(2);
                }
                reads.set(reads.get() + 1);
                (capacity.get() & !0xffff_ffff) | low
            },
        );
        assert_eq!(result, 0x1_0000_0010);
        assert_eq!(reads.get(), 2);
    }

    #[ktest]
    fn legacy_block_capacity_requires_consecutive_equal_reads() {
        let reads = Cell::new(0);
        let result = read_config_consistently(
            || None,
            || {
                reads.set(reads.get() + 1);
                if reads.get() == 1 {
                    0x1_ffff_fff0u64
                } else {
                    0x1_0000_0010
                }
            },
        );
        assert_eq!(result, 0x1_0000_0010);
        assert_eq!(reads.get(), 4);
    }
}
