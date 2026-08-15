// SPDX-License-Identifier: MPL-2.0

//! FrameV block frontend provider for the FrameVM service.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::{string::String, sync::Arc, vec::Vec};
use core::{
    fmt,
    sync::atomic::{AtomicU32, Ordering},
};

use aster_block::{
    BlockDevice, BlockDeviceMeta, MajorIdOwner,
    bio::{BioEnqueueError, BioStatus, BioType, SubmittedBio, bio_segment_pool_init},
    request_queue::BioRequest,
};
use component::{ComponentInitError, init_component};
use device_id::{DeviceId, MinorId};
use framev_blk_common::{FrameVBlkConfig, FrameVBlkStatus};
use spin::Once;

/// Upper bound for one FrameV-blk BIO.
pub const FRAMEV_BLK_MAX_SEGMENTS_PER_BIO: usize = framev_blk_common::FRAMEV_BLK_MAX_EXTENTS;

const FRAMEV_BLK_DEVICE_NAME_PREFIX: &str = "framevblk";

static FRAMEV_BLK_MAJOR_ID: Once<MajorIdOwner> = Once::new();
static NR_FRAMEV_BLK_DEVICE: AtomicU32 = AtomicU32::new(0);

/// Service-side whole-disk FrameV block device.
pub struct FrameVBlkDevice {
    block: framev_pci::FrameVBlock,
    config: FrameVBlkConfig,
    id: DeviceId,
    name: String,
}

impl FrameVBlkDevice {
    fn new(block: framev_pci::FrameVBlock, config: FrameVBlkConfig) -> Self {
        let index = NR_FRAMEV_BLK_DEVICE.fetch_add(1, Ordering::Relaxed);
        let id = DeviceId::new(
            FRAMEV_BLK_MAJOR_ID
                .call_once(|| aster_block::allocate_major().unwrap())
                .get(),
            MinorId::new(index),
        );

        Self {
            block,
            config,
            id,
            name: alloc::format!("{FRAMEV_BLK_DEVICE_NAME_PREFIX}{index}"),
        }
    }

    fn handle_request(&self, request: BioRequest) {
        match request.type_() {
            BioType::Read | BioType::Write | BioType::Flush => {
                for bio in request.into_bios() {
                    let status = self.process_bio(&bio);
                    bio.complete(status);
                }
            }
        }
    }

    fn process_bio(&self, bio: &SubmittedBio) -> BioStatus {
        match bio.type_() {
            BioType::Flush => self.flush_bio(),
            BioType::Read | BioType::Write => self.process_segment_bio(bio),
        }
    }

    fn process_segment_bio(&self, bio: &SubmittedBio) -> BioStatus {
        let Some(sector) = bio.sid_range().start.to_raw().checked_add(bio.sid_offset()) else {
            return BioStatus::IoError;
        };

        let status = match bio.type_() {
            BioType::Read => self.read_bio(sector, bio),
            BioType::Write => self.write_bio(sector, bio),
            BioType::Flush => unreachable!(),
        };
        match status {
            Ok(status) => bio_status(status),
            Err(()) => BioStatus::IoError,
        }
    }

    fn read_bio(&self, sector: u64, bio: &SubmittedBio) -> Result<FrameVBlkStatus, ()> {
        let writers = bio
            .segments()
            .iter()
            .map(|segment| segment.writer_for_device().map_err(|_| ()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut destinations = framev_pci::BlockDestinations::new(writers).map_err(|_| ())?;
        self.block.read(sector, &mut destinations).map_err(|_| ())
    }

    fn write_bio(&self, sector: u64, bio: &SubmittedBio) -> Result<FrameVBlkStatus, ()> {
        let readers = bio
            .segments()
            .iter()
            .map(|segment| segment.reader_for_device().map_err(|_| ()))
            .collect::<Result<Vec<_>, _>>()?;
        let mut sources = framev_pci::BlockSources::new(readers).map_err(|_| ())?;
        self.block.write(sector, &mut sources).map_err(|_| ())
    }

    fn flush_bio(&self) -> BioStatus {
        self.block
            .flush()
            .map(bio_status)
            .unwrap_or(BioStatus::IoError)
    }
}

impl fmt::Debug for FrameVBlkDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrameVBlkDevice")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl BlockDevice for FrameVBlkDevice {
    fn enqueue(&self, bio: SubmittedBio) -> Result<(), BioEnqueueError> {
        if bio.segments().len() > FRAMEV_BLK_MAX_SEGMENTS_PER_BIO {
            return Err(BioEnqueueError::TooBig);
        }

        self.handle_request(BioRequest::from(bio));
        Ok(())
    }

    fn metadata(&self) -> BlockDeviceMeta {
        BlockDeviceMeta {
            max_nr_segments_per_bio: FRAMEV_BLK_MAX_SEGMENTS_PER_BIO,
            nr_sectors: self.config.capacity_sectors() as usize,
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn id(&self) -> DeviceId {
        self.id
    }
}

#[init_component(kthread)]
fn init() -> Result<(), ComponentInitError> {
    init_for_framevm_component_profile()
}

/// Initializes the FrameV block frontend in the FrameVM component profile.
pub fn init_for_framevm_component_profile() -> Result<(), ComponentInitError> {
    NR_FRAMEV_BLK_DEVICE.store(0, Ordering::Relaxed);
    let blocks = framev_pci::blocks().map_err(|_| ComponentInitError::Unknown)?;
    for block in blocks {
        let config = block.config().map_err(|_| ComponentInitError::Unknown)?;
        let device = Arc::new(FrameVBlkDevice::new(block, config));
        aster_block::register(device).map_err(|_| ComponentInitError::Unknown)?;
    }
    bio_segment_pool_init();
    Ok(())
}

fn bio_status(status: FrameVBlkStatus) -> BioStatus {
    match status {
        FrameVBlkStatus::Ok => BioStatus::Complete,
        FrameVBlkStatus::IoErr => BioStatus::IoError,
        FrameVBlkStatus::Unsupported => BioStatus::NotSupported,
    }
}
