// SPDX-License-Identifier: MPL-2.0

//! FrameV block frontend provider for the FrameVM service.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::{string::String, sync::Arc, vec, vec::Vec};
use core::{
    fmt,
    sync::atomic::{AtomicU32, Ordering},
};

use aster_block::{
    BlockDevice, BlockDeviceMeta, MajorIdOwner,
    bio::{BioEnqueueError, BioStatus, BioType, SubmittedBio, bio_segment_pool_init},
    request_queue::{BioRequest, BioRequestSingleQueue},
};
use component::{ComponentInitError, init_component};
use device_id::{DeviceId, MinorId};
use framev_blk_common::{
    FRAMEV_BLK_SECTOR_SIZE, FrameVBlkBioStatusIntent, FrameVBlkConfig, FrameVBlkStatus,
};
use spin::Once;

/// Upper bound for one FrameV-blk BIO.
pub const FRAMEV_BLK_MAX_SEGMENTS_PER_BIO: usize = 32;

const FRAMEV_BLK_DEVICE_NAME: &str = "framevblk0";

static FRAMEV_BLK_MAJOR_ID: Once<MajorIdOwner> = Once::new();
static NR_FRAMEV_BLK_DEVICE: AtomicU32 = AtomicU32::new(0);

/// Service-side whole-disk FrameV block device.
pub struct FrameVBlkDevice {
    block: framev_bus::FrameVBlock,
    config: FrameVBlkConfig,
    queue: BioRequestSingleQueue,
    id: DeviceId,
    name: String,
}

impl FrameVBlkDevice {
    fn new(block: framev_bus::FrameVBlock, config: FrameVBlkConfig) -> Self {
        let index = NR_FRAMEV_BLK_DEVICE.fetch_add(1, Ordering::Relaxed);
        debug_assert_eq!(index, 0, "FrameV-blk v1 supports one whole disk");
        let id = DeviceId::new(
            FRAMEV_BLK_MAJOR_ID
                .call_once(|| aster_block::allocate_major().unwrap())
                .get(),
            MinorId::new(index),
        );

        Self {
            block,
            config,
            queue: BioRequestSingleQueue::with_max_nr_segments_per_bio(
                FRAMEV_BLK_MAX_SEGMENTS_PER_BIO + 1,
            ),
            id,
            name: String::from(FRAMEV_BLK_DEVICE_NAME),
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
        let Ok(segment_sectors) = self.validate_segment_bio(bio) else {
            return BioStatus::IoError;
        };

        for (segment, sector) in bio.segments().iter().zip(segment_sectors) {
            let status = match bio.type_() {
                BioType::Read => self.read_segment(sector, segment),
                BioType::Write => self.write_segment(sector, segment),
                BioType::Flush => unreachable!(),
            };
            if status != BioStatus::Complete {
                return status;
            }
        }

        BioStatus::Complete
    }

    fn validate_segment_bio(&self, bio: &SubmittedBio) -> Result<Vec<u64>, ()> {
        let Some(mut sector) = bio.sid_range().start.to_raw().checked_add(bio.sid_offset()) else {
            return Err(());
        };

        let mut segment_sectors = Vec::with_capacity(bio.segments().len());
        for segment in bio.segments() {
            let len_bytes = segment.nbytes();
            if len_bytes == 0 || !is_framev_blk_aligned(len_bytes) {
                return Err(());
            }
            let Some(next_sector) = next_sector(sector, len_bytes) else {
                return Err(());
            };
            if next_sector > self.config.capacity_sectors() {
                return Err(());
            }
            segment_sectors.push(sector);
            sector = next_sector;
        }

        Ok(segment_sectors)
    }

    fn read_segment(&self, sector: u64, segment: &aster_block::bio::BioSegment) -> BioStatus {
        let mut bytes = vec![0; segment.nbytes()];
        let status = match self.block.read(sector, &mut bytes) {
            Ok(status) => bio_status(status),
            Err(_) => BioStatus::IoError,
        };
        if status != BioStatus::Complete {
            return status;
        }
        if segment.write_from_device_bytes(&bytes).is_err() {
            return BioStatus::IoError;
        }
        BioStatus::Complete
    }

    fn write_segment(&self, sector: u64, segment: &aster_block::bio::BioSegment) -> BioStatus {
        let mut bytes = vec![0; segment.nbytes()];
        if segment.read_to_device_bytes(&mut bytes).is_err() {
            return BioStatus::IoError;
        }
        self.block
            .write(sector, &bytes)
            .map(bio_status)
            .unwrap_or(BioStatus::IoError)
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

        self.queue.enqueue(bio)?;
        let request = self.queue.dequeue();
        self.handle_request(request);
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
    let Some(block) = framev_bus::block().map_err(|_| ComponentInitError::Unknown)? else {
        return Ok(());
    };
    let config = block.config().map_err(|_| ComponentInitError::Unknown)?;
    let device = Arc::new(FrameVBlkDevice::new(block, config));
    aster_block::register(device).map_err(|_| ComponentInitError::Unknown)?;
    bio_segment_pool_init();
    Ok(())
}

fn next_sector(sector: u64, len_bytes: usize) -> Option<u64> {
    sector.checked_add((len_bytes as u64).checked_div(FRAMEV_BLK_SECTOR_SIZE)?)
}

fn is_framev_blk_aligned(len_bytes: usize) -> bool {
    (len_bytes as u64).is_multiple_of(FRAMEV_BLK_SECTOR_SIZE)
}

fn bio_status(status: FrameVBlkStatus) -> BioStatus {
    match status.bio_status_intent() {
        FrameVBlkBioStatusIntent::Complete => BioStatus::Complete,
        FrameVBlkBioStatusIntent::IoError => BioStatus::IoError,
        FrameVBlkBioStatusIntent::NotSupported => BioStatus::NotSupported,
    }
}
