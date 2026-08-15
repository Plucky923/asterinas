// SPDX-License-Identifier: MPL-2.0

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use framev_blk_common::{
    FRAMEV_BLK_MAX_EXTENTS, FRAMEV_BLK_SECTOR_SIZE, FrameVBlkConfig, FrameVBlkConfigFlags,
    FrameVBlkStatus,
};
use host_ostd::mm::{Fallible, Infallible, VmReader, VmWriter};

use super::state::FunctionRuntime;
use crate::{
    Error, Result,
    sync::{SpinLock, WaitQueue},
};

/// Maximum number of memory extents accepted by one block operation.
pub const MAX_BLOCK_EXTENTS: usize = FRAMEV_BLK_MAX_EXTENTS;

/// Error returned by a raw block image backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockImageError {
    /// The backend returned fewer bytes than requested for a read.
    ShortRead {
        offset_bytes: u64,
        requested_bytes: usize,
        actual_bytes: usize,
    },
    /// The backend wrote fewer bytes than requested.
    ShortWrite {
        offset_bytes: u64,
        requested_bytes: usize,
        actual_bytes: usize,
    },
    /// The backend rejected a write because the image is readonly.
    Readonly,
    /// The backend reported an I/O failure while reading or writing.
    Io,
    /// The backend reported an I/O failure while flushing durable state.
    Flush,
}

/// Memory extents containing bytes sent to a block device.
///
/// Construction validates the complete scatter/gather shape once. The private
/// fields preserve that validation across the FrameVM-to-FrameVisor call.
pub struct BlockSources<'a> {
    readers: Vec<VmReader<'a, Fallible>>,
    byte_len: usize,
}

impl<'a> BlockSources<'a> {
    /// Creates sector-aligned source extents for one block operation.
    pub fn new(readers: Vec<VmReader<'a, Infallible>>) -> Result<Self> {
        let byte_len = validate_extents(readers.iter().map(VmReader::remain))?;
        Ok(Self {
            readers: readers.into_iter().map(VmReader::to_fallible).collect(),
            byte_len,
        })
    }

    /// Returns the validated total byte length.
    pub fn byte_len(&self) -> usize {
        self.byte_len
    }

    /// Returns the source cursors to the image backend.
    pub fn readers_mut(&mut self) -> &mut [VmReader<'a, Fallible>] {
        &mut self.readers
    }
}

/// Memory extents that receive bytes read from a block device.
///
/// Construction validates the complete scatter/gather shape once. The private
/// fields preserve that validation across the FrameVM-to-FrameVisor call.
pub struct BlockDestinations<'a> {
    writers: Vec<VmWriter<'a, Fallible>>,
    byte_len: usize,
}

impl<'a> BlockDestinations<'a> {
    /// Creates sector-aligned destination extents for one block operation.
    pub fn new(writers: Vec<VmWriter<'a, Infallible>>) -> Result<Self> {
        let byte_len = validate_extents(writers.iter().map(VmWriter::avail))?;
        Ok(Self {
            writers: writers.into_iter().map(VmWriter::to_fallible).collect(),
            byte_len,
        })
    }

    /// Returns the validated total byte length.
    pub fn byte_len(&self) -> usize {
        self.byte_len
    }

    /// Returns the destination cursors to the image backend.
    pub fn writers_mut(&mut self) -> &mut [VmWriter<'a, Fallible>] {
        &mut self.writers
    }
}

fn validate_extents(lengths: impl Iterator<Item = usize>) -> Result<usize> {
    let mut extent_count = 0;
    let mut byte_len = 0_usize;
    for length in lengths {
        extent_count += 1;
        if extent_count > MAX_BLOCK_EXTENTS
            || length == 0
            || !(length as u64).is_multiple_of(FRAMEV_BLK_SECTOR_SIZE)
        {
            return Err(Error::InvalidArgs);
        }
        byte_len = byte_len.checked_add(length).ok_or(Error::InvalidArgs)?;
    }
    if extent_count == 0 {
        return Err(Error::InvalidArgs);
    }
    Ok(byte_len)
}

/// Raw byte-addressed image used by the FrameV block backend.
///
/// FrameV-blk validates sector units and the complete SG shape before calling
/// this trait. Implementations transfer directly between image storage and the
/// supplied cursors; they must not create a payload-sized staging buffer.
pub trait BlockImage: Send + Sync {
    /// Reads exactly all destination bytes at `offset_bytes`.
    fn read_exact_at(
        &self,
        offset_bytes: u64,
        destinations: &mut BlockDestinations<'_>,
    ) -> core::result::Result<(), BlockImageError>;

    /// Writes exactly all source bytes at `offset_bytes`.
    fn write_all_at(
        &self,
        offset_bytes: u64,
        sources: &mut BlockSources<'_>,
    ) -> core::result::Result<(), BlockImageError>;

    /// Flushes all previously completed writes to the backend durability boundary.
    fn flush(&self) -> core::result::Result<(), BlockImageError>;

    /// Returns the raw image capacity in bytes.
    fn capacity_bytes(&self) -> u64;

    /// Returns whether writes must be rejected before mutating the image.
    fn readonly(&self) -> bool;
}

/// Typed host handle for one VM's FrameV block backend.
pub struct Block {
    runtime: Arc<FunctionRuntime>,
    image: Arc<dyn BlockImage>,
    config: FrameVBlkConfig,
    operation_sequence: OperationSequence,
}

impl Block {
    pub(super) fn config_for_image(image: &dyn BlockImage) -> Result<FrameVBlkConfig> {
        let capacity_bytes = image.capacity_bytes();
        if capacity_bytes == 0 || !capacity_bytes.is_multiple_of(FRAMEV_BLK_SECTOR_SIZE) {
            return Err(Error::InvalidArgs);
        }

        let mut flags = FrameVBlkConfigFlags::FLUSH;
        if image.readonly() {
            flags |= FrameVBlkConfigFlags::READONLY;
        }
        FrameVBlkConfig::new(
            capacity_bytes / FRAMEV_BLK_SECTOR_SIZE,
            FRAMEV_BLK_SECTOR_SIZE as u32,
            flags,
        )
        .map_err(|_| Error::InvalidArgs)
    }

    pub(super) fn new(
        runtime: Arc<FunctionRuntime>,
        image: Arc<dyn BlockImage>,
        config: FrameVBlkConfig,
    ) -> Self {
        Self {
            runtime,
            image,
            config,
            operation_sequence: OperationSequence::new(),
        }
    }

    pub(super) fn runtime(&self) -> &FunctionRuntime {
        &self.runtime
    }

    /// Returns the backend-authoritative FrameV-blk configuration.
    pub fn config(&self) -> FrameVBlkConfig {
        self.config
    }

    /// Reads one validated SG operation from the image.
    pub fn read(&self, sector: u64, destinations: &mut BlockDestinations<'_>) -> FrameVBlkStatus {
        let Some(offset_bytes) = self.validate_range(sector, destinations.byte_len()) else {
            return FrameVBlkStatus::IoErr;
        };
        let Some(_turn) = self.operation_sequence.enter() else {
            return FrameVBlkStatus::IoErr;
        };
        match self.image.read_exact_at(offset_bytes, destinations) {
            Ok(()) => FrameVBlkStatus::Ok,
            Err(_) => FrameVBlkStatus::IoErr,
        }
    }

    /// Writes one validated SG operation to the image.
    pub fn write(&self, sector: u64, sources: &mut BlockSources<'_>) -> FrameVBlkStatus {
        if self.config.flags().readonly() {
            return FrameVBlkStatus::IoErr;
        }
        let Some(offset_bytes) = self.validate_range(sector, sources.byte_len()) else {
            return FrameVBlkStatus::IoErr;
        };
        let Some(_turn) = self.operation_sequence.enter() else {
            return FrameVBlkStatus::IoErr;
        };
        match self.image.write_all_at(offset_bytes, sources) {
            Ok(()) => FrameVBlkStatus::Ok,
            Err(_) => FrameVBlkStatus::IoErr,
        }
    }

    /// Flushes all earlier operations in the same FIFO sequence.
    pub fn flush(&self) -> FrameVBlkStatus {
        let Some(_turn) = self.operation_sequence.enter() else {
            return FrameVBlkStatus::IoErr;
        };
        match self.image.flush() {
            Ok(()) => FrameVBlkStatus::Ok,
            Err(_) => FrameVBlkStatus::IoErr,
        }
    }

    fn validate_range(&self, sector: u64, byte_len: usize) -> Option<u64> {
        let offset_bytes = sector.checked_mul(FRAMEV_BLK_SECTOR_SIZE)?;
        let end = offset_bytes.checked_add(u64::try_from(byte_len).ok()?)?;
        (end <= self.image.capacity_bytes()).then_some(offset_bytes)
    }
}

struct OperationSequence {
    state: SpinLock<OperationSequenceState>,
}

struct OperationSequenceState {
    next_ticket: u64,
    current_ticket: u64,
    waiters: VecDeque<(u64, Arc<WaitQueue>)>,
}

impl OperationSequence {
    const fn new() -> Self {
        Self {
            state: SpinLock::new(OperationSequenceState {
                next_ticket: 0,
                current_ticket: 0,
                waiters: VecDeque::new(),
            }),
        }
    }

    fn enter(&self) -> Option<OperationTurn<'_>> {
        let (ticket, wait_queue) = {
            let mut state = self.state.lock();
            let ticket = state.next_ticket;
            state.next_ticket = state.next_ticket.checked_add(1)?;
            let wait_queue = if ticket == state.current_ticket {
                None
            } else {
                let wait_queue = Arc::new(WaitQueue::new());
                state.waiters.push_back((ticket, wait_queue.clone()));
                Some(wait_queue)
            };
            (ticket, wait_queue)
        };
        if let Some(wait_queue) = wait_queue {
            wait_queue.wait_until(|| {
                let state = self.state.lock();
                (state.current_ticket == ticket).then_some(())
            });
        }
        Some(OperationTurn {
            sequence: self,
            ticket,
        })
    }
}

struct OperationTurn<'a> {
    sequence: &'a OperationSequence,
    ticket: u64,
}

impl Drop for OperationTurn<'_> {
    fn drop(&mut self) {
        let mut state = self.sequence.state.lock();
        debug_assert_eq!(state.current_ticket, self.ticket);
        state.current_ticket = state
            .current_ticket
            .checked_add(1)
            .expect("block operation ticket cannot overflow after admission");
        let next_waiter = state.waiters.pop_front().map(|(ticket, waiter)| {
            debug_assert_eq!(ticket, state.current_ticket);
            waiter
        });
        drop(state);
        if let Some(waiter) = next_waiter {
            waiter.wake_one();
        }
    }
}

#[cfg(ktest)]
mod tests {
    use alloc::vec;

    use host_ostd::{mm::FallibleVmWrite, prelude::ktest};

    use super::*;

    #[ktest]
    fn extent_validation_rejects_empty_unaligned_and_excessive_sg() {
        assert_eq!(
            validate_extents(core::iter::empty()),
            Err(Error::InvalidArgs)
        );
        assert_eq!(validate_extents([511].into_iter()), Err(Error::InvalidArgs));
        assert_eq!(
            validate_extents(core::iter::repeat_n(512, MAX_BLOCK_EXTENTS + 1)),
            Err(Error::InvalidArgs)
        );
        assert_eq!(validate_extents(vec![512, 1024].into_iter()), Ok(1536));
    }

    #[ktest]
    fn uncontended_operation_sequence_does_not_enqueue_waiter() {
        let sequence = OperationSequence::new();
        let turn = sequence.enter().unwrap();

        assert!(sequence.state.lock().waiters.is_empty());
        drop(turn);

        assert!(sequence.state.lock().waiters.is_empty());
    }

    struct PatternImage;

    impl BlockImage for PatternImage {
        fn read_exact_at(
            &self,
            _offset_bytes: u64,
            destinations: &mut BlockDestinations<'_>,
        ) -> core::result::Result<(), BlockImageError> {
            let pattern = [0x5a; FRAMEV_BLK_SECTOR_SIZE as usize];
            for writer in destinations.writers_mut() {
                let written = writer
                    .write_fallible(&mut VmReader::from(pattern.as_slice()))
                    .map_err(|_| BlockImageError::Io)?;
                if written != pattern.len() {
                    return Err(BlockImageError::Io);
                }
            }
            Ok(())
        }

        fn write_all_at(
            &self,
            _offset_bytes: u64,
            _sources: &mut BlockSources<'_>,
        ) -> core::result::Result<(), BlockImageError> {
            Ok(())
        }

        fn flush(&self) -> core::result::Result<(), BlockImageError> {
            Ok(())
        }

        fn capacity_bytes(&self) -> u64 {
            FRAMEV_BLK_SECTOR_SIZE * 2
        }

        fn readonly(&self) -> bool {
            false
        }
    }

    #[ktest]
    fn scatter_read_mutates_original_backing() {
        let mut first = [0; FRAMEV_BLK_SECTOR_SIZE as usize];
        let mut second = [0; FRAMEV_BLK_SECTOR_SIZE as usize];
        let writers = vec![
            VmWriter::from(first.as_mut_slice()),
            VmWriter::from(second.as_mut_slice()),
        ];
        let mut destinations = BlockDestinations::new(writers).unwrap();

        PatternImage.read_exact_at(0, &mut destinations).unwrap();
        drop(destinations);

        assert!(first.iter().all(|byte| *byte == 0x5a));
        assert!(second.iter().all(|byte| *byte == 0x5a));
    }
}
