// SPDX-License-Identifier: MPL-2.0

//! Physical-block lifecycle management for a single ext2 inode.

mod block_ptr_tree;
mod indirect_block_manager;

use core::sync::atomic::{AtomicUsize, Ordering};

use aster_block::bio::BioCompleteFn;

pub(super) use self::block_ptr_tree::{BlockPtrTree, RawBlockPtrs};
use self::block_ptr_tree::{NewBlockInitialization, ResolvedBlockRange};
use super::io_range::IoRangeIter;
use crate::{
    fs::ext2::{fs::Ext2, prelude::*},
    vm::page_cache::{CachePage, PageWritebackBio, complete_page_writeback},
};

/// Matches the FrameV scatter/gather limit while bounding one BIO's descriptors.
const MAX_COALESCED_WRITEBACK_PAGES: usize = 32;

/// Bridges the inode's logical file view and the physical block device.
///
/// `InodeBlockManager` maintains the relationship between logical file
/// blocks, ext2 physical block addresses, and the page-cache view of file
/// contents. Sparse logical ranges are represented by absent block mappings,
/// while allocated ranges must remain consistent with the inode's
/// block-pointer tree.
#[derive(Debug)]
pub(super) struct InodeBlockManager {
    /// Translates logical file block indices to physical device block addresses and
    /// manages block allocation and truncation.
    block_ptr_tree: RwMutex<BlockPtrTree>,
    /// Cached `npages` bound for `PageCache`.
    npages: AtomicUsize,
    /// File system handle for indirect I/O and BIO submission.
    fs: Weak<Ext2>,
}

impl InodeBlockManager {
    /// Creates a new block manager wrapping the given block-pointer tree.
    pub(super) fn new(block_ptr_tree: BlockPtrTree, fs: Weak<Ext2>, npages: usize) -> Self {
        Self {
            block_ptr_tree: RwMutex::new(block_ptr_tree),
            npages: AtomicUsize::new(npages),
            fs,
        }
    }

    /// Returns a strong reference to the owning filesystem.
    pub(super) fn fs(&self) -> Result<Arc<Ext2>> {
        self.fs
            .upgrade()
            .ok_or_else(|| Error::with_message(Errno::EIO, "filesystem already dropped"))
    }

    /// Looks up a single logical block -> physical block.
    pub(super) fn lookup_block(&self, iblock: Iblock) -> Result<Option<Ext2Bid>> {
        let tree = self.block_ptr_tree.read();
        tree.lookup_block(iblock)
    }

    /// Returns a snapshot of the raw block pointer state.
    pub(super) fn raw_block_ptrs(&self) -> RawBlockPtrs {
        *self.block_ptr_tree.read().raw_block_ptrs()
    }

    /// Returns whether the block-pointer tree has uncommitted changes.
    pub(super) fn is_dirty(&self) -> bool {
        self.block_ptr_tree.read().is_dirty()
    }

    /// Clears the block-pointer dirty flag after writeback.
    pub(super) fn clear_dirty(&self) {
        self.block_ptr_tree.write().clear_dirty();
    }

    /// Creates an iterator over existing and hole block ranges.
    ///
    /// The returned iterator holds a read lock on the block-pointer tree for
    /// its entire lifetime. Callers should consume it promptly to avoid
    /// blocking concurrent allocations or truncations on this inode.
    pub(super) fn iter_io_ranges(&self, block_range: Range<Iblock>) -> IoRangeIter<'_> {
        let tree = self.block_ptr_tree.read();
        IoRangeIter::new(block_range, tree)
    }

    /// Truncates blocks to the new_size (best-effort).
    pub(super) fn truncate_to_byte_len(&self, new_size: usize) {
        let fs = match self.fs() {
            Ok(fs) => fs,
            Err(err) => {
                error!("truncate: failed to get fs reference, err: {:?}", err);
                return;
            }
        };
        let mut tree = self.block_ptr_tree.write();
        tree.truncate_to_byte_len(&fs, new_size)
    }

    /// Flushes all dirty cached indirect blocks to the device.
    pub(super) fn sync_indirect_blocks(&self) -> Result<()> {
        self.block_ptr_tree.write().sync_indirect_blocks()
    }

    /// Allocates missing data blocks that cover the requested logical block range.
    pub(super) fn allocate_range_blocks(&self, start_block: usize, end_block: usize) -> Result<()> {
        self.allocate_range_blocks_with_initialization(
            start_block,
            end_block,
            NewBlockInitialization::Storage,
        )
    }

    /// Allocates blocks whose real contents are staged in a writeback batch.
    fn allocate_writeback_blocks(&self, start_block: usize, end_block: usize) -> Result<()> {
        self.allocate_range_blocks_with_initialization(
            start_block,
            end_block,
            NewBlockInitialization::Writeback,
        )
    }

    fn allocate_range_blocks_with_initialization(
        &self,
        start_block: usize,
        end_block: usize,
        initialization: NewBlockInitialization,
    ) -> Result<()> {
        let fs = self.fs()?;
        let mut tree = self.block_ptr_tree.write();
        let mut current_block = start_block;
        while current_block < end_block {
            let iblock = Iblock::try_from(current_block)
                .map_err(|_| Error::with_message(Errno::EINVAL, "logical block number overflow"))?;
            let remaining = u32::try_from(end_block - current_block)
                .map_err(|_| Error::with_message(Errno::EINVAL, "block range length overflow"))?;

            let block_range = match initialization {
                NewBlockInitialization::Storage => {
                    tree.resolve_block_range(&fs, iblock, remaining)?
                }
                NewBlockInitialization::Writeback => {
                    tree.resolve_writeback_block_range(&fs, iblock, remaining)?
                }
            };
            match block_range {
                ResolvedBlockRange::Existing(range) => {
                    debug_assert!(!range.is_empty());
                    current_block += range.len();
                }
                ResolvedBlockRange::NewlyAllocated(range) => {
                    debug_assert!(!range.is_empty());
                    current_block += range.len();
                }
            }
        }
        Ok(())
    }

    /// Updates the cached page-cache capacity bound.
    pub(super) fn set_npages(&self, npages: usize) {
        self.npages.store(npages, Ordering::Release);
    }

    fn resolve_write_bid(&self, idx: usize, nblocks: usize, fs: &Ext2) -> Result<Ext2Bid> {
        if idx >= self.npages.load(Ordering::Acquire) {
            return_errno_with_message!(Errno::EINVAL, "invalid write size");
        }
        let iblock = Iblock::try_from(idx)
            .map_err(|_| Error::with_message(Errno::EINVAL, "logical block number overflow"))?;

        if let Some(bid) = self.lookup_block(iblock)? {
            return Ok(bid);
        }

        let nblocks = u32::try_from(nblocks)
            .map_err(|_| Error::with_message(Errno::EINVAL, "block range length overflow"))?;
        let mut tree = self.block_ptr_tree.write();
        let step = tree.resolve_block_range(fs, iblock, nblocks)?;
        Ok(match step {
            ResolvedBlockRange::NewlyAllocated(range) => range.start,
            ResolvedBlockRange::Existing(range) => range.start,
        })
    }
}

impl BlockAsPageCacheBackend for InodeBlockManager {
    fn writeback_batch_size(&self) -> Result<usize> {
        Ok(MAX_COALESCED_WRITEBACK_PAGES)
    }

    fn submit_read_bio(
        &self,
        idx: usize,
        bio_segment: BioSegment,
        complete_fn: BioCompleteFn,
        io_batch: &mut IoBatch,
    ) -> Result<()> {
        if idx >= self.npages.load(Ordering::Acquire) {
            return_errno_with_message!(Errno::EINVAL, "invalid read size");
        }
        let iblock = Iblock::try_from(idx)
            .map_err(|_| Error::with_message(Errno::EINVAL, "logical block number overflow"))?;
        match self.lookup_block(iblock)? {
            Some(bid) => {
                let fs = self.fs()?;
                fs.read_blocks_async(bid, bio_segment, Some(complete_fn), io_batch)
            }
            None => {
                // Encountered a hole, zero fill the page.
                complete_fn(BioStatus::Zeros);
                Ok(())
            }
        }
    }

    fn submit_write_bio(
        &self,
        idx: usize,
        bio_segment: BioSegment,
        complete_fn: BioCompleteFn,
        io_batch: &mut IoBatch,
    ) -> Result<()> {
        let fs = self.fs()?;
        let bid = self.resolve_write_bid(idx, bio_segment.nblocks(), &fs)?;
        fs.write_blocks_async(bid, bio_segment, Some(complete_fn), io_batch)
    }

    fn submit_write_bios(
        &self,
        mut writebacks: Vec<PageWritebackBio>,
        io_batch: &mut IoBatch,
    ) -> Result<()> {
        if writebacks.is_empty() {
            return Ok(());
        }

        if writebacks.len() == 1 {
            let Some(writeback) = writebacks.pop() else {
                unreachable!("writeback length was checked")
            };
            let (idx, bio_segment, page) = writeback.into_parts();
            let complete_fn: BioCompleteFn =
                Box::new(move |status| complete_page_writeback(idx, &page, status));
            return self.submit_write_bio(idx, bio_segment, complete_fn, io_batch);
        }

        writebacks.sort_unstable_by_key(PageWritebackBio::idx);
        let mut run_start = writebacks[0].idx();
        let mut run_end = run_start + 1;
        for writeback in &writebacks[1..] {
            let idx = writeback.idx();
            if idx == run_end {
                run_end += 1;
                continue;
            }
            self.allocate_writeback_blocks(run_start, run_end)?;
            run_start = idx;
            run_end = idx + 1;
        }
        self.allocate_writeback_blocks(run_start, run_end)?;

        let fs = self.fs()?;
        let mut group: Option<WritebackGroup> = None;

        for writeback in writebacks {
            let (idx, bio_segment, page) = writeback.into_parts();
            let bid = self.resolve_write_bid(idx, bio_segment.nblocks(), &fs)?;

            let can_append = group.as_ref().is_some_and(|group| group.next_bid == bid);
            if !can_append && let Some(group) = group.take() {
                group.submit(&fs, io_batch)?;
            }

            let group = group.get_or_insert_with(|| WritebackGroup::new(bid));
            let nblocks = u32::try_from(bio_segment.nblocks())
                .map_err(|_| Error::with_message(Errno::EINVAL, "block range length overflow"))?;
            group.next_bid = group
                .next_bid
                .checked_add(nblocks)
                .ok_or_else(|| Error::with_message(Errno::EINVAL, "block address overflow"))?;
            group.bio_segments.push(bio_segment);
            group.pages.push((idx, page));
        }

        if let Some(group) = group {
            group.submit(&fs, io_batch)?;
        }
        Ok(())
    }
}

struct WritebackGroup {
    start_bid: Ext2Bid,
    next_bid: Ext2Bid,
    bio_segments: Vec<BioSegment>,
    pages: Vec<(usize, CachePage)>,
}

impl WritebackGroup {
    fn new(start_bid: Ext2Bid) -> Self {
        Self {
            start_bid,
            next_bid: start_bid,
            bio_segments: Vec::new(),
            pages: Vec::new(),
        }
    }

    fn submit(self, fs: &Ext2, io_batch: &mut IoBatch) -> Result<()> {
        let pages = self.pages;
        let complete_fn: BioCompleteFn = Box::new(move |status| {
            for (idx, page) in pages {
                complete_page_writeback(idx, &page, status);
            }
        });
        fs.write_block_segments_async(
            self.start_bid,
            self.bio_segments,
            Some(complete_fn),
            io_batch,
        )
    }
}
