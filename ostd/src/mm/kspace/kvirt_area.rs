// SPDX-License-Identifier: MPL-2.0

//! Kernel virtual memory allocation

use alloc::vec::Vec;
use core::ops::Range;

use self::allocator::kvirt_area_allocator;
use super::{KERNEL_PAGE_TABLE, KernelPtConfig, MappedItem};
use crate::{
    irq,
    mm::{
        HasSize, PAGE_SIZE, Paddr, Split, Vaddr,
        frame::{Frame, meta::AnyFrameMeta},
        page_prop::PageProperty,
        page_table::{CursorMut, PageTableFrag, largest_pages},
    },
};

mod allocator {
    use crate::{
        irq::DisabledLocalIrqGuard, mm::kspace::VMALLOC_VADDR_RANGE,
        util::range_alloc::RangeAllocator,
    };

    static KVIRT_AREA_ALLOCATOR: RangeAllocator = RangeAllocator::new(VMALLOC_VADDR_RANGE);

    /// Returns a reference to the kernel virtual memory allocator.
    ///
    /// [`DisabledLocalIrqGuard`] is required because DMA objects may be
    /// dropped in IRQ handlers. So the guard is necessary to prevent
    /// deadlocks. For more details, see [`crate::mm::dma`].
    ///
    /// Meanwhile, note that deadlocks may occur if the page table nodes locked
    /// in this file are also locked in other files where only preemption is
    /// disabled. This requires extra care.
    pub(super) fn kvirt_area_allocator(_guard: &DisabledLocalIrqGuard) -> &RangeAllocator {
        &KVIRT_AREA_ALLOCATOR
    }
}

/// Kernel virtual area.
///
/// A kernel virtual area manages a range of memory in [`VMALLOC_VADDR_RANGE`].
/// It can map a portion or the entirety of its virtual memory pages to
/// physical memory, whether tracked with metadata or not.
///
/// It is the caller's responsibility to ensure TLB coherence before using the
/// mapped virtual address on a certain CPU.
//
// FIXME: This caller-ensured design is very error-prone. A good option is to
// use a guard the pins the CPU and ensures TLB coherence while accessing the
// `KVirtArea`. However, `IoMem` need some non trivial refactoring to support
// being implemented on a `!Send` and `!Sync` guard.
#[derive(Debug)]
pub(crate) struct KVirtArea {
    range: Range<Vaddr>,
}

impl HasSize for KVirtArea {
    fn size(&self) -> usize {
        self.range.len()
    }
}

impl Split for KVirtArea {
    fn split(self, offset: usize) -> (Self, Self) {
        assert!(offset.is_multiple_of(PAGE_SIZE));
        assert!(0 < offset && offset < self.size());

        let old = core::mem::ManuallyDrop::new(self);

        let left_range = old.start()..old.start() + offset;
        let right_range = old.start() + offset..old.end();
        (
            KVirtArea { range: left_range },
            KVirtArea { range: right_range },
        )
    }
}

impl KVirtArea {
    pub(crate) fn start(&self) -> Vaddr {
        self.range.start
    }

    pub(crate) fn end(&self) -> Vaddr {
        self.range.end
    }

    pub(crate) fn range(&self) -> Range<Vaddr> {
        self.range.start..self.range.end
    }

    #[cfg(ktest)]
    pub(crate) fn query<'a, G: crate::task::atomic_mode::AsAtomicModeGuard>(
        &'a self,
        guard: &'a G,
        addr: Vaddr,
    ) -> Option<super::MappedItemRef<'a>> {
        use align_ext::AlignExt;

        assert!(self.start() <= addr && self.end() >= addr);

        let start = addr.align_down(PAGE_SIZE);
        let vaddr = start..start + PAGE_SIZE;

        let page_table = KERNEL_PAGE_TABLE.get().unwrap();
        let mut cursor = page_table.cursor(guard, &vaddr).unwrap();

        cursor.query().unwrap().1
    }

    /// Reserves an unmapped kernel range, returning an error on exhaustion.
    pub(crate) fn try_reserve(area_size: usize) -> crate::Result<Self> {
        Self::try_reserve_aligned(area_size, PAGE_SIZE)
    }

    /// Reserves an unmapped range with a power-of-two virtual alignment.
    pub(crate) fn try_reserve_aligned(area_size: usize, alignment: usize) -> crate::Result<Self> {
        if area_size == 0
            || !area_size.is_multiple_of(PAGE_SIZE)
            || alignment < PAGE_SIZE
            || !alignment.is_power_of_two()
        {
            return Err(crate::Error::InvalidArgs);
        }
        let reserved_size = area_size
            .checked_add(alignment - PAGE_SIZE)
            .ok_or(crate::Error::Overflow)?;
        let irq_guard = irq::disable_local();
        let allocator = kvirt_area_allocator(&irq_guard);
        let reserved = allocator
            .alloc(reserved_size)
            .map_err(|_| crate::Error::NoMemory)?;
        // The allocator returns page-aligned bounds. The extra reservation
        // therefore covers every possible padding up to alignment - PAGE_SIZE.
        let padding = (alignment - reserved.start % alignment) % alignment;
        let range = reserved.start + padding..reserved.start + padding + area_size;
        if reserved.start < range.start {
            allocator.free(reserved.start..range.start);
        }
        if range.end < reserved.end {
            allocator.free(range.end..reserved.end);
        }
        Ok(Self { range })
    }

    /// Creates a kernel virtual area and maps tracked pages into it.
    ///
    /// The created virtual area will have a size of `area_size`, and the pages
    /// will be mapped starting from `map_offset` in the area.
    ///
    /// # Panics
    ///
    /// This function panics if
    ///  - the area size is not a multiple of [`PAGE_SIZE`];
    ///  - the map offset is not aligned to [`PAGE_SIZE`];
    ///  - the map offset plus the size of the pages exceeds the area size.
    pub(crate) fn map_frames<T: AnyFrameMeta + ?Sized>(
        area_size: usize,
        map_offset: usize,
        frames: impl Iterator<Item = Frame<T>>,
        prop: PageProperty,
    ) -> Self {
        assert!(area_size.is_multiple_of(PAGE_SIZE));
        assert!(map_offset.is_multiple_of(PAGE_SIZE));

        let irq_guard = irq::disable_local();

        let range = kvirt_area_allocator(&irq_guard).alloc(area_size).unwrap();
        let cursor_range = range.start + map_offset..range.end;

        let page_table = KERNEL_PAGE_TABLE.get().unwrap();
        let mut cursor = page_table.cursor_mut(&irq_guard, &cursor_range).unwrap();

        for frame in frames.into_iter() {
            // SAFETY: The constructor of the `KVirtArea` has already ensured
            // that this mapping does not affect kernel's memory safety.
            unsafe { cursor.map(MappedItem::Tracked(Frame::from_unsized(frame), prop)) };
        }

        Self { range }
    }

    /// Maps new tracked pages into an unmapped part of this reservation.
    ///
    /// Existing mappings are never replaced. The owner serializes growth and
    /// retains the area until all users of the new mapping have detached.
    pub(crate) fn map_additional_frames<T: AnyFrameMeta + ?Sized>(
        &self,
        offset: usize,
        frames: impl ExactSizeIterator<Item = Frame<T>>,
        prop: PageProperty,
    ) -> crate::Result<()> {
        self.map_additional_frames_batch(core::iter::once((offset, frames)), prop)
    }

    /// Maps disjoint, previously unmapped ranges without sleeping.
    /// Every returned error leaves all mappings unchanged.
    pub(crate) fn map_additional_frames_batch<
        T: AnyFrameMeta + ?Sized,
        I: ExactSizeIterator<Item = Frame<T>>,
    >(
        &self,
        mappings: impl ExactSizeIterator<Item = (usize, I)>,
        prop: PageProperty,
    ) -> crate::Result<()> {
        let mut batches = Vec::new();
        batches
            .try_reserve_exact(mappings.len())
            .map_err(|_| crate::Error::NoMemory)?;
        for (offset, frames) in mappings {
            let bytes = frames
                .len()
                .checked_mul(PAGE_SIZE)
                .ok_or(crate::Error::Overflow)?;
            let end = offset.checked_add(bytes).ok_or(crate::Error::Overflow)?;
            if !offset.is_multiple_of(PAGE_SIZE) || bytes == 0 || end > self.size() {
                return Err(crate::Error::InvalidArgs);
            }
            batches.push((self.start() + offset..self.start() + end, frames));
        }
        if batches.is_empty() {
            return Err(crate::Error::InvalidArgs);
        }
        batches.sort_unstable_by_key(|(range, _)| range.start);
        if batches
            .windows(2)
            .any(|pair| pair[0].0.end > pair[1].0.start)
        {
            return Err(crate::Error::InvalidArgs);
        }
        let range = batches.first().unwrap().0.start..batches.last().unwrap().0.end;
        let guard = irq::disable_local();
        let table = KERNEL_PAGE_TABLE.get().unwrap();
        let mut cursor = table.cursor_mut(&guard, &range).unwrap();
        // One cursor retains exclusive access across every precheck and map.
        // A rejection in a later range cannot leave earlier ranges installed.
        for (range, _) in &batches {
            for addr in range.clone().step_by(PAGE_SIZE) {
                cursor.jump(addr).unwrap();
                if cursor.query().unwrap().1.is_some() {
                    return Err(crate::Error::InvalidArgs);
                }
            }
        }
        // Allocate every intermediate node before transferring any frame into
        // a leaf. An OOM in a later range leaves earlier ranges unmapped.
        for (range, _) in &batches {
            for addr in range.clone().step_by(PAGE_SIZE) {
                cursor.prepare_mapping(addr, 1)?;
            }
        }
        for (range, frames) in batches {
            cursor.jump(range.start).unwrap();
            for frame in frames {
                // SAFETY: This reservation owns the previously unmapped range.
                unsafe { cursor.map(MappedItem::Tracked(Frame::from_unsized(frame), prop)) };
            }
        }
        Ok(())
    }

    /// Creates a kernel virtual area and maps untracked frames into it.
    ///
    /// The created virtual area will have a size of `area_size`, and the
    /// physical addresses will be mapped starting from `map_offset` in
    /// the area.
    ///
    /// You can provide a `0..0` physical range to create a virtual area without
    /// mapping any physical memory.
    ///
    /// # Panics
    ///
    /// This function panics if
    ///  - the area size is not a multiple of [`PAGE_SIZE`];
    ///  - the map offset is not aligned to [`PAGE_SIZE`];
    ///  - the provided physical range is not aligned to [`PAGE_SIZE`];
    ///  - the map offset plus the length of the physical range exceeds the
    ///    area size;
    ///  - the provided physical range contains tracked physical addresses.
    pub(crate) unsafe fn map_untracked_frames(
        area_size: usize,
        map_offset: usize,
        pa_range: Range<Paddr>,
        prop: PageProperty,
    ) -> Self {
        assert!(pa_range.start.is_multiple_of(PAGE_SIZE));
        assert!(pa_range.end.is_multiple_of(PAGE_SIZE));
        assert!(area_size.is_multiple_of(PAGE_SIZE));
        assert!(map_offset.is_multiple_of(PAGE_SIZE));
        assert!(map_offset + pa_range.len() <= area_size);

        let irq_guard = irq::disable_local();

        let range = kvirt_area_allocator(&irq_guard).alloc(area_size).unwrap();

        if !pa_range.is_empty() {
            let len = pa_range.len();
            let va_range = range.start + map_offset..range.start + map_offset + len;

            let page_table = KERNEL_PAGE_TABLE.get().unwrap();
            let max_map_level =
                largest_pages::<KernelPtConfig>(va_range.start, pa_range.start, len)
                    .map(|(_, level)| level)
                    .max()
                    .unwrap();
            let mut cursor = page_table
                .cursor_mut_for_mapping(&irq_guard, &va_range, max_map_level)
                .unwrap();
            if max_map_level > 1 {
                // A former base-page reservation may have left empty tables.
                prepare_unmapped_range(&mut cursor, &va_range).unwrap();
            }

            for (pa, level) in largest_pages::<KernelPtConfig>(va_range.start, pa_range.start, len)
            {
                // SAFETY: The caller of `map_untracked_frames` has ensured the safety of this mapping.
                unsafe { cursor.map(MappedItem::Untracked(pa, level, prop)) };
            }
        }

        Self { range }
    }
}

/// Checks the whole range before removing any empty page-table structure.
/// The cursor keeps the same exclusive range lock through checking and removal.
fn prepare_unmapped_range(
    cursor: &mut CursorMut<'_, KernelPtConfig>,
    range: &Range<Vaddr>,
) -> crate::Result<()> {
    if cursor.find_next(range.len()).is_some() {
        return Err(crate::Error::InvalidArgs);
    }
    // find_next reached the barrier end. This jump resets the traversal to
    // the locked root, so take_next can see and retire empty child tables.
    cursor.jump(range.start).unwrap();
    while let Some(fragment) =
        // SAFETY: The same exclusive cursor just proved the entire range has
        // no mapped items. Only empty child tables can be removed. take_next
        // marks them stray and their RcuDrop owners defer reclamation until
        // software walkers have left their RCU read-side critical sections.
        unsafe { cursor.take_next(range.end - cursor.virt_addr()) }
    {
        debug_assert!(matches!(
            &fragment,
            PageTableFrag::StrayPageTable { num_frames: 0, .. }
        ));
        drop(fragment);
    }
    cursor.jump(range.start).unwrap();
    Ok(())
}

impl Drop for KVirtArea {
    fn drop(&mut self) {
        let irq_guard = irq::disable_local();

        // 1. Unmap all mapped pages.
        let page_table = KERNEL_PAGE_TABLE.get().unwrap();
        let range = self.start()..self.end();
        let mut cursor = page_table.cursor_mut(&irq_guard, &range).unwrap();
        loop {
            // SAFETY: The range is under `KVirtArea`, so it is safe to unmap.
            let Some(frag) = (unsafe { cursor.take_next(self.end() - cursor.virt_addr()) }) else {
                break;
            };
            drop(frag);
        }
        drop(cursor);

        // 2. Free the virtual block.
        kvirt_area_allocator(&irq_guard).free(range);
    }
}
