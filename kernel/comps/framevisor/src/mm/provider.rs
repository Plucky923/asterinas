// SPDX-License-Identifier: MPL-2.0

//! Per-FrameVM OSTD provider state.
//!
//! The service image still sees OSTD's `GlobalFrameAllocator` and
//! `GlobalHeapAllocator` contracts. The loader relocates the OSTD getter
//! symbols to one `FrameVmAllocator` instance. Rust's allocation entry points
//! are relocated only when the image explicitly installs a custom heap
//! provider; the default service keeps the shared Rust heap until the
//! cross-boundary allocation audit is complete. In either case, explicit
//! OSTD frame/heap requests use the VM-local, OSTD-shaped dispatch.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    alloc::{AllocError, Layout},
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(ktest)]
use host_ostd::mm::FrameAllocOptions as OstdFrameAllocOptions;
use host_ostd::mm::{
    Frame as OstdFrame, HasPaddr, HasSize, PAGE_SIZE, Segment as OstdSegment,
    frame::{GlobalFrameAllocator, meta::AnyFrameMeta, zero_raw},
    heap::{GlobalHeapAllocator, HeapSlot, SlotInfo},
};

use crate::{
    Error, Result,
    mm::{
        Frame, FrameAllocOptions, Paddr,
        frame::segment::{Segment, SegmentLease},
        ownership,
    },
    sync::SpinLock,
    vm::{MemoryDomain, VmId},
};

const FRAME_ALLOCATOR_REF: &[u8] = b"__GLOBAL_FRAME_ALLOCATOR_REF";
const HEAP_ALLOCATOR_REF: &[u8] = b"__GLOBAL_HEAP_ALLOCATOR_REF";
const HEAP_SLOT_MAP: &[u8] = b"__global_heap_slot_info_from_layout";
const FRAME_ALLOCATOR_GETTER: &[u8] = b"get_global_frame_allocator";
const HEAP_ALLOCATOR_GETTER: &[u8] = b"get_global_heap_allocator";
const HEAP_SLOT_MAP_GETTER: &[u8] = b"slot_size_from_layout";
const RUST_ALLOC_SUFFIX: &[u8] = b"___rust_alloc";
const RUST_ALLOC_ZEROED_SUFFIX: &[u8] = b"___rust_alloc_zeroed";
const RUST_DEALLOC_SUFFIX: &[u8] = b"___rust_dealloc";
const RUST_REALLOC_SUFFIX: &[u8] = b"___rust_realloc";
const RUST_ALLOC_ERROR_SUFFIX: &[u8] = b"___rust_alloc_error_handler";
const ALLOC_HANDLE_ERROR_SUFFIX: &[u8] = b"5alloc18handle_alloc_error";

const SMALL_SLOT_SIZES: &[usize] = &[8, 16, 32, 64, 128, 256, 512, 1024, 2048];

/// One page of small-object storage owned by one FrameVM heap provider.
///
/// The page remains an ordinary untyped Frame.  Keeping the free bitmap in
/// Host-side provider metadata avoids giving OSTD a second typed slab owner
/// that could not be drained safely at VM teardown.
struct SmallPage {
    frame: Frame<()>,
    slot_size: usize,
    free: [u64; 8],
    free_slots: usize,
}

impl SmallPage {
    fn new(frame: Frame<()>, slot_size: usize) -> Self {
        let slots = PAGE_SIZE / slot_size;
        let mut free = [0; 8];
        for index in 0..slots {
            free[index / 64] |= 1 << (index % 64);
        }
        Self {
            frame,
            slot_size,
            free,
            free_slots: slots,
        }
    }

    fn alloc(&mut self) -> Option<HeapSlot> {
        let word = self.free.iter().position(|bits| *bits != 0)?;
        let bit = self.free[word].trailing_zeros() as usize;
        self.free[word] &= !(1_u64 << bit);
        self.free_slots -= 1;
        let index = word * 64 + bit;
        let paddr = self
            .frame
            .paddr()
            .checked_add(index.checked_mul(self.slot_size)?)?;
        HeapSlot::from_raw_parts(paddr, SlotInfo::SlabSlot(self.slot_size)).ok()
    }

    fn dealloc(&mut self, slot: HeapSlot) -> Result<(), AllocError> {
        if slot.info() != SlotInfo::SlabSlot(self.slot_size) {
            return Err(AllocError);
        }
        let offset = slot
            .paddr()
            .checked_sub(self.frame.paddr())
            .ok_or(AllocError)?;
        if !offset.is_multiple_of(self.slot_size) || offset >= PAGE_SIZE {
            return Err(AllocError);
        }
        let index = offset / self.slot_size;
        let word = index / 64;
        let bit = index % 64;
        let mask = 1_u64 << bit;
        if self.free[word] & mask != 0 {
            return Err(AllocError);
        }
        self.free[word] |= mask;
        self.free_slots += 1;
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.free_slots == PAGE_SIZE / self.slot_size
    }

    fn has_free_slot(&self) -> bool {
        self.free_slots != 0
    }
}

struct HeapState {
    pages: [Vec<SmallPage>; 9],
    large: Vec<LargeAllocation>,
}

impl HeapState {
    fn new() -> Self {
        Self {
            pages: core::array::from_fn(|_| Vec::new()),
            large: Vec::new(),
        }
    }

    fn clear_empty(&mut self) {
        for pages in &mut self.pages {
            pages.retain(|page| !page.is_empty());
        }
        self.large.retain(|allocation| allocation.in_use);
    }
}

/// Tracks one contiguous large heap allocation. The FrameVisor segment keeps
/// every member page's owner lease until the backing is dropped, so an empty
/// allocation can become same-domain cached memory without reconstructing
/// OSTD metadata.
struct LargeAllocation {
    segment: Segment<()>,
    slot_size: usize,
    in_use: bool,
}

/// Owns the provider cells relocated into one loaded FrameVM image.
pub(crate) struct FrameVmAllocator {
    frame: Box<Box<dyn GlobalFrameAllocator + Send + Sync>>,
    heap: Box<Box<dyn GlobalHeapAllocator + Send + Sync>>,
    heap_state: Arc<SpinLock<HeapState>>,
    frame_cell: SpinLock<Option<host_ostd::loader::FrameAllocatorCell>>,
    heap_cell: SpinLock<Option<host_ostd::loader::HeapAllocatorCell>>,
    /// Remembers whether the observed cells point at image-defined providers.
    ///
    /// Reading a loader cell dereferences the service image.  Teardown may
    /// need to inspect provider state after service tasks have stopped, so it
    /// must use this load-time fact instead of dereferencing an image address
    /// during the image-retention decision.
    custom_frame_provider: AtomicBool,
    custom_heap_provider: AtomicBool,
    granted_ranges: SpinLock<Vec<(Paddr, usize)>>,
    /// Ranges whose OSTD metadata is being constructed but has not yet been
    /// published to `FrameOwners`.  Drops from a partially-built Segment are
    /// intercepted here so OSTD cannot return a prefix and then make the
    /// whole raw grant look free a second time.
    unpublished_ranges: SpinLock<Vec<(Paddr, usize)>>,
    active: AtomicBool,
    provider_faulted: AtomicBool,
    /// Suppresses provider idle callbacks while an accepted custom value is
    /// being published into `FrameOwners`.  OSTD may drop a provisional
    /// hidden reference during a failed adoption; calling the image's cache
    /// hook in that window would let it recycle a range whose admission is
    /// about to be quarantined.
    provider_callbacks_suppressed: AtomicBool,
    #[cfg(ktest)]
    reject_next_admission: AtomicBool,
    domain: MemoryDomain,
    vm_id: VmId,
}

impl FrameVmAllocator {
    pub(crate) fn new(domain: MemoryDomain, vm_id: VmId) -> Self {
        let frame: Box<dyn GlobalFrameAllocator + Send + Sync> =
            Box::new(FrameProvider::new(domain.clone(), vm_id));
        let heap_state = Arc::new(SpinLock::new(HeapState::new()));
        let heap: Box<dyn GlobalHeapAllocator + Send + Sync> =
            Box::new(HeapProvider::new(domain.clone(), vm_id, heap_state.clone()));
        Self {
            frame: Box::new(frame),
            heap: Box::new(heap),
            heap_state,
            frame_cell: SpinLock::new(None),
            heap_cell: SpinLock::new(None),
            custom_frame_provider: AtomicBool::new(false),
            custom_heap_provider: AtomicBool::new(false),
            granted_ranges: SpinLock::new(Vec::new()),
            unpublished_ranges: SpinLock::new(Vec::new()),
            active: AtomicBool::new(true),
            provider_faulted: AtomicBool::new(false),
            provider_callbacks_suppressed: AtomicBool::new(false),
            #[cfg(ktest)]
            reject_next_admission: AtomicBool::new(false),
            domain: domain.clone(),
            vm_id,
        }
    }

    #[cfg(ktest)]
    pub(crate) fn reject_next_admission_for_test(&self) {
        self.reject_next_admission.store(true, Ordering::Release);
    }

    /// Records one validated provider cell defined by the loaded image.
    pub(crate) fn observe_symbol(
        &self,
        symbol: &host_ostd::loader::DefinedSymbol<'_>,
    ) -> Result<()> {
        if !self.active.load(Ordering::Acquire) || self.provider_faulted.load(Ordering::Acquire) {
            return Err(Error::AccessDenied);
        }
        let frame_cell = symbol.frame_allocator_cell();
        if symbol.name() == FRAME_ALLOCATOR_REF && frame_cell.is_none() {
            return Err(Error::InvalidArgs);
        }
        let heap_cell = symbol.heap_allocator_cell();
        if symbol.name() == HEAP_ALLOCATOR_REF && heap_cell.is_none() {
            return Err(Error::InvalidArgs);
        }
        if let Some(cell) = frame_cell {
            let is_custom = if cell.matches(&**self.frame) {
                false
            } else if cell.is_image_trait_object() {
                true
            } else {
                return Err(Error::InvalidArgs);
            };
            let mut current = self.frame_cell.lock();
            if current.is_some() {
                return Err(Error::InvalidArgs);
            }
            *current = Some(cell);
            self.custom_frame_provider
                .store(is_custom, Ordering::Release);
        }
        if let Some(cell) = heap_cell {
            let is_custom = if cell.matches(&**self.heap) {
                false
            } else if cell.is_image_trait_object() {
                true
            } else {
                return Err(Error::InvalidArgs);
            };
            let mut current = self.heap_cell.lock();
            if current.is_some() {
                return Err(Error::InvalidArgs);
            }
            *current = Some(cell);
            self.custom_heap_provider
                .store(is_custom, Ordering::Release);
        }
        Ok(())
    }

    /// Resolves only the provider symbols that must be VM-local.
    pub(crate) fn resolve_symbol(&self, name: &[u8]) -> Option<usize> {
        if !self.active.load(Ordering::Acquire) || self.provider_faulted.load(Ordering::Acquire) {
            return None;
        }
        match name {
            FRAME_ALLOCATOR_REF => Some(self.frame.as_ref() as *const _ as usize),
            HEAP_ALLOCATOR_REF => Some(self.heap.as_ref() as *const _ as usize),
            HEAP_SLOT_MAP => Some(framevm_heap_slot_info as *const () as usize),
            _ if is_ostd_allocator_getter(name, FRAME_ALLOCATOR_GETTER) => {
                Some(framevm_get_global_frame_allocator as *const () as usize)
            }
            _ if is_ostd_allocator_getter(name, HEAP_ALLOCATOR_GETTER) => {
                Some(framevm_get_global_heap_allocator as *const () as usize)
            }
            _ if is_ostd_allocator_getter(name, HEAP_SLOT_MAP_GETTER) => {
                Some(framevm_heap_slot_info as *const () as usize)
            }
            _ if self.has_custom_heap_provider()
                && is_rust_allocator_symbol(name, RUST_ALLOC_SUFFIX, b"__rust_alloc") =>
            {
                Some(framevm_alloc as *const () as usize)
            }
            _ if self.has_custom_heap_provider()
                && is_rust_allocator_symbol(
                    name,
                    RUST_ALLOC_ZEROED_SUFFIX,
                    b"__rust_alloc_zeroed",
                ) =>
            {
                Some(framevm_alloc_zeroed as *const () as usize)
            }
            _ if self.has_custom_heap_provider()
                && is_rust_allocator_symbol(name, RUST_DEALLOC_SUFFIX, b"__rust_dealloc") =>
            {
                Some(framevm_dealloc as *const () as usize)
            }
            _ if self.has_custom_heap_provider()
                && is_rust_allocator_symbol(name, RUST_REALLOC_SUFFIX, b"__rust_realloc") =>
            {
                Some(framevm_realloc as *const () as usize)
            }
            _ if is_rust_allocator_symbol(
                name,
                RUST_ALLOC_ERROR_SUFFIX,
                b"__rust_alloc_error_handler",
            ) =>
            {
                Some(framevm_alloc_error_handler as *const () as usize)
            }
            _ if is_rust_allocator_symbol(
                name,
                ALLOC_HANDLE_ERROR_SUFFIX,
                b"alloc::alloc::handle_alloc_error",
            ) =>
            {
                Some(framevm_handle_alloc_error as *const () as usize)
            }
            _ => None,
        }
    }

    /// Returns whether the loader must wait for provider discovery before
    /// resolving this Rust allocator symbol.
    pub(crate) fn should_defer_symbol(name: &[u8]) -> bool {
        is_rust_allocator_symbol(name, RUST_ALLOC_SUFFIX, b"__rust_alloc")
            || is_rust_allocator_symbol(name, RUST_ALLOC_ZEROED_SUFFIX, b"__rust_alloc_zeroed")
            || is_rust_allocator_symbol(name, RUST_DEALLOC_SUFFIX, b"__rust_dealloc")
            || is_rust_allocator_symbol(name, RUST_REALLOC_SUFFIX, b"__rust_realloc")
    }

    pub(crate) fn alloc_heap(&self, layout: Layout, zeroed: bool) -> *mut u8 {
        let Ok(slot) = self.heap_alloc(layout) else {
            return core::ptr::null_mut();
        };
        let pointer = slot.as_ptr();
        if zeroed {
            let Some((start, bytes)) = self.heap_slot_range(&slot) else {
                let _ = self.heap_dealloc(slot);
                return core::ptr::null_mut();
            };
            let result = ownership::zero_heap_range(start, bytes, self.vm_id, &self.domain);
            if result.is_err() {
                let _ = self.heap_dealloc(slot);
                return core::ptr::null_mut();
            }
        }
        pointer
    }

    pub(crate) fn dealloc_heap(&self, pointer: *mut u8, layout: Layout) -> bool {
        let Some(info) = heap_slot_info(layout) else {
            return false;
        };
        let Ok(slot) = HeapSlot::from_ptr_parts(pointer, info) else {
            return false;
        };
        self.heap_dealloc(slot).is_ok()
    }

    pub(crate) fn realloc_heap(
        &self,
        pointer: *mut u8,
        old_layout: Layout,
        new_layout: Layout,
    ) -> *mut u8 {
        if old_layout.size() == 0 {
            return self.alloc_heap(new_layout, false);
        }
        if new_layout.size() == 0 {
            let _ = self.dealloc_heap(pointer, old_layout);
            return core::ptr::null_mut();
        }

        let Some(old_info) = heap_slot_info(old_layout) else {
            return core::ptr::null_mut();
        };
        let Ok(old_slot) = HeapSlot::from_ptr_parts(pointer, old_info) else {
            return core::ptr::null_mut();
        };
        if heap_slot_info(new_layout).is_none() {
            return core::ptr::null_mut();
        }
        let Ok(new_slot) = self.heap_alloc(new_layout) else {
            return core::ptr::null_mut();
        };
        let new_pointer = new_slot.as_ptr();
        let copy_result = ownership::copy_heap_range(
            old_slot.paddr(),
            new_slot.paddr(),
            old_layout.size().min(new_layout.size()),
            self.vm_id,
            &self.domain,
        );
        if copy_result.is_err() {
            let _ = self.heap_dealloc(new_slot);
            return core::ptr::null_mut();
        }
        if self.heap_dealloc(old_slot).is_err() {
            let _ = self.heap_dealloc(new_slot);
            return core::ptr::null_mut();
        }
        new_pointer
    }

    /// Allocates a service-visible OSTD frame through this VM's provider.
    ///
    /// The returned value is intentionally the native OSTD shape: its drop
    /// path runs in the service image and therefore dispatches back to this
    /// allocator.  Host-side failure paths never drop an unadmitted frame;
    /// they retain the physical allocation and fault the provider instead.
    pub(crate) fn alloc_service_untyped_frame(&self, zeroed: bool) -> Result<OstdFrame<()>> {
        // This Host-side compatibility path constructs the OSTD value before
        // returning it to the service. A custom image provider must construct
        // and reject its own value inside the service image, where Drop
        // dispatches back to that provider; otherwise a rejected Host value
        // would return the custom grant through Host OSTD.
        if self.has_custom_frame_provider() {
            return Err(Error::AccessDenied);
        }

        // A cached built-in page already has valid OSTD metadata and a hidden
        // FrameVisor owner. Reusing that handle is the only safe way to keep
        // same-domain reuse zero-copy; reconstructing it with `from_unused`
        // would violate OSTD's reference-count invariant. Custom image
        // providers retain their own cache policy and therefore stay on the
        // refill path below.
        if !self.has_custom_frame_provider()
            && let Some((frame, lease)) = ownership::reserve_cached_frame(self.vm_id, &self.domain)
        {
            let paddr = frame.paddr();
            let reservation = match self.domain.reserve_reusable(PAGE_SIZE) {
                Ok(reservation) => reservation,
                Err(_) => {
                    let _ = ownership::restore_cached_frame(paddr, self.vm_id, &self.domain);
                    drop(frame);
                    drop(lease);
                    return self.alloc_service_frame((), zeroed);
                }
            };
            if let Err(error) = reservation.commit() {
                let _ = ownership::restore_cached_frame(paddr, self.vm_id, &self.domain);
                drop(frame);
                drop(lease);
                return Err(error);
            }
            ownership::commit_cached_frame(paddr, self.vm_id, &self.domain);
            drop(lease);
            if zeroed {
                frame.zero();
            }
            return Ok(frame);
        }

        self.alloc_service_frame((), zeroed)
    }

    pub(crate) fn alloc_service_frame<M: AnyFrameMeta>(
        &self,
        metadata: M,
        zeroed: bool,
    ) -> Result<OstdFrame<M>> {
        // This Host-side compatibility path constructs the OSTD value before
        // returning it to the service. A custom image provider must construct
        // and reject its own value inside the service image, where Drop
        // dispatches back to that provider; otherwise a rejected Host value
        // would return the custom grant through Host OSTD.
        if self.has_custom_frame_provider() {
            return Err(Error::AccessDenied);
        }

        let layout =
            Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).map_err(|_| Error::InvalidArgs)?;

        let paddr = self.frame_alloc(layout).ok_or(Error::NoMemory)?;
        let frame = match OstdFrame::from_unused(paddr, metadata) {
            Ok(frame) => frame,
            Err(_) => {
                self.rollback_unpublished_range(paddr, PAGE_SIZE);
                return Err(Error::NoMemory);
            }
        };
        if zeroed {
            frame.zero();
        }
        let accepted =
            self.accept_frame(OstdFrame::<dyn AnyFrameMeta>::from_unsized(frame.clone()));
        if !accepted {
            // `on_frame_allocated` follows OSTD's rejection contract: the
            // public value is still dropped by the caller.  For an image
            // provider the grant remains domain-owned and the drop returns
            // the page to that provider; only the built-in path returns the
            // charge to Host.
            drop(frame);
            if !self.has_custom_frame_provider() {
                self.rollback_rejected_builtin_range(paddr, PAGE_SIZE);
            }
            return Err(Error::NoMemory);
        }
        Ok(frame)
    }

    /// Allocates one Host-loader section backed by this VM's memory domain.
    ///
    /// The section is part of the loaded image, not a service-owned OSTD
    /// allocation.  Marking it as service-owned would make the image's own
    /// backing prevent `Program` from being dropped at stop time.
    pub(crate) fn alloc_loader_segment<M: AnyFrameMeta, F>(
        &self,
        nframes: usize,
        mut metadata_fn: F,
        zeroed: bool,
    ) -> Result<OstdSegment<M>>
    where
        F: FnMut(Paddr) -> M,
    {
        if self.has_custom_frame_provider() {
            return Err(Error::AccessDenied);
        }
        if nframes == 0 {
            return Err(Error::InvalidArgs);
        }
        let bytes = nframes.checked_mul(PAGE_SIZE).ok_or(Error::Overflow)?;
        let layout = Layout::from_size_align(bytes, PAGE_SIZE).map_err(|_| Error::InvalidArgs)?;
        let start = self.frame_alloc(layout).ok_or(Error::NoMemory)?;
        let end = match start.checked_add(bytes) {
            Some(end) => end,
            None => {
                self.rollback_unpublished_range(start, bytes);
                return Err(Error::Overflow);
            }
        };
        if self.begin_unpublished_range(start, bytes).is_err() {
            self.rollback_unpublished_range(start, bytes);
            return Err(Error::NoMemory);
        }
        let mut initialized_pages: usize = 0;
        let segment = match OstdSegment::from_unused(start..end, |paddr| {
            // `Segment::from_unused` calls this closure immediately before
            // each `Frame::from_unused` attempt. On an error, its Drop path
            // has already returned every page before the failed attempt.
            initialized_pages = initialized_pages.saturating_add(1);
            metadata_fn(paddr)
        }) {
            Ok(segment) => segment,
            Err(_) => {
                self.finish_unpublished_range(start, bytes);
                if self.has_custom_frame_provider() {
                    // `Segment::from_unused` drops every prefix it managed to
                    // construct before returning the error. The pending-range
                    // guard suppresses those per-page returns, but FrameVisor
                    // still cannot know whether the provider retained an
                    // additional OSTD reference. Quarantine the complete
                    // opaque grant instead of guessing the prefix state; the
                    // provider stays mapped for a later retry.
                    self.provider_fault(
                        "custom provider returned a range that OSTD could not construct",
                    );
                } else {
                    self.rollback_partial_builtin_segment(start, bytes, initialized_pages);
                }
                return Err(Error::NoMemory);
            }
        };
        self.finish_unpublished_range(start, bytes);
        if zeroed {
            segment.zero();
        }
        let accepted = ownership::adopt_existing_segment_for_loader(
            OstdSegment::<dyn AnyFrameMeta>::from_unsized(segment.clone()),
            self.vm_id,
            &self.domain,
        );
        if !accepted {
            // See the frame path above: OSTD drops the public segment after
            // a rejected acceptance callback.  Custom providers keep the
            // range charged and reusable through their grant table; the
            // built-in path returns it to Host.
            drop(segment);
            if !self.has_custom_frame_provider() {
                self.rollback_rejected_builtin_range(start, bytes);
            }
            return Err(Error::NoMemory);
        }
        Ok(segment)
    }

    /// Drops all built-in heap backing before domain teardown.
    ///
    /// The service image is still mapped while this runs.  Built-in slots can
    /// therefore be dropped here without leaving a frame metadata vtable
    /// pointing into an unmapped image.  A custom provider's opaque state is
    /// deliberately not inspected or destroyed by this method.
    pub(crate) fn quiesce(&self) {
        // `release_stopped_memory` can be called again by the Host destroy
        // path after the first stop pass has already deactivated the image
        // provider. The first pass drains the built-in heap before that
        // deactivation; a later pass must not re-enter provider state while
        // its image-backed callbacks are no longer admissible.
        if !self.active.load(Ordering::Acquire) {
            return;
        }
        // Move the backing handles out of the spinlock before dropping them.
        // A final Frame drop can scrub and return a physical page, which may
        // touch a fallible mapping; that path must not run with local IRQs
        // disabled by the heap-state lock.
        let state = {
            let mut heap_state = self.heap_state.lock();
            core::mem::replace(&mut *heap_state, HeapState::new())
        };
        let HeapState { pages, large } = state;
        for pages in pages {
            drop(pages);
        }
        drop(large);
    }

    /// Releases empty built-in slab pages so Host-pressure reclaim can see
    /// their hidden FrameVM owners. Custom heap providers remain opaque and
    /// are never guessed to be empty.
    pub(crate) fn clear_empty_heap_pages(&self) {
        self.heap_state.lock().clear_empty();
    }

    /// Deactivates image-backed provider cells before their mappings are gone.
    pub(crate) fn deactivate(&self) {
        self.active.store(false, Ordering::Release);
        *self.frame_cell.lock() = None;
        *self.heap_cell.lock() = None;
        self.custom_frame_provider.store(false, Ordering::Release);
        self.custom_heap_provider.store(false, Ordering::Release);
    }

    /// Deactivates provider cells only after opaque state has drained.
    ///
    /// OSTD does not expose a generic provider-cache destruction callback.
    /// Keeping the cells live while a grant or provider-owned frame remains is
    /// therefore the only safe fallback: a later lifecycle retry can still
    /// execute the provider's own drop path, while an image unload cannot
    /// leave a stale vtable behind. An image-local provider *pointer* alone
    /// is not retained state: static provider cells do not own Host resources
    /// until FrameVisor records a grant or a provider-managed frame.
    pub(crate) fn deactivate_if_quiescent(&self) -> bool {
        if self.has_retained_opaque_state() {
            return false;
        }
        self.deactivate();
        true
    }

    /// Returns whether opaque provider state still anchors image-backed state.
    pub(crate) fn has_retained_opaque_state(&self) -> bool {
        // A failed image load clears the observed cells, but an image-local
        // provider may already have received a grant or published an opaque
        // frame record. Those records still require the image to stay mapped
        // even though the cell itself is no longer reachable.
        self.custom_state_retained()
    }

    /// Reopens this provider for a new service-image run.
    ///
    /// A `FrameVm` may be stopped and started again while retaining its
    /// allocator object. The previous image's cells must be cleared before
    /// the new loader observes its provider symbols; all physical grants are
    /// already required to have drained by `MemoryDomain::resume`.
    pub(crate) fn activate(&self) {
        self.provider_faulted.store(false, Ordering::Release);
        self.custom_frame_provider.store(false, Ordering::Release);
        self.custom_heap_provider.store(false, Ordering::Release);
        self.active.store(true, Ordering::Release);
    }

    fn has_custom_provider(&self) -> bool {
        self.has_custom_frame_provider() || self.has_custom_heap_provider()
    }

    fn has_custom_frame_provider(&self) -> bool {
        self.custom_frame_provider.load(Ordering::Acquire)
    }

    fn has_custom_heap_provider(&self) -> bool {
        self.custom_heap_provider.load(Ordering::Acquire)
    }

    fn custom_state_retained(&self) -> bool {
        // Provider cells are only pointers into the service image. They do
        // not themselves retain a Host allocation, and image statics are not
        // dropped during program unload. Physical ownership is represented
        // exhaustively by grants and provider-managed owner records, so only
        // those records (or a fault that makes their state ambiguous) require
        // the image to stay mapped.
        self.provider_faulted.load(Ordering::Acquire)
            || !self.granted_ranges.lock().is_empty()
            || ownership::has_provider_managed_for_vm(self.vm_id)
    }

    fn begin_unpublished_range(&self, start: Paddr, size: usize) -> Result<()> {
        let mut ranges = self.unpublished_ranges.lock();
        ranges.try_reserve(1).map_err(|_| Error::NoMemory)?;
        ranges.push((start, size));
        Ok(())
    }

    fn finish_unpublished_range(&self, start: Paddr, size: usize) {
        let mut ranges = self.unpublished_ranges.lock();
        if let Some(index) = ranges
            .iter()
            .position(|(range_start, range_size)| *range_start == start && *range_size == size)
        {
            ranges.swap_remove(index);
        }
    }

    fn contains_unpublished_range(&self, start: Paddr, size: usize) -> bool {
        let Some(end) = start.checked_add(size) else {
            return false;
        };
        self.unpublished_ranges.lock().iter().any(|(base, bytes)| {
            base.checked_add(*bytes)
                .is_some_and(|range_end| start >= *base && end <= range_end)
        })
    }

    fn frame_alloc(&self, layout: Layout) -> Option<Paddr> {
        if !self.active.load(Ordering::Acquire) || self.provider_faulted.load(Ordering::Acquire) {
            return None;
        }
        if !self.has_custom_frame_provider() {
            return (**self.frame).alloc(layout);
        }

        let cell = self.frame_cell.lock().as_ref().cloned();
        let provider = match cell.as_ref() {
            Some(cell) => match cell.get() {
                Some(provider) => provider,
                None => {
                    self.provider_fault("custom frame provider is unavailable");
                    return None;
                }
            },
            None => &**self.frame,
        };
        if let Some(paddr) = provider.alloc(layout) {
            if self.custom_frame_range_is_valid(paddr, layout) {
                return Some(paddr);
            }
            // Do not call back into an image provider with an address that
            // failed the grant/alignment/provenance checks. Its deallocation
            // contract is only valid for ranges it actually received from
            // FrameVisor; returning an arbitrary value could corrupt either
            // the provider cache or a sibling domain.
            self.provider_fault("custom frame provider returned an ungranted range");
            return None;
        }

        self.grant_frame_memory(provider, layout)?;
        let Some(paddr) = provider.alloc(layout) else {
            self.provider_fault("custom frame provider refused a freshly granted range");
            return None;
        };
        if self.custom_frame_range_is_valid(paddr, layout) {
            Some(paddr)
        } else {
            self.provider_fault("custom frame provider returned an invalid refill range");
            None
        }
    }

    fn custom_frame_range_is_valid(&self, start: Paddr, layout: Layout) -> bool {
        layout.size() != 0
            && layout.size().is_multiple_of(PAGE_SIZE)
            && layout.align() >= PAGE_SIZE
            && start.is_multiple_of(PAGE_SIZE)
            && start.is_multiple_of(layout.align())
            && self.grant_contains(start, layout.size())
            && ownership::range_is_unowned(start, layout.size())
    }

    fn grant_frame_memory(
        &self,
        provider: &dyn GlobalFrameAllocator,
        layout: Layout,
    ) -> Option<()> {
        if layout.size() == 0
            || !layout.size().is_multiple_of(PAGE_SIZE)
            || layout.align() < PAGE_SIZE
        {
            return None;
        }
        let reservation = self.domain.reserve(layout.size()).ok()?;
        let paddr = match host_ostd::mm::frame::alloc_raw(layout) {
            Some(paddr) => paddr,
            None => {
                if !reclaim_after_oom(self.vm_id).ok()? {
                    return None;
                }
                host_ostd::mm::frame::alloc_raw(layout)?
            }
        };
        if zero_raw(paddr, layout.size()).is_err() {
            host_ostd::mm::frame::dealloc_raw(paddr, layout.size());
            return None;
        }
        if reservation.commit().is_err() {
            host_ostd::mm::frame::dealloc_raw(paddr, layout.size());
            return None;
        }
        {
            let mut grants = self.granted_ranges.lock();
            if grants.try_reserve(1).is_err() {
                drop(grants);
                host_ostd::mm::frame::dealloc_raw(paddr, layout.size());
                let _ = self.domain.release(layout.size(), false);
                return None;
            }
            grants.push((paddr, layout.size()));
        }
        provider.add_free_memory(paddr, layout.size());
        Some(())
    }

    fn grant_contains(&self, start: Paddr, bytes: usize) -> bool {
        let Some(end) = start.checked_add(bytes) else {
            return false;
        };
        self.granted_ranges.lock().iter().any(|(base, size)| {
            base.checked_add(*size)
                .is_some_and(|grant_end| start >= *base && end <= grant_end)
        })
    }

    fn consume_grant(&self, start: Paddr, bytes: usize) -> bool {
        let Some(end) = start.checked_add(bytes) else {
            return false;
        };
        let mut grants = self.granted_ranges.lock();
        let Some(index) = grants.iter().position(|(base, size)| {
            base.checked_add(*size)
                .is_some_and(|grant_end| start >= *base && end <= grant_end)
        }) else {
            return false;
        };

        let (base, size) = grants[index];
        let grant_end = base + size;
        let left = start - base;
        let right = grant_end - end;
        match (left != 0, right != 0) {
            (false, false) => {
                grants.remove(index);
            }
            (true, false) => grants[index] = (base, left),
            (false, true) => grants[index] = (end, right),
            (true, true) => {
                if grants.try_reserve(1).is_err() {
                    return false;
                }
                grants[index] = (base, left);
                grants.insert(index + 1, (end, right));
            }
        }
        true
    }

    fn restore_grant(&self, start: Paddr, bytes: usize) -> bool {
        let Some(end) = start.checked_add(bytes) else {
            return false;
        };
        let mut grants = self.granted_ranges.lock();
        if grants.iter().any(|(base, size)| {
            base.checked_add(*size)
                .is_some_and(|grant_end| start < grant_end && *base < end)
        }) {
            return false;
        }
        if grants.try_reserve(1).is_err() {
            return false;
        }
        grants.push((start, bytes));
        true
    }

    fn provider_fault(&self, reason: &str) {
        self.provider_faulted.store(true, Ordering::Release);
        ::log::error!(
            "[framevisor] FrameVM {} allocator provider fault: {}",
            self.vm_id,
            reason
        );
    }

    fn suppress_provider_callbacks(&self) -> ProviderCallbackSuppression<'_> {
        self.provider_callbacks_suppressed
            .store(true, Ordering::Release);
        ProviderCallbackSuppression { allocator: self }
    }

    fn provider_callbacks_suppressed(&self) -> bool {
        self.provider_callbacks_suppressed.load(Ordering::Acquire)
    }

    fn frame_dealloc(&self, addr: Paddr, size: usize) {
        if self.contains_unpublished_range(addr, size) {
            // `Segment::from_unused` may drop a successfully constructed
            // prefix before returning an error.  The enclosing transaction
            // still owns the complete raw range and will roll it back once;
            // do not return this page independently.
            return;
        }
        if ownership::has_owner(addr) {
            if ownership::provider_managed(addr) {
                // The image provider owns the opaque cache policy. Its
                // notification was delivered when the public references
                // drained; do not promote the page into FrameVisor's cache.
                return;
            }
            // A service can hand an arbitrary physical address to the
            // OSTD-shaped deallocator.  The address must belong to this
            // allocator's current VM ownership token and the complete returned
            // range must be recorded before it can affect cache state.  In
            // particular, do not let VM B cache a page owned by VM A merely
            // because both paths share the same dispatch object.
            let Some(end) = addr.checked_add(size) else {
                return;
            };
            if !ownership::range_belongs_to_vm(addr, size, self.vm_id, &self.domain) {
                return;
            }
            for paddr in (addr..end).step_by(PAGE_SIZE) {
                let _ = ownership::cache_if_idle(paddr);
            }
        } else if self.grant_contains(addr, size) {
            // The range was already donated to the image provider through
            // `add_free_memory`; a failed OSTD construction returns it to
            // that provider, not directly to Host. Keep the grant charged so
            // an opaque provider cannot later hand the range to a sibling VM.
            if !self.active.load(Ordering::Acquire) || self.provider_faulted.load(Ordering::Acquire)
            {
                self.provider_fault("provider disappeared while returning a frame grant");
                return;
            }
            let returned = match self.frame_cell.lock().as_ref().cloned() {
                Some(cell) if self.has_custom_frame_provider() => match cell.get() {
                    Some(provider) => {
                        provider.dealloc(addr, size);
                        true
                    }
                    None => false,
                },
                Some(_) | None => {
                    (**self.frame).dealloc(addr, size);
                    true
                }
            };
            if !returned {
                self.provider_fault("provider disappeared while returning a frame grant");
            }
        }
        // A service-context deallocation is valid only for a recorded owner
        // or an outstanding provider grant. An unknown raw address is ignored;
        // it must never become a Host free operation.
    }

    fn notify_frame_idle(&self, paddr: Paddr) {
        // A failed custom-provider admission can drop a provisional OSTD
        // reference while its owner record is still being published.  Do not
        // let that transient drop call the image's cache hook; the admission
        // path either restores the grant or faults the provider closed.
        if self.provider_callbacks_suppressed() {
            return;
        }
        if ownership::provider_managed(paddr) {
            if !self.active.load(Ordering::Acquire) || self.provider_faulted.load(Ordering::Acquire)
            {
                return;
            }
            match self.frame_cell.lock().as_ref().cloned() {
                Some(cell) if self.has_custom_frame_provider() => match cell.get() {
                    Some(provider) => provider.on_frame_idle(paddr),
                    None => self.provider_faulted.store(true, Ordering::Release),
                },
                Some(_) | None => (**self.frame).on_frame_idle(paddr),
            }
        } else if !matches!(ownership::detach_segment_if_idle(paddr), Ok(pages) if pages > 0) {
            let _ = ownership::cache_if_idle(paddr);
        }
    }

    fn frame_add_free_memory(&self, addr: Paddr, size: usize) {
        if self.grant_contains(addr, size) {
            if !self.active.load(Ordering::Acquire) || self.provider_faulted.load(Ordering::Acquire)
            {
                return;
            }
            match self.frame_cell.lock().as_ref().cloned() {
                Some(cell) if self.has_custom_frame_provider() => match cell.get() {
                    Some(provider) => provider.add_free_memory(addr, size),
                    None => self.provider_faulted.store(true, Ordering::Release),
                },
                Some(_) | None => (**self.frame).add_free_memory(addr, size),
            }
        }
    }

    /// Rolls back a physical range after OSTD rejected its public value.
    ///
    /// Built-in allocation commits directly to the domain, so the raw range
    /// and its charge are released together. A custom provider receives
    /// ranges through its opaque free-memory callback; those ranges remain
    /// domain-owned and are restored to the grant table rather than being
    /// returned to Host.
    fn rollback_unpublished_range(&self, start: Paddr, size: usize) {
        if self.has_custom_frame_provider() {
            if !self.active.load(Ordering::Acquire) || self.provider_faulted.load(Ordering::Acquire)
            {
                self.provider_fault("provider disappeared while rolling back a frame range");
                return;
            }
            let returned = match self.frame_cell.lock().as_ref().cloned() {
                Some(cell) => match cell.get() {
                    Some(provider) => {
                        provider.dealloc(start, size);
                        true
                    }
                    None => false,
                },
                None => {
                    (**self.frame).dealloc(start, size);
                    true
                }
            };
            if !returned {
                self.provider_fault("provider disappeared while rolling back a frame range");
                return;
            }
            if !self.grant_contains(start, size) && !self.restore_grant(start, size) {
                self.provider_fault("failed to restore a custom frame grant");
            }
            return;
        }

        host_ostd::mm::frame::dealloc_raw(start, size);
        if self.domain.release(size, false).is_err() {
            ::log::error!(
                "[framevisor] failed to roll back unpublished frame range for VM {}",
                self.vm_id
            );
        }
    }

    /// Rolls back a built-in segment after OSTD released a successfully-built
    /// prefix during `Segment::from_unused` failure.
    ///
    /// The prefix is already back in the Host allocator through its native
    /// `Frame` drops. Only the unconstructed suffix is still a raw allocation;
    /// deallocating the complete range here would double-free that prefix.
    fn rollback_partial_builtin_segment(&self, start: Paddr, size: usize, attempted_pages: usize) {
        let total_pages = size / PAGE_SIZE;
        let constructed_pages = attempted_pages.saturating_sub(1).min(total_pages);
        let constructed_bytes = constructed_pages * PAGE_SIZE;
        let suffix_start = start.saturating_add(constructed_bytes);
        let suffix_bytes = size.saturating_sub(constructed_bytes);
        if suffix_bytes != 0 {
            host_ostd::mm::frame::dealloc_raw(suffix_start, suffix_bytes);
        }
        if self.domain.release(size, false).is_err() {
            ::log::error!(
                "[framevisor] failed to roll back partial frame segment for VM {}",
                self.vm_id
            );
        }
    }

    /// Returns a freshly admitted built-in range after OSTD rejected its
    /// public value.
    ///
    /// The value has already been dropped by the caller. Its native Host OSTD
    /// drop path returned the physical range exactly once, so this helper must
    /// never issue a second raw deallocation. An ambiguous owner is retained
    /// rather than risking a Host double free.
    fn rollback_rejected_builtin_range(&self, start: Paddr, size: usize) {
        if !ownership::range_is_unowned(start, size) {
            ::log::error!(
                "[framevisor] retaining ambiguous rejected frame range for VM {}",
                self.vm_id
            );
            return;
        }
        if self.domain.release(size, false).is_err() {
            ::log::error!(
                "[framevisor] failed to roll back rejected frame charge for VM {}",
                self.vm_id
            );
        }
    }

    fn accept_frame(&self, frame: OstdFrame<dyn AnyFrameMeta>) -> bool {
        if !self.active.load(Ordering::Acquire) || self.provider_faulted.load(Ordering::Acquire) {
            return false;
        }
        let custom = self.has_custom_frame_provider();
        let cell = self.frame_cell.lock().as_ref().cloned();
        let provider = match cell.as_ref() {
            Some(cell) if custom => match cell.get() {
                Some(provider) => provider,
                None => {
                    self.provider_faulted.store(true, Ordering::Release);
                    return false;
                }
            },
            Some(_) | None => &**self.frame,
        };

        let paddr = frame.paddr();
        if custom {
            if !self.grant_contains(paddr, PAGE_SIZE) || ownership::has_owner(paddr) {
                return false;
            }
            if !self.consume_grant(paddr, PAGE_SIZE) {
                return false;
            }
        }
        #[cfg(ktest)]
        if self.reject_next_admission.swap(false, Ordering::AcqRel) {
            if custom && !self.restore_grant(paddr, PAGE_SIZE) {
                self.provider_fault("failed to restore a rejected frame grant");
            }
            return false;
        }
        if custom && !provider.on_frame_allocated(frame.clone()) {
            // The public frame is dropped by OSTD after this callback.
            // Restore the domain grant before that drop so the final
            // provider deallocation keeps the range reusable without
            // releasing its already-committed domain charge.
            if !self.restore_grant(paddr, PAGE_SIZE) {
                self.provider_fault("failed to restore a rejected frame grant");
            }
            return false;
        }
        let accepted = if custom {
            let _suppression = self.suppress_provider_callbacks();
            ownership::adopt_existing_frame_with_provider(frame, self.vm_id, &self.domain)
        } else {
            ownership::adopt_existing_frame_for_service(frame, self.vm_id, &self.domain)
        };
        if accepted {
            return true;
        }
        if custom {
            // The custom provider has already accepted a clone. Restoring
            // the raw grant here could make the same physical page appear
            // free while the provider still retains it, so fail closed and
            // leave the charge quarantined.
            self.provider_fault("frame grant became ambiguous during ownership admission");
        }
        false
    }

    fn accept_segment(&self, segment: OstdSegment<dyn AnyFrameMeta>) -> bool {
        if !self.active.load(Ordering::Acquire) || self.provider_faulted.load(Ordering::Acquire) {
            return false;
        }
        let custom = self.has_custom_frame_provider();
        let cell = self.frame_cell.lock().as_ref().cloned();
        let provider = match cell.as_ref() {
            Some(cell) if custom => match cell.get() {
                Some(provider) => provider,
                None => {
                    self.provider_faulted.store(true, Ordering::Release);
                    return false;
                }
            },
            Some(_) | None => &**self.frame,
        };

        let start = segment.paddr();
        let size = segment.size();
        if custom {
            // Validate the complete extent before notifying the image or
            // consuming its grant.  `Segment::from_unused` may otherwise
            // construct a value that overlaps an existing owner; discovering
            // that only during adoption would leave the provider callback and
            // grant table mutated after a rejected admission.
            if !size.is_multiple_of(PAGE_SIZE)
                || !start.is_multiple_of(PAGE_SIZE)
                || !self.grant_contains(start, size)
                || !ownership::range_is_unowned(start, size)
            {
                return false;
            }
            if !self.consume_grant(start, size) {
                return false;
            }
        }
        #[cfg(ktest)]
        if self.reject_next_admission.swap(false, Ordering::AcqRel) {
            if custom && !self.restore_grant(start, size) {
                self.provider_fault("failed to restore a rejected segment grant");
            }
            return false;
        }
        if custom && !provider.on_segment_allocated(segment.clone()) {
            // As with a rejected frame, restore the grant before OSTD
            // drops the public segment. Its member drops then return
            // the extent to the image provider while the domain charge
            // stays committed.
            if !self.restore_grant(start, size) {
                self.provider_fault("failed to restore a rejected segment grant");
            }
            return false;
        }
        let accepted = if custom {
            let _suppression = self.suppress_provider_callbacks();
            ownership::adopt_existing_segment_with_provider(segment, self.vm_id, &self.domain)
        } else {
            ownership::adopt_existing_segment_for_service(segment, self.vm_id, &self.domain)
        };
        if accepted {
            return true;
        }
        if custom {
            self.provider_fault("segment grant became ambiguous during ownership admission");
        }
        false
    }

    fn heap_alloc(&self, layout: Layout) -> Result<HeapSlot, AllocError> {
        if !self.active.load(Ordering::Acquire) || self.provider_faulted.load(Ordering::Acquire) {
            return Err(AllocError);
        }
        let slot = match self.heap_cell.lock().as_ref().cloned() {
            Some(cell) if self.has_custom_heap_provider() => {
                let Some(provider) = cell.get() else {
                    self.provider_faulted.store(true, Ordering::Release);
                    return Err(AllocError);
                };
                provider.alloc(layout)?
            }
            Some(_) | None => (**self.heap).alloc(layout)?,
        };
        if !heap_slot_matches_layout(layout, &slot) {
            if self.has_custom_heap_provider() {
                self.provider_fault("custom heap provider returned an invalid slot shape");
            }
            // Do not pass a malformed provider result back through an
            // arbitrary deallocation callback.  The provider owns that
            // opaque result, so retaining it is safer than guessing how its
            // slot map interprets the pointer.
            return Err(AllocError);
        }
        if self.has_custom_heap_provider() && !self.heap_slot_owned(&slot) {
            self.provider_fault("custom heap provider returned an unowned slot");
            return Err(AllocError);
        }
        Ok(slot)
    }

    fn heap_dealloc(&self, slot: HeapSlot) -> Result<(), AllocError> {
        if self.has_custom_heap_provider() && !self.heap_slot_owned(&slot) {
            return Err(AllocError);
        }
        if !self.active.load(Ordering::Acquire) || self.provider_faulted.load(Ordering::Acquire) {
            return Err(AllocError);
        }
        match self.heap_cell.lock().as_ref().cloned() {
            Some(cell) if self.has_custom_heap_provider() => {
                let Some(provider) = cell.get() else {
                    self.provider_faulted.store(true, Ordering::Release);
                    return Err(AllocError);
                };
                provider.dealloc(slot)
            }
            Some(_) | None => (**self.heap).dealloc(slot),
        }
    }

    fn heap_slot_owned(&self, slot: &HeapSlot) -> bool {
        self.heap_slot_range(slot).is_some_and(|(start, bytes)| {
            ownership::raw_range_belongs_to_vm(start, bytes, self.vm_id, &self.domain)
        })
    }

    fn heap_slot_range(&self, slot: &HeapSlot) -> Option<(Paddr, usize)> {
        if self.has_custom_heap_provider() {
            return Some((slot.paddr(), slot.info().size()));
        }
        builtin_heap_slot_range(slot)
    }
}

struct ProviderCallbackSuppression<'a> {
    allocator: &'a FrameVmAllocator,
}

impl Drop for ProviderCallbackSuppression<'_> {
    fn drop(&mut self) {
        self.allocator
            .provider_callbacks_suppressed
            .store(false, Ordering::Release);
    }
}

/// Returns whether a raw symbol is one of OSTD's private allocator helpers.
///
/// The service object can carry a hash-qualified Rust symbol, while tests and
/// hand-written images may use the plain name.  Matching the complete path
/// suffix keeps unrelated symbols from being redirected accidentally.
fn is_ostd_allocator_getter(name: &[u8], suffix: &[u8]) -> bool {
    name == suffix || (name.starts_with(b"_R") && name.ends_with(suffix))
}

/// Dispatches OSTD's frame allocator getter to the current FrameVM.
///
/// OSTD's getter returns a `'static` trait reference because its normal
/// provider is a process-wide symbol.  The returned object is therefore a
/// static dispatch object; only each operation selects the current service's
/// provider.  No FrameVM reference is fabricated with a lifetime extension.
pub(crate) extern "Rust" fn framevm_get_global_frame_allocator() -> &'static dyn GlobalFrameAllocator
{
    &FRAME_ALLOCATOR_DISPATCH
}

/// Dispatches OSTD's heap allocator getter to the current FrameVM.
pub(crate) extern "Rust" fn framevm_get_global_heap_allocator() -> &'static dyn GlobalHeapAllocator
{
    &HEAP_ALLOCATOR_DISPATCH
}

struct FrameAllocatorDispatch;

static FRAME_ALLOCATOR_DISPATCH: FrameAllocatorDispatch = FrameAllocatorDispatch;

impl GlobalFrameAllocator for FrameAllocatorDispatch {
    fn alloc(&self, layout: Layout) -> Option<Paddr> {
        crate::task::current_frame_vm()
            .and_then(|frame_vm| frame_vm.allocator().frame_alloc(layout))
    }

    fn dealloc(&self, addr: Paddr, size: usize) {
        if let Some(frame_vm) = crate::task::current_frame_vm() {
            frame_vm.allocator().frame_dealloc(addr, size);
        } else if let Some(vm_id) = ownership::vm_for_range(addr, size)
            && let Some(frame_vm) = crate::vm::get_vm_by_id(vm_id)
        {
            frame_vm.allocator().frame_dealloc(addr, size);
        }
    }

    fn add_free_memory(&self, addr: Paddr, size: usize) {
        if let Some(frame_vm) = crate::task::current_frame_vm() {
            frame_vm.allocator().frame_add_free_memory(addr, size);
        }
    }

    fn on_frame_allocated(&self, frame: OstdFrame<dyn AnyFrameMeta>) -> bool {
        crate::task::current_frame_vm()
            .map(|frame_vm| frame_vm.allocator().accept_frame(frame))
            .unwrap_or(false)
    }

    fn on_segment_allocated(&self, segment: OstdSegment<dyn AnyFrameMeta>) -> bool {
        crate::task::current_frame_vm()
            .map(|frame_vm| frame_vm.allocator().accept_segment(segment))
            .unwrap_or(false)
    }

    fn on_frame_idle(&self, paddr: Paddr) {
        if let Some(vm_id) = ownership::owner_vm(paddr)
            && let Some(frame_vm) = crate::vm::get_vm_by_id(vm_id)
        {
            frame_vm.allocator().notify_frame_idle(paddr);
        } else if ownership::has_owner(paddr) {
            let _ = ownership::cache_if_idle(paddr);
        } else if let Some(frame_vm) = crate::task::current_frame_vm()
            && !frame_vm.allocator().provider_callbacks_suppressed()
        {
            let allocator = frame_vm.allocator();
            if allocator.active.load(Ordering::Acquire)
                && !allocator.provider_faulted.load(Ordering::Acquire)
            {
                match allocator.frame_cell.lock().as_ref().cloned() {
                    Some(cell) if allocator.has_custom_frame_provider() => match cell.get() {
                        Some(provider) => provider.on_frame_idle(paddr),
                        None => allocator.provider_faulted.store(true, Ordering::Release),
                    },
                    Some(_) | None => (**allocator.frame).on_frame_idle(paddr),
                }
            }
        }
    }
}

struct HeapAllocatorDispatch;

static HEAP_ALLOCATOR_DISPATCH: HeapAllocatorDispatch = HeapAllocatorDispatch;

impl GlobalHeapAllocator for HeapAllocatorDispatch {
    fn alloc(&self, layout: Layout) -> Result<HeapSlot, AllocError> {
        crate::task::current_frame_vm()
            .map(|frame_vm| frame_vm.allocator().heap_alloc(layout))
            .unwrap_or(Err(AllocError))
    }

    fn dealloc(&self, slot: HeapSlot) -> Result<(), AllocError> {
        if let Some(frame_vm) = crate::task::current_frame_vm() {
            return frame_vm.allocator().heap_dealloc(slot);
        }
        let paddr = slot.paddr();
        let info = slot.info();
        for candidate in heap_slot_range_candidates(&slot).into_iter().flatten() {
            let Some(frame_vm) =
                ownership::vm_for_range(candidate.0, candidate.1).and_then(crate::vm::get_vm_by_id)
            else {
                continue;
            };
            let Ok(candidate_slot) = HeapSlot::from_raw_parts(paddr, info) else {
                continue;
            };
            if let Ok(()) = frame_vm.allocator().heap_dealloc(candidate_slot) {
                return Ok(());
            }
        }
        Err(AllocError)
    }
}

fn is_rust_allocator_symbol(name: &[u8], mangled_suffix: &[u8], plain_name: &[u8]) -> bool {
    name == plain_name || (name.starts_with(b"_R") && name.ends_with(mangled_suffix))
}

/// VM-local replacement for Rust's allocator entry point.
pub(crate) extern "Rust" fn framevm_alloc(size: usize, align: usize) -> *mut u8 {
    let Some(layout) = Layout::from_size_align(size, align).ok() else {
        return core::ptr::null_mut();
    };
    crate::task::current_frame_vm()
        .map(|frame_vm| frame_vm.alloc_service_heap(layout, false))
        .unwrap_or_default()
}

/// VM-local replacement for Rust's zeroed allocator entry point.
pub(crate) extern "Rust" fn framevm_alloc_zeroed(size: usize, align: usize) -> *mut u8 {
    let Some(layout) = Layout::from_size_align(size, align).ok() else {
        return core::ptr::null_mut();
    };
    crate::task::current_frame_vm()
        .map(|frame_vm| frame_vm.alloc_service_heap(layout, true))
        .unwrap_or_default()
}

/// VM-local replacement for Rust's deallocator entry point.
pub(crate) extern "Rust" fn framevm_dealloc(pointer: *mut u8, size: usize, align: usize) {
    let Some(layout) = Layout::from_size_align(size, align).ok() else {
        return;
    };
    if let Some(frame_vm) = crate::task::current_frame_vm() {
        let _ = frame_vm.dealloc_service_heap(pointer, layout);
        return;
    }

    // A destructor can run after the service task context has been removed.
    // Reconstruct the same OSTD slot shape so ownership, rather than the
    // current task, selects the FrameVM that must receive the free.
    let Some(info) = heap_slot_info(layout) else {
        return;
    };
    let Ok(slot) = HeapSlot::from_ptr_parts(pointer, info) else {
        return;
    };
    for candidate in heap_slot_range_candidates(&slot).into_iter().flatten() {
        let Some(frame_vm) =
            ownership::vm_for_range(candidate.0, candidate.1).and_then(crate::vm::get_vm_by_id)
        else {
            continue;
        };
        if frame_vm.dealloc_service_heap(pointer, layout) {
            return;
        }
    }
}

/// VM-local replacement for Rust's reallocator entry point.
pub(crate) extern "Rust" fn framevm_realloc(
    pointer: *mut u8,
    old_size: usize,
    align: usize,
    new_size: usize,
) -> *mut u8 {
    let Some(old_layout) = Layout::from_size_align(old_size, align).ok() else {
        return core::ptr::null_mut();
    };
    let Some(new_layout) = Layout::from_size_align(new_size, align).ok() else {
        return core::ptr::null_mut();
    };
    crate::task::current_frame_vm()
        .map(|frame_vm| frame_vm.realloc_service_heap(pointer, old_layout, new_layout))
        .unwrap_or_default()
}

/// Terminates only the current FrameVM service task after an infallible heap
/// allocation missed its fallible path.
///
/// This deliberately bypasses `poweroff`: that API is a guest-requested
/// terminal event and would schedule VM lifecycle cleanup.  An allocator
/// failure has no allocation-safe way to construct an error payload, so the
/// containment boundary only removes the faulting task and leaves the Host
/// and sibling FrameVMs running.
pub(crate) extern "Rust" fn framevm_alloc_error_handler(size: usize, align: usize) -> ! {
    crate::early_println!(
        "[framevisor] FrameVM heap allocation failed: size={} align={}",
        size,
        align
    );
    crate::task::scheduler::exit_current_task();
}

/// Adapts `alloc::alloc::handle_alloc_error` to the isolated service exit path.
pub(crate) extern "Rust" fn framevm_handle_alloc_error(layout: Layout) -> ! {
    framevm_alloc_error_handler(layout.size(), layout.align())
}

struct FrameProvider {
    domain: MemoryDomain,
    vm_id: VmId,
}

impl FrameProvider {
    const fn new(domain: MemoryDomain, vm_id: VmId) -> Self {
        Self { domain, vm_id }
    }

    fn reserve_raw(&self, layout: Layout) -> Option<Paddr> {
        if layout.size() == 0
            || !layout.size().is_multiple_of(PAGE_SIZE)
            || layout.align() < PAGE_SIZE
        {
            return None;
        }

        loop {
            let reservation = self.domain.reserve(layout.size()).ok()?;
            if let Some(paddr) = host_ostd::mm::frame::alloc_raw(layout) {
                if zero_raw(paddr, layout.size()).is_err() {
                    host_ostd::mm::frame::dealloc_raw(paddr, layout.size());
                    drop(reservation);
                    return None;
                }
                if reservation.commit().is_ok() {
                    return Some(paddr);
                }
                host_ostd::mm::frame::dealloc_raw(paddr, layout.size());
                return None;
            }
            drop(reservation);
            if !reclaim_after_oom(self.vm_id).ok()? {
                return None;
            }
        }
    }
}

impl GlobalFrameAllocator for FrameProvider {
    fn alloc(&self, layout: Layout) -> Option<Paddr> {
        self.reserve_raw(layout)
    }

    fn dealloc(&self, addr: Paddr, _size: usize) {
        // Public-reference drops are observed through `on_frame_idle`.
        if ownership::has_owner(addr) {
            let _ = ownership::cache_if_idle(addr);
        }
    }

    fn add_free_memory(&self, _addr: Paddr, _size: usize) {
        // Service code cannot donate physical memory to the Host allocator.
    }

    fn on_frame_allocated(&self, frame: OstdFrame<dyn AnyFrameMeta>) -> bool {
        ownership::adopt_existing_frame_for_service(frame, self.vm_id, &self.domain)
    }

    fn on_segment_allocated(&self, segment: OstdSegment<dyn AnyFrameMeta>) -> bool {
        ownership::adopt_existing_segment_for_service(segment, self.vm_id, &self.domain)
    }

    fn on_frame_idle(&self, paddr: Paddr) {
        if !matches!(ownership::detach_segment_if_idle(paddr), Ok(pages) if pages > 0) {
            let _ = ownership::cache_if_idle(paddr);
        }
    }
}

struct HeapProvider {
    domain: MemoryDomain,
    vm_id: VmId,
    state: Arc<SpinLock<HeapState>>,
}

impl HeapProvider {
    fn new(domain: MemoryDomain, vm_id: VmId, state: Arc<SpinLock<HeapState>>) -> Self {
        Self {
            domain,
            vm_id,
            state,
        }
    }

    fn alloc_slot(&self, layout: Layout) -> Result<HeapSlot, AllocError> {
        let slot_info = heap_slot_info(layout).ok_or(AllocError)?;
        if let SlotInfo::SlabSlot(slot_size) = slot_info {
            let class_index = small_slot_index(slot_size).ok_or(AllocError)?;
            {
                let mut state = self.state.lock();
                if let Some(page) = state.pages[class_index]
                    .iter_mut()
                    .find(|page| page.has_free_slot())
                {
                    return page.alloc().ok_or(AllocError);
                }
            }

            // The built-in heap keeps Host-side `Frame` wrappers in its
            // slab state. Always obtain those wrappers through FrameVisor's
            // Host allocator path, even while the service has installed a
            // custom OSTD Frame provider. Feeding an image-owned OSTD frame
            // into this state would make its native drop return the range to
            // the Host allocator instead of the image provider. The custom
            // provider remains available to explicit service Frame calls;
            // a custom heap provider owns its own refill policy separately.
            let mut options = FrameAllocOptions::new();
            options.zeroed(false);
            let frame = options
                .alloc_frame_for_vm(&self.domain, self.vm_id)
                .map_err(|_| AllocError)?;
            let (frame, owner) = frame.into_parts();
            let Some(owner) = owner else {
                return Err(AllocError);
            };
            let frame = Frame::new_with_owner(frame, owner);
            let mut page = SmallPage::new(frame, slot_size);
            let slot = page.alloc().ok_or(AllocError)?;
            let mut state = self.state.lock();
            if state.pages[class_index].try_reserve(1).is_err() {
                drop(state);
                drop(page);
                return Err(AllocError);
            }
            state.pages[class_index].push(page);
            return Ok(slot);
        }

        let SlotInfo::LargeSlot(slot_size) = slot_info else {
            return Err(AllocError);
        };

        {
            let mut state = self.state.lock();
            if let Some(allocation) = state
                .large
                .iter_mut()
                .find(|allocation| !allocation.in_use && allocation.slot_size == slot_size)
            {
                allocation.in_use = true;
                let base = allocation.segment.paddr();
                return HeapSlot::from_raw_parts(base, slot_info).map_err(|_| AllocError);
            }
        }

        let nframes = slot_size / PAGE_SIZE;
        // As with slab pages, retain a Host-owned FrameVisor segment in the
        // built-in heap state. This keeps its destructor on the same physical
        // ownership path regardless of the service's custom Frame provider.
        let segment = FrameAllocOptions::new().alloc_provider_segment_for_vm(
            &self.domain,
            self.vm_id,
            nframes,
        )?;
        let base = segment.paddr();
        let slot = HeapSlot::from_raw_parts(base, SlotInfo::LargeSlot(slot_size))
            .map_err(|_| AllocError)?;
        let segment = Segment::new_with_owner(segment, Arc::new(SegmentLease::new(base)));
        let mut state = self.state.lock();
        if state.large.try_reserve(1).is_err() {
            drop(state);
            drop(segment);
            return Err(AllocError);
        }
        state.large.push(LargeAllocation {
            segment,
            slot_size,
            in_use: true,
        });
        Ok(slot)
    }
}

impl GlobalHeapAllocator for HeapProvider {
    fn alloc(&self, layout: Layout) -> Result<HeapSlot, AllocError> {
        self.alloc_slot(layout)
    }

    fn dealloc(&self, slot: HeapSlot) -> Result<(), AllocError> {
        if let SlotInfo::SlabSlot(slot_size) = slot.info() {
            let class_index = small_slot_index(slot_size).ok_or(AllocError)?;
            let mut state = self.state.lock();
            let page = state.pages[class_index]
                .iter_mut()
                .find(|page| {
                    page.frame.paddr() <= slot.paddr()
                        && slot.paddr() < page.frame.paddr() + PAGE_SIZE
                })
                .ok_or(AllocError)?;
            return page.dealloc(slot);
        }

        let SlotInfo::LargeSlot(slot_size) = slot.info() else {
            return Err(AllocError);
        };
        let pointer = slot.paddr();
        let base = pointer;
        if slot_size % PAGE_SIZE != 0 || !base.is_multiple_of(PAGE_SIZE) {
            return Err(AllocError);
        }
        let mut state = self.state.lock();
        let allocation = state
            .large
            .iter_mut()
            .find(|allocation| {
                allocation.in_use
                    && allocation.slot_size == slot_size
                    && allocation.segment.paddr() == base
            })
            .ok_or(AllocError)?;
        allocation.in_use = false;
        Ok(())
    }
}

/// Returns the complete physical range represented by one heap slot.
///
/// Large slots use the same base pointer and page-rounded size as OSDK's
/// `HeapAllocator`; there is no FrameVisor-private header or pointer offset.
fn builtin_heap_slot_range(slot: &HeapSlot) -> Option<(Paddr, usize)> {
    let bytes = slot.info().size();
    Some((slot.paddr(), bytes))
}

fn heap_slot_range_candidates(slot: &HeapSlot) -> [Option<(Paddr, usize)>; 2] {
    [
        builtin_heap_slot_range(slot),
        matches!(slot.info(), SlotInfo::LargeSlot(_)).then_some((slot.paddr(), slot.info().size())),
    ]
}

/// Returns the slot shape used by the per-FrameVM heap provider.
pub(crate) extern "Rust" fn framevm_heap_slot_info(layout: Layout) -> Option<SlotInfo> {
    heap_slot_info(layout)
}

fn heap_slot_info(layout: Layout) -> Option<SlotInfo> {
    if let Some(slot_size) = small_slot_size(layout) {
        return Some(SlotInfo::SlabSlot(slot_size));
    }
    if layout.size() > PAGE_SIZE / 2 && layout.align() <= PAGE_SIZE {
        let size = layout.size().checked_add(PAGE_SIZE - 1)? & !(PAGE_SIZE - 1);
        return Some(SlotInfo::LargeSlot(size));
    }
    None
}

/// Checks the same slot contract that OSTD's `GlobalAlloc` dispatch enforces.
///
/// FrameVisor replaces that dispatch entry for a loaded service, so this
/// validation must remain at the VM-local shim boundary.  A malformed custom
/// provider result is retained and faults closed instead of being exposed as
/// an incorrectly sized or aligned Rust allocation.
fn heap_slot_matches_layout(layout: Layout, slot: &HeapSlot) -> bool {
    let Some(required_slot) = heap_slot_info(layout) else {
        return false;
    };
    required_slot.size() == slot.size()
        && slot.size() >= layout.size()
        && (slot.as_ptr() as usize).is_multiple_of(layout.align())
}

fn small_slot_size(layout: Layout) -> Option<usize> {
    SMALL_SLOT_SIZES
        .iter()
        .copied()
        .find(|size| layout.size().max(1) <= *size && layout.align() <= *size)
}

fn small_slot_index(slot_size: usize) -> Option<usize> {
    SMALL_SLOT_SIZES.iter().position(|size| *size == slot_size)
}

impl From<Error> for AllocError {
    fn from(_: Error) -> Self {
        AllocError
    }
}

pub(crate) fn reclaim_after_oom(vm_id: VmId) -> Result<bool> {
    if let Some(frame_vm) = crate::vm::get_vm_by_id(vm_id) {
        frame_vm.allocator().clear_empty_heap_pages();
    }
    ownership::reclaim_one_cached()
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn heap_provider_accounts_and_releases_page_range() {
        let vm_id = VmId::new(61);
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE * 2, 0).unwrap();
        let provider = HeapProvider::new(
            domain.clone(),
            vm_id,
            Arc::new(SpinLock::new(HeapState::new())),
        );
        let layout = Layout::from_size_align(8, 8).unwrap();

        let slot = provider.alloc(layout).unwrap();
        assert_eq!(slot.info(), SlotInfo::SlabSlot(8));
        assert_eq!(domain.stats().active, PAGE_SIZE);
        assert!(!ownership::provider_managed(slot.paddr()));

        provider.dealloc(slot).unwrap();
        provider.state.lock().clear_empty();
        assert_eq!(domain.stats().reusable, PAGE_SIZE);
        ownership::release_quiesced_for_vm(vm_id).unwrap();
        assert_eq!(domain.stats().committed, 0);
    }

    #[ktest]
    fn large_heap_slots_reuse_an_intact_segment() {
        let vm_id = VmId::new(63);
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE * 4, 0).unwrap();
        let provider = HeapProvider::new(
            domain.clone(),
            vm_id,
            Arc::new(SpinLock::new(HeapState::new())),
        );
        let layout = Layout::from_size_align(PAGE_SIZE + 1, PAGE_SIZE).unwrap();

        let first = provider.alloc(layout).unwrap();
        let first_pointer = first.as_ptr();
        let segment_bytes = first.info().size();
        assert!(!ownership::provider_managed(first.paddr()));
        provider.dealloc(first).unwrap();
        assert_eq!(domain.stats().active, segment_bytes);

        let second = provider.alloc(layout).unwrap();
        assert_eq!(second.as_ptr(), first_pointer);
        provider.dealloc(second).unwrap();

        provider.state.lock().clear_empty();
        assert_eq!(domain.stats().reusable, segment_bytes);
        assert_eq!(
            ownership::release_quiesced_for_vm(vm_id).unwrap(),
            segment_bytes / PAGE_SIZE
        );
        assert_eq!(domain.stats().committed, 0);
    }

    #[ktest]
    fn provider_symbols_route_default_heap_through_framevisor() {
        let allocator = FrameVmAllocator::new(
            MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap(),
            VmId::new(62),
        );
        assert!(allocator.resolve_symbol(FRAME_ALLOCATOR_REF).is_some());
        assert!(allocator.resolve_symbol(HEAP_ALLOCATOR_REF).is_some());
        assert!(allocator.resolve_symbol(HEAP_SLOT_MAP).is_some());
        assert!(allocator.resolve_symbol(FRAME_ALLOCATOR_GETTER).is_some());
        assert!(allocator.resolve_symbol(HEAP_ALLOCATOR_GETTER).is_some());
        assert!(allocator.resolve_symbol(HEAP_SLOT_MAP_GETTER).is_some());
        assert!(
            allocator
                .resolve_symbol(
                    b"_RNvNtNtNtCsfQwZ5Z8c8Wb_4ostd2mm5frame9allocator26get_global_frame_allocator"
                )
                .is_some()
        );
        // The default service image keeps Rust's shared heap so values that
        // cross the Host/service boundary retain one allocator lifetime.
        // Rust entry points are relocated only after an image explicitly
        // installs a custom OSTD heap provider.
        assert!(allocator.resolve_symbol(b"__rust_alloc").is_none());
        assert!(FrameVmAllocator::should_defer_symbol(b"__rust_alloc"));
        assert!(!FrameVmAllocator::should_defer_symbol(
            b"__rust_alloc_error_handler"
        ));
        assert!(
            allocator
                .resolve_symbol(b"_RNvCs2S033ihgi4L_7___rustc12___rust_alloc")
                .is_none()
        );
        assert!(
            allocator
                .resolve_symbol(b"_RNvCs2S033ihgi4L_7___rustc14___rust_realloc")
                .is_none()
        );
        assert!(allocator.resolve_symbol(b"not___rust_alloc").is_none());
    }

    #[ktest]
    fn ostd_allocator_surface_keeps_kernel_shape() {
        fn accept_frame<M: AnyFrameMeta>(_frame: Option<OstdFrame<M>>) {}
        fn accept_segment<M: AnyFrameMeta>(_segment: Option<OstdSegment<M>>) {}

        let frame_options = OstdFrameAllocOptions::new();
        let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();
        let frame_allocator: &dyn GlobalFrameAllocator = &FRAME_ALLOCATOR_DISPATCH;
        let heap_allocator: &dyn GlobalHeapAllocator = &HEAP_ALLOCATOR_DISPATCH;

        // These calls deliberately run without a bound service context and
        // therefore fail closed. Their signatures are the unchanged OSTD
        // provider contracts: no MemoryDomain or FrameVisor type appears at
        // the call site.
        assert!(frame_allocator.alloc(layout).is_none());
        assert!(heap_allocator.alloc(layout).is_err());
        let _ = frame_options;
        accept_frame::<()>(None);
        accept_segment::<()>(None);
        let _: Option<HeapSlot> = None;
    }

    #[ktest]
    fn large_heap_slot_lookup_uses_segment_base() {
        let layout = Layout::from_size_align(PAGE_SIZE + 1, PAGE_SIZE).unwrap();
        let info = heap_slot_info(layout).unwrap();
        assert_eq!(info, SlotInfo::LargeSlot(PAGE_SIZE * 2));
        let segment_base = Paddr::try_from(0x20_0000).unwrap();
        let slot = HeapSlot::from_raw_parts(segment_base, info).unwrap();

        assert_eq!(
            builtin_heap_slot_range(&slot),
            Some((segment_base, info.size()))
        );
    }

    #[ktest]
    fn heap_slot_validation_matches_ostd_contract() {
        let layout = Layout::from_size_align(32, 16).unwrap();
        let address = Paddr::try_from(0x30_0000).unwrap();

        let valid = HeapSlot::from_raw_parts(address, SlotInfo::SlabSlot(32)).unwrap();
        assert!(heap_slot_matches_layout(layout, &valid));

        let wrong_size = HeapSlot::from_raw_parts(address, SlotInfo::SlabSlot(64)).unwrap();
        assert!(!heap_slot_matches_layout(layout, &wrong_size));

        let misaligned = HeapSlot::from_raw_parts(address + 1, SlotInfo::SlabSlot(32)).unwrap();
        assert!(!heap_slot_matches_layout(layout, &misaligned));
    }

    #[ktest]
    fn allocator_dispatch_fails_closed_without_service_context() {
        let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();

        // The relocated OSTD getter is a static dispatch object, but it must
        // not silently allocate from the Host when a call arrives outside a
        // FrameVM service task.  A missing context is an allocation failure;
        // callers can then apply their normal OSTD error path.
        assert!(FRAME_ALLOCATOR_DISPATCH.alloc(layout).is_none());
        assert!(HEAP_ALLOCATOR_DISPATCH.alloc(layout).is_err());
        FRAME_ALLOCATOR_DISPATCH.dealloc(0xdead_beef, PAGE_SIZE);

        let allocator = FrameVmAllocator::new(
            MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap(),
            VmId::new(64),
        );
        allocator.deactivate();
        assert!(allocator.frame_alloc(layout).is_none());
        assert!(allocator.heap_alloc(layout).is_err());
        assert!(allocator.resolve_symbol(FRAME_ALLOCATOR_REF).is_none());
    }

    #[ktest]
    fn unpublished_builtin_range_rolls_back_domain_charge() {
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap();
        let allocator = FrameVmAllocator::new(domain.clone(), VmId::new(66));
        let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();
        let reservation = domain.reserve(PAGE_SIZE).unwrap();
        let paddr = host_ostd::mm::frame::alloc_raw(layout).unwrap();
        reservation.commit().unwrap();

        allocator.rollback_unpublished_range(paddr, PAGE_SIZE);

        assert_eq!(domain.stats().committed, 0);
        assert!(!ownership::has_owner(paddr));
    }

    #[ktest]
    fn rejected_builtin_frame_restores_domain_and_owner_state() {
        let vm_id = VmId::new(67);
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap();
        let allocator = FrameVmAllocator::new(domain.clone(), vm_id);
        let before = domain.stats();
        let owners_before = ownership::owner_count_for_vm(vm_id, &domain);

        // Exercise the real OSTD-shaped frame path: Host backing is acquired,
        // then the provider admission callback rejects the public value. The
        // rejection must drop the OSTD handle before releasing its charge.
        allocator.reject_next_admission_for_test();
        assert!(matches!(
            allocator.alloc_service_untyped_frame(false),
            Err(Error::NoMemory)
        ));

        assert_eq!(domain.stats(), before);
        assert_eq!(ownership::owner_count_for_vm(vm_id, &domain), owners_before);
        assert_eq!(ownership::release_quiesced_for_vm(vm_id).unwrap(), 0);
    }

    #[ktest]
    fn independent_allocator_instances_keep_domains_isolated() {
        let vm_a = VmId::new(68);
        let vm_b = VmId::new(69);
        let domain_a = MemoryDomain::new_with_minimum(PAGE_SIZE * 2, 0).unwrap();
        let domain_b = MemoryDomain::new_with_minimum(PAGE_SIZE * 2, 0).unwrap();
        let allocator_a = FrameVmAllocator::new(domain_a.clone(), vm_a);
        let allocator_b = FrameVmAllocator::new(domain_b.clone(), vm_b);

        let frame_a = allocator_a.alloc_service_untyped_frame(false).unwrap();
        let frame_b = allocator_b.alloc_service_untyped_frame(false).unwrap();
        assert_ne!(frame_a.paddr(), frame_b.paddr());
        assert_eq!(domain_a.stats().committed, PAGE_SIZE);
        assert_eq!(domain_b.stats().committed, PAGE_SIZE);
        assert_eq!(ownership::owner_count_for_vm(vm_a, &domain_a), 1);
        assert_eq!(ownership::owner_count_for_vm(vm_b, &domain_b), 1);

        drop(frame_a);
        drop(frame_b);
        let domain_b_before_a_release = domain_b.stats();
        let owners_b_before_a_release = ownership::owner_count_for_vm(vm_b, &domain_b);
        ownership::cache_idle_for_vm(vm_a).unwrap();
        assert_eq!(domain_a.stats().reusable, PAGE_SIZE);

        assert_eq!(ownership::release_service_owned_for_vm(vm_a).unwrap(), 1);
        assert_eq!(domain_a.stats().committed, 0);
        assert_eq!(ownership::owner_count_for_vm(vm_a, &domain_a), 0);
        assert_eq!(domain_b.stats(), domain_b_before_a_release);
        assert_eq!(
            ownership::owner_count_for_vm(vm_b, &domain_b),
            owners_b_before_a_release
        );

        ownership::cache_idle_for_vm(vm_b).unwrap();
        assert_eq!(ownership::release_service_owned_for_vm(vm_b).unwrap(), 1);
        assert_eq!(domain_b.stats().committed, 0);
        assert_eq!(ownership::owner_count_for_vm(vm_b, &domain_b), 0);
    }

    #[ktest]
    fn cross_domain_frame_deallocation_is_ignored() {
        let vm_a = VmId::new(70);
        let vm_b = VmId::new(71);
        let domain_a = MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap();
        let domain_b = MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap();
        domain_a.reserve(PAGE_SIZE).unwrap().commit().unwrap();
        let host_frame = host_ostd::mm::FrameAllocOptions::new()
            .alloc_frame()
            .unwrap();
        let paddr = host_frame.paddr();
        let (frame, lease) = ownership::adopt_frame(host_frame, vm_a, &domain_a).unwrap();
        let allocator_b = FrameVmAllocator::new(domain_b.clone(), vm_b);

        // Keep the legitimate service lease alive so VM A's page is not
        // already cached by its final-drop path. A malformed VM B deallocation
        // must not mutate A's cache or accounting.
        drop(frame);
        allocator_b.frame_dealloc(paddr, PAGE_SIZE);
        assert_eq!(domain_a.stats().reusable, 0);
        assert_eq!(
            ownership::owner_of(paddr),
            Some(ownership::FrameOwner::FrameVm(vm_a))
        );

        drop(lease);
        assert_eq!(domain_a.stats().reusable, PAGE_SIZE);
        ownership::release_cached_page(paddr, vm_a).unwrap();
        assert_eq!(domain_a.stats().committed, 0);
    }

    #[ktest]
    fn loader_segment_does_not_anchor_its_service_image() {
        let vm_id = VmId::new(65);
        let domain = MemoryDomain::new_with_minimum(PAGE_SIZE * 2, 0).unwrap();
        let allocator = FrameVmAllocator::new(domain.clone(), vm_id);
        let segment = allocator.alloc_loader_segment(2, |_| (), false).unwrap();
        let start = segment.paddr();

        drop(segment);
        assert_eq!(ownership::detach_segment_if_idle(start).unwrap(), 2);
        assert_eq!(domain.stats().reusable, PAGE_SIZE * 2);
        allocator.quiesce();
        allocator.deactivate();

        assert!(!ownership::has_service_owned_for_vm(vm_id));
        assert_eq!(ownership::release_quiesced_for_vm(vm_id).unwrap(), 2);
        assert_eq!(domain.stats().committed, 0);
        assert_eq!(ownership::owner_of(start), None);
    }

    #[ktest]
    fn provider_cells_without_owned_resources_do_not_anchor_image() {
        let allocator = FrameVmAllocator::new(
            MemoryDomain::new_with_minimum(PAGE_SIZE, 0).unwrap(),
            VmId::new(72),
        );

        // An image-local provider cell is a borrowed pointer into the image,
        // not an owner of physical memory. The image may retire when no grant
        // or provider-managed frame has been recorded for it.
        allocator
            .custom_frame_provider
            .store(true, Ordering::Release);
        assert!(!allocator.has_retained_opaque_state());
        assert!(allocator.deactivate_if_quiescent());
        assert!(!allocator.active.load(Ordering::Acquire));
    }
}
