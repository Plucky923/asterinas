// SPDX-License-Identifier: MPL-2.0

//! Virtual memory space management exposed through the OSTD-compatible surface.

use alloc::sync::Arc;
use core::ops::Range;

use host_ostd::mm::{
    VmSpace as OstdVmSpace,
    tlb::TlbFlushOp,
    vm_space::{
        Cursor as OstdCursor, CursorMut as OstdCursorMut, VmQueriedItem as OstdVmQueriedItem,
    },
};

use crate::{
    Result,
    mm::{
        CachePolicy, Fallible, Paddr, PageFlags, PageProperty, Vaddr, VmReader, VmWriter,
        frame::{FrameRef, untyped::UFrame},
    },
    sync::Once,
    task::atomic_mode::AsAtomicModeGuard,
};

/// A virtual memory space.
#[derive(Debug)]
pub struct VmSpace(Arc<OstdVmSpace>);

static FALLBACK_VM_SPACE: Once<Arc<OstdVmSpace>> = Once::new();

fn fallback_vm_space() -> &'static Arc<OstdVmSpace> {
    FALLBACK_VM_SPACE.call_once(|| Arc::new(OstdVmSpace::new()))
}

impl VmSpace {
    /// Create a new virtual memory space.
    pub fn new() -> Self {
        Self(Arc::new(OstdVmSpace::new()))
    }

    fn vmspace(&self) -> &Arc<OstdVmSpace> {
        &self.0
    }

    /// Gets an immutable cursor in the virtual address range.
    pub fn cursor<'a, G: AsAtomicModeGuard>(
        &'a self,
        guard: &'a G,
        va: &Range<Vaddr>,
    ) -> Result<Cursor<'a>> {
        Ok(Cursor::new_with_inner(
            self.vmspace().cursor(guard.get_inner(), va)?,
        ))
    }

    /// Create a mutable cursor for page table manipulation.
    pub fn cursor_mut<'a, G: AsAtomicModeGuard>(
        &'a self,
        guard: &'a G,
        va: &Range<Vaddr>,
    ) -> Result<CursorMut<'a>> {
        Ok(CursorMut::new_with_inner(
            self.vmspace().cursor_mut(guard.get_inner(), va)?,
        ))
    }

    /// Activate this virtual memory space.
    pub fn activate(self: &Arc<Self>) {
        self.vmspace().activate();
    }

    /// Create a reader for reading from user space.
    pub fn reader(&self, vaddr: Vaddr, len: usize) -> Result<VmReader<'_, Fallible>> {
        Ok(VmReader::new_with_inner(self.vmspace().reader(vaddr, len)?))
    }

    /// Create a writer for writing to user space.
    pub fn writer(&self, vaddr: Vaddr, len: usize) -> Result<VmWriter<'_, Fallible>> {
        Ok(VmWriter::new_with_inner(self.vmspace().writer(vaddr, len)?))
    }

    /// Create a reader/writer pair for the same user-space range.
    pub fn reader_writer(
        &self,
        vaddr: Vaddr,
        len: usize,
    ) -> Result<(VmReader<'_, Fallible>, VmWriter<'_, Fallible>)> {
        let (reader, writer) = self.vmspace().reader_writer(vaddr, len)?;
        Ok((
            VmReader::new_with_inner(reader),
            VmWriter::new_with_inner(writer),
        ))
    }
}

impl Default for VmSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for VmSpace {
    fn drop(&mut self) {
        fallback_vm_space().activate();
    }
}

/// The cursor for querying over the VM space without modifying it.
pub struct Cursor<'a>(OstdCursor<'a>);

impl<'a> Cursor<'a> {
    pub(crate) fn new_with_inner(cursor: OstdCursor<'a>) -> Self {
        Self(cursor)
    }

    /// Queries the mapping at the current virtual address.
    pub fn query(&mut self) -> Result<(Range<Vaddr>, Option<VmQueriedItem<'_>>)> {
        let (range, item) = self.0.query()?;
        Ok((range, item.map(VmQueriedItem::from)))
    }

    /// Moves the cursor forward to the next mapped virtual address.
    pub fn find_next(&mut self, len: usize) -> Option<Vaddr> {
        self.0.find_next(len)
    }

    /// Jumps to the virtual address.
    pub fn jump(&mut self, va: Vaddr) -> Result<()> {
        self.0.jump(va)?;
        Ok(())
    }

    /// Gets the virtual address of the current slot.
    pub fn virt_addr(&self) -> Vaddr {
        self.0.virt_addr()
    }
}

/// Mutable cursor for page table operations.
pub struct CursorMut<'a>(OstdCursorMut<'a>);

impl<'a> CursorMut<'a> {
    pub(crate) fn new_with_inner(cursor: OstdCursorMut<'a>) -> Self {
        Self(cursor)
    }

    /// Returns whether the current cursor slot is already mapped.
    pub fn is_mapped(&mut self) -> Result<bool> {
        let (_, item) = self.0.query()?;
        Ok(item.is_some())
    }

    /// Jumps to a virtual address in the cursor range.
    pub fn jump(&mut self, va: Vaddr) -> Result<()> {
        Ok(self.0.jump(va)?)
    }

    /// Map a frame at the current cursor position.
    pub fn map(&mut self, frame: UFrame, prop: PageProperty) {
        self.0.map(frame.inner(), prop.inner());
    }

    /// Unmaps pages from the current cursor position.
    pub fn unmap(&mut self, len: usize) -> usize {
        self.0.unmap(len)
    }

    /// Protects mapped pages from the current cursor position.
    pub fn protect(&mut self, len: usize, flags: PageFlags, cache: CachePolicy) -> bool {
        let start = self.0.virt_addr();
        let end = start + len;
        let mut protected = false;

        while self.0.virt_addr() < end {
            let remaining_len = end - self.0.virt_addr();
            if self
                .0
                .protect_next(remaining_len, |page_flags, cache_policy| {
                    *page_flags = flags;
                    *cache_policy = cache;
                })
                .is_none()
            {
                break;
            }
            protected = true;
        }

        if protected {
            self.0
                .flusher()
                .issue_tlb_flush(TlbFlushOp::for_range(start..end));
            self.0.flusher().dispatch_tlb_flush();
        }

        protected
    }
}

/// The result of a query over the VM space.
pub enum VmQueriedItem<'a> {
    /// The current slot is backed by allocated RAM.
    MappedRam {
        /// The mapped frame.
        frame: FrameRef<'a, dyn crate::mm::frame::untyped::AnyUFrameMeta>,
        /// The property of the slot.
        prop: PageProperty,
    },
    /// The current slot is backed by I/O memory.
    MappedIoMem {
        /// The physical address of the I/O memory.
        paddr: Paddr,
        /// The property of the slot.
        prop: PageProperty,
    },
}

impl<'a> From<OstdVmQueriedItem<'a>> for VmQueriedItem<'a> {
    fn from(item: OstdVmQueriedItem<'a>) -> Self {
        match item {
            OstdVmQueriedItem::MappedRam { frame, prop } => Self::MappedRam {
                frame: FrameRef::new_with_inner(frame),
                prop: PageProperty::new_with_inner(prop),
            },
            OstdVmQueriedItem::MappedIoMem { paddr, prop } => Self::MappedIoMem {
                paddr,
                prop: PageProperty::new_with_inner(prop),
            },
        }
    }
}

/// Initialize the VM space subsystem.
pub(super) fn init_vm_space() {
    fallback_vm_space().activate();
}
