// SPDX-License-Identifier: MPL-2.0

//! Virtual memory space management for FrameVisor.

use alloc::sync::Arc;
use core::ops::Range;

use ostd::{
    Result,
    mm::{
        Fallible, VmReader, VmSpace as OstdVmSpace, VmWriter, vm_space::CursorMut as OstdCursorMut,
    },
};

use crate::{
    mm::{Vaddr, frame::untyped::UFrame, page_prop::PageProperty},
    task::{atomic_mode::AsAtomicModeGuard, disable_preempt},
};

/// Virtual memory space wrapper for FrameVM.
#[derive(Debug)]
pub struct VmSpace(Arc<OstdVmSpace>);

impl VmSpace {
    /// Create a new virtual memory space.
    pub fn new() -> Self {
        Self(Arc::new(OstdVmSpace::new()))
    }

    fn vmspace(&self) -> &Arc<OstdVmSpace> {
        &self.0
    }

    /// Create a mutable cursor for page table manipulation.
    pub fn cursor_mut<'a, G: AsAtomicModeGuard>(
        &'a self,
        guard: &'a G,
        va: &Range<Vaddr>,
    ) -> Result<CursorMut<'a>> {
        self.vmspace()
            .cursor_mut(guard.get_inner(), va)
            .map(CursorMut::new_with_inner)
    }

    /// Activate this virtual memory space.
    pub fn activate(self: &Arc<Self>) {
        self.vmspace().activate();
    }

    /// Create a reader for reading from user space.
    pub fn reader(&self, vaddr: Vaddr, len: usize) -> Result<VmReader<'_, Fallible>> {
        self.vmspace().reader(vaddr, len)
    }

    /// Create a writer for writing to user space.
    pub fn writer(&self, vaddr: Vaddr, len: usize) -> Result<VmWriter<'_, Fallible>> {
        self.vmspace().writer(vaddr, len)
    }
}

impl Default for VmSpace {
    fn default() -> Self {
        Self::new()
    }
}

/// Mutable cursor for page table operations.
pub struct CursorMut<'a>(OstdCursorMut<'a>);

impl<'a> CursorMut<'a> {
    pub fn new_with_inner(cursor: OstdCursorMut<'a>) -> Self {
        Self(cursor)
    }

    /// Map a frame at the current cursor position.
    pub fn map(&mut self, frame: UFrame, prop: PageProperty) {
        self.0.map(frame.inner(), prop.inner());
    }
}

/// Initialize the VM space subsystem.
pub fn init_vm_space() {
    // Perform a quick sanity check by creating and activating a VM space.
    let vm_space = Arc::new(VmSpace::new());
    vm_space.activate();
}
