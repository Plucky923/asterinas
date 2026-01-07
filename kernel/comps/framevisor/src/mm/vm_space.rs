use alloc::sync::Arc;
use core::ops::Range;

use ostd::{
    early_println,
    mm::{
        vm_space::CursorMut as OstdCursorMut, Fallible, VmReader, VmSpace as OstdVmSpace, VmWriter,
    },
    task::atomic_mode::AsAtomicModeGuard as OstdAsAtomicModeGuard,
    Error, Result,
};

use crate::{
    mm::{frame::untyped::UFrame, page_prop::PageProperty, Vaddr},
    task::{atomic_mode::AsAtomicModeGuard, disable_preempt},
};

#[derive(Debug)]
pub struct VmSpace(Arc<OstdVmSpace>);

impl VmSpace {
    pub fn new() -> Self {
        early_println!("[framevisor] Creating VM space...");
        let vmspace = OstdVmSpace::new();
        early_println!("[framevisor] VM space created: {:?}", vmspace);
        early_println!("[framevisor] DEBUG");
        Self(Arc::new(vmspace))
    }

    fn vmspace(&self) -> &Arc<OstdVmSpace> {
        &self.0
    }

    pub fn cursor_mut<'a, G: AsAtomicModeGuard>(
        &'a self,
        guard: &'a G,
        va: &Range<Vaddr>,
    ) -> Result<CursorMut<'a>> {
        early_println!("[framevisor] Creating mutable cursor for VM space...");
        self.vmspace()
            .cursor_mut(guard.get_inner(), va)
            .map(CursorMut::new_with_inner)
    }

    pub fn activate(self: &Arc<Self>) {
        self.vmspace().activate();
    }

    pub fn reader(&self, vaddr: Vaddr, len: usize) -> Result<VmReader<'_, Fallible>> {
        self.vmspace().reader(vaddr, len)
    }

    pub fn writer(&self, vaddr: Vaddr, len: usize) -> Result<VmWriter<'_, Fallible>> {
        self.vmspace().writer(vaddr, len)
    }
}

pub struct CursorMut<'a>(OstdCursorMut<'a>);

impl<'a> CursorMut<'a> {
    pub fn new_with_inner(cursor: OstdCursorMut<'a>) -> Self {
        Self(cursor)
    }

    pub fn map(&mut self, frame: UFrame, prop: PageProperty) {
        self.0.map(frame.inner(), prop.inner());
    }
}

impl Drop for CursorMut<'_> {
    fn drop(&mut self) {
        early_println!("[framevisor] Dropping VM space cursor...");
    }
}

pub fn init_vm_space() {
    let vm_space = Arc::new(VmSpace::new());
    let preempt_guard = disable_preempt();
    let cursor_mut = vm_space.cursor_mut(&preempt_guard, &(0..4096)).unwrap();
    drop(cursor_mut);
    vm_space.activate();
    early_println!("[framevisor] Initializing VM space...");
}
