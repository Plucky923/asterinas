use alloc::sync::Arc;
use core::ops::Range;

use ostd::{
    early_println,
    mm::{vm_space::CursorMut as OstdCursorMut, VmSpace as OstdVmSpace},
    task::atomic_mode::AsAtomicModeGuard as OstdAsAtomicModeGuard,
};

use crate::{
    mm::{frame::untyped::UFrame, page_prop::PageProperty, Vaddr},
    task::atomic_mode::AsAtomicModeGuard,
    Result,
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
        let inner = self.vmspace().cursor_mut(guard.inner(), va)?;

        Ok(CursorMut::new_with_inner(inner))
    }

    pub fn activate(self: &Arc<Self>) {
        early_println!("[framevisor] Activating VM space...");
        self.vmspace().activate();
        early_println!("[framevisor] VM space activated");
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

pub fn init_vm_space() {
    let vm_space = Arc::new(VmSpace::new());
    vm_space.activate();
    early_println!("[framevisor] Initializing VM space...");
}
