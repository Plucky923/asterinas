// SPDX-License-Identifier: MPL-2.0

//! Memory management for FrameVisor.

use alloc::sync::Arc;

pub mod frame;
pub mod io;
pub(crate) mod page_prop;
pub(crate) mod page_table;
pub mod vm_space;

pub use frame::FrameAllocOptions;
use ostd::mm::Frame as OstdFrame;
pub use ostd::mm::{
    VmReader, VmWriter,
    frame::{meta::AnyFrameMeta as OstdAnyFrameMeta, untyped::AnyUFrameMeta as OstdAnyUFrameMeta},
};
pub use vm_space::{VmSpace, init_vm_space};

pub use self::{
    io::{FallibleVmRead, FallibleVmWrite},
    page_prop::{CachePolicy, PageFlags, PageProperty},
};
use crate::{
    Result,
    mm::frame::{init_frame, untyped::UFrame},
};

static SAFE_VM_SPACE: spin::Once<Arc<VmSpace>> = spin::Once::new();

/// Virtual addresses.
pub type Vaddr = usize;

/// Physical addresses.
pub type Paddr = usize;

/// Device addresses.
pub type Daddr = usize;

/// Frame wrapper for FrameVisor.
pub struct Frame<M: OstdAnyFrameMeta + ?Sized>(OstdFrame<M>);

impl<M: OstdAnyFrameMeta + ?Sized> Frame<M> {
    pub fn new_with_inner(ostd_frame: OstdFrame<M>) -> Self {
        Self(ostd_frame)
    }
}

impl<M: OstdAnyUFrameMeta> From<Frame<M>> for UFrame {
    fn from(frame: Frame<M>) -> Self {
        let ostd_uframe: ostd::mm::UFrame = frame.0.into();
        UFrame::new_with_inner(ostd_uframe)
    }
}

impl From<UFrame> for Frame<dyn OstdAnyFrameMeta> {
    fn from(uframe: UFrame) -> Self {
        let ostd_frame: OstdFrame<dyn OstdAnyFrameMeta> = uframe.inner().into();
        Frame::new_with_inner(ostd_frame)
    }
}

/// Initialize the memory management subsystem.
pub fn init_mm() -> Result<()> {
    init_vm_space();
    init_frame()?;
    Ok(())
}

/// Activate a long-lived VM space for kernel-only execution after guest teardown.
pub fn activate_safe_vm_space() {
    let safe_vm_space = SAFE_VM_SPACE.call_once(|| Arc::new(VmSpace::new()));
    safe_vm_space.activate();
}
