pub mod frame;
pub mod io;
pub(crate) mod page_prop;
pub(crate) mod page_table;
pub mod vm_space;

pub use frame::FrameAllocOptions;
pub use ostd::mm::{
    frame::{meta::AnyFrameMeta as OstdAnyFrameMeta, untyped::AnyUFrameMeta as OstdAnyUFrameMeta},
    VmReader, VmWriter,
};
use ostd::{early_println, mm::Frame as OstdFrame};
pub use vm_space::{init_vm_space, VmSpace};

pub use self::{
    io::{FallibleVmRead, FallibleVmWrite},
    page_prop::{CachePolicy, PageFlags, PageProperty},
};
use crate::mm::frame::{init_frame, untyped::UFrame};

/// Virtual addresses.
pub type Vaddr = usize;

/// Physical addresses.
pub type Paddr = usize;

/// Device addresses.
pub type Daddr = usize;

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

pub fn init_mm() {
    early_println!("[framevisor] Initializing MM...");
    init_vm_space();
    init_frame();
}
