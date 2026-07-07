// SPDX-License-Identifier: MPL-2.0

//! Memory management exposed through the OSTD-compatible surface.

pub mod frame;
pub mod io;
pub(crate) mod page_prop;
pub(crate) mod page_table;
pub mod vm_space;

pub use frame::{
    FrameAllocOptions, FrameRef,
    segment::{Segment, USegment},
    untyped::UFrame,
};
use host_ostd::mm::Frame as OstdFrame;
pub use host_ostd::mm::{
    HasDaddr, HasPaddr, HasPaddrRange, HasSize, KERNEL_VADDR_RANGE, MAX_USERSPACE_VADDR, PAGE_SIZE,
    Split,
    frame::{meta::AnyFrameMeta, untyped::AnyUFrameMeta},
};
use vm_space::init_vm_space;
pub use vm_space::{Cursor, CursorMut, VmQueriedItem, VmSpace};

pub use self::{
    io::{
        Fallible, FallibleVmRead, FallibleVmWrite, Infallible, PodAtomic, PodOnce, VmIo, VmIoFill,
        VmIoOnce, VmReader, VmWriter,
    },
    page_prop::{CachePolicy, PageFlags, PageProperty},
};
use crate::{Result, mm::frame::init_frame};

/// Virtual addresses.
pub type Vaddr = usize;

/// Physical addresses.
pub type Paddr = usize;

/// Device addresses.
pub type Daddr = usize;

/// A physical frame wrapper.
pub struct Frame<M: AnyFrameMeta + ?Sized>(OstdFrame<M>);

impl<M: AnyFrameMeta + ?Sized> Frame<M> {
    pub(crate) fn new_with_inner(ostd_frame: OstdFrame<M>) -> Self {
        Self(ostd_frame)
    }
}

impl<M: AnyFrameMeta + ?Sized> HasPaddr for Frame<M> {
    fn paddr(&self) -> Paddr {
        HasPaddr::paddr(&self.0)
    }
}

impl<M: AnyFrameMeta + ?Sized> HasSize for Frame<M> {
    fn size(&self) -> usize {
        HasSize::size(&self.0)
    }
}

impl<M: AnyUFrameMeta> From<Frame<M>> for UFrame {
    fn from(frame: Frame<M>) -> Self {
        let ostd_uframe: host_ostd::mm::UFrame = frame.0.into();
        UFrame::new_with_inner(ostd_uframe)
    }
}

impl From<UFrame> for Frame<dyn AnyFrameMeta> {
    fn from(uframe: UFrame) -> Self {
        let ostd_frame: OstdFrame<dyn AnyFrameMeta> = uframe.inner().into();
        Frame::new_with_inner(ostd_frame)
    }
}

/// Initialize the memory management subsystem.
pub(crate) fn init_mm() -> Result<()> {
    init_vm_space();
    init_frame()?;
    Ok(())
}
