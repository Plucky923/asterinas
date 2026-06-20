// SPDX-License-Identifier: MPL-2.0

//! Memory management exposed through the OSTD-compatible surface.

use alloc::{boxed::Box, rc::Rc, sync::Arc};
use core::ops::Range;

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
    KERNEL_VADDR_RANGE, MAX_USERSPACE_VADDR, PAGE_SIZE,
    frame::{meta::AnyFrameMeta, untyped::AnyUFrameMeta},
};
use vm_space::init_vm_space;
pub use vm_space::{Cursor, CursorMut, VmQueriedItem, VmSpace};

pub use self::{
    io::{Fallible, FallibleVmRead, FallibleVmWrite, Infallible, PodAtomic, VmReader, VmWriter},
    page_prop::{CachePolicy, PageFlags, PageProperty},
};
use crate::{Result, mm::frame::init_frame};

/// Virtual addresses.
pub type Vaddr = usize;

/// Physical addresses.
pub type Paddr = usize;

/// Device addresses.
pub type Daddr = usize;

/// Memory objects that have a start physical address.
pub trait HasPaddr {
    /// Returns the start physical address of the memory object.
    fn paddr(&self) -> Paddr;
}

/// Memory objects that have a mapped address in the device address space.
pub trait HasDaddr {
    /// Returns the base address of the mapping in the device address space.
    fn daddr(&self) -> Daddr;
}

/// Memory objects that have a length in bytes.
pub trait HasSize {
    /// Returns the size of the memory object in bytes.
    fn size(&self) -> usize;
}

/// Memory objects that have a physical address range.
pub trait HasPaddrRange: HasPaddr + HasSize {
    /// Returns the end physical address of the memory object.
    fn end_paddr(&self) -> Paddr;

    /// Returns the physical address range of the memory object.
    fn paddr_range(&self) -> Range<Paddr>;
}

impl<T: HasPaddr + HasSize> HasPaddrRange for T {
    fn end_paddr(&self) -> Paddr {
        self.paddr() + self.size()
    }

    fn paddr_range(&self) -> Range<Paddr> {
        self.paddr()..self.end_paddr()
    }
}

macro_rules! impl_has_traits_for_ref_type {
    ($t:ty, $([$trait_name:ident, $fn_name:ident]),*) => {
        $(
            impl<T: $trait_name> $trait_name for $t {
                fn $fn_name(&self) -> usize {
                    (**self).$fn_name()
                }
            }
        )*
    };
    ($($t:ty),*) => {
        $(
            impl_has_traits_for_ref_type!($t, [HasPaddr, paddr], [HasDaddr, daddr], [HasSize, size]);
        )*
    };
}

impl_has_traits_for_ref_type!(&T, &mut T, Rc<T>, Arc<T>, Box<T>);

/// Memory objects that can be split into smaller parts.
pub trait Split: Sized + HasSize {
    /// Splits the memory object into two at the given byte offset.
    fn split(self, offset: usize) -> (Self, Self);
}

/// A physical frame wrapper.
pub struct Frame<M: AnyFrameMeta + ?Sized>(OstdFrame<M>);

impl<M: AnyFrameMeta + ?Sized> Frame<M> {
    pub(crate) fn new_with_inner(ostd_frame: OstdFrame<M>) -> Self {
        Self(ostd_frame)
    }
}

impl<M: AnyFrameMeta + ?Sized> HasPaddr for Frame<M> {
    fn paddr(&self) -> Paddr {
        host_ostd::mm::HasPaddr::paddr(&self.0)
    }
}

impl<M: AnyFrameMeta + ?Sized> HasSize for Frame<M> {
    fn size(&self) -> usize {
        host_ostd::mm::HasSize::size(&self.0)
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
