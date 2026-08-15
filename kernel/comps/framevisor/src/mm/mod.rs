// SPDX-License-Identifier: MPL-2.0

//! Memory management exposed through the OSTD-compatible surface.

pub mod dma;
pub mod frame;
pub mod io;
pub(crate) mod ownership;
pub(crate) mod page_prop;
pub(crate) mod page_table;
pub(crate) mod provider;

use alloc::sync::Arc;

pub use frame::{
    FrameAllocOptions, FrameRef,
    segment::{Segment, USegment},
    untyped::UFrame,
};
use host_ostd::mm::{
    Frame as OstdFrame,
    io::util::{HasVmReaderWriter, VmReaderWriterIdentity},
};
pub use host_ostd::mm::{
    HasDaddr, HasPaddr, HasPaddrRange, HasSize, KERNEL_VADDR_RANGE, MAX_USERSPACE_VADDR, PAGE_SIZE,
    Split,
    frame::{meta::AnyFrameMeta, untyped::AnyUFrameMeta},
};
use ownership::FrameLease;

pub use self::{
    io::{
        Fallible, FallibleVmRead, FallibleVmWrite, Infallible, PodAtomic, PodOnce, VmIo, VmIoFill,
        VmIoOnce, VmReader, VmWriter,
    },
    page_prop::{CachePolicy, PageFlags, PageProperty},
};
use crate::vm::VmId;

/// Virtual addresses.
pub type Vaddr = usize;

/// Physical addresses.
pub type Paddr = usize;

/// Device addresses.
pub type Daddr = usize;

/// Allocates physical backing for a Host service-loader transaction.
///
/// This is a Host-control-plane entry, not part of the service-facing OSTD
/// facade. The returned segment is still a native Host OSTD value because the
/// loader owns its virtual mapping; its pages are admitted and tracked by the
/// selected FrameVM domain before they are published to the image.
#[doc(hidden)]
pub fn alloc_service_segment(
    vm_id: VmId,
    nframes: usize,
) -> host_ostd::Result<host_ostd::loader::SectionBacking> {
    let frame_vm = crate::vm::get_vm_by_id(vm_id).ok_or(host_ostd::Error::InvalidArgs)?;
    let segment = FrameAllocOptions::new()
        .alloc_service_segment_for_vm(frame_vm.memory(), vm_id, nframes)
        .map_err(map_framevisor_error)?;
    Ok(host_ostd::loader::SectionBacking::from_segment(segment))
}

fn map_framevisor_error(error: crate::Error) -> host_ostd::Error {
    match error {
        crate::Error::InvalidArgs => host_ostd::Error::InvalidArgs,
        crate::Error::NoMemory => host_ostd::Error::NoMemory,
        crate::Error::PageFault => host_ostd::Error::PageFault,
        crate::Error::AccessDenied => host_ostd::Error::AccessDenied,
        crate::Error::IoError => host_ostd::Error::IoError,
        crate::Error::NotEnoughResources => host_ostd::Error::NotEnoughResources,
        crate::Error::Overflow => host_ostd::Error::Overflow,
    }
}

/// A physical frame wrapper.
pub struct Frame<M: AnyFrameMeta + ?Sized> {
    inner: OstdFrame<M>,
    /// Keeps the FrameVisor owner record alive independently of the OSTD
    /// reference held by this value.  Host-only frames leave it empty.
    owner: Option<Arc<FrameLease>>,
}

impl<M: AnyFrameMeta + ?Sized> Frame<M> {
    pub(crate) fn new_with_inner(ostd_frame: OstdFrame<M>) -> Self {
        Self {
            inner: ostd_frame,
            owner: None,
        }
    }

    pub(crate) fn new_with_owner(ostd_frame: OstdFrame<M>, owner: Arc<FrameLease>) -> Self {
        Self {
            inner: ostd_frame,
            owner: Some(owner),
        }
    }

    pub(crate) fn into_parts(self) -> (OstdFrame<M>, Option<Arc<FrameLease>>) {
        (self.inner, self.owner)
    }

    /// Returns the metadata associated with this frame.
    pub fn meta(&self) -> &M
    where
        M: AnyFrameMeta + Sized,
    {
        self.inner.meta()
    }

    /// Returns the number of live OSTD references to this physical frame.
    pub fn reference_count(&self) -> u64 {
        self.inner.reference_count()
    }

    /// Borrows this frame without creating another owning service handle.
    pub fn borrow(&self) -> FrameRef<'_, M> {
        FrameRef::new_with_inner(self.inner.borrow())
    }
}

impl<M: AnyUFrameMeta + ?Sized> HasVmReaderWriter for Frame<M> {
    type Types = VmReaderWriterIdentity;

    fn reader(&self) -> VmReader<'_, Infallible> {
        self.inner.reader()
    }

    fn writer(&self) -> VmWriter<'_, Infallible> {
        self.inner.writer()
    }
}

impl<M: AnyFrameMeta + ?Sized> Clone for Frame<M> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            owner: self.owner.clone(),
        }
    }
}

impl<M: AnyFrameMeta + ?Sized> HasPaddr for Frame<M> {
    fn paddr(&self) -> Paddr {
        HasPaddr::paddr(&self.inner)
    }
}

impl<M: AnyFrameMeta + ?Sized> HasSize for Frame<M> {
    fn size(&self) -> usize {
        HasSize::size(&self.inner)
    }
}

impl<M: AnyUFrameMeta> From<Frame<M>> for UFrame {
    fn from(frame: Frame<M>) -> Self {
        let (inner, owner) = frame.into_parts();
        let ostd_uframe: host_ostd::mm::UFrame = inner.into();
        UFrame::new_with_owner(ostd_uframe, owner)
    }
}

impl<M: AnyFrameMeta> From<Frame<M>> for Frame<dyn AnyFrameMeta> {
    fn from(frame: Frame<M>) -> Self {
        let (inner, owner) = frame.into_parts();
        let inner = OstdFrame::<dyn AnyFrameMeta>::from_unsized(inner);
        match owner {
            Some(owner) => Self::new_with_owner(inner, owner),
            None => Self::new_with_inner(inner),
        }
    }
}

impl From<UFrame> for Frame<dyn AnyFrameMeta> {
    fn from(uframe: UFrame) -> Self {
        let (inner, owner) = uframe.into_parts();
        let ostd_frame: OstdFrame<dyn AnyFrameMeta> = inner.into();
        match owner {
            Some(owner) => Frame::new_with_owner(ostd_frame, owner),
            None => Frame::new_with_inner(ostd_frame),
        }
    }
}
