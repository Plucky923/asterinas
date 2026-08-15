//! Untyped frame wrappers exposed through the OSTD-compatible surface.

use alloc::sync::Arc;

pub use host_ostd::mm::frame::untyped::AnyUFrameMeta;
use host_ostd::mm::{
    UFrame as OstdUFrame,
    io::util::{HasVmReaderWriter, VmReaderWriterIdentity},
};

use crate::mm::{HasPaddr, HasSize, Paddr, ownership::FrameLease};

pub struct UFrame {
    inner: OstdUFrame,
    owner: Option<Arc<FrameLease>>,
}

impl UFrame {
    pub(crate) fn new_with_owner(ostd_frame: OstdUFrame, owner: Option<Arc<FrameLease>>) -> Self {
        Self {
            inner: ostd_frame,
            owner,
        }
    }

    pub(crate) fn into_parts(self) -> (OstdUFrame, Option<Arc<FrameLease>>) {
        (self.inner, self.owner)
    }
}

impl HasPaddr for UFrame {
    fn paddr(&self) -> Paddr {
        HasPaddr::paddr(&self.inner)
    }
}

impl HasSize for UFrame {
    fn size(&self) -> usize {
        HasSize::size(&self.inner)
    }
}

impl HasVmReaderWriter for UFrame {
    type Types = VmReaderWriterIdentity;

    fn reader(&self) -> host_ostd::mm::VmReader<'_, host_ostd::mm::Infallible> {
        self.inner.reader()
    }

    fn writer(&self) -> host_ostd::mm::VmWriter<'_, host_ostd::mm::Infallible> {
        self.inner.writer()
    }
}
