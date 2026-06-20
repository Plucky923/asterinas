//! Frame reference wrappers exposed through the OSTD-compatible surface.

use host_ostd::mm::{frame::FrameRef as OstdFrameRef, io::VmIo};

use crate::{
    mm::{
        Paddr,
        frame::{meta::AnyFrameMeta, untyped::AnyUFrameMeta},
    },
    prelude::Result,
};

/// A borrowed reference to a frame.
pub struct FrameRef<'a, M: AnyFrameMeta + ?Sized>(OstdFrameRef<'a, M>);

impl<'a, M: AnyFrameMeta + ?Sized> FrameRef<'a, M> {
    pub(crate) fn new_with_inner(inner: OstdFrameRef<'a, M>) -> Self {
        Self(inner)
    }
}

impl<M: AnyUFrameMeta + ?Sized> FrameRef<'_, M> {
    /// Reads bytes from this untyped frame.
    pub fn read_bytes(&self, offset: usize, data: &mut [u8]) -> Result<()> {
        self.0.read_bytes(offset, data).map_err(Into::into)
    }
}

impl<M: AnyFrameMeta + ?Sized> crate::mm::HasPaddr for FrameRef<'_, M> {
    fn paddr(&self) -> Paddr {
        host_ostd::mm::HasPaddr::paddr(&*self.0)
    }
}
