//! Segment wrappers around OSTD frame segments.

use host_ostd::mm::{
    Segment as OstdSegment,
    frame::{meta::AnyFrameMeta, untyped::AnyUFrameMeta},
    io::VmIo,
};

use crate::{mm::Frame, prelude::Result};
pub struct Segment<M: AnyFrameMeta + ?Sized>(OstdSegment<M>);

pub type USegment = Segment<dyn AnyUFrameMeta>;

impl<M: AnyUFrameMeta + ?Sized> Segment<M> {
    pub fn write_bytes(&self, offset: usize, data: &[u8]) -> Result<()> {
        self.0.write_bytes(offset, data).map_err(|err| err.into())
    }

    pub fn read_bytes(&self, offset: usize, data: &mut [u8]) -> Result<()> {
        self.0.read_bytes(offset, data).map_err(|err| err.into())
    }
}

impl<M: AnyFrameMeta + ?Sized> Iterator for Segment<M> {
    type Item = Frame<M>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|frame| Frame::new_with_inner(frame))
    }
}

impl<M: AnyFrameMeta + ?Sized> Segment<M> {
    pub(crate) fn new_with_inner(ostd_segment: OstdSegment<M>) -> Self {
        Self(ostd_segment)
    }
}

impl<M: AnyFrameMeta + ?Sized> crate::mm::HasPaddr for Segment<M> {
    fn paddr(&self) -> crate::mm::Paddr {
        host_ostd::mm::HasPaddr::paddr(&self.0)
    }
}

impl<M: AnyFrameMeta + ?Sized> crate::mm::HasSize for Segment<M> {
    fn size(&self) -> usize {
        host_ostd::mm::HasSize::size(&self.0)
    }
}
