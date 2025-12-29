use ostd::mm::{
    frame::{meta::AnyFrameMeta as OstdAnyFrameMeta, untyped::AnyUFrameMeta as OstdAnyUFrameMeta},
    io::VmIo,
    Segment as OstdSegment,
};

use crate::{mm::Frame, prelude::Result};
pub struct Segment<M: OstdAnyFrameMeta + ?Sized>(OstdSegment<M>);

impl<M: OstdAnyUFrameMeta + ?Sized> Segment<M> {
    pub fn write_bytes(&self, offset: usize, data: &[u8]) -> Result<()> {
        self.0.write_bytes(offset, data).map_err(|err| err.into())
    }

    pub fn read_bytes(&self, offset: usize, data: &mut [u8]) -> Result<()> {
        self.0.read_bytes(offset, data).map_err(|err| err.into())
    }
}

impl<M: OstdAnyFrameMeta + ?Sized> Iterator for Segment<M> {
    type Item = Frame<M>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|frame| Frame::new_with_inner(frame))
    }
}

impl<M: OstdAnyFrameMeta + ?Sized> Segment<M> {
    pub fn new_with_inner(ostd_segment: OstdSegment<M>) -> Self {
        Self(ostd_segment)
    }
}
