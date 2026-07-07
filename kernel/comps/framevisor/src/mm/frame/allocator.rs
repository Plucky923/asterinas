//! Frame allocator wrappers exposed through the OSTD-compatible surface.

use host_ostd::{
    early_println,
    mm::{FrameAllocOptions as OstdFrameAllocOptions, frame::meta::AnyFrameMeta},
};

use crate::{
    mm::{Frame, frame::segment::Segment},
    prelude::Result,
};

pub struct FrameAllocOptions(OstdFrameAllocOptions);

impl Default for FrameAllocOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameAllocOptions {
    pub fn new() -> Self {
        Self(OstdFrameAllocOptions::new())
    }

    pub fn zeroed(&mut self, zeroed: bool) -> &mut Self {
        self.0.zeroed(zeroed);
        self
    }

    pub fn alloc_frame(&self) -> Result<Frame<()>> {
        let frame = self.0.alloc_frame()?;
        Ok(Frame::new_with_inner(frame))
    }

    pub fn alloc_frame_with<M: AnyFrameMeta>(&self, metadata: M) -> Result<Frame<M>> {
        let frame = self.0.alloc_frame_with(metadata)?;
        Ok(Frame::new_with_inner(frame))
    }

    pub fn alloc_segment(&self, nframes: usize) -> Result<Segment<()>> {
        let ostd_segment = self.0.alloc_segment(nframes)?;
        Ok(Segment::new_with_inner(ostd_segment))
    }

    pub fn alloc_segment_with<M: AnyFrameMeta, F>(
        &self,
        nframes: usize,
        metadata_fn: F,
    ) -> Result<Segment<M>>
    where
        F: FnMut(crate::mm::Paddr) -> M,
    {
        let segment = self.0.alloc_segment_with(nframes, metadata_fn)?;
        Ok(Segment::new_with_inner(segment))
    }
}

pub(super) fn init_frame_allocator() -> Result<()> {
    early_println!("[framevisor] Initializing frame allocator...");
    let _segment = FrameAllocOptions::new().alloc_segment(1)?;
    early_println!("[framevisor] Frame allocator initialized");
    Ok(())
}
