use ostd::{early_println, mm::FrameAllocOptions as OstdFrameAllocOptions};

use crate::{mm::frame::segment::Segment, prelude::Result};

pub struct FrameAllocOptions(OstdFrameAllocOptions);

impl FrameAllocOptions {
    pub fn new() -> Self {
        Self(OstdFrameAllocOptions::new())
    }

    pub fn alloc_segment(&self, nframes: usize) -> Result<Segment<()>> {
        let ostd_segment = self.0.alloc_segment(nframes).unwrap();
        Ok(Segment::new_with_inner(ostd_segment))
    }
}

pub fn init_frame_allocator() {
    early_println!("[framevisor] Initializing frame allocator...");
    let segment = FrameAllocOptions::new().alloc_segment(1).unwrap();
    early_println!("[framevisor] Frame allocator initialized");
}
