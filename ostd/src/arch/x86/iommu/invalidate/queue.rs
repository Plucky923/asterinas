// SPDX-License-Identifier: MPL-2.0

use crate::{
    mm::{FrameAllocOptions, PAGE_SIZE, Segment, VmIo},
    prelude::*,
};

pub struct Queue {
    segment: Segment<()>,
    queue_size: usize,
    tail: usize,
}

impl Queue {
    pub fn append_descriptor(&mut self, descriptor: u128) {
        self.segment
            .write_val(self.tail * size_of::<u128>(), &descriptor)
            .unwrap();
        self.tail += 1;
        if self.tail == self.queue_size {
            // The IOMMU tail register names the next descriptor slot. Keeping
            // `queue_size` here would publish an out-of-range byte offset
            // after a submission ends at the final queue entry.
            self.tail = 0;
        }
    }

    pub fn tail(&self) -> usize {
        self.tail
    }

    pub fn size(&self) -> usize {
        self.queue_size
    }

    pub(crate) fn base_paddr(&self) -> Paddr {
        self.segment.paddr()
    }

    pub(super) fn new() -> Self {
        const DEFAULT_PAGES: usize = 1;
        let segment = FrameAllocOptions::new()
            .alloc_segment(DEFAULT_PAGES)
            .unwrap();
        Self {
            segment,
            queue_size: (DEFAULT_PAGES * PAGE_SIZE) / size_of::<u128>(),
            tail: 0,
        }
    }
}

#[cfg(ktest)]
mod tests {
    use super::*;
    use crate::prelude::ktest;

    #[ktest]
    fn tail_wraps_to_the_first_descriptor_slot() {
        let mut queue = Queue::new();

        for descriptor in 0..queue.size() {
            queue.append_descriptor(descriptor as u128);
        }
        assert_eq!(queue.tail(), 0);

        queue.append_descriptor(0);
        assert_eq!(queue.tail(), 1);
    }
}
