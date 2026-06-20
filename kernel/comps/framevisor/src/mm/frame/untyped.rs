//! Untyped frame wrappers exposed through the OSTD-compatible surface.

use host_ostd::mm::UFrame as OstdUFrame;
pub use host_ostd::mm::frame::untyped::AnyUFrameMeta;

use crate::mm::{HasPaddr, HasSize, Paddr};

pub struct UFrame(OstdUFrame);

impl UFrame {
    pub(crate) fn inner(self) -> OstdUFrame {
        self.0
    }

    pub(crate) fn new_with_inner(ostd_frame: OstdUFrame) -> Self {
        Self(ostd_frame)
    }
}

impl HasPaddr for UFrame {
    fn paddr(&self) -> Paddr {
        host_ostd::mm::HasPaddr::paddr(&self.0)
    }
}

impl HasSize for UFrame {
    fn size(&self) -> usize {
        host_ostd::mm::HasSize::size(&self.0)
    }
}
