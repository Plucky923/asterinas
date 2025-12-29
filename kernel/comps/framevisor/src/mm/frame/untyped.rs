use ostd::mm::UFrame as OstdUFrame;

pub struct UFrame(OstdUFrame);

impl UFrame {
    pub fn inner(self) -> OstdUFrame {
        self.0
    }

    pub fn new_with_inner(ostd_frame: OstdUFrame) -> Self {
        Self(ostd_frame)
    }
}
