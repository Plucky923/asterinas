use ostd::mm::UFrame as OstdUFrame;

pub struct UFrame(OstdUFrame);

impl UFrame {
    pub fn inner(self) -> OstdUFrame {
        self.0
    }
}
