use ostd::mm::{frame::meta::AnyFrameMeta as OstdAnyFrameMeta, Segment as OstdSegment};
pub struct Segment<T: OstdAnyFrameMeta + ?Sized>(OstdSegment<T>);

impl<T: OstdAnyFrameMeta + ?Sized> Segment<T> {
    pub fn new_with_inner(ostd_segment: OstdSegment<T>) -> Self {
        Self(ostd_segment)
    }
}
