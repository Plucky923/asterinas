//! Segment wrappers around OSTD frame segments.

use alloc::sync::Arc;

use host_ostd::mm::{
    Segment as OstdSegment,
    frame::{meta::AnyFrameMeta, untyped::AnyUFrameMeta},
    io::{
        VmIo,
        util::{HasVmReaderWriter, VmReaderWriterIdentity},
    },
};

use crate::{
    mm::{Frame, HasPaddr, ownership, ownership::FrameLease},
    prelude::Result,
};

/// Keeps the per-page owner records alive until the last segment handle is
/// gone. The ownership table deliberately does not cache segment members
/// one page at a time because OSTD can detach them independently.
pub(crate) struct SegmentLease {
    start: usize,
    /// Keeps a converted frame's original lease alive. A `Frame` can be
    /// converted into a one-page `Segment` without another allocator callback,
    /// so the segment lease must inherit that frame lifetime explicitly.
    #[expect(
        dead_code,
        reason = "the field is intentionally retained as a drop guard"
    )]
    frame_owner: Option<Arc<FrameLease>>,
}

impl SegmentLease {
    pub(crate) const fn new(start: usize) -> Self {
        Self {
            start,
            frame_owner: None,
        }
    }

    fn from_frame(start: usize, frame_owner: Arc<FrameLease>) -> Self {
        Self {
            start,
            frame_owner: Some(frame_owner),
        }
    }
}

impl Drop for SegmentLease {
    fn drop(&mut self) {
        // The last lease proves that no FrameVisor segment or frame wrapper
        // still represents this extent. Native service segments can also have
        // been moved into a Host DMA mapping, whose drop callback cannot reach
        // the service allocator; require the hidden OSTD references to be
        // drained before clearing the extent marker in that case.
        let _ = ownership::detach_segment_if_idle(self.start);
    }
}

pub struct Segment<M: AnyFrameMeta + ?Sized> {
    inner: OstdSegment<M>,
    owner: Option<Arc<SegmentLease>>,
}

pub type USegment = Segment<dyn AnyUFrameMeta>;

impl<M: AnyUFrameMeta + ?Sized> Segment<M> {
    pub fn write_bytes(&self, offset: usize, data: &[u8]) -> Result<()> {
        self.inner
            .write_bytes(offset, data)
            .map_err(|err| err.into())
    }

    pub fn read_bytes(&self, offset: usize, data: &mut [u8]) -> Result<()> {
        self.inner
            .read_bytes(offset, data)
            .map_err(|err| err.into())
    }
}

impl<M: AnyUFrameMeta + ?Sized> HasVmReaderWriter for Segment<M> {
    type Types = VmReaderWriterIdentity;

    fn reader(&self) -> host_ostd::mm::VmReader<'_, host_ostd::mm::Infallible> {
        self.inner.reader()
    }

    fn writer(&self) -> host_ostd::mm::VmWriter<'_, host_ostd::mm::Infallible> {
        self.inner.writer()
    }
}

impl<M: AnyFrameMeta + ?Sized> Iterator for Segment<M> {
    type Item = Frame<M>;

    fn next(&mut self) -> Option<Self::Item> {
        let frame = self.inner.next()?;
        let owner = ownership::lease_for(frame.paddr());
        Some(match owner {
            Some(owner) => Frame::new_with_owner(frame, owner),
            None => Frame::new_with_inner(frame),
        })
    }
}

impl<M: AnyFrameMeta + ?Sized> Segment<M> {
    pub(crate) fn new_with_inner(ostd_segment: OstdSegment<M>) -> Self {
        Self {
            inner: ostd_segment,
            owner: None,
        }
    }

    pub(crate) fn new_with_owner(ostd_segment: OstdSegment<M>, owner: Arc<SegmentLease>) -> Self {
        Self {
            inner: ostd_segment,
            owner: Some(owner),
        }
    }
}

impl<M: AnyFrameMeta + ?Sized> Clone for Segment<M> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            owner: self.owner.clone(),
        }
    }
}

impl<M: AnyFrameMeta + ?Sized> crate::mm::Split for Segment<M> {
    fn split(self, offset: usize) -> (Self, Self) {
        let Self { inner, owner } = self;
        let (left, right) = inner.split(offset);
        (
            Self {
                inner: left,
                owner: owner.clone(),
            },
            Self {
                inner: right,
                owner,
            },
        )
    }
}

impl<M: AnyFrameMeta + ?Sized> Segment<M> {
    /// Moves the private backing while retaining the owner lease for an
    /// adapter that outlives the FrameVM-facing segment value (for example a
    /// DMA mapping).
    pub(crate) fn into_ostd_with_owner(self) -> (OstdSegment<M>, Option<Arc<SegmentLease>>) {
        (self.inner, self.owner)
    }
}

impl<M: AnyUFrameMeta> From<Segment<M>> for Segment<dyn AnyUFrameMeta> {
    fn from(segment: Segment<M>) -> Self {
        let Segment { inner, owner } = segment;
        let inner = OstdSegment::<dyn AnyUFrameMeta>::from(inner);
        Self { inner, owner }
    }
}

impl<M: AnyFrameMeta + ?Sized> From<Frame<M>> for Segment<M> {
    fn from(frame: Frame<M>) -> Self {
        let (inner, owner) = frame.into_parts();
        let start = HasPaddr::paddr(&inner);
        let owner = owner.map(|frame_owner| {
            // The owner record is known to be a FrameVM record for every
            // FrameVisor frame lease. Keep the lease even if a stale handle
            // races teardown; its drop path remains the only safe retry for
            // the original page.
            let _ = ownership::promote_frame_to_segment(start);
            Arc::new(SegmentLease::from_frame(start, frame_owner))
        });
        Self {
            inner: OstdSegment::from(inner),
            owner,
        }
    }
}

impl<M: AnyFrameMeta + ?Sized> HasPaddr for Segment<M> {
    fn paddr(&self) -> crate::mm::Paddr {
        HasPaddr::paddr(&self.inner)
    }
}

impl<M: AnyFrameMeta + ?Sized> crate::mm::HasSize for Segment<M> {
    fn size(&self) -> usize {
        host_ostd::mm::HasSize::size(&self.inner)
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;
    use crate::{mm::FrameAllocOptions, vm::MemoryDomain};

    #[ktest]
    fn frame_to_segment_preserves_domain_ownership() {
        let vm_id = crate::vm::VmId::new(80);
        let domain = MemoryDomain::new_with_minimum(crate::mm::PAGE_SIZE, 0).unwrap();
        let frame = FrameAllocOptions::new()
            .alloc_frame_for_vm(&domain, vm_id)
            .unwrap();
        let paddr = frame.paddr();

        let segment: Segment<()> = frame.into();
        drop(segment);

        assert_eq!(domain.stats().reusable, crate::mm::PAGE_SIZE);
        assert_eq!(ownership::release_quiesced_for_vm(vm_id).unwrap(), 1);
        assert_eq!(domain.stats().committed, 0);
        assert_eq!(ownership::owner_of(paddr), None);
    }
}
