// SPDX-License-Identifier: MPL-2.0

//! DMA memory exposed through the OSTD-compatible FrameVisor surface.
//!
//! An x86-64 FrameVM with an assigned physical requester maps DMA memory into
//! that requester's isolated IOMMU domain. A FrameVM without an assignment
//! keeps the existing OSTD implementation used by simulated FrameV devices.

#[cfg(not(target_arch = "x86_64"))]
pub use host_ostd::mm::dma::*;

#[cfg(target_arch = "x86_64")]
mod x86 {
    use alloc::sync::Arc;
    use core::{fmt, marker::PhantomData, ops::Range};

    pub use host_ostd::mm::dma::{DmaDirection, FromAndToDevice, FromDevice, ToDevice};
    use host_ostd::{
        Error,
        mm::{
            Daddr, HasDaddr, HasPaddr, HasSize, Infallible, Paddr, Split, USegment, VmReader,
            VmWriter,
            dma::{
                DmaCoherent as HostDmaCoherent, DmaStream as HostDmaStream, PciDmaError,
                PciDmaSegment,
            },
            io::util::{HasVmReaderWriter, VmReaderWriterIdentity, VmReaderWriterResult},
        },
    };

    use crate::mm::{FrameAllocOptions, frame::segment::SegmentLease, ownership};

    enum StreamMapping<D: DmaDirection> {
        Assigned(PciDmaSegment, Option<Arc<SegmentLease>>),
        Simulated(HostDmaStream<D>, Option<Arc<SegmentLease>>),
    }

    /// A streaming DMA mapping selected from the current FrameVM's devices.
    pub struct DmaStream<D: DmaDirection = FromAndToDevice> {
        mapping: StreamMapping<D>,
        direction: PhantomData<D>,
    }

    impl<D: DmaDirection> DmaStream<D> {
        /// Allocates a zero-initialized streaming DMA region.
        pub fn alloc(nframes: usize, is_cache_coherent: bool) -> Result<Self, Error> {
            const { assert!(D::CAN_WRITE_TO_DEVICE) };

            let dma = Self::alloc_uninit(nframes, is_cache_coherent)?;
            dma.writer()?.fill_zeros(dma.size());
            Ok(dma)
        }

        /// Allocates an uninitialized streaming DMA region.
        pub fn alloc_uninit(nframes: usize, _is_cache_coherent: bool) -> Result<Self, Error> {
            let Some(frame_vm) = current_frame_vm() else {
                // This module is the FrameVM service surface.  Falling back
                // to Host DMA here would let an unbound caller bypass the
                // domain ledger and the service-context check.
                return Err(Error::AccessDenied);
            };
            let segment = FrameAllocOptions::new()
                .zeroed(false)
                .alloc_segment(nframes)
                .map_err(map_framevisor_error)?;
            let (segment, owner) = segment.into_ostd_with_owner();
            let segment: USegment = segment.into();
            match frame_vm.pci_dma_domain() {
                Some(domain) => domain
                    .map(segment)
                    .map(|mapping| Self::assigned(mapping, owner))
                    .map_err(map_dma_error),
                None => {
                    // A virtual FrameV device accesses the service memory
                    // through the host, so it never needs a non-coherent
                    // bounce buffer.  Keep the FrameVM-owned segment as the
                    // mapping regardless of the caller's physical-device
                    // cache hint; the hint is meaningful only for a real
                    // device behind `PciDmaDomain`.
                    HostDmaStream::map(segment, true).map(|mapping| Self::simulated(mapping, owner))
                }
            }
        }

        /// Maps an owned untyped segment for streaming DMA.
        pub fn map(segment: USegment, _is_cache_coherent: bool) -> Result<Self, Error> {
            let Some(frame_vm) = current_frame_vm().or_else(|| {
                ownership::vm_for_range(segment.paddr(), segment.size())
                    .and_then(crate::vm::get_vm_by_id)
            }) else {
                return Err(Error::AccessDenied);
            };
            if !ownership::range_belongs_to_vm(
                segment.paddr(),
                segment.size(),
                frame_vm.id(),
                frame_vm.memory(),
            ) {
                return Err(Error::AccessDenied);
            }
            // The native service `USegment` carries no FrameVisor wrapper.
            // Once it is moved into Host OSTD's DMA mapping, its final frame
            // drops would otherwise call the Host allocator's callback rather
            // than the current service provider. Keep a FrameVisor lease
            // beside the mapping so the complete extent is detached through
            // `FrameOwners` after the mapping drops.
            let owner = Arc::new(SegmentLease::new(segment.paddr()));
            match frame_vm.pci_dma_domain() {
                Some(domain) => domain
                    .map(segment)
                    .map(|mapping| Self::assigned(mapping, Some(owner)))
                    .map_err(map_dma_error),
                None => {
                    // A virtual FrameV device directly observes the
                    // FrameVM-owned segment through the host.  No bounce
                    // allocation is needed in this path.
                    HostDmaStream::map(segment, true)
                        .map(|mapping| Self::simulated(mapping, Some(owner)))
                }
            }
        }

        /// Synchronizes a device-written range before CPU access.
        pub fn sync_from_device(&self, byte_range: Range<usize>) -> Result<(), Error> {
            const { assert!(D::CAN_READ_FROM_DEVICE) };
            match &self.mapping {
                StreamMapping::Assigned(_, _) => validate_range(byte_range, self.size()),
                StreamMapping::Simulated(mapping, _) => mapping.sync_from_device(byte_range),
            }
        }

        /// Synchronizes a CPU-written range before device access.
        pub fn sync_to_device(&self, byte_range: Range<usize>) -> Result<(), Error> {
            const { assert!(D::CAN_WRITE_TO_DEVICE) };
            match &self.mapping {
                StreamMapping::Assigned(_, _) => validate_range(byte_range, self.size()),
                StreamMapping::Simulated(mapping, _) => mapping.sync_to_device(byte_range),
            }
        }

        fn assigned(mapping: PciDmaSegment, owner: Option<Arc<SegmentLease>>) -> Self {
            Self {
                mapping: StreamMapping::Assigned(mapping, owner),
                direction: PhantomData,
            }
        }

        fn simulated(mapping: HostDmaStream<D>, owner: Option<Arc<SegmentLease>>) -> Self {
            Self {
                mapping: StreamMapping::Simulated(mapping, owner),
                direction: PhantomData,
            }
        }
    }

    impl<D: DmaDirection> fmt::Debug for DmaStream<D> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("DmaStream")
                .field("daddr", &self.daddr())
                .field("size", &self.size())
                .finish()
        }
    }

    impl<D: DmaDirection> HasDaddr for DmaStream<D> {
        fn daddr(&self) -> Daddr {
            match &self.mapping {
                StreamMapping::Assigned(mapping, _) => mapping.daddr(),
                StreamMapping::Simulated(mapping, _) => mapping.daddr(),
            }
        }
    }

    impl<D: DmaDirection> HasPaddr for DmaStream<D> {
        fn paddr(&self) -> Paddr {
            match &self.mapping {
                StreamMapping::Assigned(mapping, _) => mapping.paddr(),
                StreamMapping::Simulated(mapping, _) => mapping.paddr(),
            }
        }
    }

    impl<D: DmaDirection> HasSize for DmaStream<D> {
        fn size(&self) -> usize {
            match &self.mapping {
                StreamMapping::Assigned(mapping, _) => mapping.size(),
                StreamMapping::Simulated(mapping, _) => mapping.size(),
            }
        }
    }

    impl<D: DmaDirection> Split for DmaStream<D> {
        fn split(self, offset: usize) -> (Self, Self) {
            match self.mapping {
                StreamMapping::Assigned(mapping, owner) => {
                    let (first, second) = mapping.split(offset);
                    (
                        Self::assigned(first, owner.clone()),
                        Self::assigned(second, owner),
                    )
                }
                StreamMapping::Simulated(mapping, owner) => {
                    let (first, second) = mapping.split(offset);
                    (
                        Self::simulated(first, owner.clone()),
                        Self::simulated(second, owner),
                    )
                }
            }
        }
    }

    impl<D: DmaDirection> HasVmReaderWriter for DmaStream<D> {
        type Types = VmReaderWriterResult;

        fn reader(&self) -> Result<VmReader<'_, Infallible>, Error> {
            if !D::CAN_READ_FROM_DEVICE {
                return Err(Error::AccessDenied);
            }
            match &self.mapping {
                StreamMapping::Assigned(mapping, _) => Ok(mapping.segment().reader()),
                StreamMapping::Simulated(mapping, _) => mapping.reader(),
            }
        }

        fn writer(&self) -> Result<VmWriter<'_, Infallible>, Error> {
            if !D::CAN_WRITE_TO_DEVICE {
                return Err(Error::AccessDenied);
            }
            match &self.mapping {
                StreamMapping::Assigned(mapping, _) => Ok(mapping.segment().writer()),
                StreamMapping::Simulated(mapping, _) => mapping.writer(),
            }
        }
    }

    enum CoherentMapping {
        Assigned(PciDmaSegment, Option<Arc<SegmentLease>>),
        Simulated(HostDmaCoherent, Option<Arc<SegmentLease>>),
    }

    /// A coherent DMA mapping selected from the current FrameVM's devices.
    pub struct DmaCoherent {
        mapping: CoherentMapping,
    }

    impl DmaCoherent {
        /// Allocates a zero-initialized coherent DMA region.
        pub fn alloc(nframes: usize, is_cache_coherent: bool) -> Result<Self, Error> {
            let dma = Self::alloc_uninit(nframes, is_cache_coherent)?;
            dma.writer().fill_zeros(dma.size());
            Ok(dma)
        }

        /// Allocates an uninitialized coherent DMA region.
        pub fn alloc_uninit(nframes: usize, is_cache_coherent: bool) -> Result<Self, Error> {
            let Some(frame_vm) = current_frame_vm() else {
                return Err(Error::AccessDenied);
            };
            if !is_cache_coherent {
                // A non-coherent buffer needs an architecture-specific KVA
                // bounce path.  Do not silently allocate that backing from
                // Host while the FrameVM budget is active.
                return Err(Error::InvalidArgs);
            }
            let segment = FrameAllocOptions::new()
                .zeroed(false)
                .alloc_segment(nframes)
                .map_err(map_framevisor_error)?;
            let (segment, owner) = segment.into_ostd_with_owner();
            match frame_vm.pci_dma_domain() {
                Some(domain) => domain
                    .map(segment.into())
                    .map(|mapping| Self::assigned(mapping, owner))
                    .map_err(map_dma_error),
                None => HostDmaCoherent::from_segment(segment)
                    .map(|mapping| Self::simulated(mapping, owner)),
            }
        }

        fn assigned(mapping: PciDmaSegment, owner: Option<Arc<SegmentLease>>) -> Self {
            Self {
                mapping: CoherentMapping::Assigned(mapping, owner),
            }
        }

        fn simulated(mapping: HostDmaCoherent, owner: Option<Arc<SegmentLease>>) -> Self {
            Self {
                mapping: CoherentMapping::Simulated(mapping, owner),
            }
        }
    }

    impl fmt::Debug for DmaCoherent {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("DmaCoherent")
                .field("daddr", &self.daddr())
                .field("size", &self.size())
                .finish()
        }
    }

    impl HasDaddr for DmaCoherent {
        fn daddr(&self) -> Daddr {
            match &self.mapping {
                CoherentMapping::Assigned(mapping, _) => mapping.daddr(),
                CoherentMapping::Simulated(mapping, _) => mapping.daddr(),
            }
        }
    }

    impl HasPaddr for DmaCoherent {
        fn paddr(&self) -> Paddr {
            match &self.mapping {
                CoherentMapping::Assigned(mapping, _) => mapping.paddr(),
                CoherentMapping::Simulated(mapping, _) => mapping.paddr(),
            }
        }
    }

    impl HasSize for DmaCoherent {
        fn size(&self) -> usize {
            match &self.mapping {
                CoherentMapping::Assigned(mapping, _) => mapping.size(),
                CoherentMapping::Simulated(mapping, _) => mapping.size(),
            }
        }
    }

    impl Split for DmaCoherent {
        fn split(self, offset: usize) -> (Self, Self) {
            match self.mapping {
                CoherentMapping::Assigned(mapping, owner) => {
                    let (first, second) = mapping.split(offset);
                    (
                        Self::assigned(first, owner.clone()),
                        Self::assigned(second, owner),
                    )
                }
                CoherentMapping::Simulated(mapping, owner) => {
                    let (first, second) = mapping.split(offset);
                    (
                        Self::simulated(first, owner.clone()),
                        Self::simulated(second, owner),
                    )
                }
            }
        }
    }

    impl HasVmReaderWriter for DmaCoherent {
        type Types = VmReaderWriterIdentity;

        fn reader(&self) -> VmReader<'_, Infallible> {
            match &self.mapping {
                CoherentMapping::Assigned(mapping, _) => mapping.segment().reader(),
                CoherentMapping::Simulated(mapping, _) => mapping.reader(),
            }
        }

        fn writer(&self) -> VmWriter<'_, Infallible> {
            match &self.mapping {
                CoherentMapping::Assigned(mapping, _) => mapping.segment().writer(),
                CoherentMapping::Simulated(mapping, _) => mapping.writer(),
            }
        }
    }

    #[inline(always)]
    fn current_frame_vm() -> Option<Arc<crate::vm::FrameVm>> {
        crate::task::current_frame_vm()
    }

    #[inline(always)]
    fn validate_range(byte_range: Range<usize>, size: usize) -> Result<(), Error> {
        if byte_range.start > byte_range.end || byte_range.end > size {
            return Err(Error::InvalidArgs);
        }
        Ok(())
    }

    #[inline(always)]
    fn map_dma_error(error: PciDmaError) -> Error {
        match error {
            PciDmaError::InvalidAddress | PciDmaError::InvalidRequester => Error::InvalidArgs,
            PciDmaError::RequesterBusy => Error::AccessDenied,
            PciDmaError::AddressExhausted
            | PciDmaError::MappingConflict
            | PciDmaError::MappingRollbackFailed
            | PciDmaError::NoDmaRemapping
            | PciDmaError::NoQueuedInvalidation
            | PciDmaError::ResourceExhausted => Error::NotEnoughResources,
        }
    }

    #[inline(always)]
    fn map_framevisor_error(error: crate::Error) -> Error {
        match error {
            crate::Error::InvalidArgs => Error::InvalidArgs,
            crate::Error::NoMemory => Error::NoMemory,
            crate::Error::PageFault => Error::PageFault,
            crate::Error::AccessDenied => Error::AccessDenied,
            crate::Error::IoError => Error::IoError,
            crate::Error::NotEnoughResources => Error::NotEnoughResources,
            crate::Error::Overflow => Error::Overflow,
        }
    }

    #[cfg(ktest)]
    mod tests {
        use ostd::prelude::ktest;

        use super::*;

        #[ktest]
        fn unbound_dma_allocation_fails_closed() {
            assert!(matches!(
                DmaStream::<FromAndToDevice>::alloc_uninit(1, true),
                Err(Error::AccessDenied)
            ));
            assert!(matches!(
                DmaCoherent::alloc_uninit(1, true),
                Err(Error::AccessDenied)
            ));
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub use x86::*;
