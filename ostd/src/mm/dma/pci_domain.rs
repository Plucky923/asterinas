// SPDX-License-Identifier: MPL-2.0

//! Isolated DMA address spaces for assigned PCI requesters.

use alloc::sync::Arc;
use core::{mem::ManuallyDrop, ops::Range};

use crate::{
    arch::iommu::{DmaRemappingDomain, IommuError, IommuPtConfig, PciDeviceLocation},
    irq,
    mm::{
        Daddr, HasDaddr, HasPaddr, HasSize, PAGE_SIZE, Paddr, Split, USegment,
        page_table::vaddr_range,
    },
    util::range_alloc::RangeAllocator,
};

/// Owns the right to attach one quiesced PCI requester to a DMA domain.
///
/// A lease is deliberately not `Clone` or `Copy`. The PCI reservation layer
/// creates one lease after it has disabled the device's bus mastering and
/// decoding, and the DMA domain consumes it. Keeping the lease in the domain
/// makes requester ownership part of the domain's lifetime rather than a
/// freely reusable BDF value.
pub struct PciRequesterLease {
    device: PciDeviceLocation,
    claimed: bool,
}

impl PciRequesterLease {
    /// Mints a lease for a requester that the caller has already quiesced.
    ///
    /// This is a low-level bridge for the PCI reservation implementation. A
    /// caller must hold the reservation for the complete requester group and
    /// must keep bus mastering, memory/I/O decoding, interrupts, and Host
    /// driver access quiesced until the consuming DMA domain is detached.
    /// The IOMMU also records the requester as pending, so a second lease or
    /// Host registration cannot claim the same BDF before this lease is
    /// consumed. Callers should prefer the PCI reservation layer's lease
    /// factory, which additionally prevents issuing two leases from one
    /// reservation generation.
    pub fn from_quiesced(bus: u8, device: u8, function: u8) -> Result<Self, PciDmaError> {
        let device = PciDeviceLocation {
            bus,
            device,
            function,
        };
        crate::arch::iommu::claim_pci_requester(device).map_err(PciDmaError::from)?;
        Ok(Self {
            device,
            claimed: true,
        })
    }
}

impl Drop for PciRequesterLease {
    fn drop(&mut self) {
        if self.claimed {
            crate::arch::iommu::release_pci_requester(self.device);
        }
    }
}

/// Describes why an isolated PCI DMA operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciDmaError {
    /// No device-address range is large enough for the mapping.
    AddressExhausted,
    /// An address, size, or alignment is invalid.
    InvalidAddress,
    /// The requester identifier is outside the PCI encoding limits.
    InvalidRequester,
    /// The requested IOVA conflicts with incompatible backing.
    MappingConflict,
    /// DMA remapping is unavailable.
    NoDmaRemapping,
    /// Synchronous queued invalidation is unavailable.
    NoQueuedInvalidation,
    /// The requester is already owned by another isolated domain.
    RequesterBusy,
    /// A failed mapping could not be rolled back completely.
    MappingRollbackFailed,
    /// A hardware or software domain resource is exhausted.
    ResourceExhausted,
}

/// Owns one independent DMA address space attached to a PCI requester.
///
/// Dropping the final reference first moves the requester to the deny-all
/// domain and synchronously invalidates translation caches.
pub struct PciDmaDomain {
    inner: DmaRemappingDomain,
    daddr_allocator: RangeAllocator,
    _requester_lease: PciRequesterLease,
}

impl PciDmaDomain {
    /// Creates an empty domain and attaches the leased requester to it.
    pub fn new(lease: PciRequesterLease) -> Result<Arc<Self>, PciDmaError> {
        let inner = DmaRemappingDomain::new().map_err(PciDmaError::from)?;
        // SAFETY: `PciRequesterLease` is minted by the PCI reservation
        // boundary only after the requester is quiesced, and it is consumed
        // here so the proof cannot be copied into a second domain.
        // The IOMMU consumes the pending claim when it attaches the requester.
        unsafe { inner.attach(lease.device) }.map_err(PciDmaError::from)?;
        let mut lease = lease;
        lease.claimed = false;

        let supported_range = vaddr_range::<IommuPtConfig>();
        let start = (*supported_range.start()).max(PAGE_SIZE);
        let end = *supported_range.end() & !(PAGE_SIZE - 1);
        if start >= end {
            return Err(PciDmaError::AddressExhausted);
        }

        Ok(Arc::new(Self {
            inner,
            daddr_allocator: RangeAllocator::new(start..end),
            _requester_lease: lease,
        }))
    }

    /// Maps an owned untyped segment into this domain.
    pub fn map(self: &Arc<Self>, segment: USegment) -> Result<PciDmaSegment, PciDmaError> {
        let size = segment.size();
        if size == 0 || !size.is_multiple_of(PAGE_SIZE) {
            return Err(PciDmaError::InvalidAddress);
        }

        let irq_guard = irq::disable_local();
        let daddr_range = self
            .daddr_allocator
            .alloc(size)
            .map_err(|_| PciDmaError::AddressExhausted)?;
        // SAFETY: `segment` owns an untyped, page-aligned physical range and
        // the returned mapping object retains it until every page is unmapped.
        let map_result = unsafe {
            self.inner
                .map_pages(daddr_range.start, segment.paddr(), size)
        };
        if let Err(error) = map_result {
            let error = PciDmaError::from(error);
            if matches!(error, PciDmaError::MappingRollbackFailed) {
                // A failed rollback may leave hardware pointing at part of
                // this physical range. Keep the backing alive along with the
                // leaked IOVA until the whole domain is detached; otherwise a
                // later Host allocation could turn the stale mapping into a
                // use-after-free DMA alias.
                core::mem::forget(segment);
            } else {
                self.daddr_allocator.free(daddr_range);
            }
            return Err(error);
        }
        drop(irq_guard);

        Ok(PciDmaSegment {
            domain: self.clone(),
            segment: Some(segment),
            daddr_range,
        })
    }
}

/// Registers one enumerated, non-assigned PCI requester in the shared Host
/// domain.
///
/// PCI discovery calls this after it has established that the function is not
/// reserved for assignment. Assigned requesters are intentionally left absent
/// until their reservation creates a [`PciRequesterLease`].
pub fn register_host_pci_requester(bus: u8, device: u8, function: u8) -> Result<(), PciDmaError> {
    if device > 31 || function > 7 {
        return Err(PciDmaError::InvalidRequester);
    }
    crate::arch::iommu::register_host_pci_requester(PciDeviceLocation {
        bus,
        device,
        function,
    })
    .map_err(PciDmaError::from)
}

/// Owns one mapped untyped segment and its device-address range.
pub struct PciDmaSegment {
    domain: Arc<PciDmaDomain>,
    segment: Option<USegment>,
    daddr_range: Range<Daddr>,
}

impl PciDmaSegment {
    /// Returns the mapped segment.
    pub fn segment(&self) -> &USegment {
        self.segment
            .as_ref()
            .expect("a live PCI DMA segment retains its backing")
    }
}

impl Drop for PciDmaSegment {
    fn drop(&mut self) {
        let _irq_guard = irq::disable_local();
        match self
            .domain
            .inner
            .unmap_pages(self.daddr_range.start, self.daddr_range.len())
        {
            Ok(()) => self.domain.daddr_allocator.free(self.daddr_range.clone()),
            Err(error) => {
                // Do not recycle the device-address range after a partial or
                // failed unmap: stale hardware mappings could otherwise alias
                // a later allocation. Leaking the range is the safe
                // containment policy for a destructor that cannot report an
                // error to its caller.
                crate::error!(
                    "failed to unmap PCI DMA segment at {:#x}..{:#x}: {:?}",
                    self.daddr_range.start,
                    self.daddr_range.end,
                    error
                );
                // Keep the physical backing alive because the hardware may
                // still hold a translation for part of the range. The IOVA
                // and the backing are intentionally leaked until an external
                // reset can prove the device no longer issues DMA.
                if let Some(segment) = self.segment.take() {
                    core::mem::forget(segment);
                }
            }
        }
    }
}

impl HasDaddr for PciDmaSegment {
    fn daddr(&self) -> Daddr {
        self.daddr_range.start
    }
}

impl HasPaddr for PciDmaSegment {
    fn paddr(&self) -> Paddr {
        self.segment().paddr()
    }
}

impl HasSize for PciDmaSegment {
    fn size(&self) -> usize {
        self.segment().size()
    }
}

impl Split for PciDmaSegment {
    fn split(self, offset: usize) -> (Self, Self) {
        assert!(offset.is_multiple_of(PAGE_SIZE));
        assert!(0 < offset && offset < self.size());

        let this = ManuallyDrop::new(self);
        // SAFETY: `this.segment` is moved exactly once and `this` is never
        // dropped after its fields are distributed to the two results.
        let segment = unsafe { core::ptr::read(&this.segment) }
            .expect("a live PCI DMA segment retains its backing");
        let (first_segment, second_segment) = segment.split(offset);
        let first_domain = this.domain.clone();
        // SAFETY: The original `Arc` is moved into one result, while the other
        // result owns the clone above.
        let second_domain = unsafe { core::ptr::read(&this.domain) };
        let first_daddr = this.daddr_range.start..this.daddr_range.start + offset;
        let second_daddr = this.daddr_range.start + offset..this.daddr_range.end;

        (
            Self {
                domain: first_domain,
                segment: Some(first_segment),
                daddr_range: first_daddr,
            },
            Self {
                domain: second_domain,
                segment: Some(second_segment),
                daddr_range: second_daddr,
            },
        )
    }
}

impl From<IommuError> for PciDmaError {
    fn from(error: IommuError) -> Self {
        match error {
            IommuError::AlreadyMapped => Self::MappingConflict,
            IommuError::InvalidAddress => Self::InvalidAddress,
            IommuError::InvalidDevice => Self::InvalidRequester,
            IommuError::NoIommu => Self::NoDmaRemapping,
            IommuError::NoQueuedInvalidation => Self::NoQueuedInvalidation,
            IommuError::DeviceBusy => Self::RequesterBusy,
            IommuError::MappingRollbackFailed => Self::MappingRollbackFailed,
            IommuError::NoDomainIds => Self::ResourceExhausted,
            IommuError::InvalidDomain
            | IommuError::ModificationError(_)
            | IommuError::NotMapped => Self::ResourceExhausted,
        }
    }
}
