// SPDX-License-Identifier: MPL-2.0

//! Retained DMA access to existing Image allocations on coherent x86 devices.
//!
//! This lending interface preserves the Image's existing untyped byte access.
//! It does not transfer an exclusive shared-pool grant or create frame handles.
//! Only registered Image DMA pages may be borrowed. Their registration cannot
//! retire, and their grant cannot be reclaimed, until the last lease ends.

use core::{
    fmt,
    ops::Range,
    sync::atomic::{Ordering, fence},
};

use super::guest_memory::{GuestMemory, MemoryPin};
pub use super::shared_buffer::DeviceAccess;
use crate::{
    Error, Result,
    mm::{Daddr, HasDaddr, HasSize, dma},
};

/// A checked physical-device view that retains its original Image allocation.
///
/// No CPU accessor or unrestricted backing handle is exposed. Drivers retain
/// this lease through every DMA access and callback, including cancellation.
pub struct GuestDmaLease {
    paddr: usize,
    len: usize,
    access: DeviceAccess,
    _pin: MemoryPin,
}

impl GuestDmaLease {
    /// Returns whether physical DMA addresses can be used without remapping.
    /// IOMMU and confidential-VM configurations are explicitly unsupported.
    pub fn is_supported() -> bool {
        dma::supports_borrowed_identity_dma()
    }

    pub(super) fn new(
        memory: &GuestMemory,
        paddr: u64,
        len: usize,
        access: DeviceAccess,
    ) -> Result<Self> {
        if len == 0 || !Self::is_supported() {
            return Err(Error::AccessDenied);
        }
        let address = usize::try_from(paddr).map_err(|_| Error::InvalidArgs)?;
        address.checked_add(len).ok_or(Error::Overflow)?;
        let pin = memory.pin_registered_dma(paddr, len)?;
        // Registered Image DMA storage has the existing writeback mapping.
        // On supported coherent x86 with no remapping, daddr equals paddr.
        // No duplicate DmaStream owner or second prepare_dma is constructed.
        Ok(Self {
            paddr: address,
            len,
            access,
            _pin: pin,
        })
    }

    /// Returns the operation's physical-device access mode.
    pub fn access(&self) -> DeviceAccess {
        self.access
    }

    /// Completes the coherent device-to-CPU synchronization for this range.
    pub fn sync_from_device(&self, range: Range<usize>) -> Result<()> {
        self.validate_range(range)?;
        if self.access != DeviceAccess::Write {
            return Err(Error::AccessDenied);
        }
        fence(Ordering::Acquire);
        Ok(())
    }

    /// Orders payload stores before the coherent device reads this range.
    pub fn sync_to_device(&self, range: Range<usize>) -> Result<()> {
        self.validate_range(range)?;
        if self.access != DeviceAccess::Read {
            return Err(Error::AccessDenied);
        }
        fence(Ordering::Release);
        Ok(())
    }

    fn validate_range(&self, range: Range<usize>) -> Result<()> {
        if range.start > range.end || range.end > self.len {
            return Err(Error::InvalidArgs);
        }
        Ok(())
    }
}

impl HasSize for GuestDmaLease {
    fn size(&self) -> usize {
        self.len
    }
}

impl HasDaddr for GuestDmaLease {
    fn daddr(&self) -> Daddr {
        self.paddr as Daddr
    }
}

impl fmt::Debug for GuestDmaLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GuestDmaLease")
            .field("paddr", &self.paddr)
            .field("len", &self.len)
            .field("access", &self.access)
            .finish_non_exhaustive()
    }
}
