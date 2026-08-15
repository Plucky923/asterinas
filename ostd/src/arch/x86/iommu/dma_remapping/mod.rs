// SPDX-License-Identifier: MPL-2.0

pub use context_table::RootTable;
pub use second_stage::IommuPtConfig;
use spin::Once;

use self::context_table::{ContextTableError, DomainId, HOST_DOMAIN_ID};
use super::{IommuError, invalidate::QUEUE};
use crate::{
    arch::iommu::registers::{CapabilitySagaw, IOMMU_REGS},
    info,
    mm::Daddr,
    prelude::Paddr,
    sync::{LocalIrqDisabled, SpinLock},
    warn,
};

mod context_table;
mod second_stage;

pub fn has_dma_remapping() -> bool {
    PAGE_TABLE.get().is_some()
}

/// PCI device Location
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PciDeviceLocation {
    /// Bus number
    pub bus: u8,
    /// Device number with max 31
    pub device: u8,
    /// Device number with max 7
    pub function: u8,
}

impl PciDeviceLocation {
    const MAX_DEVICE: u8 = 31;
    const MAX_FUNCTION: u8 = 7;

    fn validate(self) -> Result<(), ContextTableError> {
        if self.device > Self::MAX_DEVICE || self.function > Self::MAX_FUNCTION {
            return Err(ContextTableError::InvalidDeviceId);
        }
        Ok(())
    }
}

/// Owns one independent VT-d second-stage address space.
///
/// The domain is non-cloneable. Dropping it first moves every attached
/// requester to the deny-all domain and synchronously invalidates translation
/// caches before releasing its page tables.
pub(crate) struct DmaRemappingDomain {
    id: DomainId,
}

impl DmaRemappingDomain {
    pub(crate) fn new() -> Result<Self, IommuError> {
        if QUEUE.get().is_none() {
            return Err(IommuError::NoQueuedInvalidation);
        }
        let table = PAGE_TABLE.get().ok_or(IommuError::NoIommu)?;
        let id = table.lock().create_domain().map_err(map_error)?;
        Ok(Self { id })
    }

    /// Attaches a quiesced requester to this domain.
    ///
    /// # Safety
    ///
    /// The caller must own the complete requester group, must have disabled
    /// bus mastering and interrupts, and must prevent concurrent Host-driver
    /// access until the domain is detached.
    pub(crate) unsafe fn attach(&self, device: PciDeviceLocation) -> Result<(), IommuError> {
        let table = PAGE_TABLE.get().ok_or(IommuError::NoIommu)?;
        table
            .lock()
            .attach_device(device, self.id)
            .map_err(map_error)?;
        invalidate_dma_caches();
        Ok(())
    }

    /// Maps one contiguous untyped physical range into the domain.
    ///
    /// # Safety
    ///
    /// The complete physical range must remain untyped and alive until the
    /// matching [`Self::unmap_pages`] call.
    pub(crate) unsafe fn map_pages(
        &self,
        daddr: Daddr,
        paddr: Paddr,
        size: usize,
    ) -> Result<(), IommuError> {
        if size == 0 || !size.is_multiple_of(crate::mm::PAGE_SIZE) {
            return Err(IommuError::InvalidAddress);
        }
        daddr.checked_add(size).ok_or(IommuError::InvalidAddress)?;
        paddr.checked_add(size).ok_or(IommuError::InvalidAddress)?;

        let table = PAGE_TABLE.get().ok_or(IommuError::NoIommu)?;
        let mut table = table.lock();
        let mut mapped_size = 0;
        while mapped_size < size {
            // SAFETY: The caller guarantees that the whole range remains
            // untyped and alive through the matching unmap operation.
            let result = unsafe { table.map(self.id, daddr + mapped_size, paddr + mapped_size) };
            if let Err(error) = result {
                let mut rollback_failed = false;
                for rollback_offset in (0..mapped_size).step_by(crate::mm::PAGE_SIZE) {
                    if let Err(rollback_error) = table.unmap(self.id, daddr + rollback_offset) {
                        rollback_failed = true;
                        crate::error!(
                            "failed to roll back DMA mapping at {:#x}: {:?}",
                            daddr + rollback_offset,
                            rollback_error
                        );
                    }
                }
                drop(table);
                invalidate_dma_caches();
                return Err(if rollback_failed {
                    IommuError::MappingRollbackFailed
                } else {
                    map_error(error)
                });
            }
            mapped_size += crate::mm::PAGE_SIZE;
        }
        drop(table);
        invalidate_dma_caches();
        Ok(())
    }

    pub(crate) fn unmap_pages(&self, daddr: Daddr, size: usize) -> Result<(), IommuError> {
        if size == 0 || !size.is_multiple_of(crate::mm::PAGE_SIZE) {
            return Err(IommuError::InvalidAddress);
        }
        daddr.checked_add(size).ok_or(IommuError::InvalidAddress)?;

        let table = PAGE_TABLE.get().ok_or(IommuError::NoIommu)?;
        let mut table = table.lock();
        for offset in (0..size).step_by(crate::mm::PAGE_SIZE) {
            table.unmap(self.id, daddr + offset).map_err(map_error)?;
        }
        drop(table);
        invalidate_dma_caches();
        Ok(())
    }
}

impl Drop for DmaRemappingDomain {
    fn drop(&mut self) {
        let Some(table) = PAGE_TABLE.get() else {
            return;
        };
        let detached_domain = match table.lock().detach_domain(self.id) {
            Ok(detached_domain) => detached_domain,
            Err(error) => {
                crate::error!(
                    "failed to detach DMA-remapping domain {} during drop: {:?}",
                    self.id,
                    error
                );
                return;
            }
        };
        let domain_id = detached_domain.id;
        invalidate_dma_caches();
        drop(detached_domain);
        table.lock().recycle_domain_id(domain_id);
    }
}

/// Registers an enumerated Host requester in the shared Host domain.
pub(crate) fn register_host_pci_requester(device: PciDeviceLocation) -> Result<(), IommuError> {
    let Some(table) = PAGE_TABLE.get() else {
        return Ok(());
    };
    table
        .lock()
        .attach_device(device, HOST_DOMAIN_ID)
        .map_err(map_error)?;
    invalidate_dma_caches();
    Ok(())
}

/// Claims an unregistered requester for a soon-to-be-created isolated domain.
pub(crate) fn claim_pci_requester(device: PciDeviceLocation) -> Result<(), IommuError> {
    let Some(table) = PAGE_TABLE.get() else {
        return Ok(());
    };
    table.lock().claim_device(device).map_err(map_error)
}

/// Releases an unconsumed requester claim.
pub(crate) fn release_pci_requester(device: PciDeviceLocation) {
    let Some(table) = PAGE_TABLE.get() else {
        return;
    };
    table.lock().release_device_claim(device);
}

/// Maps a device address to a physical address.
///
/// The physical address should point to a page containing untyped, non-sensitive data that can be
/// accessed by the device.
///
/// # Safety
///
/// While the physical address is mapped as the device address (i.e. from calling this method to
/// calling [`unmap`]), it must point to an untyped memory page. Otherwise, the device may corrupt
/// kernel data, which could lead to memory safety issues.
pub unsafe fn map(daddr: Daddr, paddr: Paddr) -> Result<(), IommuError> {
    let Some(table) = PAGE_TABLE.get() else {
        return Err(IommuError::NoIommu);
    };

    let mut locked_table = table.lock();
    // SAFETY: The safety is upheld by the caller.
    unsafe { locked_table.map(HOST_DOMAIN_ID, daddr, paddr) }.map_err(map_error)
}

/// Unmaps a device address.
///
/// This method will fail if the device address is not mapped (by [`map`]) before.
pub fn unmap(daddr: Daddr) -> Result<(), IommuError> {
    let Some(table) = PAGE_TABLE.get() else {
        return Err(IommuError::NoIommu);
    };

    let mut locked_table = table.lock();
    locked_table
        .unmap(HOST_DOMAIN_ID, daddr)
        .map_err(map_error)?;
    drop(locked_table);
    invalidate_dma_caches();
    Ok(())
}

pub fn init() {
    if !IOMMU_REGS
        .get()
        .unwrap()
        .lock()
        .read_capability()
        .supported_adjusted_guest_address_widths()
        .contains(CapabilitySagaw::AGAW_39BIT_3LP)
    {
        warn!("3-level page tables not supported, disabling DMA remapping");
        return;
    }

    // Every enumerated ordinary Host requester is attached to one shared Host
    // domain. Reserved assignment requesters stay without a context entry
    // until a reservation creates an isolated domain; after teardown they are
    // explicitly moved to the deny-all domain.
    //
    // TODO: The BIOS reserves some memory regions as DMA targets and lists them in the Reserved
    // Memory Region Reporting (RMRR) structures. These regions must be mapped for the hardware or
    // firmware to function properly. For more details, see Intel(R) Virtualization Technology for
    // Directed I/O (Revision 5.0), 3.16 Handling Requests to Reserved System Memory.
    PAGE_TABLE.call_once(|| SpinLock::new(RootTable::new()));

    // Enable DMA remapping.
    let mut iommu_regs = IOMMU_REGS.get().unwrap().lock();
    iommu_regs.enable_dma_remapping(PAGE_TABLE.get().unwrap());
    info!("DMA remapping enabled");
}

fn invalidate_dma_caches() {
    IOMMU_REGS
        .get()
        .expect("DMA remapping requires IOMMU registers")
        .lock()
        .invalidate_dma_caches();
}

fn map_error(error: ContextTableError) -> IommuError {
    match error {
        ContextTableError::ModificationError(error) => IommuError::ModificationError(error),
        ContextTableError::AlreadyMapped => IommuError::AlreadyMapped,
        ContextTableError::InvalidAddress => IommuError::InvalidAddress,
        ContextTableError::InvalidDeviceId => IommuError::InvalidDevice,
        ContextTableError::DeviceBusy => IommuError::DeviceBusy,
        ContextTableError::InvalidDomain => IommuError::InvalidDomain,
        ContextTableError::NoDomainIds => IommuError::NoDomainIds,
        ContextTableError::NotMapped => IommuError::NotMapped,
    }
}

// TODO: Currently `map()` or `unmap()` could be called in both task and interrupt
// contexts (e.g., within the virtio-blk module), potentially leading to deadlocks.
// Once this issue is resolved, `LocalIrqDisabled` is no longer needed.
static PAGE_TABLE: Once<SpinLock<RootTable, LocalIrqDisabled>> = Once::new();
