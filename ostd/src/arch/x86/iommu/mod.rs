// SPDX-License-Identifier: MPL-2.0

//! The IOMMU support.

// Set this module's log prefix for `ostd::log`.
macro_rules! __log_prefix {
    () => {
        "iommu: "
    };
}

mod dma_remapping;
mod fault;
mod interrupt_remapping;
mod invalidate;
mod registers;

pub(crate) use dma_remapping::{
    DmaRemappingDomain, IommuPtConfig, PciDeviceLocation, claim_pci_requester, has_dma_remapping,
    map, register_host_pci_requester, release_pci_requester, unmap,
};
pub(crate) use fault::resume_fault_reporting;
pub(in crate::arch) use interrupt_remapping::{
    IrtEntryHandle, alloc_irt_entry, has_interrupt_remapping,
};

use crate::{io::IoMemAllocatorBuilder, mm::page_table::PageTableError};

/// An enumeration representing possible errors related to IOMMU.
#[derive(Debug)]
pub(crate) enum IommuError {
    /// The device address is already mapped to incompatible backing.
    AlreadyMapped,
    /// An address is not page-aligned or overflows the supported range.
    InvalidAddress,
    /// The requester ID is invalid.
    InvalidDevice,
    /// The requester is already attached to another isolated domain.
    DeviceBusy,
    /// A failed mapping could not be rolled back completely.
    MappingRollbackFailed,
    /// The DMA-remapping domain does not exist.
    InvalidDomain,
    /// No IOMMU is available.
    NoIommu,
    /// Queued invalidation is unavailable.
    NoQueuedInvalidation,
    /// No unused hardware domain identifier remains.
    NoDomainIds,
    /// The device address is not mapped.
    NotMapped,
    /// Error encountered during modification of the page table.
    #[expect(dead_code)]
    ModificationError(PageTableError),
}

pub(crate) fn init(io_mem_builder: &IoMemAllocatorBuilder) -> Result<(), IommuError> {
    registers::init(io_mem_builder)?;
    invalidate::init();
    dma_remapping::init();
    interrupt_remapping::init();
    Ok(())
}
