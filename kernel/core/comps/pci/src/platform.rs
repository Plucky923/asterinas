// SPDX-License-Identifier: MPL-2.0

//! Host PCI config-space, BAR-allocation, and MSI-X provider wiring.

#[cfg(target_arch = "loongarch64")]
use core::alloc::Layout;

#[cfg_attr(target_arch = "loongarch64", path = "arch/loongarch/mod.rs")]
#[cfg_attr(target_arch = "riscv64", path = "arch/riscv/mod.rs")]
#[cfg_attr(target_arch = "x86_64", path = "arch/x86/mod.rs")]
mod architecture;

pub(crate) use ostd::arch::device::io_port::{PortRead, PortWrite};
pub(crate) type PciIoMem = ostd::io::IoMem;

pub(crate) use self::architecture::{
    MSIX_DEFAULT_MSG_ADDR, construct_remappable_msix_address, init, read32, write32,
};
use crate::{PciCommonDevice, PciDeviceLocation, common_device::PciDeviceInitialization};

pub(crate) fn device_initialization(location: PciDeviceLocation) -> PciDeviceInitialization {
    if crate::reservation::is_reserved_group_member(location) {
        PciDeviceInitialization::Reserved
    } else {
        PciDeviceInitialization::Host
    }
}

pub(crate) fn reserve_for_assignment(device: PciCommonDevice) -> Option<PciCommonDevice> {
    crate::reservation::try_reserve(device)
}

/// Returns the provider-selected base for a memory BAR.
pub(crate) fn allocate_memory_bar(default_base: u64, size: u64) -> Option<u64> {
    #[cfg(target_arch = "loongarch64")]
    {
        let _ = default_base;
        let size = usize::try_from(size).ok()?;
        let layout = Layout::from_size_align(size, size).ok()?;
        return architecture::alloc_mmio(layout).map(|address| address as u64);
    }

    #[cfg(not(target_arch = "loongarch64"))]
    {
        let _ = size;
        Some(default_base)
    }
}
