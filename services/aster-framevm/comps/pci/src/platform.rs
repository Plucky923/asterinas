// SPDX-License-Identifier: MPL-2.0

//! FrameVisor-backed PCI provider wiring.

use core::ops::RangeInclusive;

use ostd::Result;
pub(crate) use ostd::io::{PortRead, PortWrite};
pub(crate) type PciIoMem = ostd::pci::IoMem;

use crate::{PciCommonDevice, PciDeviceLocation, common_device::PciDeviceInitialization};

pub(crate) const MSIX_DEFAULT_MSG_ADDR: u32 = 0xfee0_0000;

pub(crate) fn construct_remappable_msix_address(remapping_index: u32) -> u32 {
    MSIX_DEFAULT_MSG_ADDR | (remapping_index << 5) | (1 << 4) | (1 << 3)
}

pub(crate) fn init() -> Option<RangeInclusive<u8>> {
    ostd::pci::current_bus_range()
}

pub(crate) fn device_initialization(_location: PciDeviceLocation) -> PciDeviceInitialization {
    PciDeviceInitialization::Host
}

pub(crate) fn reserve_for_assignment(device: PciCommonDevice) -> Option<PciCommonDevice> {
    Some(device)
}

pub(crate) fn read32(location: &PciDeviceLocation, offset: u32) -> Result<u32> {
    Ok(ostd::pci::read_config32(
        location.bus,
        location.device,
        location.function,
        offset,
    ))
}

pub(crate) fn write32(location: &PciDeviceLocation, offset: u32, value: u32) -> Result<()> {
    ostd::pci::write_config32(
        location.bus,
        location.device,
        location.function,
        offset,
        value,
    );
    Ok(())
}

pub(crate) fn allocate_memory_bar(default_base: u64, _size: u64) -> Option<u64> {
    Some(default_base)
}
