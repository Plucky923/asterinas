// SPDX-License-Identifier: MPL-2.0

//! Provider-independent PCI enumeration.

use core::ops::RangeInclusive;

use ostd::sync::Mutex;

use crate::{PciBus, PciCommonDevice, PciDeviceLocation, platform};

pub(crate) fn enumerate(all_bus: Option<RangeInclusive<u8>>, pci_bus: &Mutex<PciBus>) {
    let Some(all_bus) = all_bus else {
        ostd::info!("no PCI bus was found");
        return;
    };
    ostd::info!("initializing the PCI bus with bus numbers `{:?}`", all_bus);

    let mut pci_bus = pci_bus.lock();
    let all_devices = PciDeviceLocation::MIN_DEVICE..=PciDeviceLocation::MAX_DEVICE;
    let all_functions = PciDeviceLocation::MIN_FUNCTION..=PciDeviceLocation::MAX_FUNCTION;

    for bus in all_bus {
        for device in all_devices.clone() {
            let mut location = PciDeviceLocation {
                bus,
                device,
                function: PciDeviceLocation::MIN_FUNCTION,
            };

            let initialization = platform::device_initialization(location);
            let Some(first_function) = PciCommonDevice::new(location, initialization) else {
                continue;
            };
            let has_multiple_functions = first_function.has_multi_funcs();
            register_or_reserve(&mut pci_bus, first_function);

            if !has_multiple_functions {
                continue;
            }
            for function in all_functions.clone().skip(1) {
                location.function = function;
                let initialization = platform::device_initialization(location);
                if let Some(common_device) = PciCommonDevice::new(location, initialization) {
                    register_or_reserve(&mut pci_bus, common_device);
                }
            }
        }
    }
}

fn register_or_reserve(pci_bus: &mut PciBus, device: PciCommonDevice) {
    if let Some(device) = platform::reserve_for_assignment(device) {
        pci_bus.register_common_device(device);
    }
}
