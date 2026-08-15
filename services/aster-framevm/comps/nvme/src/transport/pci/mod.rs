// SPDX-License-Identifier: MPL-2.0

pub(crate) mod driver;
pub(crate) mod transport;

use alloc::sync::Arc;

use spin::Once;

use self::driver::NvmePciDriver;

pub(crate) static NVME_PCI_DRIVER: Once<Arc<NvmePciDriver>> = Once::new();

pub(crate) fn nvme_pci_init() {
    NVME_PCI_DRIVER.call_once(|| Arc::new(NvmePciDriver::new()));
    aster_pci::with_bus(|bus| {
        bus.register_driver(NVME_PCI_DRIVER.get().unwrap().clone());
    });
}
