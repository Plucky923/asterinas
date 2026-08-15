// SPDX-License-Identifier: MPL-2.0

use crate::{
    Error, Result,
    arch::iommu::{IrtEntryHandle, alloc_irt_entry, has_interrupt_remapping},
    irq::PciIrqRequester,
    prelude::Arc,
    sync::SpinLock,
};

pub(crate) struct IrqRemapping {
    entry: SpinLock<Option<Arc<IrtEntryHandle>>>,
}

impl IrqRemapping {
    pub(crate) const fn new() -> Self {
        Self {
            entry: SpinLock::new(None),
        }
    }

    /// Initializes the remapping entry for the specific IRQ number.
    ///
    /// This will do nothing if the entry is already initialized or interrupt
    /// remapping is disabled or not supported by the architecture.
    pub(crate) fn init(&self, irq_num: u8) {
        if !has_interrupt_remapping() {
            return;
        }

        let handle = Arc::new(alloc_irt_entry().unwrap());
        handle.enable(irq_num);
        let mut entry = self.entry.lock();
        assert!(
            entry.is_none(),
            "an IRQ remapping entry must be reset before reuse"
        );
        *entry = Some(handle);
    }

    /// Gets the remapping index of the IRQ line.
    ///
    /// This method will return `None` if interrupt remapping is disabled or
    /// not supported by the architecture.
    pub(crate) fn remapping_index(&self) -> Option<u16> {
        Some(self.entry.lock().as_ref()?.index())
    }

    pub(crate) fn bind_pci_requester(&self, irq_num: u8, requester: PciIrqRequester) -> Result<()> {
        let handle = self.entry.lock().clone().ok_or(Error::AccessDenied)?;
        handle.enable_for_requester(irq_num, requester);
        Ok(())
    }

    pub(crate) fn reset(&self) {
        let handle = self.entry.lock().take();
        drop(handle);
    }
}
