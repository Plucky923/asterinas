// SPDX-License-Identifier: MPL-2.0

//! DMA-remapping fault delivery to the kernel.

use spin::Once;

/// Describes one hardware DMA-remapping fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DmaRemappingFault {
    source_identifier: Option<u16>,
    reason: u8,
    information: u64,
}

impl DmaRemappingFault {
    pub(crate) const fn request(source_identifier: u16, reason: u8, information: u64) -> Self {
        Self {
            source_identifier: Some(source_identifier),
            reason,
            information,
        }
    }

    pub(crate) const fn overflow() -> Self {
        Self {
            source_identifier: None,
            reason: 0,
            information: 0,
        }
    }

    /// Returns the requester ID, or `None` if hardware lost fault records.
    pub const fn source_identifier(self) -> Option<u16> {
        self.source_identifier
    }

    /// Returns the VT-d fault reason.
    pub const fn reason(self) -> u8 {
        self.reason
    }

    /// Returns hardware fault information.
    pub const fn information(self) -> u64 {
        self.information
    }

    /// Returns whether hardware reported that fault records were lost.
    pub const fn is_overflow(self) -> bool {
        self.source_identifier.is_none()
    }

    /// Creates a synthetic requester fault for a kernel test.
    ///
    /// This constructor is unavailable in production builds, so DMA fault
    /// attribution remains exclusively hardware-derived at runtime.
    #[cfg(ktest)]
    pub const fn for_test_request(source_identifier: u16, reason: u8, information: u64) -> Self {
        Self::request(source_identifier, reason, information)
    }

    /// Creates a synthetic fault-record overflow for a kernel test.
    ///
    /// This constructor is unavailable in production builds, so only hardware
    /// can report lost DMA fault records at runtime.
    #[cfg(ktest)]
    pub const fn for_test_overflow() -> Self {
        Self::overflow()
    }
}

/// Registers the single kernel DMA-fault receiver.
///
/// The receiver runs in hard-interrupt context and therefore must not allocate,
/// block, or access a device. It should only capture the record for deferred
/// processing.
pub fn register_dma_remapping_fault_handler(handler: fn(DmaRemappingFault)) {
    if DMA_FAULT_HANDLER.get().is_some() {
        return;
    }
    DMA_FAULT_HANDLER.call_once(|| handler);
    // The x86 fault interrupt is initialized masked. Publish the handler
    // before allowing hardware to deliver any recorded fault.
    resume_dma_remapping_fault_reporting();
}

/// Re-enables VT-d fault interrupts after deferred containment has completed.
pub fn resume_dma_remapping_fault_reporting() {
    #[cfg(target_arch = "x86_64")]
    crate::arch::iommu::resume_fault_reporting();
}

pub(crate) fn report_dma_remapping_fault(fault: DmaRemappingFault) {
    let Some(handler) = DMA_FAULT_HANDLER.get() else {
        // Fault reporting remains masked until registration. A synthetic test
        // or a defensive early call must not turn that containment window into
        // a kernel panic.
        return;
    };
    handler(fault);
}

/// Delivers a synthetic DMA-remapping fault to the registered kernel handler.
///
/// This exists only in kernel-test builds and is deliberately absent from the
/// production OSTD API and from every FrameVM management interface.
#[cfg(ktest)]
pub fn inject_dma_remapping_fault_for_test(fault: DmaRemappingFault) {
    report_dma_remapping_fault(fault);
}

static DMA_FAULT_HANDLER: Once<fn(DmaRemappingFault)> = Once::new();
