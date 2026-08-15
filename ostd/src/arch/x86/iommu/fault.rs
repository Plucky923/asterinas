// SPDX-License-Identifier: MPL-2.0

use alloc::vec::Vec;
use core::{fmt::Debug, ptr::NonNull};

use bitflags::bitflags;
use spin::Once;
use volatile::{VolatileRef, access::ReadWrite};

use super::registers::Capability;
use crate::{
    arch::trap::TrapFrame,
    irq::IrqLine,
    mm::dma::{DmaRemappingFault, report_dma_remapping_fault},
    sync::{LocalIrqDisabled, SpinLock},
};

const INTERRUPT_MASK: u32 = 1 << 31;

#[derive(Debug)]
pub struct FaultEventRegisters {
    status: VolatileRef<'static, u32, ReadWrite>,
    /// bit31: Interrupt Mask; bit30: Interrupt Pending.
    control: VolatileRef<'static, u32, ReadWrite>,
    _data: VolatileRef<'static, u32, ReadWrite>,
    _address: VolatileRef<'static, u32, ReadWrite>,
    _upper_address: VolatileRef<'static, u32, ReadWrite>,
    recordings: Vec<VolatileRef<'static, u128, ReadWrite>>,

    _fault_irq: IrqLine,
}

impl FaultEventRegisters {
    pub fn status(&self) -> FaultStatus {
        FaultStatus::from_bits_truncate(self.status.as_ptr().read())
    }

    /// Creates an instance from the IOMMU base address.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the base address is a valid IOMMU base address and that it has
    /// exclusive ownership of the IOMMU fault event registers.
    unsafe fn new(base_register_vaddr: NonNull<u8>) -> Option<Self> {
        // SAFETY: The safety is upheld by the caller.
        let (capability, status, mut control, mut data, mut address, upper_address) = unsafe {
            let base = base_register_vaddr;
            (
                // capability
                VolatileRef::new_read_only(base.add(0x08).cast::<u64>()),
                // status
                VolatileRef::new(base.add(0x34).cast::<u32>()),
                // control
                VolatileRef::new(base.add(0x38).cast::<u32>()),
                // data
                VolatileRef::new(base.add(0x3c).cast::<u32>()),
                // address
                VolatileRef::new(base.add(0x40).cast::<u32>()),
                // upper_address
                VolatileRef::new(base.add(0x44).cast::<u32>()),
            )
        };

        let capability_val = Capability::new(capability.as_ptr().read());
        let length = (capability_val.fault_recording_number() as usize).checked_add(1)?;
        let offset = (capability_val.fault_recording_register_offset() as usize)
            .checked_mul(size_of::<u128>())?;
        let recordings_size = length.checked_mul(size_of::<u128>())?;
        let recordings_end = offset.checked_add(recordings_size)?;

        // IommuRegisters maps and reserves only one page for the IOMMU register
        // block. Do not form volatile references outside that mapped MMIO range
        // even if the hardware reports an invalid capability value.
        if recordings_end > crate::mm::PAGE_SIZE {
            crate::warn!(
                "IOMMU fault-recording registers exceed the mapped register page: offset={}, length={}",
                offset,
                length
            );
            return None;
        }

        let mut recordings = Vec::with_capacity(length);
        for i in 0..length {
            // SAFETY: The safety is upheld by the caller and the correctness of the capability
            // value.
            recordings.push(unsafe {
                VolatileRef::new(
                    base_register_vaddr
                        .add(offset)
                        .add(i * size_of::<u128>())
                        .cast::<u128>(),
                )
            })
        }

        let mut fault_irq = IrqLine::alloc().ok()?;
        fault_irq.on_active(iommu_fault_handler);

        // Set page fault interrupt vector and address
        data.as_mut_ptr().write(fault_irq.num() as u32);
        address.as_mut_ptr().write(0xFEE0_0000);
        // Keep fault interrupts masked until the kernel installs its deferred
        // containment handler. Fault records remain available for processing
        // when reporting is resumed.
        control.as_mut_ptr().write(INTERRUPT_MASK);

        Some(FaultEventRegisters {
            status,
            control,
            _data: data,
            _address: address,
            _upper_address: upper_address,
            recordings,
            _fault_irq: fault_irq,
        })
    }
}

pub struct FaultRecording(u128);

impl FaultRecording {
    pub fn is_fault(&self) -> bool {
        self.0 & (1 << 127) != 0
    }

    pub fn clear_fault(&mut self) {
        self.0 &= !(1 << 127);
    }

    pub fn request_type(&self) -> FaultRequestType {
        // bit 126 and bit 92
        let t1 = ((self.0 & (1 << 126)) >> 125) as u8;
        let t2 = ((self.0 & (1 << 92)) >> 92) as u8;
        let typ = t1 + t2;
        match typ {
            0 => FaultRequestType::Write,
            1 => FaultRequestType::Page,
            2 => FaultRequestType::Read,
            3 => FaultRequestType::AtomicOp,
            _ => unreachable!(),
        }
    }

    pub fn address_type(&self) -> Option<FaultAddressType> {
        // bit 125:124
        match (self.0 >> 124) & 3 {
            0 => Some(FaultAddressType::UntranslatedRequest),
            1 => Some(FaultAddressType::TranslationRequest),
            2 => Some(FaultAddressType::TranslatedRequest),
            3 => None,
            _ => unreachable!(),
        }
    }

    pub fn source_identifier(&self) -> u16 {
        // bit 79:64
        ((self.0 & 0xFFFF_0000_0000_0000_0000) >> 64) as u16
    }

    /// Returns the fault information, the meaning of which depends on the fault reason.
    ///
    /// If the fault reason is one of the address translation fault conditions, this field contains
    /// bits 63:12 of the page address of the fault request.
    ///
    /// If the fault reason is one of the interrupt-remapping fault conditions other than fault
    /// reason 0x25, bits 63:48 indicate the interrupt index of the fault request and bits 47:12
    /// are cleared.
    ///
    /// If the fault reason is the interrupt-remapping fault condition caused by a blocked
    /// Compatibility format interrupt (fault reason 0x25), this field is undefined.
    pub fn fault_info(&self) -> u64 {
        // bit 63:12
        ((self.0 & 0xFFFF_FFFF_FFFF_F000) >> 12) as u64
    }

    #[expect(dead_code)]
    pub fn pasid_value(&self) -> u32 {
        // bit 123:104
        ((self.0 & 0x00FF_FFF0_0000_0000_0000_0000_0000_0000) >> 104) as u32
    }

    pub fn fault_reason(&self) -> u8 {
        // bit 103:96
        ((self.0 & 0xFF_0000_0000_0000_0000_0000_0000) >> 96) as u8
    }

    #[expect(dead_code)]
    pub fn pasid_present(&self) -> bool {
        // bit 95
        (self.0 & 0x8000_0000_0000_0000_0000_0000) != 0
    }

    #[expect(dead_code)]
    pub fn execute_permission_request(&self) -> bool {
        // bit 94
        (self.0 & 0x4000_0000_0000_0000_0000_0000) != 0
    }

    #[expect(dead_code)]
    pub fn privilege_mode_request(&self) -> bool {
        // bit 93
        (self.0 & 0x2000_0000_0000_0000_0000_0000) != 0
    }
}

impl Debug for FaultRecording {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FaultRecording")
            .field("Fault", &self.is_fault())
            .field("Request type", &self.request_type())
            .field("Address type", &self.address_type())
            .field("Source identifier", &self.source_identifier())
            .field("Fault Reason", &self.fault_reason())
            .field("Fault info", &self.fault_info())
            .field("Raw", &self.0)
            .finish()
    }
}

#[repr(u8)]
#[derive(Debug)]
pub enum FaultRequestType {
    Write = 0,
    Page = 1,
    Read = 2,
    AtomicOp = 3,
}

#[expect(clippy::enum_variant_names)]
#[repr(u8)]
#[derive(Debug)]
pub enum FaultAddressType {
    UntranslatedRequest = 0,
    TranslationRequest = 1,
    TranslatedRequest = 2,
}

bitflags! {
    pub struct FaultStatus : u32{
        /// Primary Fault Overflow, indicates overflow of the fault recording registers.
        const PFO = 1 << 0;
        /// Primary Pending Fault, indicates there are one or more pending faults logged in the fault recording registers.
        const PPF = 1 << 1;
        /// Invalidation Queue Error.
        const IQE = 1 << 4;
        /// Invalidation Completion Error. Hardware received an unexpected or invalid Device-TLB invalidation completion.
        const ICE = 1 << 5;
        /// Invalidation Time-out Error. Hardware detected a Device-TLB invalidation completion time-out.
        const ITE = 1 << 6;
        /// Fault Record Index, valid only when PPF field is set. This field indicates the index (from base) of the fault recording register
        /// to which the first pending fault was recorded when the PPF field was Set by hardware.
        const FRI = (0xFF) << 8;
    }
}

pub(super) static FAULT_EVENT_REGS: Once<SpinLock<FaultEventRegisters, LocalIrqDisabled>> =
    Once::new();

/// Initializes the fault reporting function.
///
/// # Safety
///
/// The caller must ensure that the base address is a valid IOMMU base address and that it has
/// exclusive ownership of the IOMMU fault event registers.
pub(super) unsafe fn init(base_register_vaddr: NonNull<u8>) -> bool {
    let Some(registers) = (|| {
        // SAFETY: The safety is upheld by the caller.
        unsafe { FaultEventRegisters::new(base_register_vaddr) }
    })() else {
        return false;
    };
    FAULT_EVENT_REGS.call_once(|| SpinLock::new(registers));
    true
}

fn iommu_fault_handler(_frame: &TrapFrame) {
    let Some(fault_event_regs) = FAULT_EVENT_REGS.get() else {
        return;
    };
    let mut fault_event_regs = fault_event_regs.lock();

    primary_fault_handler(&mut fault_event_regs);

    let fault_status = fault_event_regs.status();
    if fault_status.intersects(FaultStatus::IQE | FaultStatus::ICE | FaultStatus::ITE) {
        panic!(
            "Catch IOMMU invalidation error. Fault status: {:x?}",
            fault_status
        );
    }
}

fn primary_fault_handler(fault_event_regs: &mut FaultEventRegisters) {
    let mut fault_status = fault_event_regs.status();
    if !fault_status.contains(FaultStatus::PPF) {
        return;
    }

    let start_index = ((fault_event_regs.status().bits & FaultStatus::FRI.bits) >> 8) as usize;
    if start_index >= fault_event_regs.recordings.len() {
        mask_fault_reporting(fault_event_regs);
        report_dma_remapping_fault(DmaRemappingFault::overflow());
        return;
    }
    const MAX_RECORDS_PER_INTERRUPT: usize = 32;
    let recording_count = fault_event_regs.recordings.len();
    let bounded_count = recording_count.min(MAX_RECORDS_PER_INTERRUPT);
    let mut processed_count = 0;
    while processed_count < bounded_count {
        let recording_index = (start_index + processed_count) % recording_count;
        let raw_recording = fault_event_regs.recordings[recording_index].as_mut_ptr();
        let mut recording = FaultRecording(raw_recording.read());
        if !recording.is_fault() {
            break;
        }

        report_dma_remapping_fault(DmaRemappingFault::request(
            recording.source_identifier(),
            recording.fault_reason(),
            recording.fault_info(),
        ));

        // Clear Fault field
        recording.clear_fault();
        raw_recording.write(recording.0);
        processed_count += 1;
    }
    let record_limit_reached =
        processed_count == bounded_count && recording_count > bounded_count && {
            let next_index = (start_index + processed_count) % recording_count;
            FaultRecording(fault_event_regs.recordings[next_index].as_ptr().read()).is_fault()
        };
    if record_limit_reached {
        mask_fault_reporting(fault_event_regs);
        report_dma_remapping_fault(DmaRemappingFault::overflow());
    }

    if fault_status.contains(FaultStatus::PFO) {
        mask_fault_reporting(fault_event_regs);
        if !record_limit_reached {
            report_dma_remapping_fault(DmaRemappingFault::overflow());
        }
        fault_status.remove(FaultStatus::PFO);
        fault_event_regs
            .status
            .as_mut_ptr()
            .write(fault_status.bits);
    }
}

fn mask_fault_reporting(fault_event_regs: &mut FaultEventRegisters) {
    let control = fault_event_regs.control.as_ptr().read() | INTERRUPT_MASK;
    fault_event_regs.control.as_mut_ptr().write(control);
}

pub(crate) fn resume_fault_reporting() {
    let Some(registers) = FAULT_EVENT_REGS.get() else {
        return;
    };
    let mut registers = registers.lock();
    let control = registers.control.as_ptr().read() & !INTERRUPT_MASK;
    registers.control.as_mut_ptr().write(control);
}
