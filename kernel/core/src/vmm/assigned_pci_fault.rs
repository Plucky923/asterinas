// SPDX-License-Identifier: MPL-2.0

//! Deferred containment for assigned PCI DMA faults.

use ostd::{
    mm::dma::{
        DmaRemappingFault, register_dma_remapping_fault_handler,
        resume_dma_remapping_fault_reporting,
    },
    sync::LocalIrqDisabled,
};
use spin::once::Once;

use crate::{
    prelude::*,
    thread::work_queue::{WorkPriority, submit_work_item, work_item::WorkItem},
};

const PENDING_FAULT_CAPACITY: usize = 32;

struct PendingFaults {
    records: [Option<DmaRemappingFault>; PENDING_FAULT_CAPACITY],
    next_read: usize,
    next_write: usize,
    len: usize,
    overflowed: bool,
    hardware_overflow_pending: bool,
}

impl PendingFaults {
    const fn new() -> Self {
        Self {
            records: [None; PENDING_FAULT_CAPACITY],
            next_read: 0,
            next_write: 0,
            len: 0,
            overflowed: false,
            hardware_overflow_pending: false,
        }
    }

    fn push(&mut self, fault: DmaRemappingFault) {
        if fault.is_overflow() && self.hardware_overflow_pending {
            return;
        }
        if self.len == self.records.len() {
            self.overflowed = true;
            return;
        }
        self.hardware_overflow_pending |= fault.is_overflow();
        self.records[self.next_write] = Some(fault);
        self.next_write = (self.next_write + 1) % self.records.len();
        self.len += 1;
    }

    fn pop(&mut self) -> Option<DmaRemappingFault> {
        if self.len == 0 {
            return None;
        }
        let fault = self.records[self.next_read].take();
        if fault.is_some_and(DmaRemappingFault::is_overflow) {
            self.hardware_overflow_pending = false;
        }
        self.next_read = (self.next_read + 1) % self.records.len();
        self.len -= 1;
        fault
    }

    fn take_overflow(&mut self) -> bool {
        core::mem::take(&mut self.overflowed)
    }
}

/// Installs the hard-IRQ capture hook after the global work queues exist.
pub(super) fn init() {
    let work_item = WorkItem::new(Box::new(process_pending_faults));
    FAULT_WORK.call_once(|| work_item);
    register_dma_remapping_fault_handler(capture_fault);
}

fn capture_fault(fault: DmaRemappingFault) {
    PENDING_FAULTS.lock().push(fault);
    let work_item = FAULT_WORK
        .get()
        .expect("assigned PCI fault work is initialized before registration")
        .clone();
    submit_work_item(work_item, WorkPriority::High);
}

fn process_pending_faults() {
    loop {
        let (fault, queue_overflowed) = {
            let mut pending = PENDING_FAULTS.lock();
            (pending.pop(), pending.take_overflow())
        };
        let Some(fault) = fault else {
            if queue_overflowed {
                contain_fault_record_overflow();
            }
            return;
        };
        if queue_overflowed || fault.is_overflow() {
            contain_fault_record_overflow();
            if fault.is_overflow() {
                continue;
            }
        }
        let source_identifier = fault
            .source_identifier()
            .expect("non-overflow DMA faults have a requester ID");
        let identity = aster_pci::request_quarantine_for_source(source_identifier)
            .unwrap_or_else(|error| {
            panic!(
                "unattributed Host DMA-remapping fault: source={:#06x}, reason={:#04x}, information={:#x}, containment={error:?}",
                source_identifier,
                fault.reason(),
                fault.information()
            );
        });
        contain_assignment(identity);
    }
}

fn contain_fault_record_overflow() {
    let identities = aster_pci::request_quarantine_for_active_assignments();
    assert!(
        !identities.is_empty(),
        "unattributed Host DMA-remapping fault-record overflow"
    );
    for identity in identities {
        contain_assignment(identity);
    }
    resume_dma_remapping_fault_reporting();
}

fn contain_assignment(identity: aster_pci::PciAssignmentIdentity) {
    let Ok(vm_id) = u32::try_from(identity.owner()) else {
        panic!("assigned PCI fault has an invalid FrameVM owner");
    };
    let vm_id = aster_framevisor::VmId::from(vm_id);
    let Some(framevm) = aster_framevisor::get_framevm(vm_id) else {
        return;
    };
    let _ = framevm.stop_for_assigned_pci_failure();
    if !framevm.notify_assigned_device_failure() {
        let _ = aster_framevisor::destroy_framevm(vm_id);
    }
}

static PENDING_FAULTS: SpinLock<PendingFaults, LocalIrqDisabled> =
    SpinLock::new(PendingFaults::new());
static FAULT_WORK: Once<Arc<WorkItem>> = Once::new();

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn fault_queue_preserves_requester_across_wraparound() {
        let mut pending = PendingFaults::new();

        for source_identifier in 0..PENDING_FAULT_CAPACITY {
            pending.push(DmaRemappingFault::for_test_request(
                source_identifier as u16,
                0x06,
                source_identifier as u64,
            ));
        }

        let first = pending.pop().unwrap();
        assert_eq!(first.source_identifier(), Some(0));
        assert_eq!(first.reason(), 0x06);
        assert_eq!(first.information(), 0);

        pending.push(DmaRemappingFault::for_test_request(
            PENDING_FAULT_CAPACITY as u16,
            0x25,
            0xfeed,
        ));

        for source_identifier in 1..=PENDING_FAULT_CAPACITY {
            let fault = pending.pop().unwrap();
            assert_eq!(fault.source_identifier(), Some(source_identifier as u16));
        }
        assert!(pending.pop().is_none());
    }

    #[ktest]
    fn fault_queue_coalesces_pending_hardware_overflow() {
        let mut pending = PendingFaults::new();

        pending.push(DmaRemappingFault::for_test_overflow());
        pending.push(DmaRemappingFault::for_test_overflow());
        assert!(pending.pop().unwrap().is_overflow());
        assert!(pending.pop().is_none());

        pending.push(DmaRemappingFault::for_test_overflow());
        assert!(pending.pop().unwrap().is_overflow());
    }

    #[ktest]
    fn fault_queue_reports_capacity_overflow_without_replacing_records() {
        let mut pending = PendingFaults::new();

        for source_identifier in 0..PENDING_FAULT_CAPACITY {
            pending.push(DmaRemappingFault::for_test_request(
                source_identifier as u16,
                0x06,
                0,
            ));
        }
        pending.push(DmaRemappingFault::for_test_request(
            PENDING_FAULT_CAPACITY as u16,
            0x06,
            0,
        ));

        assert!(pending.take_overflow());
        assert!(!pending.take_overflow());
        for source_identifier in 0..PENDING_FAULT_CAPACITY {
            assert_eq!(
                pending.pop().unwrap().source_identifier(),
                Some(source_identifier as u16)
            );
        }
        assert!(pending.pop().is_none());
    }
}
