// SPDX-License-Identifier: MPL-2.0

//! Per-vCPU interrupt delivery.
//!
//! An [`InterruptHandler`] owns the bounded control work for one FrameVM
//! vCPU.  Device and PCI producers append typed requests to its one
//! `interrupt_log`; the handler only delivers those requests and accumulated
//! timer ticks.  Device protocol work remains in the service scheduler.

use alloc::{
    collections::VecDeque,
    sync::{Arc, Weak},
};
use core::sync::atomic::{AtomicU64, Ordering};

use host_ostd::sync::{LocalIrqDisabled as HostLocalIrqDisabled, SpinLock as HostSpinLock};

use crate::{
    error::Error,
    irq::VirtualIrqLine,
    prelude::Result,
    vm::{self, FrameSchedGroup, FrameVcpuId},
};

/// One typed request waiting for delivery by a vCPU's interrupt handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterruptRequest {
    Virtual(VirtualIrqLine),
    Physical { irq_num: u8, generation: u64 },
}

const INTERRUPT_LOG_CAPACITY: usize = 256;
const INTERRUPT_DRAIN_BATCH: usize = 1;

/// Per-vCPU owner of interrupt requests, timer ticks, and virtual-IRQ state.
pub struct InterruptHandler {
    id: FrameVcpuId,
    group: HostSpinLock<Option<Weak<FrameSchedGroup>>, HostLocalIrqDisabled>,
    interrupt_log: HostSpinLock<VecDeque<InterruptRequest>, HostLocalIrqDisabled>,
    /// Coalesced timer ticks; unlike IRQ requests, ticks do not need one log entry each.
    timer_ticks: AtomicU64,
    virtual_irq_depth: HostSpinLock<usize, HostLocalIrqDisabled>,
}

impl InterruptHandler {
    /// Creates an empty interrupt handler for one FrameVM vCPU.
    pub fn new(id: FrameVcpuId) -> Self {
        Self {
            id,
            group: HostSpinLock::new(None),
            interrupt_log: HostSpinLock::new(VecDeque::with_capacity(INTERRUPT_LOG_CAPACITY)),
            timer_ticks: AtomicU64::new(0),
            virtual_irq_depth: HostSpinLock::new(0),
        }
    }

    /// Returns the owning FrameVM vCPU identity.
    pub const fn frame_vcpu_id(&self) -> FrameVcpuId {
        self.id
    }

    /// Binds the handler to its scheduler group.
    pub fn bind_group(&self, group: &Arc<FrameSchedGroup>) {
        *self.group.lock() = Some(Arc::downgrade(group));
    }

    /// Returns the owning scheduler group while it is alive.
    pub fn group(&self) -> Option<Arc<FrameSchedGroup>> {
        self.group.lock().as_ref()?.upgrade()
    }

    /// Adds one typed request to this vCPU's interrupt log.
    pub(crate) fn enqueue(&self, request: InterruptRequest) -> bool {
        let mut interrupt_log = self.interrupt_log.lock();
        if interrupt_log.iter().any(|pending| *pending == request) {
            drop(interrupt_log);
            self.wake();
            return true;
        }
        if interrupt_log.len() >= INTERRUPT_LOG_CAPACITY {
            return false;
        }
        interrupt_log.push_back(request);
        drop(interrupt_log);
        self.wake();
        true
    }

    /// Records one accumulated timer tick.
    pub(crate) fn record_timer_tick(&self) {
        let _ = self
            .timer_ticks
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |ticks| {
                ticks.checked_add(1).or(Some(u64::MAX))
            });
        // A timer callback may arrive after the carrier consumed an earlier
        // notification. Ring the owner-scoped vCPU doorbell rather than
        // waking a separate Host interrupt carrier.
        self.force_wake();
    }

    /// Clears pending interrupt and timer notifications.
    pub(crate) fn clear_pending(&self) {
        self.interrupt_log.lock().clear();
        let _ = self.timer_ticks.swap(0, Ordering::AcqRel);
    }

    /// Returns whether virtual local interrupts are enabled for this vCPU.
    pub fn virtual_interrupts_enabled(&self) -> bool {
        *self.virtual_irq_depth.lock() == 0
    }

    /// Disables virtual local interrupt delivery.
    pub(crate) fn disable_virtual_interrupts(&self) {
        let mut depth = self.virtual_irq_depth.lock();
        *depth = depth.saturating_add(1);
    }

    /// Enables virtual local interrupt delivery.
    pub(crate) fn enable_virtual_interrupts(&self) {
        let interrupts_enabled = {
            let mut depth = self.virtual_irq_depth.lock();
            *depth = depth.saturating_sub(1);
            *depth == 0
        };
        if interrupts_enabled && self.has_pending_work() {
            self.force_wake();
        }
    }

    /// Returns whether this handler has pending timer or interrupt work.
    pub(crate) fn has_pending_work(&self) -> bool {
        self.timer_ticks.load(Ordering::Acquire) != 0 || !self.interrupt_log.lock().is_empty()
    }

    /// Returns whether this vCPU has deliverable virtual work.
    pub(crate) fn has_deliverable_work(&self) -> bool {
        self.virtual_interrupts_enabled() && self.has_pending_work()
    }

    /// Runs one bounded continuation-owned event drain.
    fn drain(&self) -> bool {
        let mut delivered = false;
        for _ in 0..INTERRUPT_DRAIN_BATCH {
            if !self.virtual_interrupts_enabled() {
                return delivered;
            }

            let mut progressed = false;
            let ticks = self.timer_ticks.swap(0, Ordering::AcqRel);
            if ticks != 0 {
                crate::task::scheduler::dispatch_timer_ticks(self.id, ticks);
                delivered = true;
                progressed = true;
            }

            if let Some(request) = self.interrupt_log.lock().pop_front() {
                self.dispatch(request);
                delivered = true;
                progressed = true;
            }

            if !progressed {
                return delivered;
            }
        }
        delivered
    }

    fn dispatch(&self, request: InterruptRequest) {
        match request {
            InterruptRequest::Virtual(irq_line) => {
                super::dispatch_framev_irq_line(self.id.vm_id(), irq_line, self.id.vcpu_index());
            }
            InterruptRequest::Physical {
                irq_num,
                generation,
            } => super::dispatch_physical_irq(
                self.id.vm_id(),
                irq_num,
                generation,
                self.id.vcpu_index(),
            ),
        }
    }

    pub(crate) fn wake(&self) {
        if self.virtual_interrupts_enabled() {
            self.force_wake();
        }
    }

    fn force_wake(&self) {
        if let Some(group) = self.group() {
            group.request_inner_preempt();
        }
    }

    /// Delivers bounded pending work directly on the resumed vCPU
    /// continuation. This has no independent Host task or stack.
    pub(crate) fn deliver_pending_on_current_vcpu(&self) {
        let _ = self.drain();
    }
}

/// Enqueues a virtual IRQ for one FrameVM vCPU.
pub(crate) fn enqueue_virtual_irq(
    vm_id: vm::VmId,
    vcpu_id: usize,
    irq_line: VirtualIrqLine,
) -> Result<()> {
    let frame_vm = vm::get_vm_by_id(vm_id).ok_or(Error::InvalidArgs)?;
    let handler = frame_vm
        .interrupt_handler(vcpu_id)
        .ok_or(Error::InvalidArgs)?;
    handler
        .enqueue(InterruptRequest::Virtual(irq_line))
        .then_some(())
        .ok_or(Error::NotEnoughResources)
}

/// Enqueues a generation-checked physical IRQ for one FrameVM vCPU.
pub(crate) fn enqueue_physical_irq(
    vm_id: vm::VmId,
    vcpu_id: usize,
    irq_num: u8,
    generation: u64,
) -> Result<()> {
    let frame_vm = vm::get_vm_by_id(vm_id).ok_or(Error::InvalidArgs)?;
    if matches!(
        frame_vm.status(),
        vm::VmStatus::Stopped | vm::VmStatus::Stopping
    ) {
        return Err(Error::AccessDenied);
    }
    let handler = frame_vm
        .interrupt_handler(vcpu_id)
        .ok_or(Error::InvalidArgs)?;
    handler
        .enqueue(InterruptRequest::Physical {
            irq_num,
            generation,
        })
        .then_some(())
        .ok_or(Error::NotEnoughResources)
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn virtual_interrupt_mask_is_nested_per_handler() {
        let first = InterruptHandler::new(FrameVcpuId::new(vm::VmId::new(0), 0));
        let second = InterruptHandler::new(FrameVcpuId::new(vm::VmId::new(0), 1));

        first.disable_virtual_interrupts();
        first.disable_virtual_interrupts();
        second.disable_virtual_interrupts();
        assert!(!first.virtual_interrupts_enabled());
        assert!(!second.virtual_interrupts_enabled());

        first.enable_virtual_interrupts();
        assert!(!first.virtual_interrupts_enabled());
        second.enable_virtual_interrupts();
        assert!(second.virtual_interrupts_enabled());
        first.enable_virtual_interrupts();
        assert!(first.virtual_interrupts_enabled());
    }

    #[ktest]
    fn interrupt_log_is_the_only_pending_request_state() {
        let handler = InterruptHandler::new(FrameVcpuId::new(vm::VmId::new(0), 0));
        let line = VirtualIrqLine::parse(1).unwrap();
        assert!(handler.enqueue(InterruptRequest::Virtual(line)));
        assert!(handler.has_pending_work());
        assert!(!handler.interrupt_log.lock().is_empty());
        handler.clear_pending();
        assert!(!handler.has_pending_work());
    }

    #[ktest]
    fn interrupt_log_rejects_distinct_requests_after_reaching_capacity() {
        let handler = InterruptHandler::new(FrameVcpuId::new(vm::VmId::new(0), 0));
        for raw_line in 1..=INTERRUPT_LOG_CAPACITY {
            let line = VirtualIrqLine::parse(raw_line as u16).unwrap();
            assert!(handler.enqueue(InterruptRequest::Virtual(line)));
        }

        let next_line = VirtualIrqLine::parse((INTERRUPT_LOG_CAPACITY + 1) as u16).unwrap();
        assert!(!handler.enqueue(InterruptRequest::Virtual(next_line)));
        assert!(handler.enqueue(InterruptRequest::Virtual(VirtualIrqLine::parse(1).unwrap())));
        assert_eq!(handler.interrupt_log.lock().len(), INTERRUPT_LOG_CAPACITY);
    }
}
