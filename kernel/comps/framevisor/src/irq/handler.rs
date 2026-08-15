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
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use host_ostd::{
    sync::{
        LocalIrqDisabled as HostLocalIrqDisabled, SpinLock as HostSpinLock,
        WaitQueue as HostWaitQueue,
    },
    task::Task,
};

use crate::{
    error::Error,
    irq::VirtualIrqLine,
    prelude::Result,
    sync::Once,
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

/// Per-vCPU owner of interrupt requests, timer ticks, and interrupt-task
/// lifecycle state.
pub struct InterruptHandler {
    id: FrameVcpuId,
    group: HostSpinLock<Option<Weak<FrameSchedGroup>>, HostLocalIrqDisabled>,
    interrupt_log: HostSpinLock<VecDeque<InterruptRequest>, HostLocalIrqDisabled>,
    /// Coalesced timer ticks; unlike IRQ requests, ticks do not need one log entry each.
    timer_ticks: AtomicU64,
    wait_queue: HostWaitQueue,
    start_wait_queue: HostWaitQueue,
    started: AtomicBool,
    should_exit: AtomicBool,
    virtual_irq_depth: HostSpinLock<usize, HostLocalIrqDisabled>,
    task: HostSpinLock<Option<Arc<Task>>, HostLocalIrqDisabled>,
}

impl InterruptHandler {
    /// Creates an empty interrupt handler for one FrameVM vCPU.
    pub fn new(id: FrameVcpuId) -> Self {
        Self {
            id,
            group: HostSpinLock::new(None),
            interrupt_log: HostSpinLock::new(VecDeque::with_capacity(INTERRUPT_LOG_CAPACITY)),
            timer_ticks: AtomicU64::new(0),
            wait_queue: HostWaitQueue::new(),
            start_wait_queue: HostWaitQueue::new(),
            started: AtomicBool::new(false),
            should_exit: AtomicBool::new(false),
            virtual_irq_depth: HostSpinLock::new(0),
            task: HostSpinLock::new(None),
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

    /// Returns whether the handler task can currently deliver pending work.
    pub(crate) fn has_deliverable_work(&self) -> bool {
        self.has_pending_start()
            || self.has_pending_exit()
            || (self.virtual_interrupts_enabled() && self.has_pending_work())
    }

    /// Returns the backing host task, if it has been created.
    pub(crate) fn task(&self) -> Option<Arc<Task>> {
        self.task.lock().clone()
    }

    /// Returns whether this handler has a backing task.
    pub(crate) fn has_task(&self) -> bool {
        self.task.lock().is_some()
    }

    /// Signals the interrupt task to exit.
    pub(crate) fn signal_exit(&self) {
        self.should_exit.store(true, Ordering::Release);
        self.force_wake();
        if let Some(task) = self.task() {
            task.wake_up();
        }
    }

    /// Waits until this handler task starts its loop.
    pub(crate) fn wait_until_started(&self) {
        self.start_wait_queue
            .wait_until(|| self.started.load(Ordering::Acquire).then_some(()));
    }

    /// Waits until this handler task exits.
    pub(crate) fn wait_for_exit(&self) {
        if let Some(task) = self.task() {
            while !task.is_completed() {
                self.force_wake();
                task.wake_up();
                Task::yield_now();
            }
        }
    }

    /// Resets task and notification state after a completed exit.
    pub(crate) fn reset_after_exit(&self) {
        self.clear_pending();
        *self.virtual_irq_depth.lock() = 0;
        self.should_exit.store(false, Ordering::Release);
        self.started.store(false, Ordering::Release);
        *self.task.lock() = None;
    }

    /// Installs the backing host task.
    pub(crate) fn set_task(&self, task: Arc<Task>) {
        *self.task.lock() = Some(task);
    }

    /// Runs one bounded interrupt-task drain.
    fn drain(&self) -> bool {
        let mut delivered = false;
        for _ in 0..INTERRUPT_DRAIN_BATCH {
            if !self.virtual_interrupts_enabled() || self.should_exit.load(Ordering::Acquire) {
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

    fn has_pending_start(&self) -> bool {
        !self.started.load(Ordering::Acquire)
            && self.task().is_some_and(|task| !task.is_completed())
    }

    pub(crate) fn has_pending_exit(&self) -> bool {
        self.should_exit.load(Ordering::Acquire)
            && self.task().is_some_and(|task| !task.is_completed())
    }

    pub(crate) fn wake(&self) {
        if self.virtual_interrupts_enabled() {
            self.force_wake();
        }
    }

    fn force_wake(&self) {
        self.wait_queue.wake_one();
        // The handler yields after dispatching work and may not have reached
        // its wait queue yet. Publish its backing task as well so an interrupt
        // arriving in that window cannot leave the scheduling group dormant.
        if let Some(task) = self.task() {
            task.wake_up();
        }
    }

    fn mark_started(&self) {
        self.started.store(true, Ordering::Release);
        self.start_wait_queue.wake_all();
    }
}

/// Creator for the host task backing one [`InterruptHandler`].
pub type InterruptTaskCreator = fn(Arc<InterruptHandler>) -> Result<Arc<Task>>;

static INTERRUPT_TASK_CREATOR: Once<InterruptTaskCreator> = Once::new();

/// Installs the host task creator used by FrameVM startup.
pub fn register_interrupt_task_creator(creator: InterruptTaskCreator) {
    INTERRUPT_TASK_CREATOR.call_once(|| creator);
}

/// Starts the host task for one interrupt handler.
pub(crate) fn start_interrupt_handler(handler: Arc<InterruptHandler>) -> Result<()> {
    let creator = INTERRUPT_TASK_CREATOR.get().ok_or(Error::InvalidArgs)?;
    let task = creator(handler.clone())?;
    handler.set_task(task.clone());
    task.run();
    Ok(())
}

/// Runs one interrupt handler until its task receives an exit request.
pub fn interrupt_handler_main(handler: Arc<InterruptHandler>) {
    crate::early_println!(
        "[FrameVM] interrupt task entry: vm={}, vcpu={}",
        handler.frame_vcpu_id().vm_id(),
        handler.frame_vcpu_id().vcpu_index(),
    );
    handler.mark_started();

    while !handler.should_exit.load(Ordering::Acquire) {
        let dispatched = handler.drain();
        if dispatched {
            if let Some(group) = handler.group() {
                if group.has_service_work_for_outer() {
                    group.request_service_handoff();
                }
            }
            Task::yield_now();
        }
        handler.wait_queue.wait_until(|| {
            if handler.should_exit.load(Ordering::Acquire)
                || (handler.virtual_interrupts_enabled() && handler.has_pending_work())
            {
                Some(())
            } else {
                None
            }
        });
    }

    if handler.frame_vcpu_id().vcpu_index() == 0
        && let Some(frame_vm) = vm::get_vm_by_id(handler.frame_vcpu_id().vm_id())
        && let Some(shutdown) = frame_vm.service_entry_points().enter_shutdown()
    {
        (shutdown.handler())();
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

    #[ktest]
    fn reset_after_exit_clears_virtual_irq_mask() {
        let handler = InterruptHandler::new(FrameVcpuId::new(vm::VmId::new(0), 0));
        handler.disable_virtual_interrupts();
        assert!(!handler.virtual_interrupts_enabled());
        handler.reset_after_exit();
        assert!(handler.virtual_interrupts_enabled());
    }
}
