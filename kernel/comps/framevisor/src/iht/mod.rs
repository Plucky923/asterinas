// SPDX-License-Identifier: MPL-2.0

//! Interrupt Handler Task (IHT) - Generic Mechanism for FrameVM
//!
//! # Design
//!
//! IHT provides a per-vCPU interrupt log and task:
//! - Subsystems log callbacks to the interrupt log
//! - IHT reads the log and executes each callback
//!
//! # Interrupt Log
//!
//! The interrupt log is a queue of callbacks.
//! When an event arrives:
//! 1. Callback is pushed to the interrupt log
//! 2. IHT is woken up
//! 3. IHT pops and executes each callback

use alloc::{
    boxed::Box,
    collections::VecDeque,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use framev_device::IrqLine;
use host_ostd::{
    sync::{SpinLock, WaitQueue},
    task::Task,
};

use crate::{
    error::Error,
    prelude::Result,
    sync::Once,
    task::{FrameTaskData, FrameTaskKind},
    timer::TimerCallback,
    vm::{self, FrameSchedGroup, FrameVcpuId},
};

mod event;

pub use event::{
    DeviceEventSource, IhtDrainOutcome, IhtEventKind, IhtEventSource, TimerTickSource,
};

// ============================================================================
// Callback Type
// ============================================================================

/// Callback stored in the interrupt log.
pub enum IrqCallback {
    FnPtr(fn()),
    Boxed(Box<dyn FnOnce() + Send + 'static>),
}

impl IrqCallback {
    #[inline]
    pub fn call(self) {
        match self {
            IrqCallback::FnPtr(f) => f(),
            IrqCallback::Boxed(cb) => cb(),
        }
    }
}

/// Typed vCPU request processed by IHT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VcpuRequest {
    VirtualIrq { vm_id: vm::VmId, irq_line: IrqLine },
}

/// Queue capacity for interrupt log (pre-allocated to avoid reallocation)
const IRQ_LOG_CAPACITY: usize = 256;
const IHT_DRAIN_BATCH: usize = 1;

// ============================================================================
// Per-vCPU Context
// ============================================================================

/// Per-vCPU IHT context with interrupt log.
pub struct IhtContext {
    /// FrameVM vCPU identity.
    id: FrameVcpuId,
    /// Owning scheduling group.
    group: SpinLock<Option<Weak<FrameSchedGroup>>>,
    /// Interrupt log: queue of callbacks to execute
    irq_log: SpinLock<VecDeque<IrqCallback>>,
    /// Typed request queue for virtual IRQ work
    request_log: SpinLock<VecDeque<VcpuRequest>>,
    /// Coalesced virtual timer source.
    timer_source: TimerTickSource,
    /// Timer callbacks registered by the FrameVM scheduler for this vCPU.
    timer_callbacks: SpinLock<Vec<TimerCallback>>,
    /// Device-originated source marker for callback and request adapters.
    device_source: DeviceEventSource,
    /// Wait queue for sleeping
    wait_queue: WaitQueue,
    /// Wait queue for task startup notification
    start_wait_queue: WaitQueue,
    /// Wait queue for exit notification
    exit_wait_queue: WaitQueue,
    /// Startup completion flag
    started: AtomicBool,
    /// Exit flag
    should_exit: AtomicBool,
    /// Exit completion flag
    exited: AtomicBool,
    /// Pending callback count (fast path, avoids lock)
    pending_count: AtomicUsize,
    /// Pending typed request count
    pending_request_count: AtomicUsize,
    /// Nested virtual local interrupt disable depth for this vCPU.
    virtual_irq_disable_depth: AtomicUsize,
    /// Task handle
    task: SpinLock<Option<Arc<Task>>>,
}

impl IhtContext {
    /// Create a new IHT context.
    pub fn new(id: FrameVcpuId) -> Self {
        Self {
            id,
            group: SpinLock::new(None),
            irq_log: SpinLock::new(VecDeque::with_capacity(IRQ_LOG_CAPACITY)),
            request_log: SpinLock::new(VecDeque::with_capacity(IRQ_LOG_CAPACITY)),
            timer_source: TimerTickSource::new(),
            timer_callbacks: SpinLock::new(Vec::new()),
            device_source: DeviceEventSource::new(),
            wait_queue: WaitQueue::new(),
            start_wait_queue: WaitQueue::new(),
            exit_wait_queue: WaitQueue::new(),
            started: AtomicBool::new(false),
            should_exit: AtomicBool::new(false),
            exited: AtomicBool::new(false),
            pending_count: AtomicUsize::new(0),
            pending_request_count: AtomicUsize::new(0),
            virtual_irq_disable_depth: AtomicUsize::new(0),
            task: SpinLock::new(None),
        }
    }

    /// Get vCPU ID.
    #[inline]
    pub fn vcpu_id(&self) -> usize {
        self.id.vcpu_index()
    }

    /// Returns the FrameVM vCPU identity.
    #[inline]
    pub fn frame_vcpu_id(&self) -> FrameVcpuId {
        self.id
    }

    /// Binds the owning scheduling group.
    pub fn bind_group(&self, group: &Arc<FrameSchedGroup>) {
        *self.group.lock() = Some(Arc::downgrade(group));
    }

    /// Returns the owning scheduling group if it is still alive.
    pub fn group(&self) -> Option<Arc<FrameSchedGroup>> {
        self.group.lock().as_ref()?.upgrade()
    }

    /// Push a callback to the interrupt log.
    #[inline]
    pub fn push_callback(&self, callback: IrqCallback) {
        self.irq_log.lock().push_back(callback);
        self.pending_count.fetch_add(1, Ordering::Release);
        self.device_source.mark_pending();
    }

    /// Push a callback and wake the owning vCPU group.
    #[inline]
    pub fn push_callback_and_wake(&self, callback: IrqCallback) {
        self.irq_log.lock().push_back(callback);
        self.pending_count.fetch_add(1, Ordering::AcqRel);
        self.device_source.mark_pending();
        self.wake();
    }

    /// Pop a callback from the interrupt log.
    #[inline]
    pub fn pop_callback(&self) -> Option<IrqCallback> {
        let mut log = self.irq_log.lock();
        let cb = log.pop_front();
        if cb.is_some() {
            self.pending_count.fetch_sub(1, Ordering::Release);
            self.refresh_device_source();
        }
        cb
    }

    /// Pushes a typed request and wakes the owning vCPU group.
    #[inline]
    pub fn push_request_and_wake(&self, request: VcpuRequest) {
        self.request_log.lock().push_back(request);
        self.pending_request_count.fetch_add(1, Ordering::AcqRel);
        self.device_source.mark_pending();
        self.wake();
    }

    /// Pops a typed request from the request log.
    #[inline]
    pub fn pop_request(&self) -> Option<VcpuRequest> {
        let mut log = self.request_log.lock();
        let request = log.pop_front();
        if request.is_some() {
            self.pending_request_count.fetch_sub(1, Ordering::Release);
            self.refresh_device_source();
        }
        request
    }

    /// Check if there are pending callbacks.
    #[inline]
    pub fn has_pending(&self) -> bool {
        self.pending_count.load(Ordering::Acquire) != 0
    }

    /// Checks if there are pending typed requests.
    #[inline]
    pub fn has_pending_requests(&self) -> bool {
        self.pending_request_count.load(Ordering::Acquire) != 0
    }

    /// Check if there is pending virtual timer work.
    #[inline]
    pub fn has_pending_timer_work(&self) -> bool {
        self.timer_source.has_pending()
    }

    /// Registers a virtual timer callback for this vCPU.
    pub(crate) fn register_timer_callback(&self, callback: TimerCallback) {
        self.timer_callbacks.lock().push(callback);
    }

    /// Returns a stable snapshot of virtual timer callbacks.
    pub(crate) fn timer_callbacks_snapshot(&self) -> Vec<TimerCallback> {
        self.timer_callbacks.lock().clone()
    }

    /// Returns whether virtual local interrupts are enabled for this vCPU.
    #[inline]
    pub fn virtual_interrupts_enabled(&self) -> bool {
        self.virtual_irq_disable_depth.load(Ordering::Acquire) == 0
    }

    /// Disables virtual local interrupts for this vCPU.
    #[inline]
    pub fn disable_virtual_interrupts(&self) {
        self.virtual_irq_disable_depth
            .fetch_add(1, Ordering::AcqRel);
    }

    /// Enables virtual local interrupts for this vCPU.
    #[inline]
    pub fn enable_virtual_interrupts(&self) {
        let previous = self.virtual_irq_disable_depth.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |depth| depth.checked_sub(1),
        );
        if previous == Ok(1) && self.has_pending_work() {
            self.force_wake();
        }
    }

    /// Records one virtual timer tick for this vCPU.
    pub fn record_timer_tick(&self) {
        self.record_timer_tick_at(host_ostd::arch::read_tsc());
    }

    /// Records one virtual timer tick at a known host deadline.
    pub fn record_timer_tick_at(&self, host_deadline: u64) {
        if let Some(vm) = vm::get_vm_by_id(self.id.vm_id()) {
            vm.record_timer_deadline(host_deadline);
        }
        self.timer_source.record_tick();
    }

    /// Clears per-vCPU event-source state.
    pub fn clear_event_sources(&self) {
        self.timer_source.take_ticks();
        self.timer_callbacks.lock().clear();
        self.device_source.clear_pending();
    }

    fn drain_timer_ticks(&self) -> IhtDrainOutcome {
        if !self.virtual_interrupts_enabled() || self.should_exit.load(Ordering::Acquire) {
            return IhtDrainOutcome::StopBeforeNextStep;
        }

        let ticks = self.timer_source.take_ticks();
        if ticks == 0 {
            return IhtDrainOutcome::NoWork;
        }

        crate::task::scheduler::dispatch_timer_ticks(self.id, ticks);
        if self.timer_source.has_pending() {
            IhtDrainOutcome::StillPending
        } else {
            IhtDrainOutcome::Drained
        }
    }

    /// Get pending callback count.
    #[inline]
    pub fn pending_count(&self) -> usize {
        self.pending_count.load(Ordering::Acquire)
    }

    /// Gets pending typed request count.
    #[inline]
    pub fn pending_request_count(&self) -> usize {
        self.pending_request_count.load(Ordering::Acquire)
    }

    fn has_pending_work(&self) -> bool {
        self.timer_source.has_pending() || self.device_source.has_pending()
    }

    fn has_pending_exit(&self) -> bool {
        self.should_exit.load(Ordering::Acquire)
            && !self.exited.load(Ordering::Acquire)
            && self.has_task()
    }

    fn can_run_pending_work(&self) -> bool {
        self.virtual_interrupts_enabled() && self.has_pending_work()
    }

    /// Returns whether pending IHT work is deliverable now.
    #[inline]
    pub(crate) fn has_deliverable_work(&self) -> bool {
        self.has_pending_exit() || self.can_run_pending_work()
    }

    /// Returns the backing IHT task.
    pub(crate) fn task(&self) -> Option<Arc<Task>> {
        self.task.lock().clone()
    }

    fn refresh_device_source(&self) {
        if self.has_pending() || self.has_pending_requests() {
            self.device_source.mark_pending();
        } else {
            self.device_source.clear_pending();
        }
    }

    fn drain_device_event(&self) -> IhtDrainOutcome {
        if !self.virtual_interrupts_enabled() || self.should_exit.load(Ordering::Acquire) {
            return IhtDrainOutcome::StopBeforeNextStep;
        }
        if !self.device_source.has_pending() {
            return IhtDrainOutcome::NoWork;
        }

        if let Some(request) = self.pop_request() {
            match request {
                VcpuRequest::VirtualIrq { vm_id, irq_line } => {
                    // IHT owns notification/control delivery only. FrameV
                    // protocol and device data-path work must become
                    // service-owned work after this handoff; starvation fixes
                    // belong in coalescing, pending clearing, batching, and
                    // service wakeup rather than in data-path execution here.
                    crate::irq::dispatch_framev_irq_line(vm_id, irq_line, self.id.vcpu_index())
                }
            }
            return self.device_drain_outcome();
        }

        if let Some(callback) = self.pop_callback() {
            // Callbacks queued to IHT must be notification-only, bounded
            // control work, or a separately specified bounded fast path.
            // Normal FrameV socket, block, console, RNG, filesystem, and
            // upper-subsystem data paths belong to FrameVM service runtime.
            callback.call();
            return self.device_drain_outcome();
        }

        self.device_source.clear_pending();
        IhtDrainOutcome::NoWork
    }

    fn device_drain_outcome(&self) -> IhtDrainOutcome {
        if !self.virtual_interrupts_enabled() || self.should_exit.load(Ordering::Acquire) {
            return IhtDrainOutcome::StopBeforeNextStep;
        }
        if self.device_source.has_pending() {
            IhtDrainOutcome::StillPending
        } else {
            IhtDrainOutcome::Drained
        }
    }

    fn drain_deliverable_work(&self) {
        let mut drained_events = 0;
        let mut drained_device_events = 0;
        loop {
            if !self.virtual_interrupts_enabled() || self.should_exit.load(Ordering::Acquire) {
                break;
            }

            let mut drained = false;
            match self.drain_timer_ticks() {
                IhtDrainOutcome::Drained | IhtDrainOutcome::StillPending => drained = true,
                IhtDrainOutcome::StopBeforeNextStep => break,
                IhtDrainOutcome::NoWork => {}
            }

            match self.drain_device_event() {
                IhtDrainOutcome::Drained | IhtDrainOutcome::StillPending => {
                    drained = true;
                    drained_device_events += 1;
                }
                IhtDrainOutcome::StopBeforeNextStep => break,
                IhtDrainOutcome::NoWork => {}
            }

            if !drained {
                break;
            }

            drained_events += 1;
            if drained_events >= IHT_DRAIN_BATCH && self.can_run_pending_work() {
                // Specification invariant: IHT delivers timer/device
                // notification and control work; FrameVM service tasks own
                // protocol and device data-path work. If device events make
                // service work runnable, wake service before yielding so the
                // next FrameSchedGroup boundary can choose service after IHT
                // notification-level deliverability is quiescent.
                if drained_device_events != 0 {
                    crate::task::wake_service_tasks_in_frame_vcpu(self.id);
                    drained_device_events = 0;
                }
                Task::yield_now();
                drained_events = 0;
            }
        }

        if drained_device_events != 0 {
            // This is the same IHT-to-service handoff at final quiescence:
            // do not keep IHT deliverable merely because service-owned device
            // backlog remains.
            crate::task::wake_service_tasks_in_frame_vcpu(self.id);
            Task::yield_now();
        }
    }

    /// Wake this IHT.
    #[inline]
    pub fn wake(&self) {
        if !self.virtual_interrupts_enabled() {
            return;
        }
        self.force_wake();
    }

    /// Wake this IHT even when virtual interrupts are disabled.
    #[inline]
    fn force_wake(&self) {
        self.wait_queue.wake_one();
        if let Some(task) = self.task() {
            task.wake_up();
        }
    }

    /// Signal this IHT to exit.
    pub fn signal_exit(&self) {
        self.should_exit.store(true, Ordering::Release);
        self.force_wake();
    }

    /// Wait until this IHT task has entered its main loop.
    pub fn wait_until_started(&self) {
        self.start_wait_queue
            .wait_until(|| self.started.load(Ordering::Acquire).then_some(()));
    }

    /// Wait until this IHT task has exited.
    pub fn wait_for_exit(&self) {
        self.exit_wait_queue.wait_until(|| {
            if self.exited.load(Ordering::Acquire) {
                Some(())
            } else {
                None
            }
        });
    }

    /// Clears pending work and lifecycle flags after the backing task exits.
    pub fn reset_after_exit(&self) {
        self.irq_log.lock().clear();
        self.request_log.lock().clear();
        self.clear_event_sources();
        self.pending_count.store(0, Ordering::Release);
        self.pending_request_count.store(0, Ordering::Release);
        self.virtual_irq_disable_depth.store(0, Ordering::Release);
        self.should_exit.store(false, Ordering::Release);
        self.started.store(false, Ordering::Release);
        self.exited.store(false, Ordering::Release);
        *self.task.lock() = None;
    }

    /// Returns whether this IHT has a backing task.
    pub fn has_task(&self) -> bool {
        self.task.lock().is_some()
    }

    /// Mark exit and wake any waiters.
    fn mark_exited(&self) {
        self.exited.store(true, Ordering::Release);
        self.exit_wait_queue.wake_all();
    }

    /// Mark startup and wake any waiters.
    fn mark_started(&self) {
        self.started.store(true, Ordering::Release);
        self.start_wait_queue.wake_all();
    }

    /// Set the task handle.
    pub fn set_task(&self, task: Arc<Task>) {
        *self.task.lock() = Some(task);
    }
}

// ============================================================================
// IHT Task Creation
// ============================================================================

/// IHT task creator function type.
pub type IhtCreator = fn(Arc<IhtContext>) -> Arc<Task>;

static IHT_CREATOR: Once<IhtCreator> = Once::new();

/// Register the IHT task creator.
pub fn register_iht_creator(creator: IhtCreator) {
    IHT_CREATOR.call_once(|| creator);
}

/// Start an IHT task for the given context.
pub fn start_iht_task(ctx: Arc<IhtContext>) -> Result<()> {
    let creator = match IHT_CREATOR.get() {
        Some(c) => c,
        None => return Err(Error::InvalidArgs),
    };

    let task = creator(ctx.clone());
    ctx.set_task(task);
    ctx.task()
        .expect("IHT task must be registered before run")
        .run();
    Ok(())
}

// ============================================================================
// IHT Main Loop
// ============================================================================

/// IHT main loop.
///
/// Simple event loop:
/// 1. Pop callback from interrupt log
/// 2. Execute callback
/// 3. Repeat until log is empty
/// 4. Sleep until woken
pub fn iht_main_loop(ctx: Arc<IhtContext>) {
    ctx.mark_started();

    loop {
        // Check exit
        if ctx.should_exit.load(Ordering::Acquire) {
            break;
        }

        if ctx.virtual_interrupts_enabled() {
            ctx.drain_deliverable_work();
        }

        // No callbacks, sleep until woken
        ctx.wait_queue.wait_until(|| {
            if ctx.should_exit.load(Ordering::Acquire) {
                return Some(());
            }
            if ctx.can_run_pending_work() {
                return Some(());
            }
            None
        });
    }

    crate::task::clear_current_frame_vcpu();
    ctx.mark_exited();
}

// ============================================================================
// Public API
// ============================================================================

/// Log a callback to the interrupt log and wake IHT.
#[inline]
pub fn log_irq<F>(vcpu_id: usize, callback: F)
where
    F: FnOnce() + Send + 'static,
{
    if let Some(vm) = vm::get_vm() {
        if let Some(ctx) = vm.iht_context(vcpu_id) {
            ctx.push_callback_and_wake(IrqCallback::Boxed(Box::new(callback)));
        }
    }
}

/// Enqueues a typed virtual IRQ request for one vCPU.
#[inline]
pub fn enqueue_virtual_irq(vm_id: vm::VmId, vcpu_id: usize, irq_line: IrqLine) -> Result<()> {
    let vm = vm::get_vm_by_id(vm_id).ok_or(Error::InvalidArgs)?;
    let ctx = vm.iht_context(vcpu_id).ok_or(Error::InvalidArgs)?;
    ctx.push_request_and_wake(VcpuRequest::VirtualIrq { vm_id, irq_line });
    Ok(())
}

/// Coalesces a virtual timer tick for the owning vCPU.
#[inline]
pub fn inject_timer_tick(frame_vcpu_id: FrameVcpuId) {
    if let Some(vm) = vm::get_vm_by_id(frame_vcpu_id.vm_id())
        && let Some(ctx) = vm.iht_context(frame_vcpu_id.vcpu_index())
    {
        ctx.record_timer_tick();
        ctx.wake();
    }
}

/// Disables virtual local interrupts for the owning IHT.
#[inline]
pub fn disable_virtual_interrupts(frame_vcpu_id: FrameVcpuId) {
    if let Some(vm) = vm::get_vm_by_id(frame_vcpu_id.vm_id())
        && let Some(ctx) = vm.iht_context(frame_vcpu_id.vcpu_index())
    {
        ctx.disable_virtual_interrupts();
    }
}

/// Enables virtual local interrupts for the owning IHT.
#[inline]
pub fn enable_virtual_interrupts(frame_vcpu_id: FrameVcpuId) {
    if let Some(vm) = vm::get_vm_by_id(frame_vcpu_id.vm_id())
        && let Some(ctx) = vm.iht_context(frame_vcpu_id.vcpu_index())
    {
        ctx.enable_virtual_interrupts();
    }
}

/// Returns whether virtual local interrupts are enabled for the vCPU.
#[inline]
pub fn virtual_interrupts_enabled(frame_vcpu_id: FrameVcpuId) -> bool {
    let Some(vm) = vm::get_vm_by_id(frame_vcpu_id.vm_id()) else {
        return true;
    };
    let Some(ctx) = vm.iht_context(frame_vcpu_id.vcpu_index()) else {
        return true;
    };
    ctx.virtual_interrupts_enabled()
}

/// Returns whether the IHT for a vCPU has pending virtual work.
#[inline]
pub(crate) fn has_pending_work(frame_vcpu_id: FrameVcpuId) -> bool {
    let Some(vm) = vm::get_vm_by_id(frame_vcpu_id.vm_id()) else {
        return false;
    };
    let Some(ctx) = vm.iht_context(frame_vcpu_id.vcpu_index()) else {
        return false;
    };
    ctx.has_pending_work()
}

/// Get current vCPU ID if running in an IHT task.
#[inline]
pub fn current_vcpu_index() -> Option<usize> {
    let current = Task::current()?;
    let data = current.extension().downcast_ref::<FrameTaskData>()?;
    (data.kind() == FrameTaskKind::Iht).then_some(data.vcpu_index())
}

/// Gets the current vCPU ID if running in an IHT task.
#[inline]
pub fn current_frame_vcpu_id() -> Option<FrameVcpuId> {
    let current = Task::current()?;
    let data = current.extension().downcast_ref::<FrameTaskData>()?;
    if data.kind() != FrameTaskKind::Iht {
        return None;
    }
    let group = data.group()?;
    Some(FrameVcpuId::new(group.vm_id(), group.vcpu_index()))
}

/// Log a callback directly to a specific IHT context.
#[inline]
pub fn log_irq_to_context<F>(ctx: &Arc<IhtContext>, callback: F)
where
    F: FnOnce() + Send + 'static,
{
    ctx.push_callback_and_wake(IrqCallback::Boxed(Box::new(callback)));
}

/// Log a callback without waking IHT (for batch operations).
#[inline]
pub fn log_irq_no_wake<F>(vcpu_id: usize, callback: F)
where
    F: FnOnce() + Send + 'static,
{
    if let Some(vm) = vm::get_vm() {
        if let Some(ctx) = vm.iht_context(vcpu_id) {
            ctx.push_callback(IrqCallback::Boxed(Box::new(callback)));
        }
    }
}

/// Log a function pointer callback (no allocation) and wake IHT.
#[inline]
pub fn log_irq_fn(vcpu_id: usize, callback: fn()) {
    if let Some(vm) = vm::get_vm() {
        if let Some(ctx) = vm.iht_context(vcpu_id) {
            ctx.push_callback_and_wake(IrqCallback::FnPtr(callback));
        }
    }
}

/// Log a function pointer callback (no allocation) to a specific context and wake.
#[inline]
pub fn log_irq_fn_to_context(ctx: &Arc<IhtContext>, callback: fn()) {
    ctx.push_callback_and_wake(IrqCallback::FnPtr(callback));
}

/// Wake IHT without logging (for deferred wake after batch).
#[inline]
pub fn wake(vcpu_id: usize) {
    if let Some(vm) = vm::get_vm() {
        if let Some(ctx) = vm.iht_context(vcpu_id) {
            ctx.wake();
        }
    }
}

/// Check if a vCPU has pending callbacks.
#[inline]
pub fn has_pending(vcpu_id: usize) -> bool {
    if let Some(vm) = vm::get_vm() {
        if let Some(ctx) = vm.iht_context(vcpu_id) {
            return ctx.has_pending();
        }
    }
    false
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    fn empty_irq_callback() {}

    #[ktest]
    fn virtual_interrupt_disable_defers_pending_work() {
        let ctx = IhtContext::new(FrameVcpuId::new(0, 0));

        ctx.disable_virtual_interrupts();
        ctx.push_callback(IrqCallback::FnPtr(empty_irq_callback));

        assert!(ctx.has_pending());
        assert!(!ctx.can_run_pending_work());

        ctx.enable_virtual_interrupts();
        assert!(ctx.can_run_pending_work());
    }

    #[ktest]
    fn nested_virtual_interrupt_disable_requires_matching_enable() {
        let ctx = IhtContext::new(FrameVcpuId::new(0, 0));

        ctx.disable_virtual_interrupts();
        ctx.disable_virtual_interrupts();
        ctx.enable_virtual_interrupts();

        assert!(!ctx.virtual_interrupts_enabled());

        ctx.enable_virtual_interrupts();
        assert!(ctx.virtual_interrupts_enabled());
    }

    #[ktest]
    fn callback_drain_stops_when_virtual_interrupts_are_disabled() {
        let ctx = Arc::new(IhtContext::new(FrameVcpuId::new(0, 0)));
        let callback_ctx = ctx.clone();
        ctx.push_callback(IrqCallback::Boxed(Box::new(move || {
            callback_ctx.disable_virtual_interrupts();
        })));
        ctx.push_callback(IrqCallback::FnPtr(empty_irq_callback));

        ctx.drain_deliverable_work();

        assert!(!ctx.virtual_interrupts_enabled());
        assert_eq!(ctx.pending_count(), 1);
        assert!(ctx.has_pending());

        ctx.enable_virtual_interrupts();
        ctx.drain_deliverable_work();

        assert!(ctx.virtual_interrupts_enabled());
        assert_eq!(ctx.pending_count(), 0);
        assert!(!ctx.has_pending());
    }
}
