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

use alloc::{boxed::Box, collections::VecDeque, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use host_ostd::{
    sync::{SpinLock, WaitQueue},
    task::Task,
};
#[cfg(not(feature = "host-api"))]
use vm::FrameTaskGroupId;

#[cfg(not(feature = "host-api"))]
use crate::service_domain as vm;
#[cfg(feature = "host-api")]
use crate::vm::{self, FrameTaskGroupId};
use crate::{error::Error, prelude::Result, sync::Once};

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

/// Queue capacity for interrupt log (pre-allocated to avoid reallocation)
const IRQ_LOG_CAPACITY: usize = 256;

// ============================================================================
// Per-vCPU Context
// ============================================================================

/// Per-vCPU IHT context with interrupt log.
pub struct IhtContext {
    /// Task group identity
    task_group_id: FrameTaskGroupId,
    /// vCPU ID
    vcpu_id: usize,
    /// Interrupt log: queue of callbacks to execute
    irq_log: SpinLock<VecDeque<IrqCallback>>,
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
    /// Nested virtual local interrupt disable depth for this vCPU.
    virtual_irq_disable_depth: AtomicUsize,
    /// Task handle
    task: SpinLock<Option<Arc<Task>>>,
}

impl IhtContext {
    /// Create a new IHT context.
    pub fn new(task_group_id: FrameTaskGroupId) -> Self {
        Self {
            task_group_id,
            vcpu_id: task_group_id.vcpu_id(),
            irq_log: SpinLock::new(VecDeque::with_capacity(IRQ_LOG_CAPACITY)),
            wait_queue: WaitQueue::new(),
            start_wait_queue: WaitQueue::new(),
            exit_wait_queue: WaitQueue::new(),
            started: AtomicBool::new(false),
            should_exit: AtomicBool::new(false),
            exited: AtomicBool::new(false),
            pending_count: AtomicUsize::new(0),
            virtual_irq_disable_depth: AtomicUsize::new(0),
            task: SpinLock::new(None),
        }
    }

    /// Get vCPU ID.
    #[inline]
    pub fn vcpu_id(&self) -> usize {
        self.vcpu_id
    }

    /// Get task group ID.
    #[inline]
    pub fn task_group_id(&self) -> FrameTaskGroupId {
        self.task_group_id
    }

    /// Push a callback to the interrupt log.
    #[inline]
    pub fn push_callback(&self, callback: IrqCallback) {
        self.irq_log.lock().push_back(callback);
        self.pending_count.fetch_add(1, Ordering::Release);
    }

    /// Push a callback and wake only if transitioning from empty to non-empty.
    #[inline]
    pub fn push_callback_and_wake(&self, callback: IrqCallback) {
        self.irq_log.lock().push_back(callback);
        if self.pending_count.fetch_add(1, Ordering::AcqRel) == 0 {
            self.wake();
        }
    }

    /// Pop a callback from the interrupt log.
    #[inline]
    pub fn pop_callback(&self) -> Option<IrqCallback> {
        let mut log = self.irq_log.lock();
        let cb = log.pop_front();
        if cb.is_some() {
            self.pending_count.fetch_sub(1, Ordering::Release);
        }
        cb
    }

    /// Check if there are pending callbacks.
    #[inline]
    pub fn has_pending(&self) -> bool {
        self.pending_count.load(Ordering::Acquire) != 0
    }

    /// Check if there is pending virtual timer work.
    #[inline]
    pub fn has_pending_timer_work(&self) -> bool {
        vm::get_task_group_by_id(self.task_group_id)
            .is_some_and(|task_group| task_group.has_pending_timer_work())
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

    fn drain_timer_ticks(&self) {
        let Some(task_group) = vm::get_task_group_by_id(self.task_group_id) else {
            return;
        };
        let ticks = task_group.take_pending_timer_ticks();
        if ticks != 0 {
            crate::task::scheduler::dispatch_timer_ticks(self.task_group_id, ticks);
        }
    }

    /// Get pending callback count.
    #[inline]
    pub fn pending_count(&self) -> usize {
        self.pending_count.load(Ordering::Acquire)
    }

    fn has_pending_work(&self) -> bool {
        self.has_pending() || self.has_pending_timer_work()
    }

    fn can_run_pending_work(&self) -> bool {
        self.virtual_interrupts_enabled() && self.has_pending_work()
    }

    fn run_ready_callbacks(&self) {
        while let Some(callback) = self.pop_callback() {
            callback.call();
            if self.should_exit.load(Ordering::Acquire) || !self.virtual_interrupts_enabled() {
                break;
            }
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

/// Extension data attached to IHT backing tasks.
pub struct IhtTaskData {
    vcpu_id: usize,
    task_group_id: FrameTaskGroupId,
}

impl IhtTaskData {
    /// Creates IHT task data.
    pub fn new(vcpu_id: usize, task_group_id: FrameTaskGroupId) -> Self {
        Self {
            vcpu_id,
            task_group_id,
        }
    }

    /// Returns the vCPU ID.
    pub fn vcpu_id(&self) -> usize {
        self.vcpu_id
    }

    /// Returns the task group ID.
    pub fn task_group_id(&self) -> FrameTaskGroupId {
        self.task_group_id
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
            // Scheduler ticks must be visible before ordinary virtual interrupts.
            ctx.drain_timer_ticks();

            // Process callbacks without moving out the interrupt-log buffer.
            ctx.run_ready_callbacks();
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

    crate::task::clear_current_frame_task_group();
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

/// Coalesces a virtual timer tick for the owning vCPU.
#[inline]
pub fn inject_timer_tick(task_group_id: FrameTaskGroupId) {
    let Some(task_group) = vm::get_task_group_by_id(task_group_id) else {
        return;
    };
    task_group.inject_timer_tick();

    if let Some(vm) = vm::get_vm_by_id(task_group_id.vm_id())
        && let Some(ctx) = vm.iht_context(task_group_id.vcpu_id())
    {
        ctx.wake();
    }
}

/// Disables virtual local interrupts for the owning IHT.
#[inline]
pub fn disable_virtual_interrupts(task_group_id: FrameTaskGroupId) {
    if let Some(vm) = vm::get_vm_by_id(task_group_id.vm_id())
        && let Some(ctx) = vm.iht_context(task_group_id.vcpu_id())
    {
        ctx.disable_virtual_interrupts();
    }
}

/// Enables virtual local interrupts for the owning IHT.
#[inline]
pub fn enable_virtual_interrupts(task_group_id: FrameTaskGroupId) {
    if let Some(vm) = vm::get_vm_by_id(task_group_id.vm_id())
        && let Some(ctx) = vm.iht_context(task_group_id.vcpu_id())
    {
        ctx.enable_virtual_interrupts();
    }
}

/// Returns whether virtual local interrupts are enabled for the task group.
#[inline]
pub fn virtual_interrupts_enabled(task_group_id: FrameTaskGroupId) -> bool {
    let Some(vm) = vm::get_vm_by_id(task_group_id.vm_id()) else {
        return true;
    };
    let Some(ctx) = vm.iht_context(task_group_id.vcpu_id()) else {
        return true;
    };
    ctx.virtual_interrupts_enabled()
}

/// Returns whether the IHT for a task group has pending virtual work.
#[inline]
pub(crate) fn has_pending_work(task_group_id: FrameTaskGroupId) -> bool {
    let Some(vm) = vm::get_vm_by_id(task_group_id.vm_id()) else {
        return false;
    };
    let Some(ctx) = vm.iht_context(task_group_id.vcpu_id()) else {
        return false;
    };
    ctx.has_pending_work()
}

/// Get current vCPU ID if running in an IHT task.
#[inline]
pub fn current_vcpu_id() -> Option<usize> {
    let current = Task::current()?;
    current
        .extension()
        .downcast_ref::<IhtTaskData>()
        .map(IhtTaskData::vcpu_id)
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
        let ctx = IhtContext::new(FrameTaskGroupId::new(0, 0));

        ctx.disable_virtual_interrupts();
        ctx.push_callback(IrqCallback::FnPtr(empty_irq_callback));

        assert!(ctx.has_pending());
        assert!(!ctx.can_run_pending_work());

        ctx.enable_virtual_interrupts();
        assert!(ctx.can_run_pending_work());
    }

    #[ktest]
    fn nested_virtual_interrupt_disable_requires_matching_enable() {
        let ctx = IhtContext::new(FrameTaskGroupId::new(0, 0));

        ctx.disable_virtual_interrupts();
        ctx.disable_virtual_interrupts();
        ctx.enable_virtual_interrupts();

        assert!(!ctx.virtual_interrupts_enabled());

        ctx.enable_virtual_interrupts();
        assert!(ctx.virtual_interrupts_enabled());
    }

    #[ktest]
    fn callback_drain_stops_when_virtual_interrupts_are_disabled() {
        let ctx = Arc::new(IhtContext::new(FrameTaskGroupId::new(0, 0)));
        let callback_ctx = ctx.clone();
        ctx.push_callback(IrqCallback::Boxed(Box::new(move || {
            callback_ctx.disable_virtual_interrupts();
        })));
        ctx.push_callback(IrqCallback::FnPtr(empty_irq_callback));

        ctx.run_ready_callbacks();

        assert!(!ctx.virtual_interrupts_enabled());
        assert_eq!(ctx.pending_count(), 1);
        assert!(ctx.has_pending());

        ctx.enable_virtual_interrupts();
        ctx.run_ready_callbacks();

        assert!(ctx.virtual_interrupts_enabled());
        assert_eq!(ctx.pending_count(), 0);
        assert!(!ctx.has_pending());
    }
}
