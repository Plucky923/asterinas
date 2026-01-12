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

use ostd::{
    sync::{SpinLock, WaitQueue},
    task::Task,
};
use spin::Once;

use crate::vm;

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
    /// vCPU ID
    vcpu_id: usize,
    /// Interrupt log: queue of callbacks to execute
    irq_log: SpinLock<VecDeque<IrqCallback>>,
    /// Wait queue for sleeping
    wait_queue: WaitQueue,
    /// Wait queue for exit notification
    exit_wait_queue: WaitQueue,
    /// Exit flag
    should_exit: AtomicBool,
    /// Exit completion flag
    exited: AtomicBool,
    /// Pending callback count (fast path, avoids lock)
    pending_count: AtomicUsize,
    /// Task handle
    task: SpinLock<Option<Arc<Task>>>,
}

impl IhtContext {
    /// Create a new IHT context.
    pub fn new(vcpu_id: usize) -> Self {
        Self {
            vcpu_id,
            irq_log: SpinLock::new(VecDeque::with_capacity(IRQ_LOG_CAPACITY)),
            wait_queue: WaitQueue::new(),
            exit_wait_queue: WaitQueue::new(),
            should_exit: AtomicBool::new(false),
            exited: AtomicBool::new(false),
            pending_count: AtomicUsize::new(0),
            task: SpinLock::new(None),
        }
    }

    /// Get vCPU ID.
    #[inline]
    pub fn vcpu_id(&self) -> usize {
        self.vcpu_id
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

    /// Pop all callbacks in a batch.
    #[inline]
    pub fn pop_all_callbacks(&self) -> VecDeque<IrqCallback> {
        let mut log = self.irq_log.lock();
        let callbacks = core::mem::take(&mut *log);
        self.pending_count.store(0, Ordering::Release);
        callbacks
    }

    /// Check if there are pending callbacks.
    #[inline]
    pub fn has_pending(&self) -> bool {
        self.pending_count.load(Ordering::Acquire) != 0
    }

    /// Get pending callback count.
    #[inline]
    pub fn pending_count(&self) -> usize {
        self.pending_count.load(Ordering::Acquire)
    }

    /// Wake this IHT.
    #[inline]
    pub fn wake(&self) {
        self.wait_queue.wake_one();
    }

    /// Signal this IHT to exit.
    pub fn signal_exit(&self) {
        self.should_exit.store(true, Ordering::Release);
        self.wake();
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
pub fn start_iht_task(ctx: Arc<IhtContext>) {
    let creator = match IHT_CREATOR.get() {
        Some(c) => c,
        None => return,
    };

    let task = creator(ctx.clone());
    ctx.set_task(task);
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
    loop {
        // Check exit
        if ctx.should_exit.load(Ordering::Acquire) {
            break;
        }

        // Process all callbacks in the interrupt log
        let callbacks = ctx.pop_all_callbacks();
        for callback in callbacks {
            callback.call();
            if ctx.should_exit.load(Ordering::Acquire) {
                break;
            }
        }

        // No callbacks, sleep until woken
        ctx.wait_queue.wait_until(|| {
            if ctx.should_exit.load(Ordering::Acquire) {
                return Some(());
            }
            if ctx.has_pending() {
                return Some(());
            }
            None
        });
    }

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

/// Get current vCPU ID if running in an IHT task.
#[inline]
pub fn current_vcpu_id() -> Option<usize> {
    let current = Task::current()?;
    current.extension().downcast_ref::<usize>().copied()
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
