// SPDX-License-Identifier: MPL-2.0

//! Tasks are the unit of code execution.

#[cfg(feature = "kernelet")]
pub(crate) mod accounting;
pub mod atomic_mode;
#[cfg_attr(feature = "kernelet", path = "kernelet_stack.rs")]
pub(crate) mod kernel_stack;
mod preempt;

mod processor;
pub mod scheduler;
mod utils;

use core::{
    any::Any,
    borrow::Borrow,
    cell::{Cell, SyncUnsafeCell},
    ops::Deref,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};
#[cfg(feature = "kernelet")]
use core::{
    cell::RefCell,
    sync::atomic::{AtomicPtr, AtomicU32},
};

use kernel_stack::KernelStack;
#[cfg(feature = "kernelet")]
pub(crate) use processor::after_switching_to;
use processor::current_task;
use spin::Once;
use utils::ForceSync;

pub use self::{
    preempt::{DisabledPreemptGuard, disable_preempt, halt_cpu},
    scheduler::info::{AtomicCpuId, TaskScheduleInfo},
};
#[cfg(feature = "kernelet")]
use crate::Error;
use crate::{
    arch::task::TaskContext,
    irq::{DisabledLocalIrqGuard, InterruptLevel},
    prelude::*,
};

static PRE_SCHEDULE_HANDLER: Once<fn(&DisabledLocalIrqGuard)> = Once::new();

static POST_SCHEDULE_HANDLER: Once<fn()> = Once::new();

#[cfg(all(ktest, target_arch = "x86_64"))]
pub(crate) fn preempt_guard_count() -> u32 {
    preempt::cpu_local::get_guard_count()
}

/// Injects a handler to be executed before scheduling.
pub fn inject_pre_schedule_handler(handler: fn(&DisabledLocalIrqGuard)) {
    PRE_SCHEDULE_HANDLER.call_once(|| handler);
}

/// Injects a handler to be executed after scheduling.
pub fn inject_post_schedule_handler(handler: fn()) {
    POST_SCHEDULE_HANDLER.call_once(|| handler);
}

/// Size of the `LinuxPtRegs` save area reserved at the top of each user Task's
/// kernel stack (168 bytes rounded up to 16-byte stack alignment).
#[cfg(feature = "kernelet")]
pub(crate) const PT_REGS_SAVE_AREA_BYTES: usize =
    size_of::<crate::arch::cpu::context::LinuxPtRegs>().next_multiple_of(16);

/// Ends the current Task using the normal return-path cleanup.
///
/// This never returns. The caller must release any owned resources on its
/// stack before calling it, because the stack will be discarded after switching.
pub(crate) fn exit_current_task() -> ! {
    #[cfg(feature = "kernelet")]
    {
        crate::mm::VmSpace::deactivate();
        let _irq_guard = crate::irq::disable_local();
        if let Some(current) = Task::current() {
            current.exiting.store(true, Ordering::Release);
        }
    }

    scheduler::exit_current();
}

/// Adopts this vCPU's live bootstrap stack as a one-shot current Task.
///
/// This Task never enters a runqueue: it runs initialization to completion,
/// then exits. It cannot yield, park, halt, run again, or be woken. IRQs remain
/// deliverable; only inner scheduling and RCU callback dispatch are deferred.
/// The caller must have initialized the allocator, CPU-local storage, and RCU,
/// and must still hold virtual IRQs disabled with no guard or deferral active.
#[cfg(feature = "kernelet")]
pub(crate) fn adopt_boot_task() {
    assert!(!crate::arch::irq::is_local_enabled());
    assert!(InterruptLevel::current().is_task_context());
    assert_eq!(preempt::cpu_local::get_guard_count(), 0);
    assert!(!virq_delivery_deferred());
    assert!(Task::current().is_none());

    let vcpu_record = crate::kernelet::entry::vcpu_record();
    let base = vcpu_record.stack_limit.load(Ordering::Acquire) as usize;
    assert!(base.is_multiple_of(crate::mm::PAGE_SIZE));
    let rsp: usize;
    // SAFETY: Reading RSP does not access memory or change execution state.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags))
    };
    // SAFETY: Entry is executing on the Host-provided live boot slot. The
    // bounds below are checked before publishing its one-shot Task owner.
    let kstack = unsafe { KernelStack::adopt_boot(base) };
    assert!((base..kstack.end_vaddr()).contains(&rsp));

    let task = Arc::new(Task {
        func: ForceSync::new(Cell::new(None)),
        data: Box::new(()),
        local_data: ForceSync::new(Box::new(())),
        // The first ordinary context_switch writes this context. It is
        // never restored because a boot Task cannot be scheduled again.
        ctx: SyncUnsafeCell::new(TaskContext::new()),
        kstack,
        switched_to_cpu: AtomicBool::new(true),
        scheduling_in_progress: AtomicBool::new(false),
        virq_deferral_depth: AtomicU32::new(0),
        active_vm_space: ForceSync::new(RefCell::new(None)),
        is_user: false,
        exiting: AtomicBool::new(false),
        active_pt_regs: AtomicPtr::new(core::ptr::null_mut()),
        active_vcpu_record: AtomicPtr::new(core::ptr::from_ref(vcpu_record).cast_mut()),
        schedule_info: TaskScheduleInfo {
            cpu: AtomicCpuId::default(),
        },
    });
    processor::adopt_current_boot_task(task);
}

/// Whether this vCPU is still executing its non-enqueued boot Task.
#[cfg(feature = "kernelet")]
pub(crate) fn in_boot_task() -> bool {
    preempt::cpu_local::in_boot_task()
}

/// A task that executes a function to the end.
///
/// Each task is associated with per-task data and an optional user space.
/// If having a user space, the task can switch to the user space to
/// execute user code. Multiple tasks can share a single user space.
#[derive(Debug)]
pub struct Task {
    #[expect(clippy::type_complexity)]
    func: ForceSync<Cell<Option<Box<dyn FnOnce() + Send>>>>,

    data: Box<dyn Any + Send + Sync>,
    local_data: ForceSync<Box<dyn Any + Send>>,

    ctx: SyncUnsafeCell<TaskContext>,
    /// kernel stack, note that the top is SyscallFrame/TrapFrame
    kstack: KernelStack,

    /// If we have switched this task to a CPU.
    ///
    /// This is to enforce not context switching to an already running task.
    /// See [`processor::switch_to_task`] for more details.
    switched_to_cpu: AtomicBool,

    /// Defers preemption from a scheduler decision until its context switch.
    scheduling_in_progress: AtomicBool,

    /// Defers virtual interrupt delivery while this Task finishes an upcall.
    #[cfg(feature = "kernelet")]
    virq_deferral_depth: AtomicU32,

    /// Retains the user space last activated by this Guest Task.
    #[cfg(feature = "kernelet")]
    active_vm_space: ForceSync<RefCell<Option<Arc<crate::mm::VmSpace>>>>,

    /// Whether this Task executes user mode via `UserEventHandler`.
    #[cfg(feature = "kernelet")]
    is_user: bool,

    /// Set once the Task enters `exit_current_task` so preemption cannot
    /// re-establish `PT_REGS_OWNER` on it before exit completes.
    #[cfg(feature = "kernelet")]
    exiting: AtomicBool,

    /// Live Host `pt_regs` pointer on the vCPU currently hosting this user Task.
    #[cfg(feature = "kernelet")]
    active_pt_regs: AtomicPtr<crate::arch::cpu::context::LinuxPtRegs>,

    /// Host record for the executing vCPU, refreshed before each switch-in.
    #[cfg(feature = "kernelet")]
    active_vcpu_record: AtomicPtr<crate::kernelet::abi::VcpuRecord>,

    schedule_info: TaskScheduleInfo,
}

impl Task {
    /// Settles a batch captured while this Task owned its vCPU's execution.
    /// IRQs must be off, and an outgoing Task must still be switched_to_cpu.
    #[cfg(feature = "kernelet")]
    fn account_sampled_ticks(&self, batch: u64) {
        debug_assert!(!crate::arch::irq::is_local_enabled());
        debug_assert!(self.switched_to_cpu.load(Ordering::Acquire));
        let (user, kernel) = crate::kernelet::abi::PendingTaskTicks::split(batch);
        if user != 0 {
            crate::irq::call_sampled_task_tick_callback_functions(
                self,
                crate::cpu::PrivilegeLevel::User,
                user,
            );
        }
        if kernel != 0 {
            crate::irq::call_sampled_task_tick_callback_functions(
                self,
                crate::cpu::PrivilegeLevel::Kernel,
                kernel,
            );
        }
    }

    /// Gets the current task.
    ///
    /// It returns `None` in Native bootstrap or before Guest boot adopts its Task.
    pub fn current() -> Option<CurrentTask> {
        let current_task = current_task()?;

        // SAFETY: `current_task` is the current task.
        Some(unsafe { CurrentTask::new(current_task) })
    }

    /// Gets the current Task through an IRQ-pinned CPU-local access.
    #[cfg(feature = "kernelet")]
    pub(crate) fn current_with(
        access: &crate::arch::cpu::local::CpuLocalAccess<'_>,
    ) -> Option<CurrentTask> {
        let current_task = processor::current_task_with(access)?;
        // SAFETY: The borrowed IRQ guard pins the Task pointer during this lookup.
        Some(unsafe { CurrentTask::new(current_task) })
    }

    pub(super) fn ctx(&self) -> &SyncUnsafeCell<TaskContext> {
        &self.ctx
    }

    #[cfg(feature = "kernelet")]
    pub(super) fn is_boot_task(&self) -> bool {
        self.kstack.is_boot()
    }

    #[cfg(feature = "kernelet")]
    pub(crate) fn is_user(&self) -> bool {
        self.is_user
    }

    #[cfg(feature = "kernelet")]
    pub(super) fn is_exiting(&self) -> bool {
        self.exiting.load(Ordering::Acquire)
    }

    #[cfg(feature = "kernelet")]
    pub(super) fn event_rsp(&self) -> usize {
        debug_assert!(self.is_user);
        self.kstack.end_vaddr() - PT_REGS_SAVE_AREA_BYTES
    }

    #[cfg(feature = "kernelet")]
    pub(super) fn pt_regs_save_area(&self) -> *mut crate::arch::cpu::context::LinuxPtRegs {
        self.event_rsp() as *mut crate::arch::cpu::context::LinuxPtRegs
    }

    #[cfg(feature = "kernelet")]
    pub(crate) fn active_pt_regs(&self) -> &AtomicPtr<crate::arch::cpu::context::LinuxPtRegs> {
        &self.active_pt_regs
    }

    /// Returns the CPU-local section byte offset of `CURRENT_TASK_PTR`.
    #[cfg(feature = "kernelet")]
    #[inline(always)]
    pub(crate) fn current_task_ptr_offset() -> usize {
        processor::current_task_ptr_offset()
    }

    /// Returns the CPU-local section byte offset of `PREEMPT_INFO`.
    #[cfg(feature = "kernelet")]
    #[inline(always)]
    pub(crate) fn preempt_info_offset() -> usize {
        preempt::cpu_local::preempt_info_offset()
    }

    /// Returns whether we need to yield execution to another task.
    ///
    /// If the scheduler decides to preempt the current task in favor of
    /// another (for example, if the current task has exhausted its runtime
    /// budget or if the new task has a higher priority), this method will
    /// return `true`.
    pub fn need_yield() -> bool {
        preempt::cpu_local::need_preempt()
    }

    /// Yields execution so that another task may be scheduled.
    ///
    /// Note that this method cannot be simply named "yield" as the name is
    /// a Rust keyword.
    ///
    /// # Panics
    ///
    /// Panics if the current Task is a kernelet's one-shot boot Task.
    #[track_caller]
    pub fn yield_now() {
        scheduler::yield_now()
    }

    /// Kicks the task scheduler to run the task.
    ///
    /// BUG: This method highly depends on the current scheduling policy.
    ///
    /// # Panics
    ///
    /// Panics if this is a kernelet's one-shot boot Task.
    #[track_caller]
    pub fn run(self: &Arc<Self>) {
        #[cfg(feature = "kernelet")]
        assert!(!self.kstack.is_boot(), "a boot Task cannot be run again");
        scheduler::run_new_task(self.clone());
    }

    /// Returns the task data.
    pub fn data(&self) -> &Box<dyn Any + Send + Sync> {
        &self.data
    }

    /// Get the attached scheduling information.
    pub fn schedule_info(&self) -> &TaskScheduleInfo {
        &self.schedule_info
    }
}

crate::cpu_local_cell! {
    static BOOT_SCHEDULING_IN_PROGRESS: bool = false;
}

pub(crate) fn scheduling_in_progress() -> bool {
    Task::current().map_or_else(
        || BOOT_SCHEDULING_IN_PROGRESS.load(),
        |task| task.scheduling_in_progress.load(Ordering::Relaxed),
    )
}

/// Completes this Task's scheduling transition before callbacks can reschedule.
pub(super) fn finish_scheduling() {
    if let Some(task) = Task::current() {
        task.scheduling_in_progress.store(false, Ordering::Relaxed);
    } else {
        BOOT_SCHEDULING_IN_PROGRESS.store(false);
    }
}

/// Keeps IRQ preemption from reentering a Task's unfinished scheduler decision.
///
/// The mark follows the Task across a context switch. It does not mask IRQs or
/// add a preemption guard, so the scheduler can still switch to another Task.
pub(crate) struct SchedulingGuard;

impl !Send for SchedulingGuard {}

impl SchedulingGuard {
    pub(crate) fn new() -> Self {
        debug_assert!(!scheduling_in_progress());
        if let Some(task) = Task::current() {
            task.scheduling_in_progress.store(true, Ordering::Relaxed);
        } else {
            BOOT_SCHEDULING_IN_PROGRESS.store(true);
        }
        Self
    }
}

impl Drop for SchedulingGuard {
    fn drop(&mut self) {
        finish_scheduling();
    }
}

#[cfg(feature = "kernelet")]
crate::cpu_local_cell! {
    static BOOT_VIRQ_DEFERRAL_DEPTH: u32 = 0;
}

/// Returns whether the current Task is in a virtual-interrupt deferral region.
#[cfg(feature = "kernelet")]
pub(crate) fn virq_delivery_deferred() -> bool {
    scheduling_in_progress()
        || Task::current().map_or_else(
            || BOOT_VIRQ_DEFERRAL_DEPTH.load() != 0,
            |task| task.virq_deferral_depth.load(Ordering::Relaxed) != 0,
        )
}

/// Holds off nested virtual interrupts until this Task has finished its
/// upcall epilogue. The mark follows the Task across a context switch;
/// another Task can still receive pending notices on the same vCPU.
#[cfg(feature = "kernelet")]
pub(crate) struct VirtualIrqDeferral;

#[cfg(feature = "kernelet")]
impl VirtualIrqDeferral {
    pub(crate) fn new() -> Self {
        if let Some(task) = Task::current() {
            task.virq_deferral_depth.fetch_add(1, Ordering::Relaxed);
        } else {
            BOOT_VIRQ_DEFERRAL_DEPTH.add_assign(1);
        }
        Self
    }
}

#[cfg(feature = "kernelet")]
impl Drop for VirtualIrqDeferral {
    fn drop(&mut self) {
        if let Some(task) = Task::current() {
            let previous = task.virq_deferral_depth.fetch_sub(1, Ordering::Relaxed);
            debug_assert!(previous > 0);
        } else {
            debug_assert!(BOOT_VIRQ_DEFERRAL_DEPTH.load() > 0);
            BOOT_VIRQ_DEFERRAL_DEPTH.sub_assign(1);
        }
    }
}

/// Options to create or spawn a new task.
pub struct TaskOptions {
    entry: TaskEntry,
    data: Option<Box<dyn Any + Send + Sync>>,
    local_data: Option<Box<dyn Any + Send>>,
}

enum TaskEntry {
    Kernel(Box<dyn FnOnce() + Send>),
    #[cfg(feature = "kernelet")]
    User(crate::arch::cpu::context::UserContext),
}

/// A fallibly reserved Task stack, owned until task construction or Drop.
///
/// Reserve this before entering an infallible cyclic-owner constructor.
pub struct PreparedTaskStack(KernelStack);

impl TaskOptions {
    /// Creates a set of options for a task.
    pub fn new<F>(func: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            entry: TaskEntry::Kernel(Box::new(func)),
            data: None,
            local_data: None,
        }
    }

    /// Creates a set of options for a kernelet user-mode task handled via
    /// [`crate::user::UserEventHandler`].
    #[cfg(feature = "kernelet")]
    pub fn new_user(user_ctx: crate::arch::cpu::context::UserContext) -> Self {
        Self {
            entry: TaskEntry::User(user_ctx),
            data: None,
            local_data: None,
        }
    }

    /// Replaces the task's entry point with a kernel function.
    pub fn func<F>(mut self, func: F) -> Self
    where
        F: Fn() + Send + 'static,
    {
        self.entry = TaskEntry::Kernel(Box::new(func));
        self
    }

    /// Sets the data associated with the task.
    pub fn data<T>(mut self, data: T) -> Self
    where
        T: Any + Send + Sync,
    {
        self.data = Some(Box::new(data));
        self
    }

    /// Sets the local data associated with the task.
    pub fn local_data<T>(mut self, data: T) -> Self
    where
        T: Any + Send,
    {
        self.local_data = Some(Box::new(data));
        self
    }

    /// Builds a new task without running it immediately.
    /// Returns [`Error::InvalidArgs`] if user task data does not match the linked handler.
    pub fn build(self) -> Result<Task> {
        self.validate()?;
        Ok(self.build_validated(Self::prepare_stack()?))
    }

    /// Reserves the stack before publishing cyclic Task/Thread ownership.
    pub fn prepare_stack() -> Result<PreparedTaskStack> {
        KernelStack::new_with_guard_page().map(PreparedTaskStack)
    }

    /// Builds a dormant task using an already reserved stack.
    /// Returns [`Error::InvalidArgs`] if user task data does not match the linked handler.
    pub fn build_with_stack(self, stack: PreparedTaskStack) -> Result<Task> {
        self.validate()?;
        Ok(self.build_validated(stack))
    }

    fn validate(&self) -> Result<()> {
        #[cfg(feature = "kernelet")]
        if matches!(self.entry, TaskEntry::User(_))
            && (self.data.as_ref().map(|data| (**data).type_id())
                != Some(crate::user::user_event_handler_data_type_id())
                || self.local_data.as_ref().map(|data| (**data).type_id())
                    != Some(crate::user::user_event_handler_local_data_type_id()))
        {
            return Err(Error::InvalidArgs);
        }
        Ok(())
    }

    fn build_validated(self, stack: PreparedTaskStack) -> Task {
        // All tasks will enter this function. It is meant to execute the `task_fn` in `Task`.
        //
        // We provide an assembly wrapper for this function as the end of call stack so we
        // have to disable name mangling for it.
        //
        // # Safety
        //
        // This function must be called from `switch.S` when the context is prepared correctly.
        // SAFETY: The name does not collide with other symbols.
        #[unsafe(no_mangle)]
        unsafe extern "C" fn kernel_task_entry() -> ! {
            // SAFETY: The new task is switched on a CPU for the first time, `after_switching_to`
            // hasn't been called yet.
            #[cfg(feature = "kernelet")]
            unsafe {
                after_switching_to()
            };
            #[cfg(not(feature = "kernelet"))]
            unsafe {
                processor::after_switching_to()
            };

            let current_task = Task::current()
                .expect("no current task, it should have current task in kernel task entry");

            // SAFETY: The `func` field will only be accessed by the current task in the task
            // context, so the data won't be accessed concurrently.
            let task_func = unsafe { current_task.func.get() };
            let task_func = task_func
                .take()
                .expect("task function is `None` when trying to run");
            task_func();

            // Manually drop all the on-stack variables to prevent memory leakage!
            // This is needed because `scheduler::exit_current()` will never return.
            //
            // However, `current_task` _borrows_ the current task without holding
            // an extra reference count. So we do nothing here.

            exit_current_task();
        }

        let kstack = stack.0;

        #[cfg(feature = "kernelet")]
        let is_user = matches!(self.entry, TaskEntry::User(_));
        let mut ctx = TaskContext::new();
        let func = match self.entry {
            TaskEntry::Kernel(func) => {
                ctx.set_instruction_pointer(
                    crate::arch::task::kernel_task_entry_wrapper as *const () as usize,
                );
                // Reserve the return address and maintain the ABI's 16-byte alignment.
                ctx.set_stack_pointer(kstack.end_vaddr() - 16);
                Some(func)
            }
            #[cfg(feature = "kernelet")]
            TaskEntry::User(user_ctx) => {
                let event_rsp = kstack.end_vaddr() - PT_REGS_SAVE_AREA_BYTES;
                let save_area = event_rsp as *mut crate::arch::cpu::context::LinuxPtRegs;
                // SAFETY: This reserved area belongs to the dormant task's stack.
                unsafe { save_area.write(user_ctx.into_sanitized_pt_regs()) };
                ctx.set_instruction_pointer(
                    crate::arch::task::first_user_task_entry_wrapper as *const () as usize,
                );
                ctx.set_stack_pointer(event_rsp - 16);
                None
            }
        };

        Task {
            func: ForceSync::new(Cell::new(func)),
            data: self.data.unwrap_or_else(|| Box::new(())),
            local_data: ForceSync::new(self.local_data.unwrap_or_else(|| Box::new(()))),
            ctx: SyncUnsafeCell::new(ctx),
            kstack,
            switched_to_cpu: AtomicBool::new(false),
            scheduling_in_progress: AtomicBool::new(false),
            #[cfg(feature = "kernelet")]
            virq_deferral_depth: AtomicU32::new(0),
            #[cfg(feature = "kernelet")]
            active_vm_space: ForceSync::new(RefCell::new(None)),
            #[cfg(feature = "kernelet")]
            is_user,
            #[cfg(feature = "kernelet")]
            exiting: AtomicBool::new(false),
            #[cfg(feature = "kernelet")]
            active_pt_regs: AtomicPtr::new(core::ptr::null_mut()),
            #[cfg(feature = "kernelet")]
            active_vcpu_record: AtomicPtr::new(core::ptr::null_mut()),
            schedule_info: TaskScheduleInfo {
                cpu: AtomicCpuId::default(),
            },
        }
    }

    /// Builds a new task and runs it immediately.
    #[track_caller]
    pub fn spawn(self) -> Result<Arc<Task>> {
        let task = Arc::new(self.build()?);
        task.run();
        Ok(task)
    }
}

/// The current task.
///
/// This type is not `Send`, so it cannot outlive the current task.
///
/// This type is also not `Sync`, so it can provide access to the local data of the current task.
#[derive(Debug)]
pub struct CurrentTask(NonNull<Task>);

// The intern `NonNull<Task>` contained by `CurrentTask` implies that `CurrentTask` is `!Send` and
// `!Sync`. But it is still good to do this explicitly because these properties are key for
// soundness.
impl !Send for CurrentTask {}
impl !Sync for CurrentTask {}

impl CurrentTask {
    /// Returns the location updated before this task resumes on a vCPU.
    ///
    /// Load and use the pointer with virtual IRQs disabled or inside one
    /// `.text.kernelet_cpu_access` sequence, so migration cannot intervene.
    #[cfg(feature = "kernelet")]
    #[inline(always)]
    pub(crate) fn active_vcpu_record_ptr(
        &self,
    ) -> *const AtomicPtr<crate::kernelet::abi::VcpuRecord> {
        core::ptr::from_ref(&self.active_vcpu_record)
    }

    /// Settles this Task's physical tick samples before publishing an exit.
    ///
    /// Only explicit-owner accounting callbacks run. No global timer callback
    /// is replayed, and this method does not change the running Task identity.
    #[cfg(feature = "kernelet")]
    pub fn flush_sampled_ticks(&self) {
        assert!(InterruptLevel::current().is_task_context());
        let _irq_guard = crate::irq::disable_local();
        assert_eq!(current_task(), Some(self.0));
        let batch = crate::kernelet::entry::vcpu_record().task_ticks.take();
        self.account_sampled_ticks(batch);
    }

    #[cfg(feature = "kernelet")]
    pub(crate) fn replace_active_vm_space(
        &self,
        space: Option<Arc<crate::mm::VmSpace>>,
        _irq_guard: &DisabledLocalIrqGuard,
    ) -> Option<Arc<crate::mm::VmSpace>> {
        // SAFETY: The current Task owns this cache, and the IRQ guard excludes
        // Guest upcalls that could access it before this replacement finishes.
        unsafe { self.active_vm_space.get() }.replace(space)
    }

    /// # Safety
    ///
    /// The caller must ensure that `task` is the current task.
    unsafe fn new(task: NonNull<Task>) -> Self {
        Self(task)
    }

    /// Wraps an already-validated current-task pointer without cloning.
    ///
    /// # Safety
    ///
    /// `task` must be the current task executing on this CPU.
    #[cfg(feature = "kernelet")]
    #[inline(always)]
    pub(crate) unsafe fn from_raw(task: NonNull<Task>) -> Self {
        Self(task)
    }

    /// Returns the local data of the current task without rechecking interrupt level.
    ///
    /// # Safety
    ///
    /// The caller must be executing in task context on this `CurrentTask`.
    #[cfg(feature = "kernelet")]
    #[inline(always)]
    pub(crate) unsafe fn local_data_unchecked(&self) -> &(dyn Any + Send) {
        debug_assert!(InterruptLevel::current().is_task_context());

        let local_data = &self.local_data;

        // SAFETY: Caller guarantees task context, so `local_data` is exclusive to this task.
        &**unsafe { local_data.get() }
    }

    /// Returns the local data of the current task.
    ///
    /// Note that the local data is only accessible in the task context. Although there is a
    /// current task in the non-task context (e.g. IRQ handlers), access to the local data is
    /// forbidden as it may cause soundness problems.
    ///
    /// # Panics
    ///
    /// This method will panic if called in a non-task context.
    pub fn local_data(&self) -> &(dyn Any + Send) {
        assert!(InterruptLevel::current().is_task_context());

        let local_data = &self.local_data;

        // SAFETY: The `local_data` field will only be accessed by the current task in the task
        // context, so the data won't be accessed concurrently.
        &**unsafe { local_data.get() }
    }

    /// Returns a cloned `Arc<Task>`.
    pub fn cloned(&self) -> Arc<Task> {
        let ptr = self.0.as_ptr();

        // SAFETY: The current task is always a valid task and it is always contained in an `Arc`.
        unsafe { Arc::increment_strong_count(ptr) };

        // SAFETY: We've increased the reference count in the current `Arc<Task>` above.
        unsafe { Arc::from_raw(ptr) }
    }
}

impl Deref for CurrentTask {
    type Target = Task;

    fn deref(&self) -> &Self::Target {
        // SAFETY: The current task is always a valid task.
        unsafe { self.0.as_ref() }
    }
}

impl AsRef<Task> for CurrentTask {
    fn as_ref(&self) -> &Task {
        self
    }
}

impl Borrow<Task> for CurrentTask {
    fn borrow(&self) -> &Task {
        self
    }
}

/// A trait that provides methods to manipulate the task context.
pub(crate) trait TaskContextApi {
    /// Sets the instruction pointer.
    fn set_instruction_pointer(&mut self, ip: usize);

    /// Sets the stack pointer.
    fn set_stack_pointer(&mut self, sp: usize);
}

#[cfg(ktest)]
mod test {
    use crate::prelude::*;

    #[ktest]
    fn create_task() {
        #[expect(clippy::eq_op)]
        let task = || {
            assert_eq!(1, 1);
        };
        let task = Arc::new(
            crate::task::TaskOptions::new(task)
                .data(())
                .build()
                .unwrap(),
        );
        task.run();
    }

    #[ktest]
    fn spawn_task() {
        #[expect(clippy::eq_op)]
        let task = || {
            assert_eq!(1, 1);
        };
        let _ = crate::task::TaskOptions::new(task).data(()).spawn();
    }
}
