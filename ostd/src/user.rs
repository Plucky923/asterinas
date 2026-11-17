// SPDX-License-Identifier: MPL-2.0

//! User mode.

use crate::arch::trap::TrapFrame;
#[cfg(not(feature = "kernelet"))]
use crate::{arch::cpu::context::UserContext, irq::DisabledLocalIrqGuard};

/// The internal interface that every CPU architecture-specific [`UserContext`] implements.
///
/// This is only visible in `ostd`.
pub(crate) trait UserContextApiInternal {
    /// Starts executing in the user mode.
    #[cfg(not(feature = "kernelet"))]
    fn execute<T: UserModeHooks>(&mut self, hooks: &T) -> ReturnReason;

    /// Uses the information inside CpuContext to build a trapframe
    fn as_trap_frame(&self) -> TrapFrame;
}

/// The common interface that every CPU architecture-specific [`UserContext`] implements.
pub trait UserContextApi {
    /// Sets the instruction pointer
    fn set_instruction_pointer(&mut self, ip: usize);

    /// Gets the instruction pointer
    fn instruction_pointer(&self) -> usize;

    /// Sets the stack pointer
    fn set_stack_pointer(&mut self, sp: usize);

    /// Gets the stack pointer
    fn stack_pointer(&self) -> usize;
}

/// Code execution in the user mode.
///
/// This type enables executing the code in user space from a task in the kernel
/// space safely.
///
/// Here is a sample code on how to use `UserMode`.
///
/// ```no_run
/// # fn handle_return(_reason: crate::user::ReturnReason) {}
/// #
/// use crate::{
///     arch::cpu::context::UserContext,
///     user::{DummyUserHooks, UserMode},
/// };
///
/// let user_ctx = UserContext::default();
/// let mut user_mode = UserMode::new(user_ctx);
///
/// // Note: Users should activate a suitable `VmSpace` before to support
/// // user-mode execution.
///
/// loop {
///     // Execute in the user space until some interesting events occur.
///     let return_reason = user_mode.execute(&DummyUserHooks);
///     // Handle the event, e.g., a system call.
///     handle_return(return_reason);
/// }
/// ```
#[cfg(not(feature = "kernelet"))]
pub struct UserMode {
    context: UserContext,
}

// An instance of `UserMode` is bound to the current task. So it must not be sent to other tasks.
#[cfg(not(feature = "kernelet"))]
impl !Send for UserMode {}
// Note that implementing `!Sync` is unnecessary
// because entering the user space via `UserMode` requires taking a mutable reference.

#[cfg(not(feature = "kernelet"))]
impl UserMode {
    /// Creates a new `UserMode`.
    pub fn new(context: UserContext) -> Self {
        Self { context }
    }

    /// Starts executing in the user mode. Make sure current task is the task in `UserMode`.
    ///
    /// The method returns for one of three possible reasons indicated by [`ReturnReason`].
    /// 1. A system call is issued by the user space;
    /// 2. A CPU exception is triggered by the user space;
    /// 3. A kernel event is pending, as indicated by the given closure.
    ///
    /// After handling whatever user or kernel events that
    /// cause the method to return
    /// and updating the user-mode CPU context,
    /// this method can be invoked again to go back to the user space.
    ///
    /// # Panics
    ///
    /// This method panics if called in atomic mode.
    #[cfg(not(feature = "kernelet"))]
    #[track_caller]
    pub fn execute<T: UserModeHooks>(&mut self, hooks: &T) -> ReturnReason {
        crate::task::atomic_mode::might_sleep();
        self.context.execute(hooks)
    }

    /// Returns an immutable reference the user-mode CPU context.
    pub fn context(&self) -> &UserContext {
        &self.context
    }

    /// Returns a mutable reference the user-mode CPU context.
    pub fn context_mut(&mut self) -> &mut UserContext {
        &mut self.context
    }
}

/// A reason as to why the control of the CPU is returned from
/// the user space to the kernel.
#[derive(Debug, Eq, PartialEq)]
#[cfg(not(feature = "kernelet"))]
pub enum ReturnReason {
    /// A system call is issued by the user space.
    UserSyscall,
    /// A CPU exception is triggered by the user space.
    UserException,
    /// A kernel event is pending
    KernelEvent,
}

/// Hooks that will be called during [`UserMode::execute`].
#[cfg(not(feature = "kernelet"))]
pub trait UserModeHooks {
    /// Checks whether a kernel event is pending.
    ///
    /// This method will be called after user space is interrupted
    /// by external interrupts. If the result is `true`,
    /// [`UserMode::execute`] will return with [`ReturnReason::KernelEvent`].
    fn has_kernel_event(&self) -> bool {
        false
    }

    /// Prepares user space execution.
    ///
    /// This method will be called just before entering user space.
    /// Local IRQs are disabled and will only be enabled after entering user space.
    fn pre_user_run(&self, _guard: &DisabledLocalIrqGuard) {}
}

/// A struct that provides dummy (no-op) user mode hooks.
#[cfg(not(feature = "kernelet"))]
pub struct DummyUserHooks;

#[cfg(not(feature = "kernelet"))]
impl UserModeHooks for DummyUserHooks {}

#[cfg(feature = "kernelet")]
mod kernelet_events {
    use core::{any::TypeId, ptr::NonNull, sync::atomic::Ordering};

    use crate::{
        arch::cpu::{
            context::{CpuException, LinuxPtRegs, UserContext},
            local::CpuLocalAccess,
        },
        irq::DisabledLocalIrqGuard,
        kernelet::{
            abi::{USER_EVENT_EXCEPTION, USER_EVENT_KERNEL_EVENT, USER_EVENT_SYSCALL},
            entry,
        },
        task::{CurrentTask, Task},
    };

    /// Reason why control returned from user mode to [`user_event_entry`].
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum UserEvent {
        /// A system call issued by user space.
        Syscall,
        /// A CPU exception triggered by user space.
        Exception,
        /// A pending kernel event or reschedule notice.
        KernelEvent,
    }

    /// Kernel callbacks invoked by OSTD's non-returning user-mode event loop.
    ///
    /// Mark the image's implementation with [`macro@crate::user_event_handler`].
    /// OSTD checks its `Arc<Self>` task data and `Self::LocalData` local data
    /// at construction and calls the generated symbols directly, without runtime
    /// handler registration.
    pub trait UserEventHandler: Send + Sync + 'static {
        /// Task-local state type stored in `TaskOptions::local_data`.
        type LocalData: 'static;

        /// Initializes user-mode execution on a user task's first entry.
        /// Returns `true` if the task should exit instead of entering user mode.
        fn init(
            &self,
            local: &Self::LocalData,
            task: &CurrentTask,
            user_ctx: &mut UserContext,
        ) -> bool;

        /// Handles a user-mode return event.
        /// Returns `true` if the task should exit instead of resuming user mode.
        fn handle(
            &self,
            local: &Self::LocalData,
            task: &CurrentTask,
            event: UserEvent,
            user_ctx: &mut UserContext,
        ) -> bool;

        /// Returns whether a kernel event (such as a pending signal) is pending.
        fn has_kernel_event(&self, local: &Self::LocalData, task: &CurrentTask) -> bool;

        /// Prepares user-space execution immediately before entering user mode
        /// with local interrupts disabled.
        fn pre_user_run(&self, local: &Self::LocalData, guard: &DisabledLocalIrqGuard);
    }

    // These Rust-ABI symbols are supplied by the image's annotated handler.
    // Task construction checks the exported type IDs before publishing its data
    // and local data; safe APIs cannot replace them while the Task is alive.
    unsafe extern "Rust" {
        fn __ostd_user_data_type_id() -> TypeId;
        fn __ostd_user_local_data_type_id() -> TypeId;
        fn __ostd_user_init(
            data: *const (),
            local: *const (),
            task: &CurrentTask,
            user_ctx: &mut UserContext,
        ) -> bool;
        fn __ostd_user_handle(
            data: *const (),
            local: *const (),
            task: &CurrentTask,
            event: UserEvent,
            user_ctx: &mut UserContext,
        ) -> bool;
        fn __ostd_user_has_kernel_event(
            data: *const (),
            local: *const (),
            task: &CurrentTask,
        ) -> bool;
        fn __ostd_user_pre_user_run(
            data: *const (),
            local: *const (),
            guard: &DisabledLocalIrqGuard,
        );
    }

    pub(crate) fn user_event_handler_data_type_id() -> TypeId {
        // SAFETY: The macro exports the type ID of the single linked handler's Arc.
        unsafe { __ostd_user_data_type_id() }
    }

    pub(crate) fn user_event_handler_local_data_type_id() -> TypeId {
        // SAFETY: The macro exports the type ID of the single linked handler's LocalData.
        unsafe { __ostd_user_local_data_type_id() }
    }

    #[cold]
    #[inline(never)]
    fn panic_active_preempt_guard(guards: u32) -> ! {
        panic!("returning to user mode with active preemption guard (guards={guards})");
    }

    #[cold]
    #[inline(never)]
    fn invalid_user_event(raw_event: u64) -> ! {
        panic!("invalid user_event_entry event: {raw_event}");
    }

    #[cold]
    #[inline(never)]
    fn missing_current_task() -> ! {
        panic!("user_event_entry requires a current Task");
    }

    #[inline(always)]
    fn enter_user_mode(
        handler_data: *const (),
        handler_local: *const (),
        current_task: &CurrentTask,
        user_ctx: &mut UserContext,
    ) -> ! {
        let (guard, guards) = DisabledLocalIrqGuard::disable_for_user_return();
        if guards != 0 {
            panic_active_preempt_guard(guards);
        }
        user_ctx.sync_to_frame(current_task.active_pt_regs());
        // SAFETY: `handler_data` points to `current_task.data()` (`Arc<H>`) and
        // `handler_local` points to `current_task.local_data()` (`H::LocalData`).
        unsafe { __ostd_user_pre_user_run(handler_data, handler_local, &guard) };
        core::mem::forget(guard);
        (entry::services().user_run)(core::ptr::null_mut());
        unreachable!("user_run should not return under kernelet PR #3");
    }

    /// Fuses vCPU lookup, `CURRENT_TASK_PTR` load, virtual IRQ unmask (`vrec.irq_off = 0`),
    /// and `(vrec.pending, PREEMPT_INFO)` read into one `.text.kernelet_cpu_access`
    /// block for the `raw_event != USER_EVENT_EXCEPTION` fast path.
    ///
    /// # Safety
    ///
    /// Must only be called on `user_event_entry` entry while `vrec.irq_off == 1`.
    #[inline(always)]
    unsafe fn fast_enter_user_event() -> (CurrentTask, u64, u32) {
        let mut current_task_ptr = Task::current_task_ptr_offset();
        let mut preempt_info = Task::preempt_info_offset();
        let pending: u64;
        // SAFETY: `vrec.irq_off == 1` on entry, and the entire table lookup,
        // IRQ unmask and state check stay inside one
        // nonredirectable `.text.kernelet_cpu_access` block.
        unsafe {
            core::arch::asm!(
                "jmp 2f",
                ".pushsection .text.kernelet_cpu_access, \"ax\", @progbits",
                "2:",
                "lea {vrec}, [rip + {fast_cpu}]",
                "mov {slot}, qword ptr [{vrec} + {slot_gs_off}]",
                "movzx {slot:e}, word ptr gs:[{slot} + 2]",
                "mov {local_base}, qword ptr [{vrec} + {slot} * 8 + {local_bases_off}]",
                "mov {vrec}, qword ptr [{vrec} + {slot} * 8 + {record_ptrs_off}]",
                "mov {task}, qword ptr [{local_base} + {task}]",
                "mov dword ptr [{vrec} + {vrec_irq_off}], 0",
                "mov {pending}, qword ptr [{vrec} + {vrec_pending_off}]",
                "mov {preempt:e}, dword ptr [{local_base} + {preempt}]",
                "jmp 3f",
                ".popsection",
                "3:",
                vrec = out(reg) _,
                slot = out(reg) _,
                local_base = out(reg) _,
                pending = out(reg) pending,
                task = inout(reg) current_task_ptr,
                preempt = inout(reg) preempt_info,
                fast_cpu = sym entry::KERNELET_FAST_CPU,
                slot_gs_off = const core::mem::offset_of!(entry::FastCpuTable, slot_gs_offset),
                local_bases_off = const core::mem::offset_of!(entry::FastCpuTable, local_bases),
                record_ptrs_off = const core::mem::offset_of!(entry::FastCpuTable, record_ptrs),
                vrec_irq_off = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, irq_off),
                vrec_pending_off = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, pending),
                options(nostack),
            );
        }
        let current_task =
            NonNull::new(current_task_ptr as *mut Task).unwrap_or_else(|| missing_current_task());
        // SAFETY: `CURRENT_TASK_PTR` identifies the live running task on this CPU.
        let current_task = unsafe { CurrentTask::from_raw(current_task) };
        debug_assert!(current_task.is_user());
        (current_task, pending, preempt_info as u32)
    }

    #[cold]
    #[inline(never)]
    unsafe fn user_exception_entry() -> ! {
        let (current_task, handler_data, handler_local, mut user_ctx) = {
            // SAFETY: The Host's user-event entry contract masks virtual IRQs.
            let irq_guard = unsafe { DisabledLocalIrqGuard::from_disabled() };
            let access = CpuLocalAccess::new(&irq_guard);
            let urec = entry::user_event_record_for(access.record());
            let pt_regs_ptr = urec.pt_regs.load(Ordering::Acquire) as *mut LinuxPtRegs;
            debug_assert!(!pt_regs_ptr.is_null());
            let trap_num = urec.trap_num.load(Ordering::Acquire) as usize;
            let error_code = urec.error_code.load(Ordering::Acquire) as usize;
            let fault_addr = urec.fault_addr.load(Ordering::Acquire) as usize;
            let exception = CpuException::from_raw(trap_num, error_code, fault_addr)
                .expect("user_event_entry exception without a valid trap number");
            let current_task =
                Task::current_with(&access).expect("user_event_entry requires a current Task");
            debug_assert!(current_task.is_user());
            debug_assert_eq!(
                current_task.active_pt_regs().load(Ordering::Relaxed),
                pt_regs_ptr
            );
            let handler_data = core::ptr::from_ref(current_task.data().as_ref()).cast::<()>();
            // SAFETY: `user_exception_entry` executes in task context on `current_task`.
            let handler_local =
                core::ptr::from_ref(unsafe { current_task.local_data_unchecked() }).cast::<()>();
            // SAFETY: `current_task.active_pt_regs()` holds this vCPU's live carrier
            // `pt_regs`, updated across any task switch by `after_switching_to`.
            let user_ctx =
                unsafe { UserContext::from_frame(current_task.active_pt_regs(), Some(exception)) };
            (current_task, handler_data, handler_local, user_ctx)
        };
        crate::arch::irq::enable_local();
        // SAFETY: `handler_data` and `handler_local` match the linked handler's types.
        if unsafe {
            __ostd_user_handle(
                handler_data,
                handler_local,
                &current_task,
                UserEvent::Exception,
                &mut user_ctx,
            )
        } {
            crate::task::exit_current_task();
        }
        enter_user_mode(handler_data, handler_local, &current_task, &mut user_ctx);
    }

    /// First entry point for a user task created via `TaskOptions::new_user`.
    ///
    /// # Safety
    ///
    /// Only `first_user_task_entry_wrapper` may call this function on a freshly
    /// switched-in user task with virtual interrupts disabled.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn first_user_task_entry() -> ! {
        // SAFETY: The new user task was just switched onto this CPU with
        // virtual interrupts disabled and `after_switching_to` has not run yet.
        unsafe { crate::task::after_switching_to() };

        let (current_task, handler_data, handler_local) = {
            let irq_guard = crate::irq::disable_local();
            let access = CpuLocalAccess::new(&irq_guard);
            let current_task =
                Task::current_with(&access).expect("first_user_task_entry requires a current Task");
            debug_assert!(
                !current_task
                    .active_pt_regs()
                    .load(Ordering::Relaxed)
                    .is_null()
            );
            debug_assert!(current_task.is_user());
            let handler_data = core::ptr::from_ref(current_task.data().as_ref()).cast::<()>();
            // SAFETY: `first_user_task_entry` runs in task context on `current_task`.
            let handler_local =
                core::ptr::from_ref(unsafe { current_task.local_data_unchecked() }).cast::<()>();
            (current_task, handler_data, handler_local)
        };
        // SAFETY: `current_task.active_pt_regs()` holds this vCPU's live carrier
        // `pt_regs`, updated across any task switch by `after_switching_to`.
        let mut user_ctx = unsafe { UserContext::from_frame(current_task.active_pt_regs(), None) };
        // SAFETY: `handler_data` and `handler_local` match the linked handler's types.
        if unsafe { __ostd_user_init(handler_data, handler_local, &current_task, &mut user_ctx) } {
            crate::task::exit_current_task();
        }
        enter_user_mode(handler_data, handler_local, &current_task, &mut user_ctx);
    }

    /// Re-entry point called by the Host when a user task leaves user mode.
    ///
    /// # Safety
    ///
    /// The Host must call this on `urec.event_rsp` with virtual interrupts
    /// masked (`vrec.irq_off == 1`), `urec.pt_regs` valid for the active user
    /// task, and `raw_event` equal to one of `USER_EVENT_*`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn user_event_entry(raw_event: u64) -> ! {
        if raw_event == USER_EVENT_EXCEPTION {
            // SAFETY: Same entry contract as `user_event_entry`, with virtual IRQs still masked.
            unsafe { user_exception_entry() };
        }
        let event = match raw_event {
            USER_EVENT_SYSCALL => UserEvent::Syscall,
            USER_EVENT_KERNEL_EVENT => UserEvent::KernelEvent,
            _ => invalid_user_event(raw_event),
        };
        // SAFETY: The Host's user-event entry contract masks virtual IRQs.
        let (current_task, pending, preempt_info) = unsafe { fast_enter_user_event() };
        if pending != 0 || preempt_info == 0 {
            crate::arch::irq::finish_enable_local_slow();
        }
        let handler_data = core::ptr::from_ref(current_task.data().as_ref()).cast::<()>();
        // SAFETY: `user_event_entry` runs in task context on `current_task`.
        let handler_local =
            core::ptr::from_ref(unsafe { current_task.local_data_unchecked() }).cast::<()>();
        // SAFETY: `current_task.active_pt_regs()` holds this vCPU's live carrier
        // `pt_regs`, updated across any task switch by `after_switching_to`.
        let mut user_ctx = unsafe { UserContext::from_frame(current_task.active_pt_regs(), None) };

        // SAFETY: `handler_data` and `handler_local` match the linked handler's types.
        if event != UserEvent::KernelEvent
            || unsafe { __ostd_user_has_kernel_event(handler_data, handler_local, &current_task) }
        {
            // SAFETY: Same as above.
            if unsafe {
                __ostd_user_handle(
                    handler_data,
                    handler_local,
                    &current_task,
                    event,
                    &mut user_ctx,
                )
            } {
                crate::task::exit_current_task();
            }
        }
        enter_user_mode(handler_data, handler_local, &current_task, &mut user_ctx);
    }
}

#[cfg(feature = "kernelet")]
pub use kernelet_events::{UserEvent, UserEventHandler};
#[cfg(feature = "kernelet")]
pub(crate) use kernelet_events::{
    user_event_handler_data_type_id, user_event_handler_local_data_type_id,
};
