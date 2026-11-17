// SPDX-License-Identifier: MPL-2.0

#[cfg(feature = "kernelet")]
use ostd::{
    arch::cpu::context::UserContext,
    irq::DisabledLocalIrqGuard,
    mm::VmIo,
    sync::Waiter,
    task::{CurrentTask, PreparedTaskStack, Task, TaskOptions},
    user::{UserContextApi, UserEvent, UserEventHandler},
};
#[cfg(not(feature = "kernelet"))]
use ostd::{
    arch::cpu::context::UserContext,
    irq::DisabledLocalIrqGuard,
    mm::VmIo,
    sync::Waiter,
    task::{PreparedTaskStack, Task, TaskOptions},
    user::{ReturnReason, UserContextApi, UserMode, UserModeHooks},
};

#[cfg(not(feature = "kernelet"))]
use super::AsThread;
use super::{Thread, oops};
use crate::{
    context::current_userspace,
    cpu::LinuxAbi,
    prelude::*,
    process::{
        posix_thread::{AsPosixThread, FIRST_POSIX_TID, ThreadLocal, ptrace::PtraceStopResult},
        signal::{HandlePendingSignal, PauseReason, handle_pending_signal},
    },
    syscall::handle_syscall,
    thread::exception::handle_exception,
    vm::vmar::is_userspace_vaddr,
};

/// create new task with userspace and parent process
#[cfg(feature = "kernelet")]
pub(crate) fn create_new_user_task(
    user_ctx: Box<UserContext>,
    thread_ref: Arc<Thread>,
    thread_local: ThreadLocal,
    stack: PreparedTaskStack,
) -> Task {
    TaskOptions::new_user(*user_ctx)
        .data(thread_ref)
        .local_data(thread_local)
        .build_with_stack(stack)
        .expect("Thread and ThreadLocal match the linked user event handler")
}

#[cfg(feature = "kernelet")]
#[cold]
#[inline(never)]
fn exit_current_after_oops(thread: &Thread, local: &ThreadLocal, task: &CurrentTask) {
    let posix_thread = thread.as_posix_thread().unwrap();
    let process = posix_thread.process();
    let ctx = Context {
        process: &process,
        thread_local: local,
        posix_thread,
        thread,
        task,
    };
    crate::process::posix_thread::exit_after_oops(&ctx);
}

#[cfg(feature = "kernelet")]
#[cold]
#[inline(never)]
fn wait_while_stopped(thread: &Thread, ctx: &Context<'_>, user_ctx: &mut UserContext) {
    while ctx.process.is_stopped() && !thread.is_exited() {
        let (stop_waiter, _) = Waiter::new_pair();
        let _ = stop_waiter.pause_until_by(
            || (!ctx.process.is_stopped()).then_some(()),
            PauseReason::StopBySignal,
        );
        handle_pending_signal(user_ctx, ctx);
    }
}

#[cfg(feature = "kernelet")]
#[ostd::user_event_handler]
impl UserEventHandler for Thread {
    type LocalData = ThreadLocal;

    fn init(&self, local: &ThreadLocal, task: &CurrentTask, user_ctx: &mut UserContext) -> bool {
        let result = oops::catch_panics_as_oops(|| {
            let current_posix_thread = self.as_posix_thread().unwrap();
            let process_ref = local.process().borrow();
            let current_process = process_ref.as_ref().unwrap();

            debug!(
                "task entry: rip = {:#x}, rsp = {:#x}, rax = {:#x}",
                user_ctx.instruction_pointer(),
                user_ctx.stack_pointer(),
                user_ctx.syscall_ret(),
            );

            // The `clone` syscall may require the child process to write its thread TID to the
            // specified address. Make sure that the store operation completes before we return
            // control to user space in the child process.
            let child_tid_ptr = local.set_child_tid().get();
            if is_userspace_vaddr(child_tid_ptr) {
                let _ = current_userspace!().write_val(child_tid_ptr, &current_posix_thread.tid());
            }

            let ctx = Context {
                process: current_process,
                thread_local: local,
                posix_thread: current_posix_thread,
                thread: self,
                task,
            };

            // The startup method is only executed when the first user thread starts up.
            if ctx.posix_thread.tid() == FIRST_POSIX_TID {
                crate::init::on_first_process_startup(&ctx);
            }
        });
        if result.is_err() {
            exit_current_after_oops(self, local, task);
        }
        if self.is_exited() {
            let _ = local.process().borrow_mut().take();
            true
        } else {
            false
        }
    }

    fn handle(
        &self,
        local: &ThreadLocal,
        task: &CurrentTask,
        event: UserEvent,
        user_ctx: &mut UserContext,
    ) -> bool {
        let result = oops::catch_panics_as_oops(|| {
            let current_posix_thread = self.as_posix_thread().unwrap();
            let process_ref = local.process().borrow();
            let current_process = process_ref.as_ref().unwrap();

            let ctx = Context {
                process: current_process,
                thread_local: local,
                posix_thread: current_posix_thread,
                thread: self,
                task,
            };

            match event {
                UserEvent::Exception => {
                    let exception = user_ctx.take_exception().unwrap();
                    ctx.thread_local.set_orig_syscall_ret(None);
                    handle_exception(&ctx, user_ctx, exception);
                }
                UserEvent::Syscall => {
                    ctx.thread_local
                        .set_orig_syscall_ret(Some(user_ctx.syscall_ret()));

                    let res = ctx.posix_thread.ptrace_may_stop_on_syscall(&ctx, user_ctx);
                    if !matches!(res, PtraceStopResult::Interrupted) {
                        handle_syscall(&ctx, user_ctx);

                        ctx.posix_thread.ptrace_may_stop_on_syscall(&ctx, user_ctx);
                    }
                }
                UserEvent::KernelEvent => {
                    ctx.thread_local.set_orig_syscall_ret(None);
                }
            }

            if self.is_exited() {
                return;
            }

            handle_pending_signal(user_ctx, &ctx);

            if ctx.process.is_stopped() {
                wait_while_stopped(self, &ctx, user_ctx);
            }
        });
        if result.is_err() {
            exit_current_after_oops(self, local, task);
        }
        if self.is_exited() {
            let _ = local.process().borrow_mut().take();
            true
        } else {
            false
        }
    }

    fn has_kernel_event(&self, local: &ThreadLocal, task: &CurrentTask) -> bool {
        let current_posix_thread = self.as_posix_thread().unwrap();
        let process_ref = local.process().borrow();
        let Some(current_process) = process_ref.as_ref() else {
            return false;
        };
        let ctx = Context {
            process: current_process,
            thread_local: local,
            posix_thread: current_posix_thread,
            thread: self,
            task,
        };
        ctx.has_pending()
    }

    fn pre_user_run(&self, local: &ThreadLocal, guard: &DisabledLocalIrqGuard) {
        local.supp_user_context().before_user_exec(guard);
    }
}

/// create new task with userspace and parent process
#[cfg(not(feature = "kernelet"))]
pub(crate) fn create_new_user_task(
    user_ctx: Box<UserContext>,
    thread_ref: Arc<Thread>,
    thread_local: ThreadLocal,
    stack: PreparedTaskStack,
) -> Task {
    let user_task_entry = move |user_ctx: UserContext| {
        let current_task = Task::current().unwrap();
        let current_thread = current_task.as_thread().unwrap();
        let current_posix_thread = current_thread.as_posix_thread().unwrap();
        let current_thread_local = current_task.as_thread_local().unwrap();
        let current_process = current_posix_thread.process();
        let (stop_waiter, _) = Waiter::new_pair();

        let mut user_mode = UserMode::new(user_ctx);
        debug!(
            "task entry: rip = {:#x}, rsp = {:#x}, rax = {:#x}",
            user_mode.context().instruction_pointer(),
            user_mode.context().stack_pointer(),
            user_mode.context().syscall_ret(),
        );

        // The `clone` syscall may require the child process to write its thread TID to the
        // specified address. Make sure that the store operation completes before we return control
        // to user space in the child process.
        let child_tid_ptr = current_thread_local.set_child_tid().get();
        if is_userspace_vaddr(child_tid_ptr) {
            // At this point, we can do almost nothing if the address is not valid and the store
            // operation fails. So we ignore the error here.
            let _ = current_userspace!().write_val(child_tid_ptr, &current_posix_thread.tid());
        }

        let ctx = Context {
            process: &current_process,
            thread_local: current_thread_local,
            posix_thread: current_posix_thread,
            thread: current_thread.as_ref(),
            task: &current_task,
        };

        // The startup method is only executed when the first user thread starts up.
        if ctx.posix_thread.tid() == FIRST_POSIX_TID {
            crate::init::on_first_process_startup(&ctx);
        }

        while !current_thread.is_exited() {
            // Execute the user code
            let return_reason = user_mode.execute(&ctx);

            // Handle user events
            let user_ctx = user_mode.context_mut();
            match return_reason {
                ReturnReason::UserException => {
                    let exception = user_ctx.take_exception().unwrap();
                    ctx.thread_local.set_orig_syscall_ret(None);
                    handle_exception(&ctx, user_ctx, exception)
                }
                ReturnReason::UserSyscall => {
                    ctx.thread_local
                        .set_orig_syscall_ret(Some(user_ctx.syscall_ret()));

                    let res = ctx.posix_thread.ptrace_may_stop_on_syscall(&ctx, user_ctx);
                    if !matches!(res, PtraceStopResult::Interrupted) {
                        handle_syscall(&ctx, user_ctx);

                        ctx.posix_thread.ptrace_may_stop_on_syscall(&ctx, user_ctx);
                    }
                }
                ReturnReason::KernelEvent => {
                    ctx.thread_local.set_orig_syscall_ret(None);
                }
            };

            // Exit if the thread terminates
            if current_thread.is_exited() {
                break;
            }

            // Handle signals
            handle_pending_signal(user_ctx, &ctx);

            // Handle signals while the thread is stopped
            // FIXME: Currently, we handle all signals when the process is stopped.
            // However, when the process is stopped, at least signals with user-provided handlers
            // should not be handled; these signals should only be handled when the process is continued.
            // Certain signals, such as SIGKILL, should be handled even if the process is stopped.
            // We need to further investigate Linux behavior regarding which signals should be handled
            // when the thread is stopped.
            while !current_thread.is_exited() && ctx.process.is_stopped() {
                let _ = stop_waiter.pause_until_by(
                    || (!ctx.process.is_stopped()).then_some(()),
                    // We currently do not support ptrace.
                    PauseReason::StopBySignal,
                );
                handle_pending_signal(user_ctx, &ctx);
            }
        }
    };

    let user_task_func = move || user_task_entry(*user_ctx);

    TaskOptions::new(move || {
        if oops::catch_panics_as_oops(user_task_func).is_err() {
            // Unwinding must also complete the POSIX lifecycle. Otherwise the
            // dead OSTD Task remains in the process task set indefinitely.
            let current_task = Task::current().unwrap();
            let thread = current_task.as_thread().unwrap();
            let posix_thread = thread.as_posix_thread().unwrap();
            let process = posix_thread.process();
            let ctx = Context {
                process: &process,
                thread_local: current_task.as_thread_local().unwrap(),
                posix_thread,
                thread,
                task: &current_task,
            };
            crate::process::posix_thread::exit_after_oops(&ctx);
        }
    })
    .data(thread_ref)
    .local_data(thread_local)
    .build_with_stack(stack)
    .expect("kernel task construction has no user handler requirements")
}

#[cfg(not(feature = "kernelet"))]
impl UserModeHooks for Context<'_> {
    fn has_kernel_event(&self) -> bool {
        self.has_pending()
    }

    fn pre_user_run(&self, guard: &DisabledLocalIrqGuard) {
        self.thread_local
            .supp_user_context()
            .before_user_exec(guard);
    }
}
