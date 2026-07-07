// SPDX-License-Identifier: MPL-2.0

//! User-mode execution APIs.

use crate::arch::cpu::context::UserContext;

type UserModeExecutor =
    fn(&mut host_ostd::user::UserMode, &mut dyn FnMut() -> bool) -> ReturnReason;

/// Code execution in user mode.
#[repr(C)]
pub struct UserMode {
    inner: host_ostd::user::UserMode,
    executor: UserModeExecutor,
}

impl UserMode {
    /// Creates a new `UserMode`.
    pub fn new(context: UserContext) -> Self {
        Self {
            inner: host_ostd::user::UserMode::new(context),
            executor: default_user_mode_executor(),
        }
    }

    /// Starts executing in user mode until a syscall, exception, or kernel event.
    pub fn execute<F>(&mut self, mut has_kernel_event: F) -> ReturnReason
    where
        F: FnMut() -> bool,
    {
        if has_kernel_event() {
            return ReturnReason::KernelEvent;
        }

        (self.executor)(&mut self.inner, &mut has_kernel_event)
    }

    /// Returns an immutable reference to the user-mode CPU context.
    pub fn context(&self) -> &UserContext {
        self.inner.context()
    }

    /// Returns a mutable reference to the user-mode CPU context.
    pub fn context_mut(&mut self) -> &mut UserContext {
        self.inner.context_mut()
    }
}

/// The reason control returned from user mode.
#[derive(Debug, Eq, PartialEq)]
pub enum ReturnReason {
    /// A system call was issued by user space.
    UserSyscall,
    /// A CPU exception was triggered by user space.
    UserException,
    /// A kernel event is pending.
    KernelEvent,
}

impl From<host_ostd::user::ReturnReason> for ReturnReason {
    fn from(reason: host_ostd::user::ReturnReason) -> Self {
        match reason {
            host_ostd::user::ReturnReason::UserSyscall => Self::UserSyscall,
            host_ostd::user::ReturnReason::UserException => Self::UserException,
            host_ostd::user::ReturnReason::KernelEvent => Self::KernelEvent,
        }
    }
}

fn default_user_mode_executor() -> UserModeExecutor {
    execute_user_mode_on_host
}

fn execute_user_mode_on_host(
    inner: &mut host_ostd::user::UserMode,
    has_kernel_event: &mut dyn FnMut() -> bool,
) -> ReturnReason {
    inner.execute(has_kernel_event).into()
}
