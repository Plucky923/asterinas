// SPDX-License-Identifier: MPL-2.0

//! User-mode execution APIs.

use core::cell::RefCell;

use host_ostd::user::UserModeHooks;

use crate::arch::cpu::context::UserContext;

struct KernelEventHooks<F>(RefCell<F>);

impl<F: FnMut() -> bool> UserModeHooks for KernelEventHooks<F> {
    fn has_kernel_event(&self) -> bool {
        (self.0.borrow_mut())()
    }

    fn pre_user_run(&self, guard: &host_ostd::irq::DisabledLocalIrqGuard) {
        // `UserMode::execute` is an OSTD boundary: before it enters the
        // service user context, FrameVisor must restore the current
        // FrameVM's VMAR and per-thread CPU state.  Leaving this hook at
        // OSTD's no-op default lets the Host context leak into the service
        // task, so an otherwise initialized FrameVM can never run its first
        // userspace instruction.
        let _ = crate::task::dispatch_pre_user_run(guard);
    }
}

/// Code execution in user mode.
#[repr(C)]
pub struct UserMode {
    inner: host_ostd::user::UserMode,
}

impl UserMode {
    /// Creates a new `UserMode`.
    pub fn new(context: UserContext) -> Self {
        Self {
            inner: host_ostd::user::UserMode::new(context),
        }
    }

    /// Starts executing in user mode until a syscall, exception, or kernel event.
    pub fn execute<F>(&mut self, has_kernel_event: F) -> ReturnReason
    where
        F: FnMut() -> bool,
    {
        let hooks = KernelEventHooks(RefCell::new(has_kernel_event));
        if hooks.has_kernel_event() {
            return ReturnReason::KernelEvent;
        }

        self.inner.execute(&hooks).into()
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
