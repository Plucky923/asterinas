// SPDX-License-Identifier: MPL-2.0

//! The architecture support of context switch.

use crate::task::TaskContextApi;

core::arch::global_asm!(include_str!("switch.S"));
core::arch::global_asm!(include_str!("stack_switch.S"));

#[derive(Debug, Clone)]
#[repr(C)]
pub(crate) struct TaskContext {
    regs: CalleeRegs,
    rip: usize,
    fsbase: usize,
}

impl TaskContext {
    pub(crate) const fn new() -> Self {
        Self {
            regs: CalleeRegs::new(),
            rip: 0,
            fsbase: 0,
        }
    }
}

/// Callee-saved registers.
#[derive(Debug, Clone)]
#[repr(C)]
struct CalleeRegs {
    rsp: u64,
    rbx: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

impl CalleeRegs {
    /// Creates new `CalleeRegs`
    pub(self) const fn new() -> Self {
        CalleeRegs {
            rsp: 0,
            rbx: 0,
            rbp: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        }
    }
}

impl TaskContextApi for TaskContext {
    fn set_instruction_pointer(&mut self, ip: usize) {
        self.rip = ip;
    }

    fn set_stack_pointer(&mut self, sp: usize) {
        self.regs.rsp = sp as u64;
    }
}

unsafe extern "C" {
    pub(crate) unsafe fn context_switch(nxt: *const TaskContext, cur: *mut TaskContext);
    pub(crate) unsafe fn first_context_switch(nxt: *const TaskContext);
    pub(crate) unsafe fn kernel_task_entry_wrapper();
}

// Stack switching support
unsafe extern "C" {
    /// Switches to a new stack and calls a function.
    ///
    /// # Arguments
    ///
    /// * `new_stack_top` - The top of the new stack (high address)
    /// * `func_ptr` - Pointer to the function to call
    /// * `arg_ptr` - Argument to pass to the function
    ///
    /// # Safety
    ///
    /// - `new_stack_top` must be a valid, properly aligned stack address
    /// - `func_ptr` must be a valid function pointer
    /// - The function will be called with `arg_ptr` as its first argument
    pub(crate) unsafe fn call_on_stack(
        new_stack_top: usize,
        func_ptr: usize,
        arg_ptr: usize,
    );
}
