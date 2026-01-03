use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use aster_framevisor::{
    arch::cpu::context::UserContext,
    mm::VmSpace,
    println,
    task::{Task, TaskOptions},
    user::{ReturnReason, UserMode},
};

use crate::{
    error::{Error, Result},
    syscall::handle_syscall,
};

/// Data associated with the user task
pub struct UserTaskData {
    pub vm_space: Arc<VmSpace>,
    pub entry_point: usize,
    pub stack_top: usize,
    pub finished: Arc<AtomicBool>,
}

impl UserTaskData {
    pub fn vm_space(&self) -> Arc<VmSpace> {
        self.vm_space.clone()
    }
}

/// Handler called when the task is scheduled
pub fn post_schedule_handler() {
    if let Some(task) = Task::current() {
        if let Some(user_task_data) = task.data().downcast_ref::<UserTaskData>() {
            user_task_data.vm_space().activate();
        }
    }
}

/// Creates a user context with entry point and stack
fn create_user_context(entry_point: usize, stack_top: usize) -> UserContext {
    let mut user_ctx = UserContext::default();
    user_ctx.set_rip(entry_point);
    user_ctx.set_rsp(stack_top);
    user_ctx
}

/// Executor for the user task loop
struct UserExecutor {
    user_mode: UserMode,
    vm_space: Arc<VmSpace>,
}

impl UserExecutor {
    fn new(entry_point: usize, stack_top: usize, vm_space: Arc<VmSpace>) -> Self {
        println!("[FrameVM] Creating user context and mode");
        let user_ctx = create_user_context(entry_point, stack_top);
        let user_mode = UserMode::new(user_ctx);
        Self {
            user_mode,
            vm_space,
        }
    }

    fn run(&mut self) {
        println!("[FrameVM] Entering user mode execution loop");
        loop {
            // Execute user code until an event occurs (syscall, exception, etc.)
            let return_reason = self.user_mode.execute(|| false);

            if self.handle_exit_reason(return_reason) {
                break;
            }
        }
        println!("[FrameVM] User mode execution loop finished");
    }

    /// Handles the reason for returning from user mode. Returns true if the task should exit.
    fn handle_exit_reason(&mut self, reason: ReturnReason) -> bool {
        let user_context = self.user_mode.context_mut();

        match reason {
            ReturnReason::UserSyscall => {
                let should_exit = handle_syscall(user_context, &self.vm_space);
                should_exit
            }
            ReturnReason::UserException => {
                let exception = user_context.take_exception();
                println!(
                    "[FrameVM] User exception occurred: {:?}, RIP: 0x{:x}",
                    exception,
                    user_context.rip()
                );
                true // Exit on exception
            }
            ReturnReason::KernelEvent => {
                // Kernel event (e.g., interrupt, signal)
                // IRQ callbacks are already invoked by the interrupt injection mechanism
                // Just continue execution
                false
            }
        }
    }
}

/// user task
fn user_task_routine() {
    println!("[FrameVM] User task started");

    // Retrieve task data
    let current_task = Task::current().expect("Task::current() returned None in user task");
    let task_data = current_task
        .data()
        .downcast_ref::<UserTaskData>()
        .expect("Task data missing or incorrect type");

    // Initialize and run the executor
    let mut executor = UserExecutor::new(
        task_data.entry_point,
        task_data.stack_top,
        task_data.vm_space.clone(),
    );
    executor.run();

    // Mark task as finished
    task_data.finished.store(true, Ordering::SeqCst);
}

pub fn create_user_task(
    vm_space: Arc<VmSpace>,
    entry_point: usize,
    stack_top: usize,
) -> Result<Arc<Task>> {
    println!("[FrameVM] Building user task...");

    let task_data = UserTaskData {
        vm_space,
        entry_point,
        stack_top,
        finished: Arc::new(AtomicBool::new(false)),
    };

    TaskOptions::new(user_task_routine)
        .data(task_data)
        .build()
        .map(Arc::new)
        .map_err(|e| Error::from(e))
}
