// SPDX-License-Identifier: MPL-2.0

//! Tasks are the unit of code execution.

pub mod atomic_mode;
mod binding;
mod frame_task;
mod handle;
mod hooks;
mod preempt;
pub mod scheduler;

pub use binding::{
    bind_vcpu_runtime, bootstrap_frame_sched_group_for_ostd_task, frame_sched_group_for_ostd_task,
    inject_host_task_ops,
};
pub(crate) use binding::{current_frame_vcpu_id, current_frame_vm};
pub use frame_task::{FrameTaskData, FrameTaskKind};
pub use handle::{CurrentTask, Task, TaskOptions};
pub(crate) use hooks::inject_user_page_fault_handler;
pub use hooks::{
    dispatch_post_schedule, dispatch_pre_schedule, dispatch_pre_user_run, dispatch_user_page_fault,
    inject_post_schedule_handler, inject_pre_schedule_handler, inject_pre_user_run_handler,
    inject_shutdown_handler,
};
pub use preempt::{DisabledPreemptGuard, disable_preempt};
