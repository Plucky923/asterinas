// SPDX-License-Identifier: MPL-2.0

//! Tasks are the unit of code execution.

pub mod atomic_mode;
mod binding;
mod current;
mod frame_task;
mod handle;
mod hooks;
mod preempt;
pub mod scheduler;

pub use binding::inject_build_host_task;
pub use current::{clear_current_task, install_current_task};
pub(crate) use current::{
    current_frame_vcpu_id, current_frame_vm, current_state_for_current_task,
    current_task_for_scheduler,
};
pub use frame_task::{FrameTaskKind, FrameTaskState};
pub use handle::{CurrentTask, FrameTaskLocalData, Task, TaskOptions, build_bootstrap_task};
pub(crate) use hooks::inject_user_page_fault_handler;
#[doc(hidden)]
pub use hooks::{dispatch_physical_post_schedule, dispatch_physical_pre_schedule};
pub use hooks::{
    dispatch_post_schedule, dispatch_pre_schedule, dispatch_pre_user_run, dispatch_user_page_fault,
    inject_physical_post_schedule_handler, inject_physical_pre_schedule_handler,
    inject_post_schedule_handler, inject_pre_schedule_handler, inject_pre_user_run_handler,
    inject_shutdown_handler,
};
pub use preempt::{DisabledPreemptGuard, disable_preempt};
