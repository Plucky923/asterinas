// SPDX-License-Identifier: MPL-2.0

//! Task scheduler injection and FrameVM scheduler bridges.

pub mod info;
mod queue;
mod share;
mod timer;
mod types;

pub use queue::enqueue_service_task_from_host_wake;
pub(crate) use queue::{
    enqueue_task, exit_current_task, park_current, park_service_task, unpark_target,
};

use crate::{task, vm};
/// Installs the scheduler owned by the current FrameVM.
pub fn inject_scheduler(scheduler: &'static dyn Scheduler<task::Task>) {
    let frame_vcpu_id =
        task::current_frame_vcpu_id().expect("scheduler injection requires a current task context");
    let frame_vm = vm::get_vm_by_id(frame_vcpu_id.vm_id())
        .expect("scheduler injection requires an owning FrameVM");
    assert!(
        frame_vm.install_scheduler(scheduler),
        "a scheduler has already been initialized"
    );
}

pub use share::{
    DEFAULT_FRAMEVM_SHARE, MAX_FRAMEVM_SHARE, MIN_FRAMEVM_SHARE, validate_framevm_share,
};
pub(crate) use timer::dispatch_timer_ticks;
pub use timer::enable_preemption_on_cpu;
pub use types::{EnqueueFlags, LocalRunQueue, Scheduler, UpdateFlags};
