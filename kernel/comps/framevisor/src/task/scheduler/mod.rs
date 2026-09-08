// SPDX-License-Identifier: MPL-2.0

//! Task scheduler injection and FrameVM scheduler bridges.

pub mod info;
mod queue;
mod share;
mod timer;
mod types;

pub(crate) use queue::{exit_current_task, park_current, run_task, unpark_target, yield_current};

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

/// Registers the Host-carried bootstrap task with the current FrameVM's
/// service scheduler.
///
/// The bootstrap task intentionally is not a service `Thread`, but it must
/// remain selectable until startup publishes ordinary service tasks.
pub fn install_current_bootstrap_task() {
    let bootstrap = task::current_task_for_scheduler()
        .expect("bootstrap scheduler registration requires a current FrameVM task");
    assert!(
        bootstrap.state().kind() == task::FrameTaskKind::Bootstrap,
        "only a FrameVM bootstrap task may register the startup continuation"
    );
    let scheduler = bootstrap
        .state()
        .frame_vm()
        .scheduler()
        .expect("bootstrap scheduler registration requires an injected scheduler");
    scheduler.install_bootstrap_task(bootstrap);
}

pub use share::{
    DEFAULT_FRAMEVM_SHARE, MAX_FRAMEVM_SHARE, MIN_FRAMEVM_SHARE, validate_framevm_share,
};
pub(crate) use timer::dispatch_timer_ticks;
pub use timer::enable_preemption_on_cpu;
pub use types::{EnqueueFlags, LocalRunQueue, Scheduler, UpdateFlags};
