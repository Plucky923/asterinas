// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, sync::Arc};
use core::any::Any;

use aster_framevisor::{
    iht::{IhtContext, iht_main_loop},
    task::inject_task_creator,
};
use ostd::{
    cpu::CpuSet,
    task::{Task as OstdTask, TaskOptions},
};

use crate::{
    sched::SchedPolicy,
    thread::{AsThread, Thread},
};

struct FrameVmThread;

fn create_framevm_task(
    func: Box<dyn FnOnce() + Send>,
    extension: Box<dyn Any + Send + Sync>,
) -> core::result::Result<Arc<OstdTask>, aster_framevisor::error::Error> {
    // Keep the FrameVM task on default scheduling and affinity for fairness.
    let affinity = CpuSet::new_full();
    let policy = SchedPolicy::default();

    Ok(Arc::new_cyclic(|weak_task| {
        let thread = Arc::new(Thread::new(
            weak_task.clone(),
            FrameVmThread,
            affinity,
            policy,
        ));

        TaskOptions::new(func)
            .data(thread)
            .extension_any(extension)
            .build()
            .unwrap()
    }))
}

fn create_iht_task(ctx: Arc<IhtContext>) -> Arc<OstdTask> {
    use crate::thread::kernel_thread::ThreadOptions;

    let vcpu_id = ctx.vcpu_id();
    let thread_fn = move || iht_main_loop(ctx);

    let task = ThreadOptions::new(thread_fn).extension(vcpu_id).build();

    // Must spawn (run) the task!
    let thread = task.as_thread().unwrap().clone();
    thread.run();

    task
}

pub fn init() {
    inject_task_creator(create_framevm_task);
    aster_framevisor::iht::register_iht_creator(create_iht_task);
    // Note: start_all() is called from aster_framevisor::start_framevm()
    // after IHT and vsock are properly initialized
}
