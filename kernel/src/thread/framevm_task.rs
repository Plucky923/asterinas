// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, sync::Arc};
use core::any::Any;

use aster_framevisor::{
    iht::{PerVcpuContext, iht_main_loop},
    task::inject_task_creator,
};
use ostd::{
    cpu::CpuSet,
    task::{Task as OstdTask, TaskOptions},
};

use crate::{
    sched::{Nice, SchedPolicy},
    thread::{AsThread, Thread},
};

struct FrameVmThread;

fn create_framevm_task(
    func: Box<dyn FnOnce() + Send>,
    extension: Box<dyn Any + Send + Sync>,
) -> core::result::Result<Arc<OstdTask>, aster_framevisor::error::Error> {
    let affinity = CpuSet::new_full();
    let policy = SchedPolicy::Fair(Nice::default());

    Ok(Arc::new_cyclic(|weak_task| {
        let thread = Arc::new(Thread::new(
            weak_task.clone(),
            FrameVmThread,
            affinity,
            policy,
            // SchedPolicy::Fair(Nice::default())
        ));

        TaskOptions::new(func)
            .data(thread)
            .extension_any(extension)
            .build()
            .unwrap()
    }))
}

fn create_iht_task(ctx: Arc<PerVcpuContext>) -> Arc<OstdTask> {
    use crate::{
        sched::{RealTimePolicy, RealTimePriority},
        thread::kernel_thread::ThreadOptions,
    };

    // Use RT priority 50
    let rt_prio = RealTimePriority::new(50);
    let rt_policy = RealTimePolicy::Fifo;

    let thread_fn = move || iht_main_loop(ctx);

    // IHT handles interrupts, so it should run on any CPU or bound to specific vCPU's PCPU.
    // For now use full affinity.
    let affinity = CpuSet::new_full();

    let task = ThreadOptions::new(thread_fn)
        .sched_policy(SchedPolicy::RealTime { rt_prio, rt_policy })
        .cpu_affinity(affinity)
        .build();

    // Must spawn (run) the task!
    let thread = task.as_thread().unwrap().clone();
    thread.run();

    task
}

pub fn init() {
    inject_task_creator(create_framevm_task);
    aster_framevisor::iht::inject_iht_creator(create_iht_task);
    // Start IHTs now that the creator is registered
    // This must be called after inject_iht_creator
    aster_framevisor::iht::start_ihts();
}
