// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, sync::Arc};
use core::any::Any;

use aster_framevisor::task::inject_task_creator;
use ostd::{
    cpu::CpuSet,
    task::{Task as OstdTask, TaskOptions},
};

use crate::{
    sched::{Nice, SchedPolicy},
    thread::Thread,
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
        ));

        TaskOptions::new(func)
            .data(thread)
            .extension_any(extension)
            .build()
            .unwrap()
    }))
}

pub fn init() {
    inject_task_creator(create_framevm_task);
}
