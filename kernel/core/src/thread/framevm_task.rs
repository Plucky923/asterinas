// SPDX-License-Identifier: MPL-2.0

//! Host carriers for FrameVM tasks.

use alloc::{boxed::Box, sync::Arc};

use aster_framevisor::task::{self, FrameTaskLocalData, FrameTaskState};
use ostd::{
    cpu::CpuSet,
    task::{Task as OstdTask, TaskOptions},
};

use crate::{
    sched::{Nice, SchedPolicy},
    thread::Thread,
};

/// The Host thread data that identifies a carrier as a FrameVM task.
pub(crate) struct FrameVmThread {
    state: Arc<FrameTaskState>,
}

impl FrameVmThread {
    fn new(state: Arc<FrameTaskState>) -> Self {
        Self { state }
    }
}

impl Thread {
    /// Returns the explicit FrameVM state carried by this Host thread.
    pub(crate) fn framevm_task_state(&self) -> Option<&Arc<FrameTaskState>> {
        self.data()
            .downcast_ref::<FrameVmThread>()
            .map(|thread| &thread.state)
    }
}

fn create_framevm_task(
    func: Box<dyn FnOnce() + Send>,
    state: Arc<FrameTaskState>,
    local_data: FrameTaskLocalData,
) -> Result<Arc<OstdTask>, aster_framevisor::Error> {
    // A carrier begins with neutral Host affinity. Binding it to a FrameVM
    // scheduler group is a separate, explicit operation after construction.
    // In particular, construction does not depend on a vCPU identity.
    let thread = Arc::new(Thread::new_unbound(
        FrameVmThread::new(state),
        CpuSet::new_full(),
        SchedPolicy::Fair(Nice::default()),
    ));
    let task = Arc::new(
        TaskOptions::new(func)
            .data(thread.clone())
            .local_data(local_data)
            .build()
            .map_err(aster_framevisor::Error::from)?,
    );

    // `TaskOptions::build` never publishes the task. Bind its Thread view
    // before returning the only strong task reference to Framevisor.
    thread.bind_task(Arc::downgrade(&task));
    Ok(task)
}

pub(super) fn init() {
    task::inject_build_host_task(create_framevm_task);
}
