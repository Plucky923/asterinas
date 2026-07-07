// SPDX-License-Identifier: MPL-2.0

use core::any::Any;

use ostd::{
    cpu::CpuSet,
    task::{Task, TaskOptions},
};

use super::{AsThread, Thread, oops};
use crate::{
    prelude::*,
    sched::{Nice, SchedPolicy},
};

/// The inner data of a kernel thread.
struct KernelThread;

/// Options to create or spawn a new kernel thread.
pub struct ThreadOptions {
    func: Option<Box<dyn FnOnce() + Send>>,
    cpu_affinity: CpuSet,
    sched_policy: SchedPolicy,
    extension: Option<Box<dyn Any + Send + Sync>>,
}

impl ThreadOptions {
    /// Creates the thread options with the thread function.
    pub fn new<F>(func: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        let cpu_affinity = CpuSet::new_full();
        let sched_policy = SchedPolicy::Fair(Nice::default());
        Self {
            func: Some(Box::new(func)),
            cpu_affinity,
            sched_policy,
            extension: None,
        }
    }

    /// Sets the CPU affinity of the new thread.
    pub fn cpu_affinity(mut self, cpu_affinity: CpuSet) -> Self {
        self.cpu_affinity = cpu_affinity;
        self
    }

    /// Sets the scheduling policy.
    pub fn sched_policy(mut self, sched_policy: SchedPolicy) -> Self {
        self.sched_policy = sched_policy;
        self
    }

    /// Sets the extension data associated with the task.
    pub fn extension<T>(self, extension: T) -> Self
    where
        T: Any + Send + Sync,
    {
        self.extension_any(Box::new(extension))
    }

    /// Sets the extension data associated with the task, but with an already-boxed value.
    pub fn extension_any(mut self, extension: Box<dyn Any + Send + Sync>) -> Self {
        self.extension = Some(extension);
        self
    }

    /// Builds a new kernel thread without running it immediately.
    pub fn build(mut self) -> Arc<Task> {
        let task_fn = self.func.take().unwrap();
        let thread_fn = move || {
            let _ = oops::catch_panics_as_oops(task_fn);
            // Ensure that the thread exits.
            current_thread!().exit();
        };

        let extension = self.extension;
        let cpu_affinity = self.cpu_affinity;
        let sched_policy = self.sched_policy;

        Arc::new_cyclic(|weak_task| {
            let thread = {
                let kernel_thread = KernelThread;
                Arc::new(Thread::new(
                    weak_task.clone(),
                    kernel_thread,
                    cpu_affinity,
                    sched_policy,
                ))
            };

            let mut options = TaskOptions::new(thread_fn).data(thread);
            if let Some(extension) = extension {
                options = options.extension_any(extension);
            }
            options.build().unwrap()
        })
    }

    /// Builds a new kernel thread and runs it immediately.
    #[track_caller]
    pub fn spawn(self) -> Arc<Thread> {
        let task = self.build();
        let thread = task.as_thread().unwrap().clone();
        thread.run();
        thread
    }
}
