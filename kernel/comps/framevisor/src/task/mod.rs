pub mod atomic_mode;
mod preempt;

use alloc::sync::Arc;
use core::any::Any;

use ostd::{
    early_println,
    task::{CurrentTask as OstdCurrentTask, Task as OstdTask, TaskOptions as OstdTaskOptions},
};
pub use preempt::disable_preempt;

use crate::prelude::Result;

pub struct CurrentTask(OstdCurrentTask);

pub struct Task(OstdTask);

impl Task {
    pub fn current() -> Option<CurrentTask> {
        OstdTask::current().map(CurrentTask)
    }

    pub fn yield_now() {
        OstdTask::yield_now();
    }

    fn ostd_task(&self) -> &OstdTask {
        &self.0
    }
}

pub struct TaskOptions(OstdTaskOptions);

impl TaskOptions {
    pub fn new<F>(entry: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self(OstdTaskOptions::new(entry))
    }

    pub fn data<T>(self, data: T) -> Self
    where
        T: Any + Send + Sync,
    {
        Self(self.0.data(data))
    }

    pub fn build(self) -> Result<Task> {
        let ostd_task = self
            .0
            .build()
            .map_err(|_| crate::error::Error::InvalidArgs)?;
        Ok(Task(ostd_task))
    }
}

pub fn init_task() {
    Task::current();
    let task = Arc::new(TaskOptions::new(|| {}).build().ok().unwrap());

    preempt::init_preempt();
    early_println!("[framevisor] Initializing task...");
}
