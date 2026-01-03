// SPDX-License-Identifier: MPL-2.0

pub mod atomic_mode;
mod preempt;

use alloc::{boxed::Box, sync::Arc};
use core::{any::Any, borrow::Borrow, ffi::c_void, ops::Deref};

use ostd::{
    early_println,
    task::{CurrentTask as OstdCurrentTask, Task as OstdTask},
};
pub use preempt::disable_preempt;

use crate::prelude::Result;

pub trait FramevmTaskCreator: Send + Sync {
    fn create_task(
        &self,
        func: Box<dyn FnOnce() + Send>,
        framevm: Box<dyn Any + Send + Sync>,
    ) -> Result<Arc<OstdTask>>;
}

static CREATOR: spin::Once<Box<dyn FramevmTaskCreator>> = spin::Once::new();

pub fn register_creator(creator: Box<dyn FramevmTaskCreator>) {
    CREATOR.call_once(|| creator);
}

pub fn inject_post_schedule_handler(handler: fn()) {
    ostd::task::inject_post_framevm_task_schedule_handler(handler);
}

pub fn clear_post_framevm_task_schedule_handler() {
    ostd::task::clear_post_framevm_task_schedule_handler();
}

pub struct CurrentTask(Task);

#[derive(Debug)]
pub struct Task(Arc<OstdTask>);

impl Task {
    pub fn current() -> Option<CurrentTask> {
        OstdTask::current().map(|ostd_current| CurrentTask(Task(ostd_current.cloned())))
    }

    pub fn yield_now() {
        OstdTask::yield_now();
    }

    /// Returns the task data.
    pub fn data(&self) -> &Box<dyn Any + Send + Sync> {
        let framevm = self.ostd_task().framevm();
        framevm
    }

    fn ostd_task(&self) -> &Arc<OstdTask> {
        &self.0
    }

    fn new(task: Arc<OstdTask>) -> Self {
        Self(task)
    }

    pub fn run(self: &Arc<Self>) {
        early_println!("[framevisor] Task::run: About to run ostd task...");
        self.ostd_task().run();
        early_println!("[framevisor] Task::run: ostd_task.run() returned");
    }
}

impl Deref for CurrentTask {
    type Target = Task;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Task> for CurrentTask {
    fn as_ref(&self) -> &Task {
        self
    }
}

impl Borrow<Task> for CurrentTask {
    fn borrow(&self) -> &Task {
        self
    }
}

pub struct TaskOptions {
    func: Option<Box<dyn FnOnce() + Send>>,
    data: Option<Box<dyn Any + Send + Sync>>,
}

impl TaskOptions {
    pub fn new<F>(entry: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            func: Some(Box::new(entry)),
            data: None,
        }
    }

    // Framevm Task Info
    pub fn data<T>(mut self, data: T) -> Self
    where
        T: Any + Send + Sync + 'static,
    {
        self.data = Some(Box::new(data));
        self
    }

    pub fn build(mut self) -> Result<Task> {
        let func = self.func.take().unwrap();

        if let Some(creator) = CREATOR.get() {
            if let Some(data) = self.data {
                creator.create_task(func, data).map(|t| Task::new(t))
            } else {
                let data = Box::new(());
                creator.create_task(func, data).map(|t| Task::new(t))
            }
        } else {
            // Fallback to bare ostd task
            let mut options = ostd::task::TaskOptions::new(func);
            if let Some(data) = self.data {
                // Redirect data storage to framevm field in OSTD Task
                // to avoid conflict with thread data.
                options = options.framevm_any(data);
            }
            // We do not set options.data() here, leaving it as default (None or Box::new(())).

            Ok(Task::new(Arc::new(
                options.build().map_err(crate::error::Error::from)?,
            )))
        }
    }
}

pub fn init_task() {
    Task::current();
    let _task = TaskOptions::new(|| {}).build().ok().unwrap();

    preempt::init_preempt();
    early_println!("[framevisor] Initializing task...");
}
