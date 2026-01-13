// SPDX-License-Identifier: MPL-2.0

//! Task management for FrameVisor.
//!
//! This module provides task creation and scheduling primitives for FrameVM,
//! including post-schedule handlers for VM space activation.

pub mod atomic_mode;
mod preempt;

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc};
use core::{any::Any, borrow::Borrow, ops::Deref};

use ostd::{
    sync::RwLock,
    task::{Task as OstdTask},
};
pub use preempt::disable_preempt;

use crate::prelude::Result;

/// Function signature for task creator injected from kernel.
pub type TaskCreatorFn =
    fn(Box<dyn FnOnce() + Send>, Box<dyn Any + Send + Sync>) -> Result<Arc<OstdTask>>;

static TASK_CREATOR: spin::Once<TaskCreatorFn> = spin::Once::new();

/// Extension data for FrameVM tasks, wrapping user data and post-schedule handler.
pub struct FrameVmTaskExt {
    handler: Option<fn()>,
    user_data: Box<dyn Any + Send + Sync>,
}

/// Mapping from root task pointer to handler (using task pointer address as key).
static ROOT_HANDLERS: RwLock<BTreeMap<usize, fn()>> = RwLock::new(BTreeMap::new());

/// Inject task creator from kernel.
pub fn inject_task_creator(creator: TaskCreatorFn) {
    TASK_CREATOR.call_once(|| creator);
}

/// Register a post-schedule handler for the current task.
pub fn inject_post_schedule_handler(handler: fn()) {
    if let Some(current) = OstdTask::current() {
        let task_ptr = Arc::as_ptr(&current.cloned()) as usize;
        ROOT_HANDLERS.write().insert(task_ptr, handler);
    }
}

/// Clear the post-schedule handler for the current task.
pub fn clear_post_schedule_handler() {
    if let Some(current) = OstdTask::current() {
        let task_ptr = Arc::as_ptr(&current.cloned()) as usize;
        ROOT_HANDLERS.write().remove(&task_ptr);
    }
}

fn get_current_handler() -> Option<fn()> {
    let current = OstdTask::current()?;
    let task = current.cloned();

    // If current is a FrameVM task, inherit handler from extension
    if let Some(ext) = task.extension().downcast_ref::<FrameVmTaskExt>() {
        return ext.handler;
    }

    // Otherwise check ROOT_HANDLERS (current is kernel root task)
    let task_ptr = Arc::as_ptr(&task) as usize;
    ROOT_HANDLERS.read().get(&task_ptr).copied()
}

/// Dispatch post-schedule handler for FrameVM tasks.
/// Returns true if handler was dispatched.
pub fn dispatch_post_schedule() -> bool {
    if let Some(current) = OstdTask::current() {
        if let Some(ext) = current
            .cloned()
            .extension()
            .downcast_ref::<FrameVmTaskExt>()
        {
            if let Some(handler) = ext.handler {
                handler();
            }
            return true;
        }
    }
    false
}

/// Wrapper for the current task.
pub struct CurrentTask(Task);

/// Task wrapper for FrameVM.
#[derive(Debug)]
pub struct Task(Arc<OstdTask>);

impl Task {
    /// Get the current task if available.
    pub fn current() -> Option<CurrentTask> {
        OstdTask::current().map(|ostd_current| CurrentTask(Task(ostd_current.cloned())))
    }

    /// Yield the current task.
    pub fn yield_now() {
        OstdTask::yield_now();
    }

    /// Returns the task data.
    pub fn data(&self) -> &Box<dyn Any + Send + Sync> {
        let ext = self.ostd_task().extension();
        if let Some(fvt_ext) = ext.downcast_ref::<FrameVmTaskExt>() {
            &fvt_ext.user_data
        } else {
            ext
        }
    }

    fn ostd_task(&self) -> &Arc<OstdTask> {
        &self.0
    }

    fn new(task: Arc<OstdTask>) -> Self {
        Self(task)
    }

    /// Run this task.
    pub fn run(self: &Arc<Self>) {
        self.ostd_task().run();
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

/// Builder for creating FrameVM tasks.
pub struct TaskOptions {
    func: Option<Box<dyn FnOnce() + Send>>,
    data: Option<Box<dyn Any + Send + Sync>>,
}

impl TaskOptions {
    /// Create a new task builder with the given entry function.
    pub fn new<F>(entry: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            func: Some(Box::new(entry)),
            data: None,
        }
    }

    /// Set task-specific data.
    pub fn data<T>(mut self, data: T) -> Self
    where
        T: Any + Send + Sync + 'static,
    {
        self.data = Some(Box::new(data));
        self
    }

    /// Build and return the task.
    pub fn build(mut self) -> Result<Task> {
        let func = self.func.take().unwrap();
        let user_data = self.data.take().unwrap_or_else(|| Box::new(()));

        // Inherit handler from parent task
        let handler = get_current_handler();
        let ext = FrameVmTaskExt { handler, user_data };
        let ext_box: Box<dyn Any + Send + Sync> = Box::new(ext);

        if let Some(creator) = TASK_CREATOR.get() {
            creator(func, ext_box).map(Task::new)
        } else {
            // Fallback to bare ostd task
            let options = ostd::task::TaskOptions::new(func).extension_any(ext_box);
            Ok(Task::new(Arc::new(
                options.build().map_err(crate::error::Error::from)?,
            )))
        }
    }
}

/// Initialize the task subsystem.
pub fn init_task() {
    // Verify task creation works
    Task::current();
    let _task = TaskOptions::new(|| {}).build().ok().unwrap();
    preempt::init_preempt();
}
