// SPDX-License-Identifier: MPL-2.0

pub mod atomic_mode;
mod preempt;

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc};
use core::{any::Any, borrow::Borrow, ffi::c_void, ops::Deref};

use ostd::{
    early_println,
    sync::RwLock,
    task::{CurrentTask as OstdCurrentTask, Task as OstdTask},
};
pub use preempt::disable_preempt;

use crate::prelude::Result;

pub type TaskCreatorFn = fn(
    Box<dyn FnOnce() + Send>,
    Box<dyn Any + Send + Sync>,
) -> Result<Arc<OstdTask>>;

static TASK_CREATOR: spin::Once<TaskCreatorFn> = spin::Once::new();

/// FrameVM task 的 extension 数据，包装用户数据和 handler
pub struct FrameVmTaskExt {
    handler: Option<fn()>,
    user_data: Box<dyn Any + Send + Sync>,
}

/// root task 到 handler 的映射（使用 task 指针地址作为 key）
static ROOT_HANDLERS: RwLock<BTreeMap<usize, fn()>> = RwLock::new(BTreeMap::new());

pub fn inject_task_creator(creator: TaskCreatorFn) {
    TASK_CREATOR.call_once(|| creator);
}

pub fn inject_post_schedule_handler(handler: fn()) {
    // 获取当前 task 的指针地址作为 key
    if let Some(current) = OstdTask::current() {
        let task_ptr = Arc::as_ptr(&current.cloned()) as usize;
        ROOT_HANDLERS.write().insert(task_ptr, handler);
    }
}

pub fn clear_post_schedule_handler() {
    if let Some(current) = OstdTask::current() {
        let task_ptr = Arc::as_ptr(&current.cloned()) as usize;
        ROOT_HANDLERS.write().remove(&task_ptr);
    }
}

fn get_current_handler() -> Option<fn()> {
    let current = OstdTask::current()?;
    let task = current.cloned();

    // 如果当前是 FrameVM task，从 extension 继承
    if let Some(ext) = task.extension().downcast_ref::<FrameVmTaskExt>() {
        return ext.handler;
    }

    // 否则检查 ROOT_HANDLERS（当前是 kernel root task）
    let task_ptr = Arc::as_ptr(&task) as usize;
    ROOT_HANDLERS.read().get(&task_ptr).copied()
}

/// 分发 FrameVM task 的调度后处理
pub fn dispatch_post_schedule() -> bool {
    if let Some(current) = OstdTask::current() {
        if let Some(ext) = current.cloned().extension().downcast_ref::<FrameVmTaskExt>() {
            if let Some(handler) = ext.handler {
                handler();
            }
            return true;
        }
    }
    false
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
        let user_data = self.data.take().unwrap_or_else(|| Box::new(()));

        // 从父任务继承 handler
        let handler = get_current_handler();
        let ext = FrameVmTaskExt { handler, user_data };
        let ext_box: Box<dyn Any + Send + Sync> = Box::new(ext);

        if let Some(creator) = TASK_CREATOR.get() {
            creator(func, ext_box).map(Task::new)
        } else {
            // Fallback to bare ostd task
            let options = ostd::task::TaskOptions::new(func).extension_any(ext_box);

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
