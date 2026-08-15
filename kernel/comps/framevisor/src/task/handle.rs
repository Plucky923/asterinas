// SPDX-License-Identifier: MPL-2.0

//! OSTD-shaped task handles and builders for FrameVisor.

use alloc::{boxed::Box, sync::Arc};
use core::{any::Any, borrow::Borrow, ops::Deref};

use host_ostd::task::{CurrentTask as OstdCurrentTask, Task as OstdTask};

use super::{
    binding::{HOST_TASK_OPS, current_frame_vcpu_id},
    frame_task::{FrameTaskData, FrameTaskKind},
    scheduler::{self, info::TaskScheduleInfo},
};
use crate::{
    error::Error,
    prelude::Result,
    vm::{self, FrameVcpuId},
};

/// Wrapper for the current task.
pub struct CurrentTask {
    task: Arc<Task>,
    current: OstdCurrentTask,
}

/// A task that executes a function to the end.
#[derive(Debug)]
pub struct Task {
    pub(super) inner: Arc<OstdTask>,
}

impl Task {
    /// Gets the current task if available.
    pub fn current() -> Option<CurrentTask> {
        let current = OstdTask::current()?;
        let ostd_task = current.cloned();
        let task_data = ostd_task.extension().downcast_ref::<FrameTaskData>()?;
        Some(CurrentTask {
            task: task_data.task(ostd_task.clone()),
            current,
        })
    }

    /// Yields the current task.
    pub fn yield_now() {
        if let Some(current) = OstdTask::current() {
            let current_ostd_task = current.cloned();
            if let Some(task_data) = current_ostd_task
                .extension()
                .downcast_ref::<FrameTaskData>()
                && let Some(scheduler) = task_data.frame_vm.scheduler()
            {
                scheduler.mut_local_rq_on_cpu_with(
                    crate::cpu::CpuId::from_raw(task_data.frame_vcpu_id().vcpu_index() as u32),
                    &mut |runqueue| {
                        if runqueue
                            .current()
                            .is_some_and(|task| Arc::ptr_eq(task.ostd_task(), &current_ostd_task))
                            && runqueue.update_current(scheduler::UpdateFlags::Yield)
                        {
                            let _ = runqueue.try_pick_next();
                        }
                    },
                );
            }
        }
        OstdTask::yield_now();
    }

    /// Returns whether this task has finished executing.
    pub fn is_completed(&self) -> bool {
        self.ostd_task().is_completed()
    }

    /// Returns the task data.
    pub fn data(&self) -> &Box<dyn Any + Send + Sync> {
        let extension = self.ostd_task().extension();
        extension
            .downcast_ref::<FrameTaskData>()
            .map_or(extension, |task_data| &task_data.data)
    }

    /// Returns the task extension data.
    pub fn extension(&self) -> &Box<dyn Any + Send + Sync> {
        let extension = self.ostd_task().extension();
        extension
            .downcast_ref::<FrameTaskData>()
            .map_or(extension, |task_data| &task_data.extension)
    }

    /// Returns the task scheduling information.
    pub fn schedule_info(&self) -> &TaskScheduleInfo {
        &self
            .ostd_task()
            .extension()
            .downcast_ref::<FrameTaskData>()
            .expect("FrameVM task metadata is missing")
            .schedule_info
    }

    pub(crate) fn ostd_task(&self) -> &Arc<OstdTask> {
        &self.inner
    }

    /// Runs this task.
    pub fn run(self: &Arc<Self>) {
        let task_data = self.ostd_task().extension().downcast_ref::<FrameTaskData>();
        let is_service_task = task_data.is_some_and(|data| data.kind() == FrameTaskKind::Service);
        if let Some(task_data) = task_data {
            let frame_vcpu_id = task_data.frame_vcpu_id();
            crate::early_println!(
                "[FrameVM] task run: task={:p}, host={:p}, kind={:?}, vm={}, vcpu={}, inner_cpu={:?}",
                Arc::as_ptr(self),
                Arc::as_ptr(self.ostd_task()),
                task_data.kind(),
                frame_vcpu_id.vm_id(),
                frame_vcpu_id.vcpu_index(),
                task_data.schedule_info.cpu.get(),
            );
            task_data.set_task(self);
        }
        let bootstrap_publishes_service_task = is_service_task
            && OstdTask::current().is_some_and(|current| {
                current
                    .extension()
                    .downcast_ref::<FrameTaskData>()
                    .is_some_and(|data| data.kind() == FrameTaskKind::Bootstrap)
            });
        let host_preempt_guard = host_ostd::task::disable_preempt();
        let enqueue_result = scheduler::enqueue_task(self.clone(), scheduler::EnqueueFlags::Spawn);
        if let Some(task_data) = task_data {
            crate::early_println!(
                "[FrameVM] task inner enqueue: kind={:?}, inner_cpu={:?}, ok={}",
                task_data.kind(),
                task_data.schedule_info.cpu.get(),
                enqueue_result.is_ok(),
            );
        }
        if bootstrap_publishes_service_task {
            enqueue_result
                .expect("bootstrap task must publish the service task to its inner runqueue");
        }
        if let Some(task_data) = task_data {
            crate::early_println!(
                "[FrameVM] task host run begin: kind={:?}, host={:p}",
                task_data.kind(),
                Arc::as_ptr(self.ostd_task()),
            );
        }
        self.ostd_task().run();
        drop(host_preempt_guard);
        if let Some(task_data) = task_data {
            crate::early_println!(
                "[FrameVM] task host run returned: kind={:?}, host={:p}",
                task_data.kind(),
                Arc::as_ptr(self.ostd_task()),
            );
        }
    }

    /// Wakes up the task.
    pub fn wake_up(self: &Arc<Self>) {
        scheduler::unpark_target(self.clone());
    }
}

impl Deref for CurrentTask {
    type Target = Task;

    fn deref(&self) -> &Self::Target {
        self.task.as_ref()
    }
}

impl CurrentTask {
    /// Returns the local data of the current task.
    pub fn local_data(&self) -> &(dyn Any + Send) {
        self.current.local_data()
    }

    /// Returns a cloned task handle.
    pub fn cloned(&self) -> Arc<Task> {
        self.task.clone()
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

/// Builder for creating tasks.
pub struct TaskOptions {
    func: Option<Box<dyn FnOnce() + Send>>,
    data: Option<Box<dyn Any + Send + Sync>>,
    extension: Option<Box<dyn Any + Send + Sync>>,
    local_data: Option<Box<dyn Any + Send>>,
    frame_task: Option<(FrameVcpuId, FrameTaskKind)>,
}

impl TaskOptions {
    /// Creates a new task builder with the given entry function.
    pub fn new<F>(entry: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            func: Some(Box::new(entry)),
            data: None,
            extension: None,
            local_data: None,
            frame_task: None,
        }
    }

    /// Binds a task to a FrameVM vCPU while the service scheduler is bootstrapping.
    pub fn bootstrap_vcpu(mut self, frame_vcpu_id: FrameVcpuId) -> Self {
        self.frame_task = Some((frame_vcpu_id, FrameTaskKind::Bootstrap));
        self
    }

    /// Sets task-specific data.
    pub fn data<T>(self, data: T) -> Self
    where
        T: Any + Send + Sync + 'static,
    {
        self.data_any(Box::new(data))
    }

    /// Sets task-specific data from an already-boxed value.
    pub fn data_any(mut self, data: Box<dyn Any + Send + Sync>) -> Self {
        self.data = Some(data);
        self
    }

    /// Sets task extension data.
    pub fn extension<T>(self, extension: T) -> Self
    where
        T: Any + Send + Sync + 'static,
    {
        self.extension_any(Box::new(extension))
    }

    /// Sets task extension data from an already-boxed value.
    pub fn extension_any(mut self, extension: Box<dyn Any + Send + Sync>) -> Self {
        self.extension = Some(extension);
        self
    }

    /// Sets current-task local data.
    pub fn local_data<T>(self, local_data: T) -> Self
    where
        T: Any + Send + 'static,
    {
        self.local_data_any(Box::new(local_data))
    }

    /// Sets current-task local data from an already-boxed value.
    pub fn local_data_any(mut self, local_data: Box<dyn Any + Send>) -> Self {
        self.local_data = Some(local_data);
        self
    }

    /// Builds and returns the task.
    pub fn build(mut self) -> Result<Task> {
        let func = self.func.take().ok_or(Error::InvalidArgs)?;
        let task_kind = self.frame_task.map(|(_, kind)| kind);
        let exits_scheduler_bootstrap = task_kind == Some(FrameTaskKind::Bootstrap);
        let frame_vcpu_id = self
            .frame_task
            .map(|(frame_vcpu_id, _)| frame_vcpu_id)
            .or_else(current_frame_vcpu_id);
        let data = self.data.take().unwrap_or_else(|| Box::new(()));
        let extension = self.extension.take().unwrap_or_else(|| Box::new(()));
        let local_data = self.local_data.take().unwrap_or_else(|| Box::new(()));
        let task_func = Box::new(move || {
            if let Some(frame_vcpu_id) = frame_vcpu_id {
                let host_task = OstdTask::current().map(|current| current.cloned());
                crate::early_println!(
                    "[FrameVM] task entry: task={:p}, host={:p}, kind={:?}, vm={}, vcpu={}",
                    Task::current()
                        .as_ref()
                        .map_or(core::ptr::null(), |current| Arc::as_ptr(&current.cloned())),
                    host_task
                        .as_ref()
                        .map_or(core::ptr::null(), |task| Arc::as_ptr(task)),
                    task_kind.unwrap_or(FrameTaskKind::Service),
                    frame_vcpu_id.vm_id(),
                    frame_vcpu_id.vcpu_index(),
                );
            }
            if exits_scheduler_bootstrap
                && let Some(current_task) = OstdTask::current()
                && let Some(group) =
                    super::bootstrap_frame_sched_group_for_ostd_task(current_task.as_ref())
            {
                group.begin_bootstrap();
            }
            func();
            scheduler::exit_current_task();
        });

        let task = if let Some(frame_vcpu_id) = frame_vcpu_id {
            let frame_vm = vm::get_vm_by_id(frame_vcpu_id.vm_id()).ok_or(Error::InvalidArgs)?;
            let sched_group = frame_vm
                .sched_group(frame_vcpu_id.vcpu_index())
                .ok_or(Error::InvalidArgs)?;
            let kind = task_kind.unwrap_or(FrameTaskKind::Service);
            let extension = Box::new(FrameTaskData::try_new(
                &frame_vm,
                sched_group,
                kind,
                data,
                extension,
            )?) as Box<dyn Any + Send + Sync>;

            let host_task_ops = HOST_TASK_OPS.get().ok_or(Error::InvalidArgs)?;
            (host_task_ops.create_task)(task_func, extension, local_data, Some(frame_vcpu_id))?
        } else {
            let options = host_ostd::task::TaskOptions::new(task_func)
                .data_any(data)
                .extension_any(extension)
                .local_data_any(local_data);
            Arc::new(options.build().map_err(Error::from)?)
        };
        Ok(Task { inner: task })
    }

    /// Builds a new task and runs it immediately.
    pub fn spawn(self) -> Result<Arc<Task>> {
        let task = Arc::new(self.build()?);
        task.run();
        Ok(task)
    }
}
