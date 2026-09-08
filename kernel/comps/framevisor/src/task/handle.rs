// SPDX-License-Identifier: MPL-2.0

//! OSTD-shaped task handles and builders for FrameVisor.

use alloc::{boxed::Box, sync::Arc};
use core::{any::Any, borrow::Borrow, ops::Deref};

use host_ostd::task::{CurrentTask as OstdCurrentTask, Task as OstdTask};

use super::{
    FrameTaskKind, FrameTaskState,
    binding::build_host_task,
    current::{clear_current_task, current_state, current_state_for_current_task, install_current_task},
    scheduler::{self, info::TaskScheduleInfo},
};
use crate::{
    error::Error,
    prelude::Result,
    vm::{FrameSchedGroup, FrameVm},
};

/// Wrapper for the current task.
pub struct CurrentTask {
    task: Arc<Task>,
    current: OstdCurrentTask,
}

/// A FrameVisor task carried by one OSTD task.
#[derive(Debug)]
pub struct Task {
    pub(super) inner: Arc<OstdTask>,
    pub(super) state: Arc<FrameTaskState>,
}

/// Opaque local data stored in a Host carrier.
///
/// The declaration order is intentional: Rust drops fields in declaration
/// order, so service-owned local data (and its drop glue) is released before
/// the final task-state reference. Once `FrameTaskState` owns the service
/// image lease, this is what keeps that image mapped through every local-data
/// destructor without making a second lifecycle authority.
#[doc(hidden)]
pub struct FrameTaskLocalData {
    payload: Box<dyn Any + Send>,
    _state: Arc<FrameTaskState>,
}

impl FrameTaskLocalData {
    fn new(payload: Box<dyn Any + Send>, state: Arc<FrameTaskState>) -> Self {
        Self {
            payload,
            _state: state,
        }
    }

    fn payload(&self) -> &(dyn Any + Send) {
        &*self.payload
    }

    pub(super) fn state(&self) -> Arc<FrameTaskState> {
        self._state.clone()
    }
}

impl Task {
    /// Gets the current FrameVM task if available.
    pub fn current() -> Option<CurrentTask> {
        let current = OstdTask::current()?;
        let carrier = current.cloned();
        let state = current_state(&carrier)?;
        // Bootstrap owns a private Host carrier solely to establish the
        // FrameVM execution domain.  It is not a service task: retaining it
        // here would make the first service task observe a Frame-only current
        // task that main OSTD does not expose during bootstrap.
        if state.kind() == FrameTaskKind::Bootstrap {
            return None;
        }
        Some(CurrentTask {
            task: state.task(carrier),
            current,
        })
    }

    /// Yields the current FrameVM task.
    pub fn yield_now() {
        scheduler::yield_current();
    }

    /// Returns the task data.
    pub fn data(&self) -> &Box<dyn Any + Send + Sync> {
        self.state.data()
    }

    /// Returns the task scheduling information.
    pub fn schedule_info(&self) -> &TaskScheduleInfo {
        self.state.schedule_info()
    }

    #[doc(hidden)]
    pub fn host_task(&self) -> &Arc<OstdTask> {
        &self.inner
    }

    pub(crate) fn ostd_task(&self) -> &Arc<OstdTask> {
        self.host_task()
    }

    pub(crate) fn state(&self) -> &Arc<FrameTaskState> {
        &self.state
    }

    /// Runs this task.
    pub fn run(self: &Arc<Self>) {
        self.state.set_task(self);
        match self.state.kind() {
            FrameTaskKind::Bootstrap => {
                let group = self
                    .state
                    .group()
                    .expect("a bootstrap task must retain its one outer group");
                group
                    .install_initial_continuation(self.clone())
                    .expect("a FrameVM vCPU may install exactly one bootstrap continuation");
                // `Task::run` is submitted by a Host workqueue. Before the
                // Host scheduler has selected this carrier, its enqueue path
                // can still enter FrameVisor synchronization on that worker.
                // Publish the bootstrap state only for this bounded handoff;
                // the carrier entry publishes itself before service code runs.
                let host_current = OstdTask::current().map(|current| current.cloned());
                if let Some(host_current) = &host_current {
                    install_current_task(host_current, &self.state);
                }
                // Host `Task::run` performs the unchanged Spawn publication.
                // The Host ClassScheduler recognizes this Frame carrier and
                // enqueues its already-committed outer group, never the
                // carrier as an ordinary Host entity.
                self.ostd_task().run();
                if host_current.is_some() {
                    clear_current_task();
                }
            }
            FrameTaskKind::Service => scheduler::run_task(self),
        }
    }
}

impl Deref for CurrentTask {
    type Target = Task;

    fn deref(&self) -> &Self::Target {
        self.task.as_ref()
    }
}

impl CurrentTask {
    /// Returns the local data of the current FrameVM task.
    pub fn local_data(&self) -> &(dyn Any + Send) {
        self.current
            .local_data()
            .downcast_ref::<FrameTaskLocalData>()
            .map(FrameTaskLocalData::payload)
            .expect("FrameVM task local data is missing")
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

/// Builder for creating service tasks in the current FrameVM.
pub struct TaskOptions {
    func: Option<Box<dyn FnOnce() + Send>>,
    data: Option<Box<dyn Any + Send + Sync>>,
    local_data: Option<Box<dyn Any + Send>>,
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
            local_data: None,
        }
    }

    /// Sets the function that represents the entry point of the task.
    pub fn func<F>(mut self, func: F) -> Self
    where
        F: Fn() + Send + 'static,
    {
        self.func = Some(Box::new(func));
        self
    }

    /// Sets task-specific data.
    pub fn data<T>(mut self, data: T) -> Self
    where
        T: Any + Send + Sync + 'static,
    {
        self.data = Some(Box::new(data));
        self
    }

    /// Sets current-task local data.
    pub fn local_data<T>(mut self, local_data: T) -> Self
    where
        T: Any + Send + 'static,
    {
        self.local_data = Some(Box::new(local_data));
        self
    }

    /// Builds and returns the task.
    pub fn build(mut self) -> Result<Task> {
        // The private execution-domain projection remains available while a
        // bootstrap carrier runs, even though the public `Task::current()` is
        // intentionally `None`. This is the only source from which a normal
        // service task may inherit its immutable FrameVM owner and exact
        // vCPU placement.
        let current_state = current_state_for_current_task().ok_or(Error::InvalidArgs)?;
        let frame_vm = current_state.frame_vm();
        let vcpu_id = current_state
            .bound_frame_vcpu_id()
            .ok_or(Error::InvalidArgs)?;
        let state = Arc::new(FrameTaskState::try_new(
            &frame_vm,
            FrameTaskKind::Service,
            self.data.take().unwrap_or_else(|| Box::new(())),
        )?);
        state
            .schedule_info()
            .cpu
            .set_anyway(crate::cpu::CpuId::from_raw(vcpu_id.vcpu_index() as u32));
        build_task(
            self.func.take().ok_or(Error::InvalidArgs)?,
            state,
            self.local_data.take().unwrap_or_else(|| Box::new(())),
        )
    }

    /// Builds a new task and runs it immediately.
    pub fn spawn(self) -> Result<Arc<Task>> {
        let task = Arc::new(self.build()?);
        task.run();
        Ok(task)
    }
}

/// Builds the initial FrameVM service task for an explicit VM and group.
///
/// This is a Host integration entry point, not part of the service-facing
/// task builder. Bootstrap placement can therefore never be inherited from an
/// unrelated Host task.
pub fn build_bootstrap_task<F>(
    frame_vm: &Arc<FrameVm>,
    group: &Arc<FrameSchedGroup>,
    entry: F,
) -> Result<Task>
where
    F: FnOnce() + Send + 'static,
{
    let state = Arc::new(FrameTaskState::try_new(
        frame_vm,
        FrameTaskKind::Bootstrap,
        Box::new(()),
    )?);
    state
        .schedule_info()
        .cpu
        .set_anyway(crate::cpu::CpuId::from_raw(group.vcpu_index() as u32));
    build_task(Box::new(entry), state, Box::new(()))
}

fn build_task(
    func: Box<dyn FnOnce() + Send>,
    state: Arc<FrameTaskState>,
    local_data: Box<dyn Any + Send>,
) -> Result<Task> {
    // A Frame task normally retires through the injected scheduler. Its final
    // stopping-vCPU path first detaches the outer continuation and then uses
    // OSTD's Host exit path. Do not capture `state` in this non-returning
    // closure: OSTD exits without unwinding this stack, so an entry capture
    // would keep the service-image lease alive after its carrier had exited.
    let task_func = Box::new(move || {
        // Publish the exact current carrier before running any service or
        // bootstrap code. The Host post-schedule hook maintains the same
        // projection for ordinary switches, but this closes the task-entry
        // window in which OSTD-shaped service initialization can access its
        // vCPU-local state.
        let current = OstdTask::current()
            .expect("a FrameVM carrier must be current before its entry runs");
        let task_state = current
            .local_data()
            .downcast_ref::<FrameTaskLocalData>()
            .map(FrameTaskLocalData::state)
            .expect("a FrameVM carrier must retain Frame task local data");
        install_current_task(&current.cloned(), &task_state);
        drop(task_state);
        func();
        scheduler::exit_current_task();
    });

    let carrier = build_host_task(
        task_func,
        state.clone(),
        FrameTaskLocalData::new(local_data, state.clone()),
    )?;
    Ok(Task {
        inner: carrier,
        state,
    })
}
