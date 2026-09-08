// SPDX-License-Identifier: MPL-2.0

//! FrameVM-owned state associated with one Host task carrier.

use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
};
use core::{any::Any, fmt};

use super::{Task, scheduler::info::TaskScheduleInfo};
use crate::{
    prelude::Result,
    vm::{FrameSchedGroup, FrameVcpuId, FrameVm, MemoryCharge},
};

/// OSTD's default kernel stack size, used when the build does not override it.
const DEFAULT_FRAME_TASK_STACK_PAGES: usize = 128;

/// The role of a Host task carrier in one FrameVM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameTaskKind {
    Bootstrap,
    Service,
}

/// FrameVM-owned state for one Host task carrier.
///
/// This is deliberately separate from `host_ostd::task::Task`: OSTD owns the
/// carrier and its scheduler bookkeeping, while FrameVisor owns the virtual
/// task identity, placement, payload, and stack charge.
pub struct FrameTaskState {
    frame_vm: Arc<FrameVm>,
    _stack_charge: MemoryCharge,
    kind: FrameTaskKind,
    data: Box<dyn Any + Send + Sync>,
    schedule_info: TaskScheduleInfo,
    task: host_ostd::sync::SpinLock<Weak<Task>, host_ostd::sync::LocalIrqDisabled>,
    // Declared last: service task data and the canonical weak task handle
    // drop before this permits image teardown to observe zero leases.
    _image_task_lease: ServiceImageTaskLease,
}

impl fmt::Debug for FrameTaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameTaskState")
            .field("frame_vm", &self.frame_vm.id())
            .field("virtual_cpu", &self.schedule_info.cpu.get())
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl FrameTaskState {
    /// Creates FrameVM task state after charging its Host kernel stack.
    pub fn try_new(
        frame_vm: &Arc<FrameVm>,
        kind: FrameTaskKind,
        data: Box<dyn Any + Send + Sync>,
    ) -> Result<Self> {
        // OSTD reads the same build-time environment variable when it defines
        // its private stack size. Guard pages are virtual-only and are not
        // charged.
        let stack_pages = option_env!("OSTD_TASK_STACK_SIZE_IN_PAGES")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_FRAME_TASK_STACK_PAGES);
        let stack_charge = frame_vm
            .memory()
            .charge_host(stack_pages.saturating_mul(crate::mm::PAGE_SIZE))?;

        let image_task_lease = ServiceImageTaskLease::new(frame_vm);
        Ok(Self {
            frame_vm: frame_vm.clone(),
            _stack_charge: stack_charge,
            kind,
            data,
            schedule_info: TaskScheduleInfo {
                cpu: Default::default(),
            },
            task: host_ostd::sync::SpinLock::new(Weak::new()),
            _image_task_lease: image_task_lease,
        })
    }

    /// Returns the owning FrameVM.
    pub fn frame_vm(&self) -> Arc<FrameVm> {
        self.frame_vm.clone()
    }

    /// Returns the FrameVM task kind.
    pub const fn kind(&self) -> FrameTaskKind {
        self.kind
    }

    /// Returns the service-owned task data.
    pub fn data(&self) -> &Box<dyn Any + Send + Sync> {
        &self.data
    }

    /// Returns the service scheduler's task information.
    pub fn schedule_info(&self) -> &TaskScheduleInfo {
        &self.schedule_info
    }

    /// Resolves the currently bound scheduling group from the owning VM.
    pub fn group(&self) -> Option<Arc<FrameSchedGroup>> {
        self.bound_cpu()
            .and_then(|cpu| self.frame_vm.sched_group(cpu.as_usize()).cloned())
    }

    /// Returns the currently bound FrameVM vCPU.
    pub fn frame_vcpu_id(&self) -> FrameVcpuId {
        self.bound_frame_vcpu_id()
            .expect("a running FrameVM task must have a virtual CPU")
    }

    /// Returns the bound FrameVM vCPU, if this task has been admitted to one.
    ///
    /// A FrameVM service task may exist while Host setup is still running and
    /// before its scheduler has selected a vCPU. Such a task has a FrameVM
    /// owner but must not enable a virtual interrupt context yet.
    pub(crate) fn bound_frame_vcpu_id(&self) -> Option<FrameVcpuId> {
        self.bound_cpu()
            .map(|cpu| FrameVcpuId::new(self.frame_vm.id(), cpu.as_usize()))
    }

    /// Resolves this task's placement against its immutable VM owner.
    ///
    /// Bootstrap runs in a Host worker before it becomes the current FrameVM
    /// task, so the current execution context cannot validate this placement.
    fn bound_cpu(&self) -> Option<crate::cpu::CpuId> {
        self.schedule_info
            .cpu
            .get_for_cpu_count(self.frame_vm.vcpu_count())
    }

    /// Returns the unique FrameVisor handle for `ostd_task`.
    pub(crate) fn task(self: &Arc<Self>, ostd_task: Arc<host_ostd::task::Task>) -> Arc<Task> {
        let mut task = self.task.lock();
        if let Some(task) = task.upgrade() {
            return task;
        }

        let new_task = Arc::new(Task {
            inner: ostd_task,
            state: self.clone(),
        });
        *task = Arc::downgrade(&new_task);
        new_task
    }

    /// Resolves the unique Frame task wrapper for this carrier.
    ///
    /// This is used only by the Host post-switch integration while holding
    /// the Host local runqueue lock; it is not a service scheduler API.
    #[doc(hidden)]
    pub fn task_for_host_carrier(
        self: &Arc<Self>,
        ostd_task: Arc<host_ostd::task::Task>,
    ) -> Arc<Task> {
        self.task(ostd_task)
    }

    pub(crate) fn set_task(&self, task: &Arc<Task>) {
        *self.task.lock() = Arc::downgrade(task);
    }
}

/// A resource lease for a task state that may execute service-image drop glue.
/// It records no task lifecycle or completion state.
struct ServiceImageTaskLease {
    frame_vm: Option<Arc<FrameVm>>,
}

impl ServiceImageTaskLease {
    fn new(frame_vm: &Arc<FrameVm>) -> Self {
        frame_vm.acquire_service_image_task_lease();
        Self {
            frame_vm: Some(frame_vm.clone()),
        }
    }
}

impl Drop for ServiceImageTaskLease {
    fn drop(&mut self) {
        if let Some(frame_vm) = self.frame_vm.take() {
            frame_vm.release_service_image_task_lease();
        }
    }
}
