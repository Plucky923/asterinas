// SPDX-License-Identifier: MPL-2.0

//! FrameVM task binding metadata.

use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
};
use core::any::Any;

use host_ostd::sync::{LocalIrqDisabled as HostLocalIrqDisabled, SpinLock as HostSpinLock};

use super::{Task, scheduler::info::TaskScheduleInfo};
use crate::{
    error::Error,
    prelude::Result,
    vm::{FrameSchedGroup, FrameVcpuId, FrameVm, MemoryCharge},
};

/// OSTD's default kernel stack size, used when the build does not override it.
const DEFAULT_FRAME_TASK_STACK_PAGES: usize = 128;

/// FrameVM host task kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameTaskKind {
    Bootstrap,
    Service,
    Interrupt,
}

/// Task-local metadata for FrameVM service and interrupt-handler host tasks.
pub struct FrameTaskData {
    pub(super) frame_vm: Arc<FrameVm>,
    _stack_charge: MemoryCharge,
    bound_vcpu: HostSpinLock<FrameVcpuId, HostLocalIrqDisabled>,
    kind: FrameTaskKind,
    pub(super) data: Box<dyn Any + Send + Sync>,
    pub(super) extension: Box<dyn Any + Send + Sync>,
    pub(super) schedule_info: TaskScheduleInfo,
    task: HostSpinLock<Weak<Task>, HostLocalIrqDisabled>,
}

impl FrameTaskData {
    /// Creates FrameVM task metadata after charging its Host kernel stack.
    pub fn try_new(
        frame_vm: &Arc<FrameVm>,
        group: &Arc<FrameSchedGroup>,
        kind: FrameTaskKind,
        data: Box<dyn Any + Send + Sync>,
        extension: Box<dyn Any + Send + Sync>,
    ) -> Result<Self> {
        if frame_vm.id() != group.vm_id() {
            return Err(Error::InvalidArgs);
        }
        let Some(owned_group) = frame_vm.sched_group(group.vcpu_index()) else {
            return Err(Error::InvalidArgs);
        };
        if !Arc::ptr_eq(owned_group, group) {
            return Err(Error::InvalidArgs);
        }

        // OSTD reads the same build-time environment variable when it defines
        // its private stack size. Keeping the parsing here in sync avoids
        // charging a fixed 128-page guess when release builds select an 8- or
        // 16-page stack. Guard pages are virtual-only and are not charged.
        let stack_pages = option_env!("OSTD_TASK_STACK_SIZE_IN_PAGES")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_FRAME_TASK_STACK_PAGES);
        let stack_charge = frame_vm
            .memory()
            .charge_host(stack_pages.saturating_mul(crate::mm::PAGE_SIZE))?;
        // `bound_vcpu` carries the execution identity. The scheduler CPU stays
        // empty until the task is published to the inner runqueue.
        let schedule_info = TaskScheduleInfo {
            cpu: Default::default(),
        };

        Ok(Self {
            frame_vm: frame_vm.clone(),
            _stack_charge: stack_charge,
            bound_vcpu: HostSpinLock::new(group.id()),
            kind,
            data,
            extension,
            schedule_info,
            task: HostSpinLock::new(Weak::new()),
        })
    }

    /// Returns the FrameVM task kind.
    pub const fn kind(&self) -> FrameTaskKind {
        self.kind
    }

    /// Returns the unique FrameVM handle for the backing OSTD task.
    pub(super) fn task(&self, ostd_task: Arc<host_ostd::task::Task>) -> Arc<Task> {
        let mut task = self.task.lock();
        if let Some(task) = task.upgrade() {
            return task;
        }

        let new_task = Arc::new(Task { inner: ostd_task });
        *task = Arc::downgrade(&new_task);
        new_task
    }

    pub(super) fn set_task(&self, task: &Arc<Task>) {
        *self.task.lock() = Arc::downgrade(task);
    }

    /// Resolves the currently bound `FrameSchedGroup` from the owning VM.
    pub(crate) fn group(&self) -> Option<Arc<FrameSchedGroup>> {
        let frame_vcpu_id = *self.bound_vcpu.lock();
        (frame_vcpu_id.vm_id() == self.frame_vm.id())
            .then(|| {
                self.frame_vm
                    .sched_group(frame_vcpu_id.vcpu_index())
                    .cloned()
            })
            .flatten()
    }

    /// Returns the currently bound FrameVM vCPU.
    pub(crate) fn frame_vcpu_id(&self) -> FrameVcpuId {
        *self.bound_vcpu.lock()
    }

    /// Rebinds the task to another vCPU owned by the same FrameVM.
    pub(super) fn rebind(
        &self,
        group: &Arc<FrameSchedGroup>,
    ) -> Result<Option<Arc<FrameSchedGroup>>> {
        let frame_vm = &self.frame_vm;
        if group.vm_id() != frame_vm.id() {
            return Err(Error::InvalidArgs);
        }
        let Some(owned_group) = frame_vm.sched_group(group.vcpu_index()) else {
            return Err(Error::InvalidArgs);
        };
        if !Arc::ptr_eq(owned_group, group) {
            return Err(Error::InvalidArgs);
        }

        let mut current_vcpu = self.bound_vcpu.lock();
        let previous_group = frame_vm.sched_group(current_vcpu.vcpu_index()).cloned();
        *current_vcpu = group.id();
        Ok(previous_group)
    }
}
