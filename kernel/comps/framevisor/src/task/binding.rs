// SPDX-License-Identifier: MPL-2.0

//! Host-task bindings owned by FrameVisor.

use alloc::{boxed::Box, sync::Arc};
use core::any::Any;

use host_ostd::task::Task as OstdTask;

use super::frame_task::{FrameTaskData, FrameTaskKind};
use crate::{
    error::Error,
    prelude::Result,
    sync::Once,
    vm::{self, FrameSchedGroup, FrameVcpuId},
};

pub(super) struct HostTaskOps {
    pub(super) create_task: fn(
        Box<dyn FnOnce() + Send>,
        Box<dyn Any + Send + Sync>,
        Box<dyn Any + Send>,
        Option<FrameVcpuId>,
    ) -> Result<Arc<OstdTask>>,
    pub(super) bind_vcpu: fn(Arc<OstdTask>, FrameVcpuId) -> Result<()>,
}

pub(super) static HOST_TASK_OPS: Once<HostTaskOps> = Once::new();

/// Installs the immutable Host task operation set.
pub fn inject_host_task_ops(
    create_task: fn(
        Box<dyn FnOnce() + Send>,
        Box<dyn Any + Send + Sync>,
        Box<dyn Any + Send>,
        Option<FrameVcpuId>,
    ) -> Result<Arc<OstdTask>>,
    bind_vcpu: fn(Arc<OstdTask>, FrameVcpuId) -> Result<()>,
) {
    HOST_TASK_OPS.call_once(|| HostTaskOps {
        create_task,
        bind_vcpu,
    });
}

/// Binds a backing task to its Host CPU and FrameVM vCPU runqueue.
pub fn bind_vcpu_runtime(task: Arc<OstdTask>, frame_vcpu_id: FrameVcpuId) -> Result<()> {
    let task_data = task
        .extension()
        .downcast_ref::<FrameTaskData>()
        .ok_or(Error::InvalidArgs)?;
    let frame_vm = task_data.frame_vm.clone();
    if frame_vm.id() != frame_vcpu_id.vm_id() {
        return Err(Error::InvalidArgs);
    }
    let target_group = frame_vm
        .sched_group(frame_vcpu_id.vcpu_index())
        .ok_or(Error::InvalidArgs)?
        .clone();

    let host_task_ops = HOST_TASK_OPS.get().ok_or(Error::InvalidArgs)?;
    (host_task_ops.bind_vcpu)(task.clone(), frame_vcpu_id)?;

    let previous_group = task_data.rebind(&target_group)?;
    if task_data.kind() == FrameTaskKind::Service {
        target_group.add_service_task(&task);
        if let Some(previous_group) = previous_group
            && !Arc::ptr_eq(&previous_group, &target_group)
        {
            previous_group.remove_service_task(&task);
        }
    }
    Ok(())
}

/// Returns the FrameVM that owns the current FrameVM task.
pub(crate) fn current_frame_vm() -> Option<Arc<vm::FrameVm>> {
    let current = OstdTask::current()?;
    current
        .extension()
        .downcast_ref::<FrameTaskData>()
        .map(|task_data| task_data.frame_vm.clone())
}

/// Returns the owning scheduling group for a host OSTD FrameVM task.
pub fn frame_sched_group_for_ostd_task(task: &OstdTask) -> Option<Arc<FrameSchedGroup>> {
    let data = task.extension().downcast_ref::<FrameTaskData>()?;
    if data.kind() == FrameTaskKind::Bootstrap {
        return None;
    }

    data.group()
}

/// Returns the scheduling group owned by a scheduler-bootstrap task.
pub fn bootstrap_frame_sched_group_for_ostd_task(task: &OstdTask) -> Option<Arc<FrameSchedGroup>> {
    let data = task.extension().downcast_ref::<FrameTaskData>()?;
    if data.kind() == FrameTaskKind::Bootstrap {
        data.group()
    } else {
        None
    }
}

/// Returns the host-backed local runqueue of the current backing task.
pub(crate) fn current_frame_vcpu_id() -> Option<FrameVcpuId> {
    let current = OstdTask::current()?;
    current
        .extension()
        .downcast_ref::<FrameTaskData>()
        .map(FrameTaskData::frame_vcpu_id)
}
