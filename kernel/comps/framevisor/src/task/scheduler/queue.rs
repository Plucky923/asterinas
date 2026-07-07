// SPDX-License-Identifier: MPL-2.0

//! Service task enqueue, park, and wake bridges.

use alloc::sync::Arc;

use super::{
    cpu_scope::try_current_cpu,
    registry::{scheduler_for_current_vm, scheduler_for_vm},
    types::{EnqueueFlags, UpdateFlags},
};
use crate::{
    cpu::CpuId,
    prelude::Result,
    task::{self, Task},
    vm::{self, FrameVcpuId, VmId},
};

pub(crate) fn enqueue_task(runnable: Arc<Task>, flags: EnqueueFlags) -> Result<()> {
    let vm_id = vm_id_for_task_or_current(&runnable).ok_or(crate::Error::InvalidArgs)?;
    let scheduler = scheduler_for_vm(vm_id);
    let scheduler_is_installed = scheduler.is_some();
    let target_cpu = scheduler
        .and_then(|scheduler| scheduler.enqueue(runnable.clone(), flags))
        .or_else(|| runnable.try_schedule_info().and_then(|info| info.cpu.get()))
        .or_else(try_current_cpu)
        .unwrap_or_else(CpuId::bsp);

    let frame_vcpu_id =
        frame_vcpu_id_for_cpu(vm_id, target_cpu).ok_or(crate::Error::InvalidArgs)?;
    if !scheduler_is_installed && let Some(group) = vm::get_sched_group_by_id(frame_vcpu_id) {
        group.enqueue_bootstrap_service_task(runnable.ostd_task().clone());
    }
    task::bind_service_vcpu_runtime(runnable.ostd_task().clone(), frame_vcpu_id)
}

/// Blocks the current service task unless `has_unparked` already observes a wake event.
///
/// Returns whether the service scheduler actually dequeued the current task. A caller that also
/// blocks the backing host task must only do so after the service task has really been parked.
pub(crate) fn park_current(has_unparked: impl Fn() -> bool) -> bool {
    if has_unparked() {
        return false;
    }

    let Some(scheduler) = scheduler_for_current_vm() else {
        Task::yield_now();
        return false;
    };

    let mut parked = false;
    let mut next_to_wake = None;
    scheduler.mut_local_rq_with(&mut |rq| {
        if has_unparked() {
            return;
        }

        let should_pick_next = rq.update_current(UpdateFlags::Wait);
        parked = rq.dequeue_current().is_some();
        if should_pick_next && let Some(next) = rq.try_pick_next() {
            next_to_wake = Some(next.ostd_task().clone());
        }
    });
    if let Some(next) = next_to_wake {
        next.wake_up();
    }
    parked
}

/// Dequeues the current service task from the FrameVM scheduler before its backing task exits.
pub(crate) fn exit_current_task() {
    let Some(scheduler) = scheduler_for_current_vm() else {
        return;
    };

    let mut next_to_wake = None;
    scheduler.mut_local_rq_with(&mut |rq| {
        let should_pick_next = rq.update_current(UpdateFlags::Exit);
        let _ = rq.dequeue_current();
        if should_pick_next && let Some(next) = rq.try_pick_next() {
            next_to_wake = Some(next.ostd_task().clone());
        }
    });
    if let Some(next) = next_to_wake {
        next.wake_up();
    }
}

/// Makes a parked task runnable again.
pub(crate) fn unpark_target(runnable: Arc<Task>) {
    let _ = enqueue_task(runnable.clone(), EnqueueFlags::Wake);
    runnable.ostd_task().wake_up();
}

fn frame_vcpu_id_for_cpu(vm_id: VmId, cpu_id: CpuId) -> Option<FrameVcpuId> {
    let vm = vm::get_vm_by_id(vm_id)?;
    (cpu_id.as_usize() < vm.vcpu_count()).then_some(FrameVcpuId::new(vm_id, cpu_id.as_usize()))
}

fn vm_id_for_task_or_current(task: &Arc<Task>) -> Option<VmId> {
    task::frame_vcpu_id_for_task(task.ostd_task())
        .or_else(task::current_frame_vcpu_id)
        .map(|frame_vcpu_id| frame_vcpu_id.vm_id())
}
