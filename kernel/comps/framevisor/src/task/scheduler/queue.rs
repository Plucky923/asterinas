// SPDX-License-Identifier: MPL-2.0

//! Service task enqueue, park, and wake bridges.

use alloc::sync::Arc;

use host_ostd::task::Task as OstdTask;

use super::types::{EnqueueFlags, UpdateFlags};
use crate::{
    cpu::CpuId,
    prelude::Result,
    task::{self, Task},
    vm::{self, FrameVcpuId},
};

pub(crate) fn enqueue_task(runnable: Arc<Task>, flags: EnqueueFlags) -> Result<()> {
    let owner_frame_vcpu_id = runnable
        .ostd_task()
        .extension()
        .downcast_ref::<task::FrameTaskData>()
        .map(task::FrameTaskData::frame_vcpu_id)
        .or_else(task::current_frame_vcpu_id)
        .ok_or(crate::Error::InvalidArgs)?;
    let vm_id = owner_frame_vcpu_id.vm_id();
    let frame_vm = vm::get_vm_by_id(vm_id).ok_or(crate::Error::InvalidArgs)?;
    let scheduler = frame_vm.scheduler();
    let scheduler_is_installed = scheduler.is_some();
    let initial_cpu = runnable
        .ostd_task()
        .extension()
        .downcast_ref::<task::FrameTaskData>()
        .and_then(|data| data.schedule_info.cpu.get())
        .unwrap_or_else(|| CpuId::from_raw(owner_frame_vcpu_id.vcpu_index() as u32));
    let initial_vcpu_index = initial_cpu.as_usize();
    if initial_vcpu_index >= frame_vm.vcpu_count() {
        return Err(crate::Error::InvalidArgs);
    }
    let initial_frame_vcpu_id = FrameVcpuId::new(vm_id, initial_vcpu_index);
    let is_bootstrap_task = runnable
        .ostd_task()
        .extension()
        .downcast_ref::<task::FrameTaskData>()
        .is_some_and(|data| data.kind() == task::FrameTaskKind::Bootstrap);
    if is_bootstrap_task {
        task::bind_vcpu_runtime(runnable.ostd_task().clone(), initial_frame_vcpu_id)?;
        return Ok(());
    }

    if flags == EnqueueFlags::HostWake {
        runnable.schedule_info().cpu.set_anyway(initial_cpu);
    }

    // Publish the Host/vCPU binding before the service scheduler can expose
    // the task on an inner runqueue. Another Host CPU may pick it immediately
    // after `enqueue` returns.
    task::bind_vcpu_runtime(runnable.ostd_task().clone(), initial_frame_vcpu_id)?;
    let target_cpu = scheduler
        .and_then(|scheduler| scheduler.enqueue(runnable.clone(), flags))
        .or_else(|| {
            runnable
                .ostd_task()
                .extension()
                .downcast_ref::<task::FrameTaskData>()
                .and_then(|data| data.schedule_info.cpu.get())
        })
        .unwrap_or(initial_cpu);

    let target_vcpu_index = target_cpu.as_usize();
    if target_vcpu_index >= frame_vm.vcpu_count() {
        return Err(crate::Error::InvalidArgs);
    }
    let target_frame_vcpu_id = FrameVcpuId::new(vm_id, target_vcpu_index);
    if !scheduler_is_installed && let Some(group) = frame_vm.sched_group(target_vcpu_index) {
        group.enqueue_bootstrap_service_task(runnable.ostd_task().clone());
    }
    if target_frame_vcpu_id != initial_frame_vcpu_id {
        task::bind_vcpu_runtime(runnable.ostd_task().clone(), target_frame_vcpu_id)?;
    }
    Ok(())
}

pub(crate) fn park_current(has_unparked: impl Fn() -> bool) -> bool {
    if has_unparked() {
        return false;
    }

    let Some(current_task) = Task::current() else {
        return false;
    };
    let current_ostd_task = current_task.ostd_task().clone();
    let Some(task_data) = current_ostd_task
        .extension()
        .downcast_ref::<task::FrameTaskData>()
    else {
        return false;
    };
    let Some(scheduler) = task_data.frame_vm.scheduler() else {
        return false;
    };

    let mut parked = false;
    scheduler.mut_local_rq_on_cpu_with(
        CpuId::from_raw(task_data.frame_vcpu_id().vcpu_index() as u32),
        &mut |runqueue| {
            if has_unparked()
                || runqueue
                    .current()
                    .is_none_or(|task| !Arc::ptr_eq(task.ostd_task(), &current_ostd_task))
            {
                return;
            }

            runqueue.update_current(UpdateFlags::Wait);
            parked = runqueue.dequeue_current().is_some();
        },
    );
    parked
}

/// Mirrors a backing Host task's wait transition into the service scheduler.
///
/// FrameVisor synchronization primitives park the service task before blocking
/// its backing task. A Host implementation called across the service boundary
/// can instead block directly through Host OSTD. In that case, the outer
/// scheduler calls this bridge while it owns the Host runqueue lock.
pub(crate) fn park_service_task(ostd_task: &Arc<OstdTask>) -> bool {
    let Some(task_data) = ostd_task.extension().downcast_ref::<task::FrameTaskData>() else {
        return false;
    };
    if task_data.schedule_info.cpu.get().is_none() {
        // FrameVisor synchronization parks the inner task before its backing
        // Host task enters a Host wait queue. Only Host-originated waits still
        // carry an inner CPU here and need the compatibility bridge below.
        return false;
    }
    let Some(frame_vcpu_id) = ostd_task
        .extension()
        .downcast_ref::<task::FrameTaskData>()
        .map(task::FrameTaskData::frame_vcpu_id)
    else {
        return false;
    };
    let Some(frame_vm) = vm::get_vm_by_id(frame_vcpu_id.vm_id()) else {
        return false;
    };
    let Some(scheduler) = frame_vm.scheduler() else {
        return false;
    };
    let mut parked = false;
    scheduler.mut_local_rq_on_cpu_with(
        CpuId::from_raw(frame_vcpu_id.vcpu_index() as u32),
        &mut |rq| {
            if rq
                .current()
                .is_none_or(|task| !Arc::ptr_eq(task.ostd_task(), ostd_task))
            {
                return;
            }

            let _ = rq.update_current(UpdateFlags::Wait);
            parked = rq.dequeue_current().is_some();
        },
    );
    parked
}

/// Mirrors a backing Host task's wake transition into the service scheduler.
///
/// The Host scheduler serializes this call with
/// [`park_service_task`] using its runqueue lock. The service
/// enqueue is intentionally separate from waking the backing task: the Host
/// wake path already owns that operation.
pub fn enqueue_service_task_from_host_wake(ostd_task: Arc<OstdTask>) -> bool {
    let Some(task_data) = ostd_task.extension().downcast_ref::<task::FrameTaskData>() else {
        return false;
    };
    if task_data.kind() != task::FrameTaskKind::Service
        || task_data.schedule_info.cpu.get().is_some()
    {
        return false;
    }
    let runnable = task_data.task(ostd_task.clone());
    enqueue_task(runnable, EnqueueFlags::HostWake).is_ok()
}

/// Dequeues the current service task from the FrameVM scheduler before its backing task exits.
pub(crate) fn exit_current_task() {
    let Some(current_task) = Task::current() else {
        return;
    };
    let current_ostd_task = current_task.ostd_task().clone();
    let Some(task_data) = current_ostd_task
        .extension()
        .downcast_ref::<task::FrameTaskData>()
    else {
        return;
    };

    let current_kind = task_data.kind();
    let frame_vcpu_id = task_data.frame_vcpu_id();
    crate::early_println!(
        "[FrameVM] service task exit: ptr={:p}, kind={:?}, vm={}, vcpu={}, completed={}",
        Arc::as_ptr(&current_ostd_task),
        current_kind,
        frame_vcpu_id.vm_id(),
        frame_vcpu_id.vcpu_index(),
        current_ostd_task.is_completed(),
    );
    let service_group = (current_kind != task::FrameTaskKind::Interrupt)
        .then(|| task_data.group())
        .flatten();
    crate::early_println!(
        "[FrameVM] service task exit resolving scheduler: kind={:?}, vm={}, vcpu={}",
        current_kind,
        frame_vcpu_id.vm_id(),
        frame_vcpu_id.vcpu_index(),
    );

    let mut next_to_wake = None;
    if let Some(frame_vm) = vm::get_vm_by_id(frame_vcpu_id.vm_id())
        && let Some(scheduler) = frame_vm.scheduler()
    {
        crate::early_println!(
            "[FrameVM] service task exit entering inner scheduler: kind={:?}, vm={}, vcpu={}",
            current_kind,
            frame_vcpu_id.vm_id(),
            frame_vcpu_id.vcpu_index(),
        );
        let exits_scheduler_bootstrap = current_kind == task::FrameTaskKind::Bootstrap;
        if exits_scheduler_bootstrap
            && let Some(group) = task::bootstrap_frame_sched_group_for_ostd_task(&current_ostd_task)
        {
            group.complete_bootstrap();
            crate::early_println!("[FrameVM] service bootstrap state completed");
        }
        crate::early_println!("[FrameVM] service task exit locking inner runqueue");
        scheduler.mut_local_rq_on_cpu_with(
            CpuId::from_raw(frame_vcpu_id.vcpu_index() as u32),
            &mut |rq| {
                crate::early_println!("[FrameVM] service task exit entered inner runqueue");
                if rq
                    .current()
                    .is_some_and(|task| Arc::ptr_eq(task.ostd_task(), &current_ostd_task))
                {
                    crate::early_println!("[FrameVM] service task exit removing inner current");
                    let _ = rq.update_current(UpdateFlags::Exit);
                    let _ = rq.dequeue_current();
                }

                if exits_scheduler_bootstrap
                    && let Some(current) = rq.current()
                    && !Arc::ptr_eq(current.ostd_task(), &current_ostd_task)
                {
                    // Installing the service scheduler can make the init task the
                    // inner current while the bootstrap backing task is still
                    // running. Wake that backing task at the bootstrap exit boundary
                    // so the Host scheduler observes the cross-level handoff.
                    next_to_wake = Some(current.ostd_task().clone());
                    return;
                }

                crate::early_println!("[FrameVM] service task exit leaving inner runqueue");
            },
        );
        crate::early_println!(
            "[FrameVM] service task exit inner scheduler finished: kind={:?}, vm={}, vcpu={}",
            current_kind,
            frame_vcpu_id.vm_id(),
            frame_vcpu_id.vcpu_index(),
        );
        if exits_scheduler_bootstrap {
            for vcpu_index in 0..frame_vm.vcpu_count() {
                if let Some(group) = frame_vm.sched_group(vcpu_index) {
                    group.wake_service_tasks();
                }
            }
        }
    }

    if let Some(group) = service_group {
        group.remove_service_task(&current_ostd_task);
        crate::early_println!(
            "[FrameVM] service task removed from group: kind={:?}, vm={}, vcpu={}",
            current_kind,
            frame_vcpu_id.vm_id(),
            frame_vcpu_id.vcpu_index(),
        );
    }
    if let Some(next) = next_to_wake {
        next.wake_up();
    }
}

/// Makes a parked task runnable again.
pub(crate) fn unpark_target(runnable: Arc<Task>) {
    let task_data = runnable
        .ostd_task()
        .extension()
        .downcast_ref::<task::FrameTaskData>();
    if task_data.is_some_and(|data| data.schedule_info.cpu.get().is_none()) {
        let flags = if task::current_frame_vcpu_id().is_some() {
            EnqueueFlags::Wake
        } else {
            EnqueueFlags::HostWake
        };
        let _ = enqueue_task(runnable.clone(), flags);
    }
    runnable.ostd_task().wake_up();
}
