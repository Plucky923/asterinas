// SPDX-License-Identifier: MPL-2.0

//! Host timer registration and FrameVM tick delivery.

use host_ostd::task::Task as OstdTask;

use super::types::UpdateFlags;
use crate::{
    cpu::CpuId,
    task,
    vm::{self, FrameVcpuId},
};

/// Registers the FrameVM timer callback on the current Host CPU.
pub fn enable_preemption_on_cpu() {
    let Some(current) = OstdTask::current() else {
        return;
    };
    let Some(group) = current
        .extension()
        .downcast_ref::<task::FrameTaskData>()
        .and_then(task::FrameTaskData::group)
    else {
        return;
    };
    group.enable_timer_on_current_cpu();
}

pub(crate) fn dispatch_timer_ticks(frame_vcpu_id: FrameVcpuId, ticks: u64) {
    if ticks == 0 {
        return;
    }

    let Some(frame_vm) = vm::get_vm_by_id(frame_vcpu_id.vm_id()) else {
        return;
    };
    if let Some(scheduler) = frame_vm.scheduler() {
        scheduler.mut_local_rq_on_cpu_with(
            CpuId::from_raw(frame_vcpu_id.vcpu_index() as u32),
            &mut |run_queue| {
                let mut should_preempt = false;
                for _ in 0..ticks {
                    should_preempt |= run_queue.update_current(UpdateFlags::Tick);
                }
                if should_preempt {
                    let _ = run_queue.try_pick_next();
                }
            },
        );
    }
    frame_vm.dispatch_timer_callbacks(frame_vcpu_id, ticks);
}
