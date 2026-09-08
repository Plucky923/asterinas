// SPDX-License-Identifier: MPL-2.0

//! Host timer registration and FrameVM tick delivery.

use super::types::UpdateFlags;
use crate::{
    task,
    vm::{self, FrameVcpuId},
};

/// Registers the FrameVM timer callback on the current Host CPU.
pub fn enable_preemption_on_cpu() {
    let Some(group) = task::current_state_for_current_task().and_then(|state| state.group()) else {
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
    // A physical tick can account only the virtual CPU whose committed
    // continuation is currently executing. It never opens another vCPU's
    // inner runqueue through the Host scheduler.
    if task::current_frame_vcpu_id() == Some(frame_vcpu_id)
        && let Some(scheduler) = frame_vm.scheduler()
    {
        let mut should_preempt = false;
        scheduler.mut_local_rq_with(&mut |run_queue| {
            for _ in 0..ticks {
                should_preempt |= run_queue.update_current(UpdateFlags::Tick);
            }
        });
        if should_preempt && let Some(group) = frame_vm.sched_group(frame_vcpu_id.vcpu_index()) {
            group.request_inner_preempt();
        }
    }
    frame_vm.dispatch_timer_callbacks(frame_vcpu_id, ticks);
}
