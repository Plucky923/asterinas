// SPDX-License-Identifier: MPL-2.0

//! Virtual timer scheduler bridge.

use alloc::collections::BTreeSet;

use host_ostd::{cpu::PinCurrentCpu, sync::RwLock, task::disable_preempt, timer};

use super::{
    registry::scheduler_for_vm,
    types::{LocalRunQueue, Scheduler, UpdateFlags},
};
use crate::{
    cpu::CpuId,
    iht, task,
    vm::{self, FrameVcpuId},
};

static VIRTUAL_TIMER_DRIVER_CPUS: RwLock<BTreeSet<usize>> = RwLock::new(BTreeSet::new());

/// Enables timer-driven preemption on the current CPU.
pub fn enable_preemption_on_cpu() {
    init_virtual_timer_on_current_cpu();
}

fn register_virtual_timer_callback_on_current_cpu() {
    timer::register_callback_on_cpu(|| {
        let _ = inject_virtual_timer_tick_for_current_host_cpu();
    });
}

fn inject_virtual_timer_tick_for_current_host_cpu() -> bool {
    let host_cpu = {
        let preempt_guard = disable_preempt();
        preempt_guard.current_cpu()
    };

    let groups = vm::get_running_sched_groups_by_host_cpu(host_cpu);
    for group in &groups {
        iht::inject_timer_tick(group.id());
    }
    !groups.is_empty()
}

pub(crate) fn init_virtual_timer_on_current_cpu() {
    let preempt_guard = disable_preempt();
    let host_cpu_id = u32::from(preempt_guard.current_cpu()) as usize;

    {
        let mut registered_cpus = VIRTUAL_TIMER_DRIVER_CPUS.write();
        if !registered_cpus.insert(host_cpu_id) {
            return;
        }
    }

    register_virtual_timer_callback_on_current_cpu();
}

#[cfg(ktest)]
pub(crate) fn clear_virtual_timer_driver_registered_cpus_for_test() {
    VIRTUAL_TIMER_DRIVER_CPUS.write().clear();
}

#[cfg(ktest)]
pub(crate) fn try_register_virtual_timer_driver_cpu_for_test(host_cpu_id: usize) -> bool {
    VIRTUAL_TIMER_DRIVER_CPUS.write().insert(host_cpu_id)
}

#[cfg(ktest)]
pub(crate) fn virtual_timer_driver_has_registered_cpu_for_test(host_cpu_id: usize) -> bool {
    VIRTUAL_TIMER_DRIVER_CPUS.read().contains(&host_cpu_id)
}

pub(crate) fn dispatch_timer_ticks(frame_vcpu_id: FrameVcpuId, ticks: u64) {
    if ticks == 0 {
        return;
    }

    let Some(scheduler) = scheduler_for_vm(frame_vcpu_id.vm_id()) else {
        crate::timer::dispatch_registered_callbacks(frame_vcpu_id, ticks);
        return;
    };

    dispatch_ticks_on_scheduler(scheduler, frame_vcpu_id, ticks);
    crate::timer::dispatch_registered_callbacks(frame_vcpu_id, ticks);
    task::wake_service_tasks_in_frame_vcpu(frame_vcpu_id);
}

fn dispatch_ticks_on_scheduler(
    scheduler: &'static dyn Scheduler<task::Task>,
    frame_vcpu_id: FrameVcpuId,
    ticks: u64,
) {
    if vm::get_sched_group_by_id(frame_vcpu_id).is_some() {
        scheduler.mut_local_rq_on_cpu_with(
            CpuId::from_raw(frame_vcpu_id.vcpu_index() as u32),
            &mut |rq| dispatch_ticks_on_runqueue(rq, ticks),
        );
        return;
    }

    scheduler.mut_local_rq_with(&mut |rq| dispatch_ticks_on_runqueue(rq, ticks));
}

fn dispatch_ticks_on_runqueue(rq: &mut dyn LocalRunQueue<task::Task>, ticks: u64) {
    for _ in 0..ticks {
        let _ = rq.update_current(UpdateFlags::Tick);
    }
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn virtual_timer_driver_registration_is_per_host_cpu() {
        clear_virtual_timer_driver_registered_cpus_for_test();

        assert!(try_register_virtual_timer_driver_cpu_for_test(0));
        assert!(!try_register_virtual_timer_driver_cpu_for_test(0));
        assert!(try_register_virtual_timer_driver_cpu_for_test(1));
        assert!(virtual_timer_driver_has_registered_cpu_for_test(0));
        assert!(virtual_timer_driver_has_registered_cpu_for_test(1));

        clear_virtual_timer_driver_registered_cpus_for_test();
    }
}
