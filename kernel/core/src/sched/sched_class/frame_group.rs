// SPDX-License-Identifier: MPL-2.0

//! Scheduler-owned state for FrameVM scheduling groups.

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, Ordering};

use aster_framevisor::{
    FrameSchedGroup,
    task::{FrameTaskData, FrameTaskKind, scheduler::UpdateFlags as FrameUpdateFlags},
};
use ostd::{
    cpu::{AtomicCpuSet, CpuSet},
    sync::SpinLock,
    task::{
        Task,
        scheduler::{UpdateFlags, info::CommonSchedInfo},
    },
};

use super::{
    fair::{self, FairAttr},
    policy::SchedPolicyKind,
    task_group::TaskGroup,
};
use crate::thread::AsThread;

/// Scheduler entity state for one FrameVM vCPU group.
#[derive(Debug)]
pub(super) struct FrameSchedEntityState {
    group: Weak<FrameSchedGroup>,
    task_group: Arc<TaskGroup>,
    fair_attr: FairAttr,
    cpu_affinity: AtomicCpuSet,
    // Host registration/placement admission; the FrameVM execution gate is
    // kept separately in `FrameSchedGroup::RunState`.
    admitted: AtomicBool,
}

impl FrameSchedEntityState {
    pub(super) fn new(
        group: &Arc<FrameSchedGroup>,
        task_group: Arc<TaskGroup>,
        cpu_affinity: CpuSet,
    ) -> Self {
        Self {
            group: Arc::downgrade(group),
            task_group,
            fair_attr: FairAttr::from_weight(u64::from(group.share())),
            cpu_affinity: AtomicCpuSet::new(cpu_affinity),
            admitted: AtomicBool::new(true),
        }
    }

    pub(super) fn group(&self) -> Option<Arc<FrameSchedGroup>> {
        self.group.upgrade()
    }

    pub(super) fn fair_attr(&self) -> &FairAttr {
        &self.fair_attr
    }

    pub(super) fn task_group(&self) -> &Arc<TaskGroup> {
        &self.task_group
    }

    pub(super) fn cpu_affinity(&self) -> CpuSet {
        self.cpu_affinity.load(Ordering::Acquire)
    }

    pub(super) fn set_cpu_affinity(&self, cpu_affinity: CpuSet) {
        self.cpu_affinity.store(&cpu_affinity, Ordering::Release);
    }

    pub(super) fn allows_host_cpu(&self, cpu: ostd::cpu::CpuId) -> bool {
        self.admitted.load(Ordering::Acquire)
            && self.cpu_affinity.load(Ordering::Acquire).contains(cpu)
    }

    pub(super) fn is_admitted(&self) -> bool {
        self.admitted.load(Ordering::Acquire)
    }

    pub(super) fn stop_admission(&self) {
        self.admitted.store(false, Ordering::Release);
    }
}

/// Refreshes one group's Host queue membership.
pub(super) fn refresh(
    state: &Arc<FrameSchedEntityState>,
    fair: &SpinLock<fair::FairClassRq>,
) -> bool {
    let Some(group) = state.group() else {
        let _ = fair.lock().try_dequeue_frame_sched_group(state);
        return false;
    };
    let allows_host_cpu = state.allows_host_cpu(group.host_cpu());
    let has_runnable_work = group.has_runnable_work();
    if !allows_host_cpu || !has_runnable_work {
        let _ = fair.lock().try_dequeue_frame_sched_group(state);
        return false;
    }
    fair.lock().enqueue_frame_sched_group(state.clone())
}

/// Republishes a group after the Host consumed its current queue entry.
pub(super) fn requeue(state: &Arc<FrameSchedEntityState>, fair: &SpinLock<fair::FairClassRq>) {
    refresh(state, fair);
}

/// Returns whether an outer current task may compete with a fair pick.
pub(super) fn current_can_compete(entity: &super::PickedSchedEntity) -> bool {
    let super::CurrentOuterEntity::FrameSchedGroup(state) = &entity.outer else {
        return false;
    };
    let Some(group) = state.group() else {
        return false;
    };
    state.allows_host_cpu(group.host_cpu())
        && entity
            .task()
            .extension()
            .downcast_ref::<FrameTaskData>()
            .map(FrameTaskData::kind)
            != Some(FrameTaskKind::Interrupt)
}

/// Returns whether enqueueing this group may preempt the Host current task.
pub(super) fn preempt_on_enqueue(
    state: &FrameSchedEntityState,
    current: Option<&super::PickedSchedEntity>,
) -> bool {
    if state.group().is_none() {
        return false;
    }
    current.is_none_or(|current| {
        current
            .task()
            .extension()
            .downcast_ref::<FrameTaskData>()
            .map(FrameTaskData::kind)
            != Some(FrameTaskKind::Bootstrap)
            && current.thread().sched_attr().policy_kind() >= SchedPolicyKind::Fair
    })
}

/// Picks an inner task and publishes it as the Host scheduler's current pair.
pub(super) fn pick_task(state: &Arc<FrameSchedEntityState>) -> Option<super::PickedSchedEntity> {
    let group = state.group()?;
    if !state.allows_host_cpu(group.host_cpu()) {
        return None;
    }
    let task = group.pick_task()?;
    if task.is_completed() {
        return None;
    }

    let thread = task.as_thread().cloned()?;
    let _ = task.cpu().set_if_is_none(group.host_cpu());
    Some(super::PickedSchedEntity {
        concrete: (task, thread),
        outer: super::CurrentOuterEntity::FrameSchedGroup(state.clone()),
    })
}

/// Updates Host fair accounting and the FrameVM current-task policy together.
pub(super) fn update_current(
    state: &Arc<FrameSchedEntityState>,
    task: &Arc<Task>,
    runtime: &super::CurrentRuntime,
    fair: &SpinLock<fair::FairClassRq>,
    flags: UpdateFlags,
) -> bool {
    let group = state.group();
    let group_should_pick = group.as_ref().is_some_and(|group| {
        group.update_current(
            task,
            match flags {
                UpdateFlags::Yield => FrameUpdateFlags::Yield,
                UpdateFlags::Wait => FrameUpdateFlags::Wait,
                UpdateFlags::Tick => FrameUpdateFlags::Tick,
                UpdateFlags::Exit => FrameUpdateFlags::Exit,
            },
        )
    });
    if matches!(flags, UpdateFlags::Yield)
        && task
            .extension()
            .downcast_ref::<FrameTaskData>()
            .is_some_and(|data| data.kind() == FrameTaskKind::Interrupt)
        && let Some(group) = group.as_ref()
        && group.has_service_work_for_outer()
    {
        group.request_service_handoff();
    }
    let placement_disallowed = group
        .as_ref()
        .is_none_or(|group| !state.allows_host_cpu(group.host_cpu()));
    let fair_should_preempt = fair
        .lock()
        .update_current_frame_group(state, runtime, flags);
    if matches!(flags, UpdateFlags::Wait | UpdateFlags::Exit) {
        requeue(state, fair);
    }
    placement_disallowed || fair_should_preempt || group_should_pick
}

#[cfg(ktest)]
mod tests {
    use aster_framevisor::{FrameVcpuId, irq::InterruptHandler};
    use ostd::{cpu::CpuId, prelude::ktest};

    use super::*;
    use crate::sched::sched_class::fair::WEIGHT_0;

    #[ktest]
    fn stopped_state_rejects_host_cpu_admission() {
        let id = FrameVcpuId::new(0.into(), 0);
        let group = Arc::new(FrameSchedGroup::new(
            id,
            WEIGHT_0 as u32,
            CpuId::bsp(),
            Arc::new(InterruptHandler::new(id)),
        ));
        let state = FrameSchedEntityState::new(&group, TaskGroup::new_root(1), CpuSet::new_full());

        assert!(state.is_admitted());
        assert!(state.allows_host_cpu(CpuId::bsp()));

        state.stop_admission();

        assert!(!state.is_admitted());
        assert!(!state.allows_host_cpu(CpuId::bsp()));
    }
}
