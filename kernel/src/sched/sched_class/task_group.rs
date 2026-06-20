// SPDX-License-Identifier: MPL-2.0

//! Task group (cgroup) for hierarchical fair group scheduling.
//!
//! # Fair Runqueue Lock Order
//!
//! Fair runqueues are per-CPU, and code must not hold fair runqueue locks from
//! different CPUs at the same time. Any fair runqueue locks held together must
//! form an ancestor-to-descendant chain on one CPU. If an operation needs to
//! update the runqueue represented by the current guard, it updates that guard
//! directly instead of locking the same `SpinLock` again.

use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
    vec::Vec,
};

use aster_framevisor::FrameTaskGroupId;
use ostd::{
    cpu::{self, CpuId},
    sync::SpinLock,
    task::{Task, scheduler::info::CommonSchedInfo},
    util::id_set::Id,
};

use super::fair::{self, FairAttr, FairClassRq};

/// A task group representing one cgroup for hierarchical fair group scheduling.
#[derive(Debug)]
pub struct TaskGroup {
    /// The scheduler entity kind represented by this group.
    kind: TaskGroupKind,

    /// Weak parent task group, or `None` for root.
    parent: Option<Weak<TaskGroup>>,

    /// Per-CPU scheduling attributes for this group's entity in the parent's runqueue.
    fair_attrs: Box<[FairAttr]>,

    /// Per-CPU fair runqueues for direct member threads and child group entities.
    fair_rqs: Box<[Arc<SpinLock<FairClassRq>>]>,
}

impl TaskGroup {
    /// Creates the root task group.
    fn new_root(cpu_count: usize) -> Arc<Self> {
        Arc::new_cyclic(|weak_self| Self {
            kind: TaskGroupKind::Cgroup,
            parent: None,
            fair_attrs: Vec::new().into_boxed_slice(),
            fair_rqs: (0..cpu_count)
                .map(|cpu| {
                    Arc::new(SpinLock::new(FairClassRq::new(
                        CpuId::new(cpu as u32),
                        weak_self.clone(),
                    )))
                })
                .collect(),
        })
    }

    /// Creates a child task group under `parent`.
    pub(crate) fn new_child(parent: &Arc<TaskGroup>, weight: u32) -> Arc<Self> {
        Self::new_child_with_kind(parent, weight, TaskGroupKind::Cgroup)
    }

    /// Creates a child task group that represents one host-side service vCPU.
    pub(crate) fn new_frame_child(
        parent: &Arc<TaskGroup>,
        weight: u32,
        task_group_id: FrameTaskGroupId,
    ) -> Arc<Self> {
        Self::new_child_with_kind(parent, weight, TaskGroupKind::Frame(task_group_id))
    }

    fn new_child_with_kind(parent: &Arc<TaskGroup>, weight: u32, kind: TaskGroupKind) -> Arc<Self> {
        let cpu_count = cpu::num_cpus();
        Arc::new_cyclic(|weak_self| Self {
            kind,
            parent: Some(Arc::downgrade(parent)),
            fair_attrs: (0..cpu_count)
                .map(|_| FairAttr::from_weight(scale_cgroup_weight(weight)))
                .collect(),
            fair_rqs: (0..cpu_count)
                .map(|cpu| {
                    Arc::new(SpinLock::new(FairClassRq::new(
                        CpuId::new(cpu as u32),
                        weak_self.clone(),
                    )))
                })
                .collect(),
        })
    }

    /// Returns the parent task group, if any.
    pub(super) fn parent(&self) -> Option<Arc<TaskGroup>> {
        self.parent.as_ref()?.upgrade()
    }

    pub(super) fn fair_queue(&self, cpu: CpuId) -> &Arc<SpinLock<FairClassRq>> {
        &self.fair_rqs[cpu.as_usize()]
    }

    /// Returns the per-CPU scheduling attributes for this group's entity.
    pub(super) fn fair_attr(&self, cpu: CpuId) -> Option<&FairAttr> {
        self.fair_attrs.get(u32::from(cpu) as usize)
    }

    pub(super) fn is_frame_entity(&self) -> bool {
        matches!(self.kind, TaskGroupKind::Frame(_))
    }

    pub(super) fn frame_task_group_id(&self) -> Option<FrameTaskGroupId> {
        match self.kind {
            TaskGroupKind::Frame(task_group_id) => Some(task_group_id),
            TaskGroupKind::Cgroup => None,
        }
    }

    /// Updates the CPU weight and refreshes any queued group entities.
    pub(crate) fn update_weight(&self, weight: u32) {
        let scaled_weight = scale_cgroup_weight(weight);
        let parent = self.parent();

        for (cpu, fair_attr) in self.fair_attrs.iter().enumerate() {
            fair_attr.update_weight(scaled_weight);
            if let Some(parent) = &parent {
                parent
                    .fair_queue(CpuId::new(cpu as u32))
                    .disable_irq()
                    .lock()
                    .refresh_queued_entity(fair_attr);
            }
        }
    }

    pub(crate) fn debug_fair_state(&self, cpu: CpuId) -> Option<(u64, u64)> {
        let fair_attr = self.fair_attr(cpu)?;
        Some((fair_attr.debug_weight(), fair_attr.debug_vruntime()))
    }

    /// Dequeues queued tasks whose task-group assignment changed to this group.
    ///
    /// Running and sleeping tasks are not returned. They observe the new task
    /// group through their thread metadata when they are enqueued again.
    ///
    /// # Locking
    ///
    /// Locks only runqueues on each task's current CPU. While the root guard is
    /// held, any additional guard is for a descendant runqueue on the same CPU.
    pub(crate) fn migrate_tasks_from(
        self: &Arc<Self>,
        tasks: &[(Arc<Task>, Arc<TaskGroup>)],
    ) -> Vec<Arc<Task>> {
        let root = root_task_group();
        let mut queued_tasks = Vec::new();

        for (task, old_group) in tasks {
            if Arc::ptr_eq(self, old_group) {
                continue;
            }

            let Some(cpu) = task.cpu().get() else {
                continue;
            };

            let mut root_rq = root.fair_queue(cpu).disable_irq().lock();
            if root_rq.try_dequeue_task(task, old_group) {
                task.cpu().set_to_none();
                queued_tasks.push(task.clone());
            }
        }

        queued_tasks
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TaskGroupKind {
    Cgroup,
    Frame(FrameTaskGroupId),
}

fn scale_cgroup_weight(weight: u32) -> u64 {
    u64::from(weight).saturating_mul(fair::WEIGHT_0) / u64::from(fair::DEFAULT_CGROUP_WEIGHT)
}

/// Global root task group.
static ROOT_TASK_GROUP: spin::Once<Arc<TaskGroup>> = spin::Once::new();

/// Returns the root task group.
pub(crate) fn root_task_group() -> &'static Arc<TaskGroup> {
    init_root_task_group(cpu::num_cpus())
}

/// Initialises the root task group.
pub(super) fn init_root_task_group(cpu_count: usize) -> &'static Arc<TaskGroup> {
    ROOT_TASK_GROUP.call_once(|| TaskGroup::new_root(cpu_count))
}

#[cfg(ktest)]
mod tests {
    use ostd::{
        prelude::ktest,
        task::scheduler::{EnqueueFlags, LocalRunQueue, UpdateFlags},
    };

    use super::{
        super::{CurrentRuntime, PerCpuClassRqSet, SchedClassRq, idle, real_time, stop, time},
        *,
    };
    use crate::{
        sched::{DEFAULT_CGROUP_WEIGHT, Nice, SchedPolicy},
        thread::{AsThread, Thread, kernel_thread::ThreadOptions},
    };

    fn test_thread(task_group: Arc<TaskGroup>) -> Arc<Task> {
        let task = ThreadOptions::new(|| {})
            .sched_policy(SchedPolicy::Fair(Nice::default()))
            .build();
        task.as_thread().unwrap().set_task_group(task_group);
        task
    }

    fn test_sched_entity(task_group: Arc<TaskGroup>) -> (Arc<Task>, Arc<Thread>) {
        let task = test_thread(task_group);
        let thread = task.as_thread().unwrap().clone();
        (task, thread)
    }

    #[ktest]
    fn fair_group_weight_biases_repeated_picks() {
        let cpu = CpuId::bsp();
        let root = TaskGroup::new_root(1);
        let low_group = TaskGroup::new_child(&root, DEFAULT_CGROUP_WEIGHT);
        let high_group = TaskGroup::new_child(&root, DEFAULT_CGROUP_WEIGHT * 4);
        let low_task = test_thread(low_group.clone());
        let high_task = test_thread(high_group.clone());
        let runtime_delta = time::min_period_clocks() * 2;

        let mut low_ticks = 0u32;
        let mut high_ticks = 0u32;
        let mut current_period_delta = 0;
        let mut rq = root.fair_queue(cpu).disable_irq().lock();
        rq.enqueue(low_task, Some(EnqueueFlags::Spawn));
        rq.enqueue(high_task, Some(EnqueueFlags::Spawn));

        let mut current = rq.pick_next().unwrap();
        for _ in 0..40 {
            current_period_delta += runtime_delta;
            let runtime = CurrentRuntime {
                start: 0,
                delta: runtime_delta,
                period_delta: current_period_delta,
            };

            let thread = current.as_thread().unwrap();
            if Arc::ptr_eq(&thread.task_group(), &low_group) {
                low_ticks += 1;
            } else if Arc::ptr_eq(&thread.task_group(), &high_group) {
                high_ticks += 1;
            }

            if rq.update_current(&runtime, thread, UpdateFlags::Tick) {
                let next = rq.pick_next().unwrap();
                rq.enqueue(current, None);
                current = next;
                current_period_delta = 0;
            }
        }

        assert!(
            high_ticks >= low_ticks.saturating_mul(2),
            "high-weight group should be picked at least twice as often: low={low_ticks}, high={high_ticks}"
        );
    }

    #[ktest]
    fn fair_frame_group_weight_biases_repeated_picks() {
        let cpu = CpuId::bsp();
        let root = TaskGroup::new_root(1);
        let low_group =
            TaskGroup::new_frame_child(&root, DEFAULT_CGROUP_WEIGHT, FrameTaskGroupId::new(1, 0));
        let high_group = TaskGroup::new_frame_child(
            &root,
            DEFAULT_CGROUP_WEIGHT * 4,
            FrameTaskGroupId::new(1, 1),
        );
        let low_task = test_thread(low_group.clone());
        let low_peer = test_thread(low_group.clone());
        let high_task = test_thread(high_group.clone());
        let high_peer = test_thread(high_group.clone());
        let runtime_delta = time::min_period_clocks() / 4;

        let mut low_ticks = 0u32;
        let mut high_ticks = 0u32;
        let mut current_period_delta = 0;
        let mut rq = root.fair_queue(cpu).disable_irq().lock();
        rq.enqueue(low_task, Some(EnqueueFlags::Spawn));
        rq.enqueue(low_peer, Some(EnqueueFlags::Spawn));
        rq.enqueue(high_task, Some(EnqueueFlags::Spawn));
        rq.enqueue(high_peer, Some(EnqueueFlags::Spawn));

        let mut current = rq.pick_next().unwrap();
        for _ in 0..80 {
            current_period_delta += runtime_delta;
            let runtime = CurrentRuntime {
                start: 0,
                delta: runtime_delta,
                period_delta: current_period_delta,
            };

            let thread = current.as_thread().unwrap();
            if Arc::ptr_eq(&thread.task_group(), &low_group) {
                low_ticks += 1;
            } else if Arc::ptr_eq(&thread.task_group(), &high_group) {
                high_ticks += 1;
            }

            if rq.update_current(&runtime, thread, UpdateFlags::Tick) {
                let next = rq.pick_next().unwrap();
                rq.enqueue(current, None);
                current = next;
                current_period_delta = 0;
            }
        }

        assert!(
            high_ticks >= low_ticks.saturating_mul(2),
            "high-weight FrameGroup should be picked at least twice as often: low={low_ticks}, high={high_ticks}"
        );
    }

    #[ktest]
    fn fair_frame_group_weight_biases_single_task_groups() {
        let cpu = CpuId::bsp();
        let root = TaskGroup::new_root(1);
        let low_group =
            TaskGroup::new_frame_child(&root, DEFAULT_CGROUP_WEIGHT, FrameTaskGroupId::new(2, 0));
        let high_group = TaskGroup::new_frame_child(
            &root,
            DEFAULT_CGROUP_WEIGHT * 4,
            FrameTaskGroupId::new(2, 1),
        );
        let low_task = test_thread(low_group.clone());
        let high_task = test_thread(high_group.clone());
        let runtime_delta = time::min_period_clocks() / 4;

        let mut low_ticks = 0u32;
        let mut high_ticks = 0u32;
        let mut current_period_delta = 0;
        let mut rq = root.fair_queue(cpu).disable_irq().lock();
        rq.enqueue(low_task, Some(EnqueueFlags::Spawn));
        rq.enqueue(high_task, Some(EnqueueFlags::Spawn));

        let mut current = rq.pick_next().unwrap();
        for _ in 0..80 {
            current_period_delta += runtime_delta;
            let runtime = CurrentRuntime {
                start: 0,
                delta: runtime_delta,
                period_delta: current_period_delta,
            };

            let thread = current.as_thread().unwrap();
            if Arc::ptr_eq(&thread.task_group(), &low_group) {
                low_ticks += 1;
            } else if Arc::ptr_eq(&thread.task_group(), &high_group) {
                high_ticks += 1;
            }

            if rq.update_current(&runtime, thread, UpdateFlags::Tick) {
                let next = rq.pick_next().unwrap();
                rq.enqueue(current, None);
                current = next;
                current_period_delta = 0;
            }
        }

        assert!(
            high_ticks >= low_ticks.saturating_mul(2),
            "high-weight single-task FrameGroup should be picked at least twice as often: low={low_ticks}, high={high_ticks}"
        );
    }

    #[ktest]
    fn frame_group_tick_pick_keeps_current_when_it_still_wins() {
        let cpu = CpuId::bsp();
        let root = TaskGroup::new_root(1);
        let low_group =
            TaskGroup::new_frame_child(&root, DEFAULT_CGROUP_WEIGHT, FrameTaskGroupId::new(3, 0));
        let high_group = TaskGroup::new_frame_child(
            &root,
            DEFAULT_CGROUP_WEIGHT * 16,
            FrameTaskGroupId::new(3, 1),
        );
        let low_entity = test_sched_entity(low_group);
        let high_entity = test_sched_entity(high_group);
        let high_task = high_entity.0.clone();

        let mut rq = PerCpuClassRqSet {
            stop: stop::StopClassRq::new(),
            real_time: real_time::RealTimeClassRq::new(cpu),
            fair: root.fair_queue(cpu).clone(),
            idle: idle::IdleClassRq::new(),
            current: Some((high_entity, CurrentRuntime::new_with_period_delta(0))),
            current_can_compete_on_pick: false,
            current_needs_runtime_update_on_pick: false,
            current_runtime_updated_since_pick: false,
        };
        rq.enqueue_entity(low_entity, Some(EnqueueFlags::Spawn));

        assert!(rq.update_current(UpdateFlags::Tick));
        assert!(rq.try_pick_next().is_none());
        assert!(
            rq.current()
                .is_some_and(|current| Arc::ptr_eq(current, &high_task)),
            "the current high-share FrameGroup should keep running"
        );
    }

    #[ktest]
    fn frame_group_leaf_preempt_runs_when_no_peer_group_exists() {
        let cpu = CpuId::bsp();
        let root = TaskGroup::new_root(1);
        let frame_group =
            TaskGroup::new_frame_child(&root, DEFAULT_CGROUP_WEIGHT, FrameTaskGroupId::new(0, 0));
        let first_task = test_thread(frame_group.clone());
        let second_task = test_thread(frame_group.clone());
        let runtime_delta = time::min_period_clocks() * 3 / 4;
        let runtime = CurrentRuntime {
            start: 0,
            delta: runtime_delta,
            period_delta: runtime_delta,
        };

        let mut rq = root.fair_queue(cpu).disable_irq().lock();
        rq.enqueue(first_task, Some(EnqueueFlags::Spawn));
        rq.enqueue(second_task, Some(EnqueueFlags::Spawn));

        let current = rq.pick_next().unwrap();
        let current_thread = current.as_thread().unwrap();
        assert!(Arc::ptr_eq(&current_thread.task_group(), &frame_group));
        assert!(rq.update_current(&runtime, current_thread, UpdateFlags::Tick));
    }

    #[ktest]
    fn frame_group_leaf_preempt_stays_within_parent_share() {
        let cpu = CpuId::bsp();
        let root = TaskGroup::new_root(1);
        let low_group =
            TaskGroup::new_frame_child(&root, DEFAULT_CGROUP_WEIGHT, FrameTaskGroupId::new(0, 0));
        let high_group = TaskGroup::new_frame_child(
            &root,
            DEFAULT_CGROUP_WEIGHT * 4,
            FrameTaskGroupId::new(0, 1),
        );
        let low_task = test_thread(low_group);
        let first_high_task = test_thread(high_group.clone());
        let second_high_task = test_thread(high_group.clone());
        let runtime_delta = time::min_period_clocks() * 3 / 4;
        let runtime = CurrentRuntime {
            start: 0,
            delta: runtime_delta,
            period_delta: runtime_delta,
        };

        let mut rq = root.fair_queue(cpu).disable_irq().lock();
        rq.enqueue(low_task, Some(EnqueueFlags::Spawn));
        rq.enqueue(first_high_task, Some(EnqueueFlags::Spawn));
        rq.enqueue(second_high_task, Some(EnqueueFlags::Spawn));
        drop(rq);

        let current = high_group
            .fair_queue(cpu)
            .disable_irq()
            .lock()
            .pick_next()
            .unwrap();
        let current_thread = current.as_thread().unwrap();
        assert!(Arc::ptr_eq(&current_thread.task_group(), &high_group));

        let mut rq = root.fair_queue(cpu).disable_irq().lock();
        assert!(rq.update_current(&runtime, current_thread, UpdateFlags::Tick));
        let next = rq.pick_next().unwrap();
        let next_thread = next.as_thread().unwrap();
        assert!(Arc::ptr_eq(&next_thread.task_group(), &high_group));
    }

    #[ktest]
    fn frame_group_internal_wait_preserves_parent_share() {
        let cpu = CpuId::bsp();
        let root = TaskGroup::new_root(1);
        let low_group =
            TaskGroup::new_frame_child(&root, DEFAULT_CGROUP_WEIGHT, FrameTaskGroupId::new(0, 0));
        let high_group = TaskGroup::new_frame_child(
            &root,
            DEFAULT_CGROUP_WEIGHT * 4,
            FrameTaskGroupId::new(0, 1),
        );
        let low_task = test_thread(low_group);
        let waiting_high_task = test_thread(high_group.clone());
        let runnable_high_task = test_thread(high_group.clone());
        let runtime_delta = time::min_period_clocks() / 8;
        let runtime = CurrentRuntime {
            start: 0,
            delta: runtime_delta,
            period_delta: runtime_delta,
        };

        let mut rq = root.fair_queue(cpu).disable_irq().lock();
        rq.enqueue(low_task, Some(EnqueueFlags::Spawn));
        rq.enqueue(waiting_high_task, Some(EnqueueFlags::Spawn));
        rq.enqueue(runnable_high_task, Some(EnqueueFlags::Spawn));
        drop(rq);

        let current = high_group
            .fair_queue(cpu)
            .disable_irq()
            .lock()
            .pick_next()
            .unwrap();
        let current_thread = current.as_thread().unwrap();
        assert!(Arc::ptr_eq(&current_thread.task_group(), &high_group));

        let mut rq = root.fair_queue(cpu).disable_irq().lock();
        assert!(rq.update_current(&runtime, current_thread, UpdateFlags::Wait));
        let next = rq.pick_next().unwrap();
        let next_thread = next.as_thread().unwrap();
        assert!(Arc::ptr_eq(&next_thread.task_group(), &high_group));
    }
}
