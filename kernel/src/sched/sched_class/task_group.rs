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
        let cpu_count = cpu::num_cpus();
        Arc::new_cyclic(|weak_self| Self {
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
        super::{CurrentRuntime, SchedClassRq, time},
        *,
    };
    use crate::{
        sched::{DEFAULT_CGROUP_WEIGHT, Nice, SchedPolicy},
        thread::{AsThread, kernel_thread::ThreadOptions},
    };

    fn test_thread(task_group: Arc<TaskGroup>) -> Arc<Task> {
        let task = ThreadOptions::new(|| {})
            .sched_policy(SchedPolicy::Fair(Nice::default()))
            .build();
        task.as_thread().unwrap().set_task_group(task_group);
        task
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
}
