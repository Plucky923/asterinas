// SPDX-License-Identifier: MPL-2.0

//! Completely Fair Scheduler (CFS).

#![warn(unused)]

use alloc::{boxed::Box, sync::Arc};
use core::{fmt, ops::Bound, sync::atomic::Ordering};

use ostd::{
    arch::read_tsc as sched_clock,
    cpu::{CpuId, CpuSet, PinCurrentCpu, all_cpus},
    irq::disable_local,
    sync::{LocalIrqDisabled, SpinLock},
    task::{
        AtomicCpuId, Task,
        scheduler::{
            EnqueueFlags, LocalRunQueue, Scheduler, UpdateFlags, enable_preemption_on_cpu,
            info::CommonSchedInfo, inject_scheduler,
        },
    },
    util::id_set::Id,
};

use super::{
    nice::Nice,
    stats::{SchedulerStats, set_stats_from_scheduler},
};
use crate::thread::{AsThread, Thread};

mod policy;
mod task_group;
mod time;

pub(crate) mod fair;
mod idle;
mod real_time;
mod stop;

pub(crate) use self::{
    fair::DEFAULT_CGROUP_WEIGHT,
    task_group::{TaskGroup, root_task_group},
};
pub use self::{
    policy::{LinuxSchedPolicy, SchedPolicy},
    real_time::{RealTimePolicy, RealTimePriority},
};
use self::{
    policy::{SchedPolicyKind, SchedPolicyState},
    task_group::init_root_task_group,
};

type SchedEntity = (Arc<Task>, Arc<Thread>);

pub fn init() {
    let scheduler = Box::leak(Box::new(ClassScheduler::new()));

    // Inject the scheduler into the ostd for actual scheduling work.
    inject_scheduler(scheduler);

    // Set the scheduler into the system for statistics.
    // We set this after injecting the scheduler into ostd,
    // so that the loadavg statistics are updated after the scheduler is used.
    set_stats_from_scheduler(scheduler);
}

pub fn init_on_each_cpu() {
    enable_preemption_on_cpu();
}

/// Represents the middle layer between scheduling classes and generic scheduler
/// traits. It consists of all the sets of run queues for CPU cores. Other global
/// information may also be stored here.
pub struct ClassScheduler {
    /// The per-CPU runqueues.
    ///
    /// We use the `LocalIrqDisabled` marker for this spinlock to ensure local IRQs are always disabled,
    /// preventing potential deadlocks due to the fact that
    /// the runqueues may be accessed in both the task and interrupt context (L1 and L2).
    rqs: Box<[SpinLock<PerCpuClassRqSet, LocalIrqDisabled>]>,
    last_chosen_cpu: AtomicCpuId,
}

/// Represents the run queue for each CPU core. It stores a list of run queues for
/// scheduling classes in its corresponding CPU core. The current task of this CPU
/// core is also stored in this structure.
struct PerCpuClassRqSet {
    stop: stop::StopClassRq,
    real_time: real_time::RealTimeClassRq,
    fair: Arc<SpinLock<fair::FairClassRq>>,
    idle: idle::IdleClassRq,
    current: Option<(SchedEntity, CurrentRuntime)>,
    current_can_compete_on_pick: bool,
    current_needs_runtime_update_on_pick: bool,
    current_runtime_updated_since_pick: bool,
}

/// Stores the runtime information of the current task.
///
/// This is used to calculate the time slice of the current task.
///
/// This struct is independent of the current `Arc<Task>` instead encapsulating the
/// task, because the scheduling class implementations use `CurrentRuntime` and
/// `SchedAttr` only.
struct CurrentRuntime {
    start: u64,
    delta: u64,
    period_delta: u64,
}

impl CurrentRuntime {
    fn new_with_period_delta(period_delta: u64) -> Self {
        CurrentRuntime {
            start: sched_clock(),
            delta: 0,
            period_delta,
        }
    }

    fn update(&mut self) {
        let now = sched_clock();
        self.delta = now - core::mem::replace(&mut self.start, now);
        self.period_delta += self.delta;
    }
}

/// The run queue for scheduling classes (the main trait). Scheduling classes
/// should implement this trait to function as expected.
trait SchedClassRq: Send + fmt::Debug {
    /// Enqueues a task into the run queue.
    fn enqueue(&mut self, task: Arc<Task>, flags: Option<EnqueueFlags>);

    /// Returns the number of threads in the run queue.
    fn len(&self) -> usize;

    /// Checks if the run queue is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Picks the next task for running.
    fn pick_next(&mut self) -> Option<Arc<Task>>;

    /// Update the information of the current task.
    ///
    /// The return value of this method indicates whether there is another task
    /// **in this run queue** to replace the current one.
    fn update_current(&mut self, rt: &CurrentRuntime, thread: &Thread, flags: UpdateFlags) -> bool;
}

/// The scheduling attribute for a thread.
///
/// This is used to store the scheduling policy and runtime parameters for each
/// scheduling class.
#[derive(Debug)]
pub struct SchedAttr {
    policy: SchedPolicyState,
    last_cpu: AtomicCpuId,
    real_time: real_time::RealTimeAttr,
    fair: fair::FairAttr,
}

impl SchedAttr {
    /// Constructs a new `SchedAttr` with the given scheduling policy.
    pub fn new(policy: SchedPolicy) -> Self {
        Self {
            policy: SchedPolicyState::new(policy),
            last_cpu: AtomicCpuId::default(),
            real_time: {
                let (prio, policy) = match policy {
                    SchedPolicy::RealTime { rt_prio, rt_policy } => (rt_prio.get(), rt_policy),
                    _ => (RealTimePriority::MAX.get(), Default::default()),
                };
                real_time::RealTimeAttr::new(prio, policy)
            },
            fair: fair::FairAttr::new(match policy {
                SchedPolicy::Fair(nice) => nice,
                _ => Nice::default(),
            }),
        }
    }

    /// Retrieves the current scheduling policy of the thread.
    pub fn policy(&self) -> SchedPolicy {
        self.policy.get()
    }

    fn policy_kind(&self) -> SchedPolicyKind {
        self.policy.kind()
    }

    /// Updates the scheduling policy of the thread.
    ///
    /// Specifically for real-time policies, if the new policy doesn't
    /// specify a base slice factor for RR, the old one will be kept.
    pub fn set_policy(&self, policy: SchedPolicy) {
        self.policy.set(policy, |policy| match policy {
            SchedPolicy::RealTime { rt_prio, rt_policy } => {
                self.real_time.update(rt_prio.get(), rt_policy);
            }
            SchedPolicy::Fair(nice) => self.fair.update(nice),
            _ => {}
        });
    }

    pub fn update_policy<T>(&self, f: impl FnOnce(&mut SchedPolicy) -> T) -> T {
        self.policy.update(|policy| {
            let ret = f(policy);
            match *policy {
                SchedPolicy::RealTime { rt_prio, rt_policy } => {
                    self.real_time.update(rt_prio.get(), rt_policy);
                }
                SchedPolicy::Fair(nice) => self.fair.update(nice),
                _ => {}
            }
            ret
        })
    }

    pub fn last_cpu(&self) -> Option<CpuId> {
        self.last_cpu.get()
    }

    fn set_last_cpu(&self, cpu_id: CpuId) {
        self.last_cpu.set_anyway(cpu_id);
    }
}

impl Scheduler for ClassScheduler {
    fn enqueue(&self, task: Arc<Task>, flags: EnqueueFlags) -> Option<CpuId> {
        let thread = task.as_thread()?.clone();

        let (still_in_rq, cpu) = {
            let selected_cpu_id = self.select_cpu(&thread, flags);

            if let Err(task_cpu_id) = task.cpu().set_if_is_none(selected_cpu_id) {
                debug_assert!(flags != EnqueueFlags::Spawn);
                (true, task_cpu_id)
            } else {
                (false, selected_cpu_id)
            }
        };

        let mut rq = self.rqs[cpu.as_usize()].lock();

        // Note: call set_if_is_none again to prevent a race condition.
        if still_in_rq && task.cpu().set_if_is_none(cpu).is_err() {
            let is_current = rq
                .current
                .as_ref()
                .is_some_and(|((current_task, _), _)| Arc::ptr_eq(current_task, &task));
            if is_current || !thread.task_group().is_frame_entity() {
                return None;
            }
        }

        // Preempt if the new task has a higher priority.
        let (should_preempt, current_can_compete_on_pick) = rq.current.as_ref().map_or(
            (true, false),
            |((rq_current_task, rq_current_thread), _)| {
                Self::enqueue_preemption_decision(
                    &task,
                    &thread,
                    rq_current_task,
                    rq_current_thread,
                )
            },
        );
        if current_can_compete_on_pick {
            rq.current_can_compete_on_pick = true;
            rq.current_needs_runtime_update_on_pick = true;
        }

        thread.sched_attr().set_last_cpu(cpu);
        rq.enqueue_entity((task, thread), Some(flags));

        should_preempt.then_some(cpu)
    }

    fn mut_local_rq_with(&self, f: &mut dyn FnMut(&mut dyn LocalRunQueue)) {
        let guard = disable_local();
        let mut lock = self.rqs[guard.current_cpu().as_usize()].lock();
        f(&mut *lock)
    }

    fn local_rq_with(&self, f: &mut dyn FnMut(&dyn LocalRunQueue)) {
        let guard = disable_local();
        f(&*self.rqs[guard.current_cpu().as_usize()].lock())
    }
}

impl ClassScheduler {
    pub fn new() -> Self {
        let root_task_group = init_root_task_group(ostd::cpu::num_cpus());
        let class_rq = |cpu| {
            SpinLock::new(PerCpuClassRqSet {
                stop: stop::StopClassRq::new(),
                real_time: real_time::RealTimeClassRq::new(cpu),
                fair: root_task_group.fair_queue(cpu).clone(),
                idle: idle::IdleClassRq::new(),
                current: None,
                current_can_compete_on_pick: false,
                current_needs_runtime_update_on_pick: false,
                current_runtime_updated_since_pick: false,
            })
        };
        ClassScheduler {
            rqs: all_cpus().map(class_rq).collect(),
            last_chosen_cpu: AtomicCpuId::default(),
        }
    }

    // TODO: Implement a better algorithm and replace the current naive implementation.
    fn select_cpu(&self, thread: &Thread, flags: EnqueueFlags) -> CpuId {
        let affinity = thread.atomic_cpu_affinity().load(Ordering::Relaxed);
        let last_cpu = thread.sched_attr().last_cpu();
        if let Some(last_cpu) = last_cpu
            && affinity.contains(last_cpu)
        {
            return last_cpu;
        }
        debug_assert!(flags == EnqueueFlags::Spawn || last_cpu.is_some());

        let guard = disable_local();

        let mut selected = guard.current_cpu();
        let mut minimum_load = u32::MAX;

        // Set `selected` as `candidate` if the candidate's load is smaller.
        let test_candidate = |candidate: CpuId| {
            let PerCpuLoadStats { queue_len, .. } =
                self.rqs[candidate.as_usize()].lock().load_stats();
            let load = queue_len;
            if load < minimum_load {
                minimum_load = load;
                selected = candidate;
            }
        };

        match self.last_chosen_cpu.get() {
            Some(cpu) => {
                // Perform a round-robin selection starting after the last chosen CPU.
                //
                // It still checks every CPU in the affinity set to find the one with the
                // minimum load, but avoids selecting the same CPU again in case of a tie.
                Self::cycle_after(cpu, &affinity).for_each(test_candidate)
            }
            None => affinity.iter().for_each(test_candidate),
        }

        self.last_chosen_cpu.set_anyway(selected);
        selected
    }

    /// Returns a cycling iterator over the CPUs in the [`CpuSet`], starting *after*
    /// the given [`CpuId`].
    ///
    /// The iteration order is ascending up to the wrapping point, after which it
    /// continues from the first CPU in the set in ascending order again.
    ///
    /// If the given [`CpuId`] is in the set, it will be the last element yielded.
    fn cycle_after(cpu: CpuId, cpu_set: &CpuSet) -> impl Iterator<Item = CpuId> + '_ {
        cpu_set
            .iter_in((Bound::Excluded(cpu), Bound::Unbounded))
            .chain(cpu_set.iter_in(..=cpu))
    }

    fn enqueue_preemption_decision(
        new_task: &Arc<Task>,
        new_thread: &Thread,
        current_task: &Arc<Task>,
        current_thread: &Thread,
    ) -> (bool, bool) {
        let new_policy = new_thread.sched_attr().policy();
        let current_policy = current_thread.sched_attr().policy();
        if new_policy.kind() == SchedPolicyKind::Fair
            && current_policy.kind() == SchedPolicyKind::Fair
        {
            let new_task_group = new_thread.task_group();
            let current_task_group = current_thread.task_group();
            if new_task_group.is_frame_entity() || current_task_group.is_frame_entity() {
                if !Arc::ptr_eq(&new_task_group, &current_task_group) {
                    return (false, false);
                }

                let Some(task_group_id) = new_task_group.frame_task_group_id() else {
                    return (new_policy < current_policy, false);
                };
                let new_is_iht = crate::thread::framevm_task::is_iht_task_for_frame_task_group(
                    new_task,
                    task_group_id,
                );
                let current_is_iht = crate::thread::framevm_task::is_iht_task_for_frame_task_group(
                    current_task,
                    task_group_id,
                );
                if new_is_iht && !current_is_iht {
                    return (true, true);
                }

                return (new_policy < current_policy, false);
            }
        }

        (new_policy < current_policy, false)
    }
}

impl PerCpuClassRqSet {
    fn sched_entity_from_task(task: Arc<Task>) -> Option<SchedEntity> {
        let thread = task.as_thread()?.clone();
        Some((task, thread))
    }

    fn pick_next_entity(&mut self) -> Option<SchedEntity> {
        if let Some(task) = self.stop.pick_next() {
            return Self::sched_entity_from_task(task);
        }
        if let Some(task) = self.real_time.pick_next() {
            return Self::sched_entity_from_task(task);
        }
        if let Some(task) = self.fair.lock().pick_next() {
            return Self::sched_entity_from_task(task);
        }
        self.idle.pick_next().and_then(Self::sched_entity_from_task)
    }

    fn inherited_period_delta(
        previous: Option<&(SchedEntity, CurrentRuntime)>,
        next: &SchedEntity,
    ) -> u64 {
        let Some(((_, previous_thread), previous_runtime)) = previous else {
            return 0;
        };
        let previous_task_group = previous_thread.task_group();
        let next_task_group = next.1.task_group();
        if previous_task_group.is_frame_entity()
            && Arc::ptr_eq(&previous_task_group, &next_task_group)
        {
            previous_runtime.period_delta
        } else {
            0
        }
    }

    fn enqueue_entity(&mut self, (task, thread): SchedEntity, flags: Option<EnqueueFlags>) {
        match thread.sched_attr().policy_kind() {
            SchedPolicyKind::Stop => self.stop.enqueue(task, flags),
            SchedPolicyKind::RealTime => self.real_time.enqueue(task, flags),
            SchedPolicyKind::Fair => self.fair.lock().enqueue(task, flags),
            SchedPolicyKind::Idle => self.idle.enqueue(task, flags),
        }
    }

    fn update_previous_before_competing(&mut self, previous: &mut (SchedEntity, CurrentRuntime)) {
        let ((_, previous_thread), previous_runtime) = previous;
        previous_runtime.update();

        match previous_thread.sched_attr().policy_kind() {
            SchedPolicyKind::Stop => {
                let _ =
                    self.stop
                        .update_current(previous_runtime, previous_thread, UpdateFlags::Tick);
            }
            SchedPolicyKind::RealTime => {
                let _ = self.real_time.update_current(
                    previous_runtime,
                    previous_thread,
                    UpdateFlags::Tick,
                );
            }
            SchedPolicyKind::Fair => {
                let _ = self.fair.lock().update_current(
                    previous_runtime,
                    previous_thread,
                    UpdateFlags::Tick,
                );
            }
            SchedPolicyKind::Idle => {
                let _ =
                    self.idle
                        .update_current(previous_runtime, previous_thread, UpdateFlags::Tick);
            }
        }
    }

    fn frame_current_can_compete_on_pick(task: &Arc<Task>, thread: &Thread) -> bool {
        let task_group = thread.task_group();
        let Some(task_group_id) = task_group.frame_task_group_id() else {
            return false;
        };

        !crate::thread::framevm_task::is_iht_task_for_frame_task_group(task, task_group_id)
    }

    fn load_stats(&self) -> PerCpuLoadStats {
        let fair_queue_len = self.fair.lock().total_queued_task_count();
        let queue_len = (self.stop.len() + self.real_time.len() + fair_queue_len) as u32;
        let is_idle = match &self.current {
            Some(((_, thread), _)) => thread.sched_attr().policy_kind() == SchedPolicyKind::Idle,
            None => true,
        };
        PerCpuLoadStats { queue_len, is_idle }
    }
}

impl LocalRunQueue for PerCpuClassRqSet {
    fn current(&self) -> Option<&Arc<Task>> {
        self.current.as_ref().map(|((task, _), _)| task)
    }

    fn try_pick_next(&mut self) -> Option<&Arc<Task>> {
        let requested_current_can_compete = self.current_can_compete_on_pick;
        let current_needs_runtime_update = self.current_needs_runtime_update_on_pick;
        let current_runtime_updated_since_pick = self.current_runtime_updated_since_pick;
        self.current_can_compete_on_pick = false;
        self.current_needs_runtime_update_on_pick = false;
        self.current_runtime_updated_since_pick = false;

        let mut previous = self.current.take();
        let current_can_compete_on_pick = requested_current_can_compete;
        let previous_frame_task_group_id = previous.as_ref().and_then(|((_, thread), _)| {
            thread
                .task_group()
                .is_frame_entity()
                .then(|| thread.task_group().frame_task_group_id())
                .flatten()
        });
        if current_needs_runtime_update
            && !current_runtime_updated_since_pick
            && let Some(previous) = &mut previous
        {
            self.update_previous_before_competing(previous);
        }
        if current_can_compete_on_pick && let Some((previous_entity, _)) = &previous {
            let previous_task_group = previous_entity.1.task_group();
            if previous_task_group.is_frame_entity() {
                self.fair
                    .lock()
                    .ensure_group_entity_queued(&previous_task_group);
            } else {
                self.enqueue_entity(previous_entity.clone(), None);
            }
            if let Some(task_group_id) = previous_frame_task_group_id {
                crate::thread::framevm_task::record_frame_task_group_current_compete(
                    task_group_id,
                    true,
                );
            }
        } else if let Some(task_group_id) = previous_frame_task_group_id {
            crate::thread::framevm_task::record_frame_task_group_current_compete(
                task_group_id,
                false,
            );
        }

        let Some(next) = self.pick_next_entity() else {
            debug_assert!(previous.is_none() || !current_can_compete_on_pick);
            self.current = previous;
            return None;
        };
        let picked_previous = previous
            .as_ref()
            .is_some_and(|((previous_task, _), _)| Arc::ptr_eq(previous_task, &next.0));
        let period_delta = Self::inherited_period_delta(previous.as_ref(), &next);

        self.current = Some((next, CurrentRuntime::new_with_period_delta(period_delta)));
        self.current_runtime_updated_since_pick = false;
        if !current_can_compete_on_pick && let Some((old, _)) = previous {
            self.enqueue_entity(old, None);
        }

        if picked_previous {
            return None;
        }
        self.current.as_ref().map(|((task, _), _)| task)
    }

    fn update_current(&mut self, flags: UpdateFlags) -> bool {
        self.current_can_compete_on_pick = false;
        self.current_needs_runtime_update_on_pick = false;
        self.current_runtime_updated_since_pick = false;

        let mut current_can_compete_after_update = false;
        let mut current_frame_task_group_id = None;
        let (should_preempt, mut lookahead) =
            if let Some(((current_task, cur), rt)) = &mut self.current {
                rt.update();
                self.current_runtime_updated_since_pick = true;
                let attr = &cur.sched_attr();
                let policy_kind = attr.policy_kind();
                current_frame_task_group_id = cur.task_group().frame_task_group_id();
                current_can_compete_after_update =
                    Self::frame_current_can_compete_on_pick(current_task, cur);

                let (should_preempt, lookahead) = match policy_kind {
                    SchedPolicyKind::Stop => (self.stop.update_current(rt, cur, flags), 0),
                    SchedPolicyKind::RealTime => (self.real_time.update_current(rt, cur, flags), 1),
                    SchedPolicyKind::Fair => (self.fair.lock().update_current(rt, cur, flags), 2),
                    SchedPolicyKind::Idle => (self.idle.update_current(rt, cur, flags), 3),
                };
                (should_preempt, lookahead)
            } else {
                (false, 4)
            };

        if matches!(flags, UpdateFlags::Wait | UpdateFlags::Exit) {
            lookahead = 4;
        }

        let frame_group_needs_iht = current_frame_task_group_id
            .is_some_and(crate::thread::framevm_task::frame_task_group_should_run_iht);
        let should_pick_next = should_preempt
            || frame_group_needs_iht
            || (lookahead >= 1 && !self.stop.is_empty())
            || (lookahead >= 2 && !self.real_time.is_empty())
            || (lookahead >= 3 && !self.fair.lock().is_empty())
            || (lookahead >= 4 && !self.idle.is_empty());
        self.current_can_compete_on_pick = false;
        self.current_needs_runtime_update_on_pick = false;
        if should_pick_next
            && matches!(flags, UpdateFlags::Tick)
            && current_can_compete_after_update
        {
            self.current_can_compete_on_pick = true;
        }
        should_pick_next
    }

    fn dequeue_current(&mut self) -> Option<Arc<Task>> {
        self.current.take().map(|((cur_task, _), _)| {
            if let Some(thread) = cur_task.as_thread() {
                let task_group = thread.task_group();
                if task_group.frame_task_group_id().is_some() {
                    let mut fair = self.fair.lock();
                    fair.ensure_group_entity_queued(&task_group);
                    fair.dequeue_group_entity_if_empty(&task_group);
                }
            }
            cur_task.schedule_info().cpu.set_to_none();
            cur_task
        })
    }
}

/// Holds per-CPU load information.
struct PerCpuLoadStats {
    /// The length of the run queue (excluding the idle task).
    queue_len: u32,
    /// If the CPU is currently idle.
    ///
    /// A CPU is said to be idle when it is running the idle task, or it is not
    /// running any task at all. The latter case is very unlikely to happen
    /// (almost a bug if it happens) as the idle task should always be runnable.
    is_idle: bool,
}

impl SchedulerStats for ClassScheduler {
    fn nr_queued_and_running(&self) -> (u32, u32) {
        let mut queued = 0u32;
        let mut running = 0u32;
        for rq in self.rqs.iter() {
            let rq = rq.lock();
            let load_stats = rq.load_stats();
            queued += load_stats.queue_len;
            if !load_stats.is_idle {
                running += 1;
            }
        }
        (queued, running)
    }
}

impl Default for ClassScheduler {
    fn default() -> Self {
        Self::new()
    }
}
