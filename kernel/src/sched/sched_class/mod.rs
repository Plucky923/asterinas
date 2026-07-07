// SPDX-License-Identifier: MPL-2.0

//! Completely Fair Scheduler (CFS).

#![warn(unused)]

use alloc::{boxed::Box, sync::Arc};
use core::{fmt, ops::Bound, sync::atomic::Ordering};

use aster_framevisor::vm::{InnerPick, RefreshAction};
use ostd::{
    arch::read_tsc as sched_clock,
    cpu::{CpuId, CpuSet, PinCurrentCpu, all_cpus},
    irq::disable_local,
    smp,
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

mod frame_group;
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

static CLASS_SCHEDULER: spin::Once<&'static ClassScheduler> = spin::Once::new();

#[derive(Clone)]
struct PickedSchedEntity {
    concrete: SchedEntity,
    outer: CurrentOuterEntity,
}

impl PickedSchedEntity {
    fn task(&self) -> &Arc<Task> {
        &self.concrete.0
    }

    fn thread(&self) -> &Arc<Thread> {
        &self.concrete.1
    }
}

#[derive(Clone)]
enum CurrentOuterEntity {
    Task,
    FrameSchedGroup(Arc<frame_group::FrameSchedEntityState>),
}

pub fn init() {
    let scheduler = Box::leak(Box::new(ClassScheduler::new()));
    CLASS_SCHEDULER.call_once(|| scheduler);

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

pub(crate) fn register_frame_sched_group(
    group: Arc<aster_framevisor::FrameSchedGroup>,
    share: u32,
) {
    if let Some(scheduler) = CLASS_SCHEDULER.get().copied() {
        let host_cpu = scheduler.select_frame_sched_group_cpu();
        group.bind_host_cpu(host_cpu);
        enable_framevisor_preemption_on_cpu(host_cpu);
    }
    frame_group::register(group, share);
}

fn enable_framevisor_preemption_on_cpu(cpu: CpuId) {
    let current_cpu = {
        let guard = disable_local();
        guard.current_cpu()
    };
    if current_cpu == cpu {
        aster_framevisor::task::scheduler::enable_preemption_on_cpu();
        return;
    }

    let mut targets = CpuSet::new_empty();
    targets.add(cpu);
    smp::inter_processor_call(
        &targets,
        aster_framevisor::task::scheduler::enable_preemption_on_cpu,
    );
}

pub(crate) fn unregister_frame_sched_groups(vm_id: aster_framevisor::VmId) {
    frame_group::unregister_vm(vm_id);
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
    current: Option<(PickedSchedEntity, CurrentRuntime)>,
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

    /// Removes a queued copy of the task from the run queue.
    fn remove_queued_task(&mut self, task: &Arc<Task>) -> bool;

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
        if task.is_completed() {
            return None;
        }

        let thread = task.as_thread()?.clone();

        if let Some(group) = aster_framevisor::task::frame_sched_group_for_ostd_task(task.as_ref())
        {
            return self.enqueue_frame_sched_group_task(task, thread, group);
        }

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
            return None;
        }

        // Preempt if the new task has a higher priority.
        let (should_preempt, current_can_compete_on_pick) =
            rq.current
                .as_ref()
                .map_or((true, false), |(rq_current_entity, _)| {
                    Self::enqueue_preemption_decision(
                        &task,
                        &thread,
                        rq_current_entity.task(),
                        rq_current_entity.thread(),
                    )
                });
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
        f(&mut *self.rqs[guard.current_cpu().as_usize()].lock());
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

    fn select_frame_sched_group_cpu(&self) -> CpuId {
        let guard = disable_local();
        let current_cpu = guard.current_cpu();
        let mut selected = current_cpu;
        let mut minimum_load = u32::MAX;
        let mut candidates = CpuSet::new_full();

        if ostd::cpu::num_cpus() > 1 {
            candidates.remove(current_cpu);
        }

        let test_candidate = |candidate: CpuId| {
            let PerCpuLoadStats { queue_len, .. } =
                self.rqs[candidate.as_usize()].lock().load_stats();
            if queue_len < minimum_load {
                minimum_load = queue_len;
                selected = candidate;
            }
        };

        match self.last_chosen_cpu.get() {
            Some(cpu) => Self::cycle_after(cpu, &candidates).for_each(test_candidate),
            None => candidates.iter().for_each(test_candidate),
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
            let _ = (new_task, current_task);
        }

        (new_policy < current_policy, false)
    }

    fn enqueue_frame_sched_group_task(
        &self,
        task: Arc<Task>,
        thread: Arc<Thread>,
        group: Arc<aster_framevisor::FrameSchedGroup>,
    ) -> Option<CpuId> {
        let cpu = group.host_cpu();
        let _ = task.cpu().set_if_is_none(cpu);
        thread.sched_attr().set_last_cpu(cpu);

        if group.refresh_action(group.has_runnable_work(), false) != RefreshAction::Enqueue {
            return None;
        }

        let state = frame_group::state_for(&group)
            .expect("live FrameSchedGroup must have scheduler entity state");
        let rq = self.rqs[cpu.as_usize()].lock();
        let should_preempt = rq.current.as_ref().is_none_or(|(current_entity, _)| {
            current_entity.thread().sched_attr().policy_kind() >= SchedPolicyKind::Fair
        });
        rq.fair.lock().enqueue_frame_sched_group(state);
        should_preempt.then_some(cpu)
    }
}

impl PerCpuClassRqSet {
    fn sched_entity_from_task(task: Arc<Task>) -> Option<PickedSchedEntity> {
        if task.is_completed() {
            task.schedule_info().cpu.set_to_none();
            return None;
        }

        let thread = task.as_thread()?.clone();
        Some(PickedSchedEntity {
            concrete: (task, thread),
            outer: CurrentOuterEntity::Task,
        })
    }

    fn pick_next_entity(&mut self) -> Option<PickedSchedEntity> {
        while let Some(task) = self.stop.pick_next() {
            if let Some(entity) = Self::sched_entity_from_task(task) {
                return Some(entity);
            }
        }
        while let Some(task) = self.real_time.pick_next() {
            if let Some(entity) = Self::sched_entity_from_task(task) {
                return Some(entity);
            }
        }
        {
            loop {
                let Some(fair_pick) = self.fair.lock().pick_next_fair() else {
                    break;
                };
                match fair_pick {
                    fair::FairPick::Task(task) => {
                        if let Some(entity) = Self::sched_entity_from_task(task) {
                            return Some(entity);
                        }
                    }
                    fair::FairPick::FrameSchedGroup(state) => {
                        if let Some(task) = state.inflight_task() {
                            if task.is_completed() {
                                state.complete_inflight_task(&task);
                                continue;
                            }
                            let thread = task.as_thread()?.clone();
                            return Some(PickedSchedEntity {
                                concrete: (task, thread),
                                outer: CurrentOuterEntity::FrameSchedGroup(state),
                            });
                        }

                        let Some(group) = state.group() else {
                            continue;
                        };
                        group.mark_picked();
                        let task = match group.try_pick_inner() {
                            InnerPick::Iht(task) | InnerPick::Service(task) => task,
                            InnerPick::NoWork => continue,
                        };
                        if task.is_completed() {
                            continue;
                        }
                        state.set_inflight_task(task.clone());
                        let thread = task.as_thread()?.clone();
                        return Some(PickedSchedEntity {
                            concrete: (task, thread),
                            outer: CurrentOuterEntity::FrameSchedGroup(state),
                        });
                    }
                }
            }
        }
        while let Some(task) = self.idle.pick_next() {
            if let Some(entity) = Self::sched_entity_from_task(task) {
                return Some(entity);
            }
        }
        None
    }

    fn inherited_period_delta(
        previous: Option<&(PickedSchedEntity, CurrentRuntime)>,
        next: &PickedSchedEntity,
    ) -> u64 {
        let Some((previous_entity, previous_runtime)) = previous else {
            return 0;
        };
        match (&previous_entity.outer, &next.outer) {
            (
                CurrentOuterEntity::FrameSchedGroup(previous_state),
                CurrentOuterEntity::FrameSchedGroup(next_state),
            ) if Arc::ptr_eq(previous_state, next_state) => previous_runtime.period_delta,
            _ => 0,
        }
    }

    fn is_same_frame_group(left: &PickedSchedEntity, right: &PickedSchedEntity) -> bool {
        matches!(
            (&left.outer, &right.outer),
            (
                CurrentOuterEntity::FrameSchedGroup(left_state),
                CurrentOuterEntity::FrameSchedGroup(right_state),
            ) if Arc::ptr_eq(left_state, right_state)
        )
    }

    fn picked_actual_current(
        previous: Option<&(PickedSchedEntity, CurrentRuntime)>,
        next: &PickedSchedEntity,
    ) -> bool {
        let Some((previous_entity, _)) = previous else {
            return false;
        };
        if !Arc::ptr_eq(previous_entity.task(), next.task()) {
            return false;
        }
        Task::current()
            .is_some_and(|current| Arc::ptr_eq(&current.cloned(), previous_entity.task()))
    }

    fn has_not_switched_to(entity: &PickedSchedEntity) -> bool {
        Task::current().is_some_and(|current| !Arc::ptr_eq(&current.cloned(), entity.task()))
    }

    fn enqueue_entity(&mut self, (task, thread): SchedEntity, flags: Option<EnqueueFlags>) {
        match thread.sched_attr().policy_kind() {
            SchedPolicyKind::Stop => self.stop.enqueue(task, flags),
            SchedPolicyKind::RealTime => self.real_time.enqueue(task, flags),
            SchedPolicyKind::Fair => self.fair.lock().enqueue(task, flags),
            SchedPolicyKind::Idle => self.idle.enqueue(task, flags),
        }
    }

    fn update_previous_before_competing(
        &mut self,
        previous: &mut (PickedSchedEntity, CurrentRuntime),
    ) {
        let (previous_entity, previous_runtime) = previous;
        let previous_thread = previous_entity.thread();
        previous_runtime.update();

        match &previous_entity.outer {
            CurrentOuterEntity::FrameSchedGroup(state) => {
                let _ = self.fair.lock().update_current_frame_group(
                    state,
                    previous_runtime,
                    UpdateFlags::Tick,
                );
            }
            CurrentOuterEntity::Task => match previous_thread.sched_attr().policy_kind() {
                SchedPolicyKind::Stop => {
                    let _ = self.stop.update_current(
                        previous_runtime,
                        previous_thread,
                        UpdateFlags::Tick,
                    );
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
                    let _ = self.idle.update_current(
                        previous_runtime,
                        previous_thread,
                        UpdateFlags::Tick,
                    );
                }
            },
        }
    }

    fn current_can_compete_on_pick(entity: &PickedSchedEntity) -> bool {
        match &entity.outer {
            CurrentOuterEntity::FrameSchedGroup(_) => {
                aster_framevisor::task::frame_task_kind_for_ostd_task(entity.task())
                    != Some(aster_framevisor::task::FrameTaskKind::Iht)
            }
            CurrentOuterEntity::Task => false,
        }
    }

    fn load_stats(&self) -> PerCpuLoadStats {
        let fair_queue_len = self.fair.lock().total_queued_task_count();
        let queue_len = (self.stop.len() + self.real_time.len() + fair_queue_len) as u32;
        let is_idle = match &self.current {
            Some((entity, _)) => {
                entity.thread().sched_attr().policy_kind() == SchedPolicyKind::Idle
            }
            None => true,
        };
        PerCpuLoadStats { queue_len, is_idle }
    }
}

impl LocalRunQueue for PerCpuClassRqSet {
    fn current(&self) -> Option<&Arc<Task>> {
        self.current.as_ref().map(|(entity, _)| entity.task())
    }

    fn has_runnable(&self) -> bool {
        self.current.is_some()
            || !self.stop.is_empty()
            || !self.real_time.is_empty()
            || !self.fair.lock().is_empty()
            || !self.idle.is_empty()
    }

    fn try_pick_next(&mut self) -> Option<&Arc<Task>> {
        let requested_current_can_compete = self.current_can_compete_on_pick;
        let current_needs_runtime_update = self.current_needs_runtime_update_on_pick;
        let current_runtime_updated_since_pick = self.current_runtime_updated_since_pick;
        self.current_can_compete_on_pick = false;
        self.current_needs_runtime_update_on_pick = false;
        self.current_runtime_updated_since_pick = false;

        let previous = self.current.take();
        if let Some((previous_entity, _)) = &previous
            && Self::has_not_switched_to(previous_entity)
        {
            self.current = previous;
            return self.current.as_ref().map(|(entity, _)| entity.task());
        }
        if let Some((previous_entity, _)) = &previous
            && let CurrentOuterEntity::FrameSchedGroup(state) = &previous_entity.outer
        {
            state.complete_inflight_task(previous_entity.task());
        }

        let mut previous = previous;
        let current_can_compete_on_pick = requested_current_can_compete;
        if current_needs_runtime_update
            && !current_runtime_updated_since_pick
            && let Some(previous) = &mut previous
        {
            self.update_previous_before_competing(previous);
        }
        if current_can_compete_on_pick && let Some((previous_entity, _)) = &previous {
            match &previous_entity.outer {
                CurrentOuterEntity::FrameSchedGroup(state) => {
                    if let Some(group) = state.group()
                        && group.refresh_action(group.has_runnable_work(), false)
                            == RefreshAction::Enqueue
                    {
                        self.fair.lock().enqueue_frame_sched_group(state.clone());
                    }
                }
                CurrentOuterEntity::Task => {
                    self.enqueue_entity(previous_entity.concrete.clone(), None);
                }
            }
        }

        let Some(next) = self.pick_next_entity() else {
            debug_assert!(previous.is_none() || !current_can_compete_on_pick);
            self.current = previous;
            return None;
        };
        let picked_previous = Self::picked_actual_current(previous.as_ref(), &next);
        let period_delta = Self::inherited_period_delta(previous.as_ref(), &next);
        let picked_same_frame_group = previous
            .as_ref()
            .is_some_and(|(previous_entity, _)| Self::is_same_frame_group(previous_entity, &next));

        self.current = Some((next, CurrentRuntime::new_with_period_delta(period_delta)));
        self.current_runtime_updated_since_pick = false;
        if !current_can_compete_on_pick
            && !picked_same_frame_group
            && let Some((old, _)) = previous
        {
            match old.outer {
                CurrentOuterEntity::FrameSchedGroup(state) => {
                    if let Some(group) = state.group()
                        && group.refresh_action(group.has_runnable_work(), false)
                            == RefreshAction::Enqueue
                    {
                        self.fair.lock().enqueue_frame_sched_group(state);
                    }
                }
                CurrentOuterEntity::Task => self.enqueue_entity(old.concrete, None),
            }
        }

        if picked_previous {
            return None;
        }
        self.current.as_ref().map(|(entity, _)| entity.task())
    }

    fn update_current(&mut self, flags: UpdateFlags) -> bool {
        self.current_can_compete_on_pick = false;
        self.current_needs_runtime_update_on_pick = false;
        self.current_runtime_updated_since_pick = false;

        let mut current_can_compete_after_update = false;
        let mut current_frame_group_needs_iht = false;
        let mut current_iht_yields_to_service = false;
        let (should_preempt, mut lookahead) = if let Some((current_entity, rt)) = &mut self.current
        {
            rt.update();
            self.current_runtime_updated_since_pick = true;
            let cur = current_entity.thread();
            let attr = &cur.sched_attr();
            let policy_kind = attr.policy_kind();
            current_can_compete_after_update = Self::current_can_compete_on_pick(current_entity);

            let (should_preempt, lookahead) = match &current_entity.outer {
                CurrentOuterEntity::FrameSchedGroup(state) => {
                    if Task::current().is_some_and(|current| {
                        Arc::ptr_eq(&current.cloned(), current_entity.task())
                    }) {
                        state.complete_inflight_task(current_entity.task());
                    }
                    let should_preempt = self
                        .fair
                        .lock()
                        .update_current_frame_group(state, rt, flags);
                    current_frame_group_needs_iht = state
                        .group()
                        .is_some_and(|group| group.has_deliverable_iht_work());
                    current_iht_yields_to_service = matches!(flags, UpdateFlags::Yield)
                        && aster_framevisor::task::frame_task_kind_for_ostd_task(
                            current_entity.task(),
                        ) == Some(aster_framevisor::task::FrameTaskKind::Iht)
                        && state.group().is_some_and(|group| group.has_service_work());
                    (should_preempt, 2)
                }
                CurrentOuterEntity::Task => match policy_kind {
                    SchedPolicyKind::Stop => (self.stop.update_current(rt, cur, flags), 0),
                    SchedPolicyKind::RealTime => (self.real_time.update_current(rt, cur, flags), 1),
                    SchedPolicyKind::Fair => (self.fair.lock().update_current(rt, cur, flags), 2),
                    SchedPolicyKind::Idle => (self.idle.update_current(rt, cur, flags), 3),
                },
            };
            (should_preempt, lookahead)
        } else {
            (false, 4)
        };

        if matches!(flags, UpdateFlags::Wait | UpdateFlags::Exit) {
            lookahead = 4;
        }

        let should_pick_next = should_preempt
            || current_frame_group_needs_iht
            || current_iht_yields_to_service
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
        let current_task = Task::current()?.cloned();
        let (entity, runtime) = self.current.take()?;
        if !Arc::ptr_eq(entity.task(), &current_task) {
            self.current = Some((entity, runtime));
            return None;
        }

        if let CurrentOuterEntity::FrameSchedGroup(state) = &entity.outer {
            state.complete_inflight_task(entity.task());
        }
        self.remove_queued_task(entity.task());
        let cur_task = entity.concrete.0;
        cur_task.schedule_info().cpu.set_to_none();
        Some(cur_task)
    }
}

impl PerCpuClassRqSet {
    fn remove_queued_task(&mut self, task: &Arc<Task>) {
        let _ = self.stop.remove_queued_task(task);
        let _ = self.real_time.remove_queued_task(task);
        let _ = self.fair.lock().remove_queued_task(task);
        let _ = self.idle.remove_queued_task(task);
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
