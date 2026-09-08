// SPDX-License-Identifier: MPL-2.0

//! Completely Fair Scheduler (CFS).

#![warn(unused)]

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use core::{fmt, ops::Bound, sync::atomic::Ordering};

use aster_framevisor::FrameVcpuId;
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
    policy::{LinuxSchedPolicy, SchedPolicy},
    real_time::{RealTimePolicy, RealTimePriority},
    task_group::{TaskGroup, root_task_group},
};
use self::{
    policy::{SchedPolicyKind, SchedPolicyState},
    task_group::init_root_task_group,
};

type SchedEntity = (Arc<Task>, Arc<Thread>);

static CLASS_SCHEDULER: spin::Once<&'static ClassScheduler> = spin::Once::new();
// The scheduler-owned FrameVM state map serializes registration, placement,
// admission, and removal. Placement paths acquire it before a per-CPU
// runqueue; ordinary picks use the `Arc<FrameSchedEntityState>` already held
// by a queue entry or `current` and never need the map. Placement paths do not
// yield or request remote preemption while the map and Host runqueue locks are
// held. A bootstrap handoff is resolved from the map before
// `mut_local_rq_with` locks the queue and retained only until the next pick.
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

pub(crate) fn init() {
    let scheduler = Box::leak(Box::new(ClassScheduler::new()));
    CLASS_SCHEDULER.call_once(|| scheduler);

    // Inject the scheduler into the ostd for actual scheduling work.
    inject_scheduler(scheduler);

    // Set the scheduler into the system for statistics.
    // We set this after injecting the scheduler into ostd,
    // so that the loadavg statistics are updated after the scheduler is used.
    set_stats_from_scheduler(scheduler);
}

pub(crate) fn init_on_each_cpu() {
    enable_preemption_on_cpu();
}

pub(crate) fn register_frame_sched_group(
    group: Arc<aster_framevisor::FrameSchedGroup>,
    task_group: Arc<TaskGroup>,
    cpu_affinity: &CpuSet,
) {
    if let Some(scheduler) = CLASS_SCHEDULER.get().copied() {
        scheduler.register_frame_sched_group(group, task_group, cpu_affinity);
    }
}

/// Applies a live CPU placement constraint to every vCPU of `vm_id`.
pub(crate) fn update_framevm_cpu_affinity(vm_id: aster_framevisor::VmId, cpu_affinity: &CpuSet) {
    let Some(scheduler) = CLASS_SCHEDULER.get().copied() else {
        return;
    };

    scheduler.update_framevm_cpu_affinity(vm_id, cpu_affinity);
}

/// Creates the scheduler-only task group that contains one FrameVM.
pub(crate) fn create_framevm_task_group(parent: &Arc<TaskGroup>, share: u32) -> Arc<TaskGroup> {
    let weight =
        share.saturating_mul(DEFAULT_CGROUP_WEIGHT) / aster_framevisor::DEFAULT_FRAMEVM_SHARE;
    TaskGroup::new_child(parent, weight.max(1))
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
    if let Some(scheduler) = CLASS_SCHEDULER.get().copied() {
        scheduler.unregister_frame_sched_groups(vm_id);
    }
}

/// Commits the concrete continuation of the current opaque FrameSchedGroup
/// after OSTD's processor has physically arrived on `carrier`.
///
/// The Host local runqueue lock is acquired before the group's continuation
/// slot. This is the sole place that transfers Host CPU metadata and replaces
/// the concrete half of `(outer group, concrete carrier)`; outer accounting
/// and runtime state remain untouched.
pub(crate) fn classify_framevm_continuation_arrival(
    carrier: &Arc<Task>,
    state: &Arc<aster_framevisor::task::FrameTaskState>,
) -> FrameContinuationArrival {
    let guard = disable_local();
    let cpu = guard.current_cpu();
    let Some(scheduler) = CLASS_SCHEDULER.get().copied() else {
        panic!("a Frame continuation arrived before the Host scheduler initialized");
    };
    scheduler.rqs[cpu.as_usize()]
        .lock()
        .classify_framevm_continuation_arrival(carrier, state, cpu)
}

/// The only two valid arrivals on a FrameSchedGroup outer current pair.
pub(crate) enum FrameContinuationArrival {
    /// Host policy resumed the already-committed continuation unchanged.
    OuterResume,
    /// The exact staged inner A -> B processor handoff has committed.
    Committed,
}

/// Re-enqueues a Host task after a scheduler-owned resource update.
///
/// This is intentionally a kernel scheduler command instead of an OSTD task
/// method: OSTD's public task API has no raw wake operation.
pub(crate) fn wake_task(task: Arc<Task>) {
    let Some(scheduler) = CLASS_SCHEDULER.get().copied() else {
        return;
    };
    if let Some(cpu) = scheduler.enqueue(task, EnqueueFlags::Wake) {
        ostd::task::__private::request_preemption_on_cpu(cpu);
    }
}

/// Represents the middle layer between scheduling classes and generic scheduler
/// traits. It consists of all the sets of run queues for CPU cores. Other global
/// information may also be stored here.
pub(crate) struct ClassScheduler {
    /// The per-CPU runqueues.
    ///
    /// We use the `LocalIrqDisabled` marker for this spinlock to ensure local IRQs are always disabled,
    /// preventing potential deadlocks due to the fact that
    /// the runqueues may be accessed in both the task and interrupt context (L1 and L2).
    rqs: Box<[SpinLock<PerCpuClassRqSet, LocalIrqDisabled>]>,
    /// Serializes FrameVM placement state while disabling local Host IRQs.
    ///
    /// Host wake and affinity paths can enter from interrupt context. The
    /// state map therefore uses the same IRQ-disabled guard as a runqueue;
    /// placement code always acquires this map before the destination
    /// runqueue.
    frame_group_states:
        SpinLock<BTreeMap<FrameVcpuId, Arc<frame_group::FrameSchedEntityState>>, LocalIrqDisabled>,
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
pub(crate) struct SchedAttr {
    policy: SchedPolicyState,
    last_cpu: AtomicCpuId,
    real_time: real_time::RealTimeAttr,
    fair: fair::FairAttr,
}

impl SchedAttr {
    /// Constructs a new `SchedAttr` with the given scheduling policy.
    pub(crate) fn new(policy: SchedPolicy) -> Self {
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
    pub(crate) fn policy(&self) -> SchedPolicy {
        self.policy.get()
    }

    fn policy_kind(&self) -> SchedPolicyKind {
        self.policy.kind()
    }

    /// Updates the scheduling policy of the thread.
    ///
    /// Specifically for real-time policies, if the new policy doesn't
    /// specify a base slice factor for RR, the old one will be kept.
    pub(crate) fn set_policy(&self, policy: SchedPolicy) {
        self.policy.set(policy, |policy| match policy {
            SchedPolicy::RealTime { rt_prio, rt_policy } => {
                self.real_time.update(rt_prio.get(), rt_policy);
            }
            SchedPolicy::Fair(nice) => self.fair.update(nice),
            _ => {}
        });
    }

    pub(crate) fn update_policy<T>(&self, f: impl FnOnce(&mut SchedPolicy) -> T) -> T {
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

    pub(crate) fn last_cpu(&self) -> Option<CpuId> {
        self.last_cpu.get()
    }

    fn set_last_cpu(&self, cpu_id: CpuId) {
        self.last_cpu.set_anyway(cpu_id);
    }
}

impl Scheduler for ClassScheduler {
    fn enqueue(&self, task: Arc<Task>, flags: EnqueueFlags) -> Option<CpuId> {
        let thread = task.as_thread()?.clone();

        let frame_task_state = thread.framevm_task_state().cloned();
        if let Some(frame_task_state) = frame_task_state
            && let Some(group) = frame_task_state.group()
        {
            return self.enqueue_frame_sched_group_task(task, thread, group, flags);
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
        let should_preempt = rq.current.as_ref().is_none_or(|(current_entity, _)| {
            thread.sched_attr().policy() < current_entity.thread().sched_attr().policy()
        });

        thread.sched_attr().set_last_cpu(cpu);
        rq.enqueue_entity((task, thread), Some(flags));

        should_preempt.then_some(cpu)
    }

    fn mut_local_rq_with(&self, f: &mut dyn FnMut(&mut dyn LocalRunQueue)) {
        let guard = disable_local();
        let mut rq = self.rqs[guard.current_cpu().as_usize()].lock();
        f(&mut *rq);
    }

    fn local_rq_with(&self, f: &mut dyn FnMut(&dyn LocalRunQueue)) {
        let guard = disable_local();
        f(&*self.rqs[guard.current_cpu().as_usize()].lock())
    }
}

impl ClassScheduler {
    pub(crate) fn new() -> Self {
        let root_task_group = init_root_task_group(ostd::cpu::num_cpus());
        let class_rq = |cpu| {
            SpinLock::new(PerCpuClassRqSet {
                stop: stop::StopClassRq::new(),
                real_time: real_time::RealTimeClassRq::new(cpu),
                fair: root_task_group.fair_queue(cpu).clone(),
                idle: idle::IdleClassRq::new(),
                current: None,
                current_can_compete_on_pick: false,
            })
        };
        ClassScheduler {
            rqs: all_cpus().map(class_rq).collect(),
            frame_group_states: SpinLock::new(BTreeMap::new()),
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

    fn select_frame_sched_group_cpu(
        &self,
        cpu_affinity: &CpuSet,
        states: &BTreeMap<FrameVcpuId, Arc<frame_group::FrameSchedEntityState>>,
    ) -> Option<CpuId> {
        if cpu_affinity.is_empty() {
            return None;
        }

        let guard = disable_local();
        let current_cpu = guard.current_cpu();
        let mut selected = None;
        let mut minimum_load = u32::MAX;
        let minimum_assignment_count = cpu_affinity
            .iter()
            .map(|cpu| self.frame_group_assignment_count(states, cpu))
            .min()?;
        let avoid_current_cpu = cpu_affinity.iter().any(|candidate| {
            candidate != current_cpu
                && self.frame_group_assignment_count(states, candidate) == minimum_assignment_count
        });

        let test_candidate = |candidate: CpuId| {
            if self.frame_group_assignment_count(states, candidate) != minimum_assignment_count
                || (avoid_current_cpu && candidate == current_cpu)
            {
                return;
            }
            let PerCpuLoadStats { queue_len, .. } =
                self.rqs[candidate.as_usize()].lock().load_stats();
            if queue_len < minimum_load {
                minimum_load = queue_len;
                selected = Some(candidate);
            }
        };

        match self.last_chosen_cpu.get() {
            Some(cpu) => Self::cycle_after(cpu, cpu_affinity).for_each(test_candidate),
            None => cpu_affinity.iter().for_each(test_candidate),
        }

        if let Some(selected) = selected {
            self.last_chosen_cpu.set_anyway(selected);
        }
        selected
    }

    fn frame_group_assignment_count(
        &self,
        states: &BTreeMap<FrameVcpuId, Arc<frame_group::FrameSchedEntityState>>,
        cpu: CpuId,
    ) -> usize {
        states
            .values()
            .filter(|state| state.is_admitted())
            .filter(|state| state.group().is_some_and(|group| group.host_cpu() == cpu))
            .count()
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

    fn register_frame_sched_group(
        &self,
        group: Arc<aster_framevisor::FrameSchedGroup>,
        task_group: Arc<TaskGroup>,
        cpu_affinity: &CpuSet,
    ) {
        let registered = self.frame_group_states.lock().clone();
        let host_cpu = self.select_frame_sched_group_cpu(cpu_affinity, &registered);
        let host_cpu = {
            let mut states = self.frame_group_states.lock();
            if states.contains_key(&group.id()) {
                debug_assert!(
                    !states.contains_key(&group.id()),
                    "FrameVM vCPU scheduling group registered twice"
                );
                return;
            }
            if let Some(host_cpu) = host_cpu {
                group.bind_host_cpu(host_cpu);
            }
            let state = Arc::new(frame_group::FrameSchedEntityState::new(
                &group,
                task_group,
                cpu_affinity.clone(),
            ));
            states.insert(group.id(), state);
            host_cpu
        };
        if let Some(host_cpu) = host_cpu {
            enable_framevisor_preemption_on_cpu(host_cpu);
        }
    }

    fn enqueue_frame_sched_group_task(
        &self,
        task: Arc<Task>,
        thread: Arc<Thread>,
        group: Arc<aster_framevisor::FrameSchedGroup>,
        _flags: EnqueueFlags,
    ) -> Option<CpuId> {
        let state = {
            let states = self.frame_group_states.lock();
            states.get(&group.id())?.clone()
        };
        if state
            .group()
            .is_none_or(|live_group| !Arc::ptr_eq(&live_group, &group))
        {
            return None;
        }
        let cpu = group.host_cpu();
        if !state.allows_host_cpu(cpu) {
            return None;
        }
        // The FrameVM runqueue must be inspected without either Host scheduler
        // lock or the FrameVM state-map lock. Virtual interrupt delivery and
        // Host wakeups can otherwise acquire these locks in the opposite order.
        //
        // A bootstrap carrier has FrameVM state but is itself a regular Host
        // task, rather than a FrameSchedGroup current entity. Its service task
        // must therefore publish the group before bootstrap exits; membership
        // in the same VM alone is not evidence that the group is already
        // visible to the Host scheduler.
        let rq = self.rqs[cpu.as_usize()].lock();
        let _ = task.cpu().set_if_is_none(cpu);
        thread.sched_attr().set_last_cpu(cpu);
        if rq.is_current_frame_group(&state) {
            return None;
        }
        if !group.has_runnable_work() {
            return None;
        }

        let should_preempt = frame_group::preempt_on_enqueue(
            &state,
            rq.current
                .as_ref()
                .map(|(current_entity, _)| current_entity),
        );
        let did_enqueue = rq.fair.lock().enqueue_frame_sched_group(state.clone());
        (did_enqueue && should_preempt).then_some(cpu)
    }

    fn update_framevm_cpu_affinity(&self, vm_id: aster_framevisor::VmId, cpu_affinity: &CpuSet) {
        let states = self
            .frame_group_states
            .lock()
            .iter()
            .filter(|(id, _)| id.vm_id() == vm_id)
            .map(|(_, state)| state.clone())
            .collect::<Vec<_>>();
        for state in states {
            self.update_frame_sched_group_cpu_affinity(state, cpu_affinity);
        }
    }

    fn update_frame_sched_group_cpu_affinity(
        &self,
        state: Arc<frame_group::FrameSchedEntityState>,
        cpu_affinity: &CpuSet,
    ) {
        {
            let mut states = self.frame_group_states.lock();
            let Some(group) = state.group() else {
                states.retain(|_, registered| !Arc::ptr_eq(registered, &state));
                return;
            };
            let Some(registered) = states.get(&group.id()) else {
                return;
            };
            if !Arc::ptr_eq(registered, &state) {
                return;
            }
            if !state.is_admitted() {
                return;
            }
            state.set_cpu_affinity(cpu_affinity.clone());
        }

        loop {
            let group = {
                let states = self.frame_group_states.lock();
                if state.cpu_affinity() != *cpu_affinity || !state.is_admitted() {
                    return;
                }
                let Some(group) = state.group() else {
                    return;
                };
                let Some(registered) = states.get(&group.id()) else {
                    return;
                };
                if !Arc::ptr_eq(registered, &state) {
                    return;
                }
                group.clone()
            };

            // Keep the inner scheduler lock outside the Host state-map and
            // runqueue locks. Host wakeups can take the state map after the
            // inner scheduler has released its runqueue lock.
            let has_runnable_work = group.has_runnable_work();

            {
                let states = self.frame_group_states.lock();
                if state.cpu_affinity() != *cpu_affinity || !state.is_admitted() {
                    return;
                }
                let Some(registered) = states.get(&group.id()) else {
                    return;
                };
                if !Arc::ptr_eq(registered, &state) {
                    return;
                }
            }
            let source_cpu = group.host_cpu();
            let source_cpu_is_allowed = state.allows_host_cpu(source_cpu);
            let source_rq = self.rqs[source_cpu.as_usize()].lock();
            if source_cpu_is_allowed {
                let did_enqueue = if source_rq.is_current_frame_group(&state) {
                    false
                } else if has_runnable_work {
                    source_rq
                        .fair
                        .lock()
                        .enqueue_frame_sched_group(state.clone())
                } else {
                    source_rq.fair.lock().try_dequeue_frame_sched_group(&state);
                    false
                };
                drop(source_rq);
                if did_enqueue {
                    ostd::task::__private::request_preemption_on_cpu(source_cpu);
                }
                return;
            }
            if source_rq.is_current_frame_group(&state) {
                drop(source_rq);
                ostd::task::__private::request_preemption_on_cpu(source_cpu);
                Task::yield_now();
                continue;
            }

            source_rq.fair.lock().try_dequeue_frame_sched_group(&state);
            drop(source_rq);

            let registered = self.frame_group_states.lock().clone();
            if state.cpu_affinity() != *cpu_affinity || !state.is_admitted() {
                return;
            }
            if registered
                .get(&group.id())
                .is_none_or(|registered| !Arc::ptr_eq(registered, &state))
            {
                return;
            }
            let Some(destination_cpu) =
                self.select_frame_sched_group_cpu(cpu_affinity, &registered)
            else {
                return;
            };

            let did_move = destination_cpu != source_cpu;
            if did_move {
                group.bind_host_cpu(destination_cpu);
            }
            let destination_rq = self.rqs[destination_cpu.as_usize()].lock();
            let did_enqueue = state.allows_host_cpu(destination_cpu)
                && has_runnable_work
                && destination_rq
                    .fair
                    .lock()
                    .enqueue_frame_sched_group(state.clone());
            drop(destination_rq);
            if did_move {
                enable_framevisor_preemption_on_cpu(destination_cpu);
            }
            if did_enqueue {
                ostd::task::__private::request_preemption_on_cpu(destination_cpu);
            }
            return;
        }
    }

    fn unregister_frame_sched_groups(&self, vm_id: aster_framevisor::VmId) {
        let removed = {
            let mut states = self.frame_group_states.lock();
            let mut removed = Vec::new();
            states.retain(|id, state| {
                if id.vm_id() != vm_id {
                    return true;
                }
                // Closing admission first makes a concurrent pick reject this
                // carrier. The stopped FrameVM has already waited for every
                // service task to exit before it reaches this teardown path.
                state.stop_admission();
                removed.push(state.clone());
                false
            });
            removed
        };

        // Registration is not just the state-map entry: every admitted group
        // can also own one entity in the selected CPU's hierarchical fair
        // queue. Leaving that entity behind poisons the queue accounting and
        // can make a later FrameVM in the same Host boot pick a dead group.
        // Placement always removes the source entry before rebinding a group,
        // so its final host CPU is the only queue that can retain it here.
        for state in removed {
            // Every caller retains the FrameVm through this cleanup. A current
            // carrier also retains FrameTaskState, which retains that FrameVm,
            // so an expired group here would be a lifecycle-order bug rather
            // than an entity that may safely be skipped.
            let group = state
                .group()
                .expect("FrameVM group must outlive Host scheduler cleanup");
            // Admission is closed before this loop starts. The next scheduling
            // boundary on `host_cpu` must therefore replace this outer entity:
            // `frame_group::update_current` observes the disallowed placement
            // even when the stopped group has no runnable inner task, and the
            // requeue path removes rather than republishes its fair entry.
            //
            // A fair dequeue alone cannot remove an entity that is currently
            // selected by this CPU. Ask the owning CPU to reach that boundary,
            // then wait until its runqueue has committed the replacement. The
            // preemption helper delivers an IPI when `host_cpu` is remote;
            // yielding here only yields the teardown task and gives the local
            // scheduler a chance to run while the remote CPU handles that IPI.
            let host_cpu = group.host_cpu();
            loop {
                let rq = self.rqs[host_cpu.as_usize()].lock();
                if !rq.is_current_frame_group(&state) {
                    let _ = rq.fair.lock().try_dequeue_frame_sched_group(&state);
                    break;
                }
                drop(rq);

                ostd::task::__private::request_preemption_on_cpu(host_cpu);
                Task::yield_now();
            }
        }
    }
}

impl PerCpuClassRqSet {
    fn classify_framevm_continuation_arrival(
        &mut self,
        carrier: &Arc<Task>,
        state: &Arc<aster_framevisor::task::FrameTaskState>,
        cpu: CpuId,
    ) -> FrameContinuationArrival {
        let to = state.task_for_host_carrier(carrier.clone());
        let (current, _) = self
            .current
            .as_mut()
            .expect("a Frame carrier must arrive with a current Host outer pair");
        let CurrentOuterEntity::FrameSchedGroup(outer_state) = &current.outer else {
            panic!("a Frame carrier may not arrive through an ordinary Host entity");
        };
        let group = outer_state
            .group()
            .expect("the current Host FrameSchedGroup must remain alive");
        if state.frame_vm().id() != group.id().vm_id()
            || state.frame_vcpu_id().vcpu_index() != group.id().vcpu_index()
        {
            panic!("an arriving Frame carrier belongs to a different virtual CPU");
        }
        let from = group
            .continuation()
            .expect("a current outer FrameSchedGroup must retain a continuation");
        if !Arc::ptr_eq(current.task(), from.host_task()) || !Arc::ptr_eq(carrier, to.host_task()) {
            panic!("a Frame carrier arrived without matching the Host outer pair");
        }

        // An outer Tick may suspend then resume A while A -> B remains
        // staged. A remains committed until B's processor arrival, so this
        // is a valid physical resume rather than a stale handoff.
        if Arc::ptr_eq(carrier, from.host_task()) {
            return FrameContinuationArrival::OuterResume;
        }
        if carrier
            .schedule_info()
            .cpu
            .get()
            .is_some_and(|carrier_cpu| carrier_cpu != cpu)
        {
            panic!("an arriving Frame continuation is bound to a different Host CPU");
        }
        let next_thread = carrier
            .as_thread()
            .cloned()
            .expect("a Frame continuation must carry a Host thread");

        group
            .commit_continuation_switch(&from, &to)
            .expect("a non-committed Frame arrival must match the exact staged A -> B pair");
        current.task().schedule_info().cpu.set_to_none();
        if carrier.schedule_info().cpu.get().is_none() {
            carrier
                .schedule_info()
                .cpu
                .set_if_is_none(cpu)
                .expect("a checked unbound continuation must bind to the current Host CPU");
        }
        next_thread.sched_attr().set_last_cpu(cpu);
        current.concrete = (carrier.clone(), next_thread);
        FrameContinuationArrival::Committed
    }

    fn is_current_frame_group(&self, state: &Arc<frame_group::FrameSchedEntityState>) -> bool {
        self.current.as_ref().is_some_and(|(entity, _)| {
            matches!(
                &entity.outer,
                CurrentOuterEntity::FrameSchedGroup(current_state)
                    if Arc::ptr_eq(current_state, state)
            )
        })
    }

    fn sched_entity_from_task(task: Arc<Task>) -> Option<PickedSchedEntity> {
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
                let fair_pick = self.fair.lock().pick_next_fair();
                let Some(fair_pick) = fair_pick else {
                    break;
                };
                match fair_pick {
                    fair::FairPick::Task(task) => {
                        if let Some(entity) = Self::sched_entity_from_task(task) {
                            return Some(entity);
                        }
                    }
                    fair::FairPick::FrameSchedGroup(state) => {
                        let Some(entity) = frame_group::pick_task(&state) else {
                            continue;
                        };
                        return Some(entity);
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

    fn load_stats(&self) -> PerCpuLoadStats {
        let fair_queue_len = self.fair.lock().total_queued_task_count();
        let queue_len = (self.stop.len() + self.real_time.len() + fair_queue_len) as u32;
        let is_idle = match &self.current {
            Some((entity, _)) => match &entity.outer {
                // Host accounting is about the outer entity. A virtual idle
                // continuation keeps a scheduled Frame vCPU non-idle until
                // its explicit outer halt dequeues the group.
                CurrentOuterEntity::FrameSchedGroup(_) => false,
                CurrentOuterEntity::Task => {
                    entity.thread().sched_attr().policy_kind() == SchedPolicyKind::Idle
                }
            },
            None => true,
        };
        PerCpuLoadStats { queue_len, is_idle }
    }
}

impl LocalRunQueue for PerCpuClassRqSet {
    fn current(&self) -> Option<&Arc<Task>> {
        self.current.as_ref().map(|(entity, _)| entity.task())
    }

    fn try_pick_next(&mut self) -> Option<&Arc<Task>> {
        let requested_current_can_compete = self.current_can_compete_on_pick;
        self.current_can_compete_on_pick = false;

        let previous = self.current.take();
        if let Some((previous_entity, _)) = &previous
            && Self::has_not_switched_to(previous_entity)
        {
            self.current = previous;
            return self.current.as_ref().map(|(entity, _)| entity.task());
        }
        let previous = previous;
        let current_can_compete_on_pick = requested_current_can_compete;
        if current_can_compete_on_pick && let Some((previous_entity, _)) = &previous {
            match &previous_entity.outer {
                CurrentOuterEntity::FrameSchedGroup(state) => {
                    frame_group::requeue(state, self.fair.as_ref());
                }
                CurrentOuterEntity::Task => {
                    self.enqueue_entity(previous_entity.concrete.clone(), None);
                }
            }
        }

        // A waiting or exiting inner task is no longer competitive, but its
        // outer group may still contain other runnable work. Make that group
        // visible before picking; deferring this until after `pick_next_entity`
        // would lose the only path to its sibling inner task.
        if !current_can_compete_on_pick
            && let Some((previous_entity, _)) = &previous
            && let CurrentOuterEntity::FrameSchedGroup(state) = &previous_entity.outer
        {
            frame_group::requeue(state, self.fair.as_ref());
        }

        let next = self.pick_next_entity();
        let Some(next) = next else {
            debug_assert!(previous.is_none() || !current_can_compete_on_pick);
            self.current = previous;
            return None;
        };
        let picked_previous = Self::picked_actual_current(previous.as_ref(), &next);
        let period_delta = Self::inherited_period_delta(previous.as_ref(), &next);
        let picked_same_frame_group = previous
            .as_ref()
            .is_some_and(|(previous_entity, _)| Self::is_same_frame_group(previous_entity, &next));

        // `current` is published while this CPU's runqueue lock is held. It
        // is the sole handoff record between the two scheduling stages: until
        // the Host switch commits, `has_not_switched_to` retains this exact
        // outer/inner pair instead of selecting another inner task.
        self.current = Some((next, CurrentRuntime::new_with_period_delta(period_delta)));
        if !current_can_compete_on_pick
            && !picked_same_frame_group
            && let Some((old, _)) = previous
        {
            match old.outer {
                CurrentOuterEntity::FrameSchedGroup(state) => {
                    frame_group::requeue(&state, self.fair.as_ref());
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
        let mut current_can_compete_after_update = false;
        let (should_preempt, mut lookahead) = if let Some((current_entity, rt)) = &mut self.current
        {
            rt.update();
            let cur = current_entity.thread();
            let attr = &cur.sched_attr();
            let policy_kind = attr.policy_kind();
            current_can_compete_after_update = frame_group::current_can_compete(current_entity);

            match &current_entity.outer {
                CurrentOuterEntity::FrameSchedGroup(state) => {
                    let should_preempt = frame_group::update_current(
                        state,
                        current_entity.task(),
                        rt,
                        self.fair.as_ref(),
                        flags,
                    );
                    (should_preempt, 2)
                }
                CurrentOuterEntity::Task => {
                    let (should_preempt, lookahead) = match policy_kind {
                        SchedPolicyKind::Stop => (self.stop.update_current(rt, cur, flags), 0),
                        SchedPolicyKind::RealTime => {
                            (self.real_time.update_current(rt, cur, flags), 1)
                        }
                        SchedPolicyKind::Fair => {
                            (self.fair.lock().update_current(rt, cur, flags), 2)
                        }
                        SchedPolicyKind::Idle => (self.idle.update_current(rt, cur, flags), 3),
                    };
                    (should_preempt, lookahead)
                }
            }
        } else {
            (false, 4)
        };

        if matches!(flags, UpdateFlags::Wait | UpdateFlags::Exit) {
            lookahead = 4;
        }

        let should_pick_next = should_preempt
            || (lookahead >= 1 && !self.stop.is_empty())
            || (lookahead >= 2 && !self.real_time.is_empty())
            || (lookahead >= 3 && !self.fair.lock().is_empty())
            || (lookahead >= 4 && !self.idle.is_empty());
        self.current_can_compete_on_pick = false;
        if should_pick_next
            && matches!(flags, UpdateFlags::Tick)
            && current_can_compete_after_update
        {
            self.current_can_compete_on_pick = true;
        }
        should_pick_next
    }

    fn dequeue_current(&mut self) -> Option<Arc<Task>> {
        // OSTD calls this only for the task represented by this runqueue's
        // `current` slot. Looking up a second, cross-layer current task here
        // can retain the slot while a FrameVM carrier is leaving it.
        let (entity, _) = self.current.take()?;

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
