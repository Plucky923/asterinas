// SPDX-License-Identifier: MPL-2.0

//! Kernel-local scheduler driven by virtual timer ticks.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use core::{
    borrow::Borrow,
    cmp,
    sync::atomic::{AtomicU64, Ordering},
};

use ostd::{
    arch::read_tsc as sched_clock,
    cpu::{self, CpuId},
    sync::{Once, SpinLock as Mutex, WaitQueue},
    task::{
        Task,
        scheduler::{EnqueueFlags, LocalRunQueue, Scheduler, UpdateFlags},
    },
};

use crate::task::UserTaskData;

const WEIGHT_0: u64 = 1024;
const BASE_SLICE_NS: u64 = 750_000;
const MIN_PERIOD_NS: u64 = 6_000_000;

struct ClassScheduler {
    rqs: Mutex<BTreeMap<CpuId, PerCpuRunQueue>>,
    wait_queue: WaitQueue,
}

static TIMER_TICK_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SchedTaskId {
    User(u32),
}

impl SchedTaskId {
    const fn user(tid: u32) -> Self {
        Self::User(tid)
    }
}

impl ClassScheduler {
    fn register_task(&self, cpu_id: CpuId, task_id: SchedTaskId, task: Arc<Task>) {
        let mut rqs = self.rqs.lock();
        let rq = rqs.entry(cpu_id).or_insert_with(PerCpuRunQueue::new);
        rq.register_task(cpu_id, task_id, task);
        drop(rqs);
        self.wait_queue.wake_all();
    }

    fn block_task(&self, cpu_id: CpuId, tid: u32) {
        let mut rqs = self.rqs.lock();
        if let Some(rq) = rqs.get_mut(&cpu_id) {
            rq.block_task(SchedTaskId::user(tid));
        }
        drop(rqs);
        self.wait_queue.wake_all();
    }

    fn mark_task_exiting(&self, cpu_id: CpuId, tid: u32) {
        let mut rqs = self.rqs.lock();
        if let Some(rq) = rqs.get_mut(&cpu_id) {
            rq.mark_task_exiting(SchedTaskId::user(tid));
        }
        drop(rqs);
        self.wait_queue.wake_all();
    }

    fn wait_until_current(&self, cpu_id: CpuId, tid: u32) {
        let task_id = SchedTaskId::user(tid);
        loop {
            {
                let rqs = self.rqs.lock();
                let Some(rq) = rqs.get(&cpu_id) else {
                    return;
                };
                if rq.is_current(task_id) {
                    return;
                }
            }

            self.wait_queue.wait_until(|| {
                let rqs = self.rqs.lock();
                let Some(rq) = rqs.get(&cpu_id) else {
                    return Some(());
                };
                rq.is_current(task_id).then_some(())
            });
        }
    }

    fn has_kernel_event(&self, cpu_id: CpuId, tid: u32) -> bool {
        let task_id = SchedTaskId::user(tid);
        let rqs = self.rqs.lock();
        let Some(rq) = rqs.get(&cpu_id) else {
            return false;
        };
        rq.has_kernel_event(task_id)
    }

    fn yield_task(&self, cpu_id: CpuId, tid: u32) {
        let mut rqs = self.rqs.lock();
        let Some(rq) = rqs.get_mut(&cpu_id) else {
            return;
        };
        rq.yield_task(SchedTaskId::user(tid));
        drop(rqs);
        self.wait_queue.wake_all();
    }

    fn reschedule_current_task(&self, cpu_id: CpuId, tid: u32) {
        let mut rqs = self.rqs.lock();
        let Some(rq) = rqs.get_mut(&cpu_id) else {
            return;
        };
        rq.reschedule_current_task(SchedTaskId::user(tid));
        drop(rqs);
        self.wait_queue.wake_all();
    }

    fn local_rq_with(&self, f: &mut dyn FnMut(&dyn LocalRunQueue<Task>)) {
        let cpu_id = current_virtual_cpu_id();
        self.local_rq_with_cpu(cpu_id, f);
    }

    fn local_rq_with_cpu(&self, cpu_id: CpuId, f: &mut dyn FnMut(&dyn LocalRunQueue<Task>)) {
        let rqs = self.rqs.lock();
        if let Some(rq) = rqs.get(&cpu_id) {
            f(rq);
        }
    }

    fn mut_local_rq_with(&self, f: &mut dyn FnMut(&mut dyn LocalRunQueue<Task>)) {
        let cpu_id = current_virtual_cpu_id();
        self.mut_local_rq_with_cpu(cpu_id, f);
    }

    fn mut_local_rq_with_cpu(
        &self,
        cpu_id: CpuId,
        f: &mut dyn FnMut(&mut dyn LocalRunQueue<Task>),
    ) {
        let mut rqs = self.rqs.lock();
        let rq = rqs.entry(cpu_id).or_insert_with(PerCpuRunQueue::new);
        f(rq);
        drop(rqs);
        self.wait_queue.wake_all();
    }
}

impl Scheduler<Task> for ClassScheduler {
    fn enqueue(&self, runnable: Arc<Task>, _flags: EnqueueFlags) -> Option<CpuId> {
        if let Some((cpu_id, task_id)) = task_identity(runnable.as_ref()) {
            self.register_task(cpu_id, task_id, runnable);
            return Some(cpu_id);
        }

        Some(CpuId::current_racy())
    }

    fn local_rq_with(&self, f: &mut dyn FnMut(&dyn LocalRunQueue<Task>)) {
        ClassScheduler::local_rq_with(self, f);
    }

    fn mut_local_rq_with(&self, f: &mut dyn FnMut(&mut dyn LocalRunQueue<Task>)) {
        ClassScheduler::mut_local_rq_with(self, f);
    }
}

struct PerCpuRunQueue {
    fair: FairRunQueue,
    tasks: BTreeMap<SchedTaskId, ScheduledTask>,
    blocked: BTreeSet<SchedTaskId>,
    exiting: BTreeSet<SchedTaskId>,
    current: Option<(CurrentEntity, CurrentRuntime)>,
    need_resched: bool,
}

impl PerCpuRunQueue {
    fn new() -> Self {
        Self {
            fair: FairRunQueue::new(),
            tasks: BTreeMap::new(),
            blocked: BTreeSet::new(),
            exiting: BTreeSet::new(),
            current: None,
            need_resched: false,
        }
    }

    fn register_task(&mut self, cpu_id: CpuId, task_id: SchedTaskId, task: Arc<Task>) {
        let _ = cpu_id;
        self.tasks
            .entry(task_id)
            .or_insert_with(|| ScheduledTask::new(task_id, task));
        self.blocked.remove(&task_id);
        self.exiting.remove(&task_id);
        self.enqueue_task(task_id, Some(EnqueueFlags::Spawn));
        if self.current.is_none() {
            let _ = self.try_pick_next();
        }
    }

    fn block_task(&mut self, task_id: SchedTaskId) {
        self.blocked.insert(task_id);
        if let Some(task) = self.tasks.get(&task_id) {
            self.fair.remove_entity_by_id(task.fair.id());
        }
        if self
            .current
            .as_ref()
            .is_some_and(|(current, _)| current.task_id == task_id)
        {
            self.current = None;
            let _ = self.try_pick_next();
        }
    }

    fn mark_task_exiting(&mut self, task_id: SchedTaskId) {
        self.exiting.insert(task_id);
        self.blocked.remove(&task_id);
        self.remove_task_from_ready_queue(task_id);
        if self.current_task_id() == Some(task_id) {
            self.current = None;
            let _ = self.dequeue_task(task_id);
            let _ = self.try_pick_next();
        }
    }

    fn enqueue_task(&mut self, task_id: SchedTaskId, flags: Option<EnqueueFlags>) {
        if self.blocked.contains(&task_id) || self.exiting.contains(&task_id) {
            return;
        }
        if self
            .current
            .as_ref()
            .is_some_and(|(current, _)| current.task_id == task_id)
        {
            return;
        }
        let Some(task) = self.tasks.get_mut(&task_id) else {
            return;
        };
        self.fair.enqueue_entity(task_id, &mut task.fair, flags);
    }

    fn first_unblocked_task(&self) -> Option<SchedTaskId> {
        self.tasks
            .keys()
            .copied()
            .find(|task_id| !self.blocked.contains(task_id) && !self.exiting.contains(task_id))
    }

    fn running_task_id() -> Option<SchedTaskId> {
        Task::current().and_then(|task| task_identity(task.as_ref()).map(|(_, task_id)| task_id))
    }

    fn current_task_id(&self) -> Option<SchedTaskId> {
        self.current.as_ref().map(|(current, _)| current.task_id)
    }

    fn running_task_is_current(&self) -> bool {
        Self::running_task_id().is_some_and(|task_id| self.current_task_id() == Some(task_id))
    }

    fn remove_task_from_ready_queue(&mut self, task_id: SchedTaskId) {
        if let Some(task) = self.tasks.get(&task_id) {
            self.fair.remove_entity_by_id(task.fair.id());
        }
    }

    fn ensure_current(&mut self) {
        if self.current.is_some() {
            return;
        }
        if self.try_pick_next().is_some() {
            return;
        }
        if let Some(task_id) = self.first_unblocked_task() {
            self.current = Some((CurrentEntity::new(task_id), CurrentRuntime::new()));
        }
    }

    fn current_task(&self) -> Option<&Arc<Task>> {
        let current = self.current.as_ref()?;
        self.tasks.get(&current.0.task_id).map(|task| &task.task)
    }

    fn is_current(&self, task_id: SchedTaskId) -> bool {
        self.current
            .as_ref()
            .is_some_and(|(current, _)| current.task_id == task_id)
    }

    fn has_kernel_event(&self, task_id: SchedTaskId) -> bool {
        !self.is_current(task_id) || self.need_resched
    }

    fn yield_task(&mut self, task_id: SchedTaskId) {
        if !self.is_current(task_id) {
            return;
        }

        if self.update_current(UpdateFlags::Yield) {
            let _ = self.try_pick_next();
        }
    }

    fn reschedule_current_task(&mut self, task_id: SchedTaskId) {
        if !self.need_resched || !self.is_current(task_id) {
            return;
        }

        self.need_resched = false;
        let _ = self.try_pick_next();
    }
}

impl LocalRunQueue<Task> for PerCpuRunQueue {
    fn current(&self) -> Option<&Arc<Task>> {
        self.current_task()
    }

    fn try_pick_next(&mut self) -> Option<&Arc<Task>> {
        if self.current.is_some() && !self.running_task_is_current() {
            return self.current_task();
        }

        let next_task_id = self.fair.pick_next()?;
        if let Some((old_current, _)) = self.current.take()
            && self.tasks.contains_key(&old_current.task_id)
        {
            self.enqueue_task(old_current.task_id, None);
        }

        self.current = Some((CurrentEntity::new(next_task_id), CurrentRuntime::new()));
        self.need_resched = false;
        self.current_task()
    }

    fn update_current(&mut self, flags: UpdateFlags) -> bool {
        if matches!(flags, UpdateFlags::Tick) {
            TIMER_TICK_COUNT.fetch_add(1, Ordering::Relaxed);
        }
        if matches!(flags, UpdateFlags::Exit)
            && let Some(task_id) = Self::running_task_id()
        {
            self.exiting.insert(task_id);
        }

        if matches!(flags, UpdateFlags::Wait | UpdateFlags::Exit)
            && self.current.is_some()
            && !self.running_task_is_current()
        {
            return false;
        }

        if self.current.is_none() {
            self.ensure_current();
        }

        let Some((current, runtime)) = self.current.as_mut() else {
            return !self.fair.is_empty();
        };
        runtime.update();

        let Some(task) = self.tasks.get_mut(&current.task_id) else {
            return !self.fair.is_empty();
        };
        let should_pick_next = self.fair.update_current_entity(
            &mut task.fair,
            runtime.delta,
            runtime.period_delta,
            flags,
        );
        if matches!(flags, UpdateFlags::Tick) && should_pick_next {
            self.need_resched = true;
        }
        should_pick_next
    }

    fn dequeue_current(&mut self) -> Option<Arc<Task>> {
        match Self::running_task_id() {
            Some(running_task_id) if self.current_task_id() != Some(running_task_id) => {
                return None;
            }
            None if self.current.is_some() => return None,
            _ => {}
        }

        let (current, _) = self.current.take()?;
        self.dequeue_task(current.task_id)
    }
}

impl PerCpuRunQueue {
    fn dequeue_task(&mut self, task_id: SchedTaskId) -> Option<Arc<Task>> {
        self.remove_task_from_ready_queue(task_id);
        let task = if self.exiting.remove(&task_id) {
            self.blocked.remove(&task_id);
            self.tasks.remove(&task_id).map(|task| task.task)
        } else {
            self.blocked.insert(task_id);
            self.tasks.get(&task_id).map(|task| task.task.clone())
        }?;
        Some(task)
    }

    #[cfg(ktest)]
    fn wake_task(&mut self, task_id: SchedTaskId) {
        if !self.tasks.contains_key(&task_id) || self.exiting.contains(&task_id) {
            return;
        }
        self.blocked.remove(&task_id);
        self.enqueue_task(task_id, Some(EnqueueFlags::Wake));
        if self.current.is_none() {
            let _ = self.try_pick_next();
        }
    }
}

struct ScheduledTask {
    task: Arc<Task>,
    fair: FairAttr,
}

impl ScheduledTask {
    fn new(_task_id: SchedTaskId, task: Arc<Task>) -> Self {
        Self {
            task,
            fair: FairAttr::from_weight(WEIGHT_0),
        }
    }
}

struct CurrentEntity {
    task_id: SchedTaskId,
}

impl CurrentEntity {
    const fn new(task_id: SchedTaskId) -> Self {
        Self { task_id }
    }
}

struct CurrentRuntime {
    start: u64,
    delta: u64,
    period_delta: u64,
}

impl CurrentRuntime {
    fn new() -> Self {
        Self {
            start: sched_clock(),
            delta: 0,
            period_delta: 0,
        }
    }

    fn update(&mut self) {
        let now = sched_clock();
        self.delta = now.saturating_sub(core::mem::replace(&mut self.start, now));
        self.period_delta = self.period_delta.saturating_add(self.delta);
    }
}

#[derive(Debug)]
struct FairAttr {
    id: u64,
    weight: u64,
    vruntime: u64,
    queued_weight: u64,
}

impl FairAttr {
    fn from_weight(weight: u64) -> Self {
        Self {
            id: next_entity_id(),
            weight,
            vruntime: 0,
            queued_weight: weight,
        }
    }

    const fn id(&self) -> u64 {
        self.id
    }

    const fn queued_weight(&self) -> u64 {
        self.queued_weight
    }

    fn fetch_weight(&self) -> (u64, u64) {
        (self.weight, self.weight)
    }

    fn vruntime(&self) -> u64 {
        self.vruntime
    }

    fn update_vruntime(&mut self, delta: u64, weight: u64) -> u64 {
        let weight = weight.max(1);
        let delta = delta.saturating_mul(WEIGHT_0) / weight;
        self.vruntime = self.vruntime.saturating_add(delta);
        self.vruntime
    }

    fn update_vruntime_at_least(&mut self, vruntime: u64) -> u64 {
        self.vruntime = self.vruntime.max(vruntime);
        self.vruntime
    }
}

fn next_entity_id() -> u64 {
    static NEXT_ENTITY_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_ENTITY_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Clone, Copy)]
struct FairQueueItem {
    key: (u64, u64),
    task_id: SchedTaskId,
    weight: u64,
}

impl FairQueueItem {
    const fn new(key: (u64, u64), task_id: SchedTaskId, weight: u64) -> Self {
        Self {
            key,
            task_id,
            weight,
        }
    }
}

impl Borrow<(u64, u64)> for FairQueueItem {
    fn borrow(&self) -> &(u64, u64) {
        &self.key
    }
}

impl PartialEq for FairQueueItem {
    fn eq(&self, other: &Self) -> bool {
        self.key.eq(&other.key)
    }
}

impl Eq for FairQueueItem {}

impl PartialOrd for FairQueueItem {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FairQueueItem {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.key.cmp(&other.key)
    }
}

struct FairRunQueue {
    entities: BTreeSet<FairQueueItem>,
    entity_keys: BTreeMap<u64, (u64, u64)>,
    min_vruntime: u64,
    total_weight: u64,
}

impl FairRunQueue {
    fn new() -> Self {
        Self {
            entities: BTreeSet::new(),
            entity_keys: BTreeMap::new(),
            min_vruntime: 0,
            total_weight: 0,
        }
    }

    fn len(&self) -> usize {
        self.entities.len()
    }

    fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    fn min_queued_vruntime(&self) -> Option<u64> {
        self.entities.iter().next().map(|item| item.key.0)
    }

    fn period(&self, queued_entity_count: usize) -> u64 {
        let period_single_cpu = (base_slice_clocks()
            .saturating_mul((queued_entity_count + 1) as u64))
        .max(min_period_clocks());
        period_single_cpu.saturating_mul(u64::from((1 + cpu::num_cpus()).ilog2()))
    }

    fn vtime_slice(&self, queued_entity_count: usize) -> u64 {
        self.period(queued_entity_count) / (queued_entity_count + 1) as u64
    }

    fn time_slice(
        &self,
        current_weight: u64,
        queued_weight: u64,
        queued_entity_count: usize,
    ) -> u64 {
        let total_weight = queued_weight.saturating_add(current_weight).max(1);
        self.period(queued_entity_count)
            .saturating_mul(current_weight)
            / total_weight
    }

    fn insert_entity(&mut self, task_id: SchedTaskId, fair_attr: &mut FairAttr) {
        let key = (fair_attr.vruntime(), fair_attr.id());
        if let Some(old_key) = self.entity_keys.get(&fair_attr.id()).copied() {
            self.remove_entity(old_key);
        }

        let weight = fair_attr.fetch_weight().1;
        fair_attr.queued_weight = weight;
        let item = FairQueueItem::new(key, task_id, fair_attr.queued_weight());
        if let Some(old_item) = self.entities.replace(item) {
            self.total_weight = self.total_weight.saturating_sub(old_item.weight);
        }
        self.entity_keys.insert(fair_attr.id(), key);
        self.total_weight = self.total_weight.saturating_add(weight);
    }

    fn enqueue_entity(
        &mut self,
        task_id: SchedTaskId,
        fair_attr: &mut FairAttr,
        flags: Option<EnqueueFlags>,
    ) {
        if !self.has_entity(fair_attr.id()) {
            let vruntime = match flags {
                Some(EnqueueFlags::Spawn) => self.min_vruntime + self.vtime_slice(self.len()),
                _ => self.min_vruntime,
            };
            fair_attr.update_vruntime_at_least(vruntime);
        }

        self.insert_entity(task_id, fair_attr);
    }

    fn remove_entity(&mut self, key: (u64, u64)) -> Option<FairQueueItem> {
        let item = self.entities.take(&key)?;
        self.entity_keys.remove(&key.1);
        self.total_weight = self.total_weight.saturating_sub(item.weight);
        Some(item)
    }

    fn remove_entity_by_id(&mut self, entity_id: u64) -> Option<FairQueueItem> {
        let key = self.entity_keys.get(&entity_id).copied()?;
        self.remove_entity(key)
    }

    fn has_entity(&self, entity_id: u64) -> bool {
        self.entity_keys.contains_key(&entity_id)
    }

    fn pick_next(&mut self) -> Option<SchedTaskId> {
        let item = *self.entities.iter().next()?;
        self.remove_entity(item.key);
        Some(item.task_id)
    }

    fn update_current_entity(
        &mut self,
        fair_attr: &mut FairAttr,
        runtime_delta: u64,
        period_delta: u64,
        flags: UpdateFlags,
    ) -> bool {
        let queued_entity = self.remove_entity_by_id(fair_attr.id());
        let was_queued = queued_entity.is_some();
        let weight = fair_attr.fetch_weight().1;
        let vruntime = fair_attr.update_vruntime(runtime_delta, weight);
        if let Some(queued_entity) = queued_entity {
            self.insert_entity(queued_entity.task_id, fair_attr);
        }
        let min_queued_vruntime = self.min_queued_vruntime();
        self.min_vruntime = match min_queued_vruntime {
            Some(min_queued_vruntime) => vruntime.min(min_queued_vruntime),
            None => vruntime,
        };

        if self.is_empty() {
            return false;
        }
        if matches!(
            flags,
            UpdateFlags::Wait | UpdateFlags::Yield | UpdateFlags::Exit
        ) {
            return true;
        }

        let Some(min_queued_vruntime) = min_queued_vruntime else {
            return false;
        };
        if vruntime <= min_queued_vruntime {
            return false;
        }

        let queued_entity_count = self.len().saturating_sub(usize::from(was_queued));
        let queued_weight = self
            .total_weight
            .saturating_sub(if was_queued { weight } else { 0 });
        period_delta > self.time_slice(weight, queued_weight, queued_entity_count)
            || vruntime > min_queued_vruntime.saturating_add(self.vtime_slice(queued_entity_count))
    }
}

fn base_slice_clocks() -> u64 {
    ns_to_clocks(BASE_SLICE_NS)
}

fn min_period_clocks() -> u64 {
    ns_to_clocks(MIN_PERIOD_NS)
}

fn ns_to_clocks(ns: u64) -> u64 {
    static TSC_FREQ: Once<u64> = Once::new();
    let freq = *TSC_FREQ.call_once(ostd::arch::tsc_freq);
    if freq == 0 {
        return ns;
    }
    (u128::from(ns) * u128::from(freq) / 1_000_000_000u128) as u64
}

static SCHEDULER: Once<ClassScheduler> = Once::new();

fn scheduler() -> &'static ClassScheduler {
    SCHEDULER.call_once(|| ClassScheduler {
        rqs: Mutex::new(BTreeMap::new()),
        wait_queue: WaitQueue::new(),
    })
}

pub fn init() {
    ostd::task::scheduler::inject_scheduler(scheduler());
    ostd::task::scheduler::enable_preemption_on_cpu();
}

pub fn block_task(cpu_id: CpuId, tid: u32) {
    scheduler().block_task(cpu_id, tid);
}

pub fn register_current_task() {
    let Some(current_task) = Task::current() else {
        return;
    };
    let task = current_task.cloned();
    register_task(task);
}

pub fn register_task(task: Arc<Task>) {
    let Some((cpu_id, task_id)) = task_identity(task.as_ref()) else {
        return;
    };
    scheduler().register_task(cpu_id, task_id, task);
}

pub fn mark_task_exiting(cpu_id: CpuId, tid: u32) {
    scheduler().mark_task_exiting(cpu_id, tid);
}

pub fn wait_until_current(cpu_id: CpuId, tid: u32) {
    scheduler().wait_until_current(cpu_id, tid);
}

pub fn has_kernel_event(cpu_id: CpuId, tid: u32) -> bool {
    scheduler().has_kernel_event(cpu_id, tid)
}

pub fn yield_current_task(cpu_id: CpuId, tid: u32) {
    scheduler().yield_task(cpu_id, tid);
}

pub fn reschedule_current_task(cpu_id: CpuId, tid: u32) {
    scheduler().reschedule_current_task(cpu_id, tid);
}

fn task_identity(task: &Task) -> Option<(CpuId, SchedTaskId)> {
    let task_data = task.data().downcast_ref::<UserTaskData>()?;
    Some((task_data.cpu_id, SchedTaskId::User(task_data.tid)))
}

fn current_virtual_cpu_id() -> CpuId {
    Task::current()
        .and_then(|task| task_identity(task.as_ref()).map(|(cpu_id, _)| cpu_id))
        .unwrap_or_else(CpuId::current_racy)
}

#[cfg(ktest)]
mod tests {
    use ostd::{prelude::ktest, task::TaskOptions};

    use super::*;

    #[ktest]
    fn fair_queue_picks_lowest_vruntime() {
        let mut rq = FairRunQueue::new();
        let mut first = FairAttr::from_weight(WEIGHT_0);
        let mut second = FairAttr::from_weight(WEIGHT_0);

        rq.enqueue_entity(SchedTaskId::user(1), &mut first, None);
        second.update_vruntime(rq.vtime_slice(1) * 2, WEIGHT_0);
        rq.enqueue_entity(SchedTaskId::user(2), &mut second, None);

        assert_eq!(rq.pick_next(), Some(SchedTaskId::user(1)));
    }

    #[ktest]
    fn fair_queue_preempts_after_weighted_slice() {
        let mut rq = FairRunQueue::new();
        let mut current = FairAttr::from_weight(WEIGHT_0);
        let mut queued = FairAttr::from_weight(WEIGHT_0);

        rq.enqueue_entity(SchedTaskId::user(2), &mut queued, None);
        let period = rq.period(1);

        assert!(rq.update_current_entity(&mut current, period, period, UpdateFlags::Tick));
    }

    #[ktest]
    fn fair_queue_does_not_preempt_single_task() {
        let mut rq = FairRunQueue::new();
        let mut current = FairAttr::from_weight(WEIGHT_0);
        let period = rq.period(0);

        assert!(!rq.update_current_entity(&mut current, period, period, UpdateFlags::Tick));
    }

    #[ktest]
    fn fair_queue_duplicate_enqueue_replaces_existing_entity() {
        let mut rq = FairRunQueue::new();
        let mut entity = FairAttr::from_weight(WEIGHT_0);

        rq.enqueue_entity(SchedTaskId::user(7), &mut entity, None);
        rq.enqueue_entity(SchedTaskId::user(7), &mut entity, Some(EnqueueFlags::Wake));

        assert_eq!(rq.len(), 1);
        assert_eq!(rq.total_weight, WEIGHT_0);
        assert_eq!(rq.pick_next(), Some(SchedTaskId::user(7)));
        assert_eq!(rq.total_weight, 0);
    }

    #[ktest]
    fn per_cpu_wake_keeps_ready_task_enqueued_once() {
        let mut rq = PerCpuRunQueue::new();
        let cpu_id = CpuId::bsp();
        let current_task = new_task();
        let waking_task = new_task();
        let waking_task_id = SchedTaskId::user(2);

        rq.register_task(cpu_id, SchedTaskId::user(1), current_task);
        rq.register_task(cpu_id, waking_task_id, waking_task);
        rq.wake_task(waking_task_id);
        rq.wake_task(waking_task_id);

        assert_eq!(rq.fair.len(), 1);
        assert_eq!(rq.fair.total_weight, WEIGHT_0);
        assert_eq!(rq.fair.pick_next(), Some(waking_task_id));
        assert_eq!(rq.fair.total_weight, 0);
    }

    #[ktest]
    fn per_cpu_exiting_current_picks_next_task() {
        let mut rq = PerCpuRunQueue::new();
        let cpu_id = CpuId::bsp();
        let current_task_id = SchedTaskId::user(1);
        let next_task_id = SchedTaskId::user(2);

        rq.register_task(cpu_id, current_task_id, new_task());
        rq.register_task(cpu_id, next_task_id, new_task());
        rq.mark_task_exiting(current_task_id);

        assert_eq!(rq.current_task_id(), Some(next_task_id));
        assert!(!rq.tasks.contains_key(&current_task_id));
    }

    #[ktest]
    fn fair_queue_update_current_excludes_current_queued_weight() {
        let mut rq = FairRunQueue::new();
        let mut current = FairAttr::from_weight(WEIGHT_0);
        let mut queued = FairAttr::from_weight(WEIGHT_0 * 3);

        rq.enqueue_entity(SchedTaskId::user(1), &mut current, None);
        rq.enqueue_entity(SchedTaskId::user(2), &mut queued, None);
        let period = rq.period(1);

        assert!(rq.update_current_entity(&mut current, period, period, UpdateFlags::Tick));
        assert_eq!(rq.len(), 2);
        assert_eq!(rq.total_weight, WEIGHT_0 * 4);
    }

    fn new_task() -> Arc<Task> {
        Arc::new(TaskOptions::new(|| {}).build().unwrap())
    }
}
