// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use core::{
    any::Any,
    sync::atomic::{AtomicU64, Ordering},
};

use aster_framevisor::{
    DEFAULT_FRAME_TASK_GROUP_SHARE, FrameTaskGroupId,
    iht::{IhtContext, IhtTaskData, iht_main_loop},
    task::{
        bind_ostd_task_to_frame_task_group, inject_frame_task_group_share_updater,
        inject_priority_booster, inject_task_creator, inject_task_group_binder,
    },
};
use ostd::{
    cpu::CpuSet,
    sync::SpinLock,
    task::{Task as OstdTask, TaskOptions},
};

use crate::{
    sched::{self, DEFAULT_CGROUP_WEIGHT, Nice, SchedPolicy, TaskGroup},
    thread::{AsThread, Thread},
};

struct FrameVmThread;

static FRAME_TASK_GROUPS: SpinLock<BTreeMap<FrameTaskGroupId, Arc<TaskGroup>>> =
    SpinLock::new(BTreeMap::new());
static FRAME_TASK_GROUP_CPU_AFFINITIES: SpinLock<BTreeMap<FrameTaskGroupId, CpuSet>> =
    SpinLock::new(BTreeMap::new());
static FRAMEVM_PRIORITY_BOOSTS: SpinLock<BTreeMap<usize, SchedPolicy>> =
    SpinLock::new(BTreeMap::new());
static FRAME_TASK_GROUP_BIND_COUNTS: SpinLock<
    BTreeMap<FrameTaskGroupId, FrameTaskGroupBindCounts>,
> = SpinLock::new(BTreeMap::new());
static FRAME_TASK_GROUP_SHARE_UPDATE_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Default)]
struct FrameTaskGroupBindCounts {
    total: u64,
    service: u64,
    iht: u64,
    schedule_in_bound: u64,
    schedule_in_unbound: u64,
    parent_pick: u64,
    parent_pick_with_any_peer: u64,
    parent_pick_with_peer: u64,
    parent_pick_child_empty: u64,
    parent_pick_empty_no_task: u64,
    parent_entity_dequeue: u64,
    current_compete: u64,
    current_requeue: u64,
    current_dequeue_empty: u64,
    queued_dequeue_empty: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameTaskGroupHostSchedSnapshot {
    pub(crate) weight: u32,
    pub(crate) actual_weight: u64,
    pub(crate) vruntime: u64,
    pub(crate) bound_task_count: usize,
    pub(crate) scheduler_bound_task_count: usize,
    pub(crate) bind_count: u64,
    pub(crate) service_bind_count: u64,
    pub(crate) iht_bind_count: u64,
    pub(crate) schedule_in_bound_count: u64,
    pub(crate) schedule_in_unbound_count: u64,
    pub(crate) parent_pick_count: u64,
    pub(crate) parent_pick_with_any_peer_count: u64,
    pub(crate) parent_pick_with_peer_count: u64,
    pub(crate) parent_pick_child_empty_count: u64,
    pub(crate) parent_pick_empty_no_task_count: u64,
    pub(crate) parent_entity_dequeue_count: u64,
    pub(crate) current_compete_count: u64,
    pub(crate) current_requeue_count: u64,
    pub(crate) current_dequeue_empty_count: u64,
    pub(crate) queued_dequeue_empty_count: u64,
    pub(crate) share_update_count: u64,
}

fn create_framevm_task(
    func: Box<dyn FnOnce() + Send>,
    extension: Box<dyn Any + Send + Sync>,
    local_data: Box<dyn Any + Send>,
    task_group_id: Option<FrameTaskGroupId>,
) -> Result<Arc<OstdTask>, aster_framevisor::Error> {
    let affinity = frame_task_group_cpu_affinity(task_group_id);
    let scheduler_task_group = task_group_id.and_then(scheduler_task_group_for_frame_task_group);

    Ok(Arc::new_cyclic(|weak_task| {
        let thread = Arc::new(Thread::new(
            weak_task.clone(),
            FrameVmThread,
            affinity,
            guest_sched_policy(task_group_id),
        ));
        if let Some(scheduler_task_group) = scheduler_task_group.clone() {
            thread.set_task_group(scheduler_task_group);
        }

        TaskOptions::new(func)
            .data(thread)
            .extension_any(extension)
            .local_data_any(local_data)
            .build()
            .unwrap()
    }))
}

fn create_iht_task(ctx: Arc<IhtContext>) -> Arc<OstdTask> {
    use crate::thread::kernel_thread::ThreadOptions;

    let vcpu_id = ctx.vcpu_id();
    let task_group_id = ctx.task_group_id();
    let policy = iht_host_sched_policy();
    let thread_fn = move || iht_main_loop(ctx);
    let affinity = frame_task_group_cpu_affinity(Some(task_group_id));

    let task = ThreadOptions::new(thread_fn)
        .cpu_affinity(affinity)
        .sched_policy(policy)
        .extension(IhtTaskData::new(vcpu_id, task_group_id))
        .build();
    bind_task_to_scheduler_group(&task, task_group_id);
    let _ = bind_ostd_task_to_frame_task_group(task.clone(), task_group_id);

    if let Some(thread) = task.as_thread() {
        thread.clone().run();
    }

    task
}

fn scheduler_task_group_for_frame_task_group(
    task_group_id: FrameTaskGroupId,
) -> Option<Arc<TaskGroup>> {
    aster_framevisor::frame_task_group_share(task_group_id)?;

    let mut task_groups = FRAME_TASK_GROUPS.lock();
    if let Some(task_group) = task_groups.get(&task_group_id) {
        return Some(task_group.clone());
    }

    let task_group = TaskGroup::new_frame_child(
        sched::root_task_group(),
        scheduler_weight_for_frame_task_group(task_group_id),
        task_group_id,
    );
    task_groups.insert(task_group_id, task_group.clone());
    Some(task_group)
}

fn scheduler_weight_for_frame_task_group(task_group_id: FrameTaskGroupId) -> u32 {
    let share = aster_framevisor::frame_task_group_share(task_group_id)
        .unwrap_or(DEFAULT_FRAME_TASK_GROUP_SHARE);
    scheduler_weight_for_share(share)
}

fn scheduler_weight_for_share(share: u32) -> u32 {
    let weight = u64::from(share).saturating_mul(u64::from(DEFAULT_CGROUP_WEIGHT))
        / u64::from(DEFAULT_FRAME_TASK_GROUP_SHARE);
    u32::try_from(weight.max(1)).unwrap_or(u32::MAX)
}

fn bind_task_to_scheduler_group(task: &Arc<OstdTask>, task_group_id: FrameTaskGroupId) {
    let Some(thread) = task.as_thread() else {
        return;
    };
    let Some(task_group) = scheduler_task_group_for_frame_task_group(task_group_id) else {
        return;
    };
    let old_task_group = thread.task_group();
    thread.set_task_group(task_group);
    apply_frame_task_group_sched_policy(task, task_group_id);
    let affinity = frame_task_group_cpu_affinity(Some(task_group_id));
    thread
        .atomic_cpu_affinity()
        .store(&affinity, Ordering::Release);
    for queued_task in thread
        .task_group()
        .migrate_tasks_from(&[(task.clone(), old_task_group)])
    {
        queued_task.wake_up();
    }
    record_frame_task_group_bind(task, task_group_id);
}

fn frame_task_group_cpu_affinity(task_group_id: Option<FrameTaskGroupId>) -> CpuSet {
    task_group_id
        .and_then(|id| FRAME_TASK_GROUP_CPU_AFFINITIES.lock().get(&id).cloned())
        .unwrap_or_else(CpuSet::new_full)
}

fn bind_framevm_task_group(
    task: Arc<OstdTask>,
    task_group_id: FrameTaskGroupId,
) -> Result<(), aster_framevisor::Error> {
    bind_task_to_scheduler_group(&task, task_group_id);
    Ok(())
}

pub(crate) fn frame_task_group_should_run_iht(task_group_id: FrameTaskGroupId) -> bool {
    aster_framevisor::frame_task_group_virtual_interrupts_enabled(task_group_id)
        && aster_framevisor::frame_task_group_needs_resched(task_group_id)
}

pub(crate) fn is_iht_task_for_frame_task_group(
    task: &Arc<OstdTask>,
    task_group_id: FrameTaskGroupId,
) -> bool {
    task.extension()
        .downcast_ref::<IhtTaskData>()
        .is_some_and(|data| data.task_group_id() == task_group_id)
}

fn boost_framevm_task_priority(task: Arc<OstdTask>, boosted: bool) {
    if task.extension().downcast_ref::<IhtTaskData>().is_some() {
        return;
    }

    let Some(thread) = task.as_thread() else {
        return;
    };

    let task_key = Arc::as_ptr(&task) as usize;
    if boosted {
        let mut boosts = FRAMEVM_PRIORITY_BOOSTS.lock();
        boosts
            .entry(task_key)
            .or_insert_with(|| thread.sched_attr().policy());
        drop(boosts);
        thread
            .sched_attr()
            .set_policy(virtual_irq_boost_sched_policy());
        return;
    }

    let previous_policy = FRAMEVM_PRIORITY_BOOSTS.lock().remove(&task_key);
    if let Some(previous_policy) = previous_policy {
        thread.sched_attr().set_policy(previous_policy);
    }
}

fn is_framevm_task_priority_boosted(task: &Arc<OstdTask>) -> bool {
    let task_key = Arc::as_ptr(task) as usize;
    FRAMEVM_PRIORITY_BOOSTS.lock().contains_key(&task_key)
}

fn record_frame_task_group_bind(task: &Arc<OstdTask>, task_group_id: FrameTaskGroupId) {
    let is_iht = task.extension().downcast_ref::<IhtTaskData>().is_some();
    let mut counts = FRAME_TASK_GROUP_BIND_COUNTS.lock();
    let count = counts.entry(task_group_id).or_default();
    count.total = count.total.saturating_add(1);
    if is_iht {
        count.iht = count.iht.saturating_add(1);
    } else {
        count.service = count.service.saturating_add(1);
    }
}

pub(crate) fn record_frame_task_group_schedule_in_binding(
    task: &Arc<OstdTask>,
    task_group_id: FrameTaskGroupId,
) {
    let Some(expected_task_group) = FRAME_TASK_GROUPS.lock().get(&task_group_id).cloned() else {
        return;
    };
    let Some(thread) = task.as_thread() else {
        return;
    };

    let is_bound = Arc::ptr_eq(&thread.task_group(), &expected_task_group);
    let mut counts = FRAME_TASK_GROUP_BIND_COUNTS.lock();
    let count = counts.entry(task_group_id).or_default();
    if is_bound {
        count.schedule_in_bound = count.schedule_in_bound.saturating_add(1);
    } else {
        count.schedule_in_unbound = count.schedule_in_unbound.saturating_add(1);
    }
}

pub(crate) fn record_frame_task_group_parent_pick(
    task_group_id: FrameTaskGroupId,
    has_any_peer: bool,
    has_frame_group_peer: bool,
) {
    let mut counts = FRAME_TASK_GROUP_BIND_COUNTS.lock();
    let count = counts.entry(task_group_id).or_default();
    count.parent_pick = count.parent_pick.saturating_add(1);
    if has_any_peer {
        count.parent_pick_with_any_peer = count.parent_pick_with_any_peer.saturating_add(1);
    }
    if has_frame_group_peer {
        count.parent_pick_with_peer = count.parent_pick_with_peer.saturating_add(1);
    }
}

pub(crate) fn record_frame_task_group_parent_pick_result(
    task_group_id: FrameTaskGroupId,
    child_is_empty: bool,
) {
    if !child_is_empty {
        return;
    }
    let mut counts = FRAME_TASK_GROUP_BIND_COUNTS.lock();
    let count = counts.entry(task_group_id).or_default();
    count.parent_pick_child_empty = count.parent_pick_child_empty.saturating_add(1);
}

pub(crate) fn record_frame_task_group_parent_pick_empty_no_task(task_group_id: FrameTaskGroupId) {
    let mut counts = FRAME_TASK_GROUP_BIND_COUNTS.lock();
    let count = counts.entry(task_group_id).or_default();
    count.parent_pick_empty_no_task = count.parent_pick_empty_no_task.saturating_add(1);
}

pub(crate) fn record_frame_task_group_parent_entity_dequeue(task_group_id: FrameTaskGroupId) {
    let mut counts = FRAME_TASK_GROUP_BIND_COUNTS.lock();
    let count = counts.entry(task_group_id).or_default();
    count.parent_entity_dequeue = count.parent_entity_dequeue.saturating_add(1);
}

pub(crate) fn record_frame_task_group_current_compete(
    task_group_id: FrameTaskGroupId,
    requeued: bool,
) {
    let mut counts = FRAME_TASK_GROUP_BIND_COUNTS.lock();
    let count = counts.entry(task_group_id).or_default();
    count.current_compete = count.current_compete.saturating_add(1);
    if requeued {
        count.current_requeue = count.current_requeue.saturating_add(1);
    }
}

pub(crate) fn record_frame_task_group_current_dequeue_empty(task_group_id: FrameTaskGroupId) {
    let mut counts = FRAME_TASK_GROUP_BIND_COUNTS.lock();
    let count = counts.entry(task_group_id).or_default();
    count.current_dequeue_empty = count.current_dequeue_empty.saturating_add(1);
}

pub(crate) fn record_frame_task_group_queued_dequeue_empty(task_group_id: FrameTaskGroupId) {
    let mut counts = FRAME_TASK_GROUP_BIND_COUNTS.lock();
    let count = counts.entry(task_group_id).or_default();
    count.queued_dequeue_empty = count.queued_dequeue_empty.saturating_add(1);
}

fn guest_sched_policy(task_group_id: Option<FrameTaskGroupId>) -> SchedPolicy {
    let nice = task_group_id
        .and_then(aster_framevisor::frame_task_group_nice_hint)
        .and_then(|nice| Nice::try_from(nice).ok())
        .unwrap_or_default();
    SchedPolicy::Fair(nice)
}

fn iht_host_sched_policy() -> SchedPolicy {
    SchedPolicy::Fair(Nice::default())
}

fn virtual_irq_boost_sched_policy() -> SchedPolicy {
    SchedPolicy::Fair(Nice::MIN)
}

fn apply_frame_task_group_sched_policy(task: &Arc<OstdTask>, task_group_id: FrameTaskGroupId) {
    if task.extension().downcast_ref::<IhtTaskData>().is_some()
        || is_framevm_task_priority_boosted(task)
    {
        return;
    }

    let Some(thread) = task.as_thread() else {
        return;
    };
    thread
        .sched_attr()
        .set_policy(guest_sched_policy(Some(task_group_id)));
}

pub fn update_frame_task_group_sched_policy(task_group_id: FrameTaskGroupId) {
    FRAME_TASK_GROUP_SHARE_UPDATE_COUNT.fetch_add(1, Ordering::Relaxed);
    let Some(task_group) = scheduler_task_group_for_frame_task_group(task_group_id) else {
        return;
    };
    task_group.update_weight(scheduler_weight_for_frame_task_group(task_group_id));

    for task in aster_framevisor::task::ostd_tasks_in_frame_task_group(task_group_id) {
        let Some(thread) = task.as_thread() else {
            continue;
        };
        if task.extension().downcast_ref::<IhtTaskData>().is_some()
            || is_framevm_task_priority_boosted(&task)
        {
            thread.sched_attr().set_policy(iht_host_sched_policy());
        } else {
            thread
                .sched_attr()
                .set_policy(guest_sched_policy(Some(task_group_id)));
        }
        thread.set_task_group(task_group.clone());
    }
}

pub(crate) fn frame_task_group_host_sched_snapshot(
    task_group_id: FrameTaskGroupId,
    share: u32,
) -> Option<FrameTaskGroupHostSchedSnapshot> {
    let task_group = FRAME_TASK_GROUPS
        .lock()
        .get(&task_group_id)
        .cloned()
        .or_else(|| scheduler_task_group_for_frame_task_group(task_group_id))?;
    let (actual_weight, vruntime) = task_group
        .debug_fair_state(ostd::cpu::CpuId::bsp())
        .unwrap_or_default();
    let mut bound_task_count = 0;
    let mut scheduler_bound_task_count = 0;

    for task in aster_framevisor::task::ostd_tasks_in_frame_task_group(task_group_id) {
        let Some(thread) = task.as_thread() else {
            continue;
        };

        bound_task_count += 1;
        if Arc::ptr_eq(&thread.task_group(), &task_group) {
            scheduler_bound_task_count += 1;
        }
    }

    let bind_counts = FRAME_TASK_GROUP_BIND_COUNTS
        .lock()
        .get(&task_group_id)
        .copied()
        .unwrap_or_default();

    Some(FrameTaskGroupHostSchedSnapshot {
        weight: scheduler_weight_for_share(share),
        actual_weight,
        vruntime,
        bound_task_count,
        scheduler_bound_task_count,
        bind_count: bind_counts.total,
        service_bind_count: bind_counts.service,
        iht_bind_count: bind_counts.iht,
        schedule_in_bound_count: bind_counts.schedule_in_bound,
        schedule_in_unbound_count: bind_counts.schedule_in_unbound,
        parent_pick_count: bind_counts.parent_pick,
        parent_pick_with_any_peer_count: bind_counts.parent_pick_with_any_peer,
        parent_pick_with_peer_count: bind_counts.parent_pick_with_peer,
        parent_pick_child_empty_count: bind_counts.parent_pick_child_empty,
        parent_pick_empty_no_task_count: bind_counts.parent_pick_empty_no_task,
        parent_entity_dequeue_count: bind_counts.parent_entity_dequeue,
        current_compete_count: bind_counts.current_compete,
        current_requeue_count: bind_counts.current_requeue,
        current_dequeue_empty_count: bind_counts.current_dequeue_empty,
        queued_dequeue_empty_count: bind_counts.queued_dequeue_empty,
        share_update_count: FRAME_TASK_GROUP_SHARE_UPDATE_COUNT.load(Ordering::Relaxed),
    })
}

pub(crate) fn active_frame_scheduler_task_groups() -> Vec<Arc<TaskGroup>> {
    FRAME_TASK_GROUPS.lock().values().cloned().collect()
}

pub fn set_frame_task_group_cpu_affinity(task_group_id: FrameTaskGroupId, affinity: CpuSet) {
    FRAME_TASK_GROUP_CPU_AFFINITIES
        .lock()
        .insert(task_group_id, affinity.clone());

    for task in aster_framevisor::task::ostd_tasks_in_frame_task_group(task_group_id) {
        let Some(thread) = task.as_thread() else {
            continue;
        };
        thread
            .atomic_cpu_affinity()
            .store(&affinity, Ordering::Release);
    }
}

pub fn clear_frame_task_group_cpu_affinity_overrides() {
    FRAME_TASK_GROUP_CPU_AFFINITIES.lock().clear();
}

pub fn bind_current_thread_to_frame_task_group(task_group_id: FrameTaskGroupId) {
    let Some(current) = OstdTask::current() else {
        return;
    };
    bind_task_to_scheduler_group(&current.cloned(), task_group_id);
}

pub fn clear_current_thread_frame_task_group() {
    let Some(current) = OstdTask::current() else {
        return;
    };
    let task = current.cloned();
    let Some(thread) = task.as_thread() else {
        return;
    };
    thread.set_task_group(sched::root_task_group().clone());
}

pub fn init() {
    inject_task_creator(create_framevm_task);
    inject_task_group_binder(bind_framevm_task_group);
    inject_priority_booster(boost_framevm_task_priority);
    inject_frame_task_group_share_updater(update_frame_task_group_sched_policy);
    aster_framevisor::iht::register_iht_creator(create_iht_task);
    // Note: start_all() is called from aster_framevisor::start_framevm()
    // after IHT and vsock are properly initialized
}
