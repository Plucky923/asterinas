// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc};
use core::{any::Any, sync::atomic::Ordering};

use aster_framevisor::{
    FrameVcpuId,
    iht::{self, IhtContext},
    task::{self, FrameTaskData, FrameTaskKind},
};
use ostd::{
    cpu::CpuSet,
    sync::SpinLock,
    task::{Task as OstdTask, TaskOptions},
};

use crate::{
    sched::{Nice, SchedPolicy},
    thread::{AsThread, Thread},
};

struct FrameVmThread;

static FRAMEVM_PRIORITY_BOOSTS: SpinLock<BTreeMap<usize, SchedPolicy>> =
    SpinLock::new(BTreeMap::new());

fn create_framevm_task(
    func: Box<dyn FnOnce() + Send>,
    extension: Box<dyn Any + Send + Sync>,
    local_data: Box<dyn Any + Send>,
    frame_vcpu_id: Option<FrameVcpuId>,
) -> Result<Arc<OstdTask>, aster_framevisor::Error> {
    let affinity = frame_sched_group_cpu_affinity(frame_vcpu_id);

    Ok(Arc::new_cyclic(|weak_task| {
        let thread = Arc::new(Thread::new(
            weak_task.clone(),
            FrameVmThread,
            affinity,
            guest_sched_policy(frame_vcpu_id),
        ));

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

    let frame_vcpu_id = ctx.frame_vcpu_id();
    let sched_group = ctx.group().expect("IHT context must be bound to a group");
    let policy = iht_host_sched_policy();
    let thread_fn = move || iht::iht_main_loop(ctx);
    let affinity = cpu_affinity_for_host_cpu(sched_group.host_cpu());

    let task = ThreadOptions::new(thread_fn)
        .cpu_affinity(affinity)
        .sched_policy(policy)
        .extension(FrameTaskData::new(&sched_group, FrameTaskKind::Iht))
        .build();
    bind_task_to_sched_group(&task, frame_vcpu_id);
    let _ = task::bind_ostd_task_to_frame_vcpu(task.clone(), frame_vcpu_id);

    task
}

fn bind_framevm_task_to_vcpu(
    task: Arc<OstdTask>,
    frame_vcpu_id: FrameVcpuId,
) -> Result<(), aster_framevisor::Error> {
    if task.as_thread().is_none() {
        return Err(aster_framevisor::Error::InvalidArgs);
    }

    bind_task_to_sched_group(&task, frame_vcpu_id);
    Ok(())
}

fn bind_task_to_sched_group(task: &Arc<OstdTask>, frame_vcpu_id: FrameVcpuId) {
    let Some(thread) = task.as_thread() else {
        return;
    };
    apply_frame_vcpu_sched_policy(task, frame_vcpu_id);
    let affinity = frame_sched_group_cpu_affinity(Some(frame_vcpu_id));
    thread
        .atomic_cpu_affinity()
        .store(&affinity, Ordering::Release);
}

fn frame_sched_group_cpu_affinity(frame_vcpu_id: Option<FrameVcpuId>) -> CpuSet {
    let Some(frame_vcpu_id) = frame_vcpu_id else {
        return CpuSet::new_full();
    };
    let frame_vcpu_id = FrameVcpuId::new(frame_vcpu_id.vm_id(), frame_vcpu_id.vcpu_index());
    let Some(group) = aster_framevisor::vm::get_sched_group_by_id(frame_vcpu_id) else {
        return CpuSet::new_full();
    };
    cpu_affinity_for_host_cpu(group.host_cpu())
}

fn cpu_affinity_for_host_cpu(cpu: ostd::cpu::CpuId) -> CpuSet {
    let mut affinity = CpuSet::new_empty();
    affinity.add(cpu);
    affinity
}

fn boost_framevm_task_priority(task: Arc<OstdTask>, boosted: bool) {
    if task::frame_task_kind_for_ostd_task(&task) == Some(FrameTaskKind::Iht) {
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

fn guest_sched_policy(frame_vcpu_id: Option<FrameVcpuId>) -> SchedPolicy {
    let _ = frame_vcpu_id;
    SchedPolicy::Fair(Nice::default())
}

fn iht_host_sched_policy() -> SchedPolicy {
    SchedPolicy::Fair(Nice::default())
}

fn virtual_irq_boost_sched_policy() -> SchedPolicy {
    SchedPolicy::Fair(Nice::MIN)
}

fn apply_frame_vcpu_sched_policy(task: &Arc<OstdTask>, frame_vcpu_id: FrameVcpuId) {
    if task::frame_task_kind_for_ostd_task(task) == Some(FrameTaskKind::Iht)
        || is_framevm_task_priority_boosted(task)
    {
        return;
    }

    let Some(thread) = task.as_thread() else {
        return;
    };
    thread
        .sched_attr()
        .set_policy(guest_sched_policy(Some(frame_vcpu_id)));
}

pub(super) fn init() {
    task::inject_task_creator(create_framevm_task);
    task::inject_vcpu_binder(bind_framevm_task_to_vcpu);
    task::inject_priority_booster(boost_framevm_task_priority);
    iht::register_iht_creator(create_iht_task);
    // Note: start_all() is called from aster_framevisor::start_framevm()
    // after IHT and vsock are properly initialized
}
