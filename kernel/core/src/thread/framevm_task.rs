// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, sync::Arc};
use core::{any::Any, sync::atomic::Ordering};

use aster_framevisor::{
    FrameVcpuId,
    irq::{self, InterruptHandler},
    task::{self, FrameTaskData, FrameTaskKind},
};
use ostd::{
    cpu::CpuSet,
    task::{Task as OstdTask, TaskOptions},
};

use crate::{
    sched::{Nice, SchedPolicy},
    thread::{AsThread, Thread},
};

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
            (),
            affinity,
            SchedPolicy::Fair(Nice::default()),
        ));

        TaskOptions::new(func)
            .data(thread)
            .extension_any(extension)
            .local_data_any(local_data)
            .build()
            .unwrap()
    }))
}

fn create_interrupt_task(
    handler: Arc<InterruptHandler>,
) -> Result<Arc<OstdTask>, aster_framevisor::Error> {
    use crate::thread::kernel_thread::ThreadOptions;

    let frame_vcpu_id = handler.frame_vcpu_id();
    let frame_vm = aster_framevisor::vm::get_vm_by_id(frame_vcpu_id.vm_id())
        .expect("interrupt handler must belong to a live FrameVM");
    let sched_group = handler
        .group()
        .expect("interrupt handler must be bound to a group");
    let thread_fn = move || irq::interrupt_handler_main(handler);
    let affinity = cpu_affinity_for_host_cpu(sched_group.host_cpu());

    let task = ThreadOptions::new(thread_fn)
        .cpu_affinity(affinity)
        .sched_policy(SchedPolicy::Fair(Nice::default()))
        .extension(FrameTaskData::try_new(
            &frame_vm,
            &sched_group,
            FrameTaskKind::Interrupt,
            Box::new(()),
            Box::new(()),
        )?)
        .build();
    let _ = task::bind_vcpu_runtime(task.clone(), frame_vcpu_id);

    Ok(task)
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
    if task
        .extension()
        .downcast_ref::<FrameTaskData>()
        .is_none_or(|data| data.kind() != FrameTaskKind::Interrupt)
    {
        thread
            .sched_attr()
            .set_policy(SchedPolicy::Fair(Nice::default()));
    }
    let affinity = frame_sched_group_cpu_affinity(Some(frame_vcpu_id));
    thread
        .atomic_cpu_affinity()
        .store(&affinity, Ordering::Release);
}

fn frame_sched_group_cpu_affinity(frame_vcpu_id: Option<FrameVcpuId>) -> CpuSet {
    let Some(frame_vcpu_id) = frame_vcpu_id else {
        return CpuSet::new_full();
    };
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

pub(super) fn init() {
    task::inject_host_task_ops(create_framevm_task, bind_framevm_task_to_vcpu);
    irq::register_interrupt_task_creator(create_interrupt_task);
    // FrameVM::start() starts the interrupt handlers after the VM and Sock
    // state are initialized.
}
