// SPDX-License-Identifier: MPL-2.0

//! Task scheduler injection.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use host_ostd::{cpu::PinCurrentCpu, sync::RwLock, task::disable_preempt, timer};

pub mod info;

#[cfg(not(feature = "host-api"))]
use vm::{FrameTaskGroupId, VmId};

use super::Task;
#[cfg(not(feature = "host-api"))]
use crate::service_domain as vm;
#[cfg(feature = "host-api")]
use crate::vm::{self, FrameTaskGroupId, VmId};
use crate::{cpu::CpuId, iht, prelude::Result};

#[derive(Clone, Copy, Debug)]
pub(crate) struct VirtualInterruptToken {
    task_group_id: FrameTaskGroupId,
}

impl VirtualInterruptToken {
    fn new(task_group_id: FrameTaskGroupId) -> Self {
        Self { task_group_id }
    }
}

/// Flags that explain why a task is enqueued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnqueueFlags {
    /// A task became runnable after creation.
    Spawn,
    /// A task became runnable after a wake operation.
    Wake,
}

/// Flags that explain why the current task is being updated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateFlags {
    /// The current task voluntarily yielded.
    Yield,
    /// The current task is about to wait.
    Wait,
    /// A timer tick arrived.
    Tick,
    /// The current task is exiting.
    Exit,
}

/// A SMP-aware task scheduler.
pub trait Scheduler<T = Task>: Send + Sync {
    /// Enqueues a runnable task.
    fn enqueue(&self, runnable: Arc<T>, flags: EnqueueFlags) -> Option<CpuId>;

    /// Gives immutable access to the local runqueue of the current CPU.
    fn local_rq_with(&self, f: &mut dyn FnMut(&dyn LocalRunQueue<T>));

    /// Gives mutable access to the local runqueue of the current CPU.
    fn mut_local_rq_with(&self, f: &mut dyn FnMut(&mut dyn LocalRunQueue<T>));
}

/// A per-CPU local runqueue.
pub trait LocalRunQueue<T = Task> {
    /// Returns the current task, if any.
    fn current(&self) -> Option<&Arc<T>>;

    /// Updates the current task and returns whether another task should run.
    fn update_current(&mut self, flags: UpdateFlags) -> bool;

    /// Picks the next task to run.
    fn pick_next(&mut self) -> &Arc<T> {
        self.try_pick_next().unwrap()
    }

    /// Tries to pick the next task to run.
    fn try_pick_next(&mut self) -> Option<&Arc<T>>;

    /// Removes the current task from this runqueue.
    fn dequeue_current(&mut self) -> Option<Arc<T>>;
}

static SERVICE_SCHEDULERS: RwLock<BTreeMap<VmId, &'static dyn Scheduler<Task>>> =
    RwLock::new(BTreeMap::new());
static VIRTUAL_TIMER_DRIVER_CPUS: RwLock<BTreeSet<usize>> = RwLock::new(BTreeSet::new());

/// Injects a task scheduler.
pub fn inject_scheduler(scheduler: &'static dyn Scheduler<Task>) {
    let vm_id = current_vm_id().expect("scheduler injection requires a current task context");
    let mut service_schedulers = SERVICE_SCHEDULERS.write();
    assert!(
        service_schedulers.insert(vm_id, scheduler).is_none(),
        "a scheduler has already been initialized"
    );
}

pub(crate) fn clear_scheduler() {
    if let Some(vm_id) = current_vm_id() {
        clear_scheduler_for_vm(vm_id);
    } else {
        SERVICE_SCHEDULERS.write().clear();
    }
}

pub(crate) fn clear_scheduler_for_vm(vm_id: VmId) {
    SERVICE_SCHEDULERS.write().remove(&vm_id);
}

/// Enables timer-driven preemption on the current CPU.
#[cfg(feature = "host-api")]
pub fn enable_preemption_on_cpu() {
    init_virtual_timer_on_current_cpu();
}

/// Enables timer-driven preemption on the current virtual CPU.
#[cfg(not(feature = "host-api"))]
pub fn enable_preemption_on_cpu() {}

/// Returns the current virtual CPU.
pub(crate) fn current_cpu() -> Option<CpuId> {
    let task_group_id = super::current_frame_task_group_id()?;
    Some(CpuId::from_raw(task_group_id.vcpu_id() as u32))
}

pub(crate) fn enqueue_task(runnable: Arc<Task>, flags: EnqueueFlags) -> Result<()> {
    let vm_id = vm_id_for_task_or_current(&runnable).ok_or(crate::Error::InvalidArgs)?;
    let scheduler = scheduler_for_vm(vm_id);
    let target_cpu = scheduler
        .and_then(|scheduler| scheduler.enqueue(runnable.clone(), flags))
        .or_else(|| runnable.try_schedule_info().and_then(|info| info.cpu.get()))
        .or_else(|| current_cpu())
        .unwrap_or_else(CpuId::bsp);

    let task_group_id =
        frame_task_group_id_for_cpu(vm_id, target_cpu).ok_or(crate::Error::InvalidArgs)?;
    super::bind_service_task_group_runtime(runnable.ostd_task().clone(), task_group_id)
}

/// Blocks the current service task unless `has_unparked` already observes a wake event.
///
/// Returns whether the service scheduler actually dequeued the current task. A caller that also
/// blocks the backing host task must only do so after the service task has really been parked.
pub(crate) fn park_current(has_unparked: impl Fn() -> bool) -> bool {
    if has_unparked() {
        return false;
    }

    let Some(scheduler) = scheduler_for_current_vm() else {
        Task::yield_now();
        return false;
    };

    let mut parked = false;
    scheduler.mut_local_rq_with(&mut |rq| {
        if has_unparked() {
            return;
        }

        let should_pick_next = rq.update_current(UpdateFlags::Wait);
        parked = rq.dequeue_current().is_some();
        if should_pick_next {
            let _ = rq.try_pick_next();
        }
    });
    parked
}

/// Makes a parked task runnable again.
pub(crate) fn unpark_target(runnable: Arc<Task>) {
    let _ = enqueue_task(runnable.clone(), EnqueueFlags::Wake);
    runnable.ostd_task().wake_up();
}

fn frame_task_group_id_for_cpu(vm_id: VmId, cpu_id: CpuId) -> Option<FrameTaskGroupId> {
    let vm = vm::get_vm_by_id(vm_id)?;
    vm.task_group(cpu_id.as_usize())
        .map(|task_group| task_group.id())
}

fn current_vm_id() -> Option<VmId> {
    super::current_frame_task_group_id().map(|task_group_id| task_group_id.vm_id())
}

fn scheduler_for_vm(vm_id: VmId) -> Option<&'static dyn Scheduler<Task>> {
    SERVICE_SCHEDULERS.read().get(&vm_id).copied()
}

fn scheduler_for_current_vm() -> Option<&'static dyn Scheduler<Task>> {
    scheduler_for_vm(current_vm_id()?)
}

fn vm_id_for_task_or_current(task: &Arc<Task>) -> Option<VmId> {
    super::task_group_id_for_task(task.ostd_task())
        .or_else(super::current_frame_task_group_id)
        .map(|task_group_id| task_group_id.vm_id())
}

/// Returns whether a host-backed local runqueue has pending scheduler work.
pub(crate) fn frame_task_group_needs_resched(task_group_id: FrameTaskGroupId) -> bool {
    vm::get_task_group_by_id(task_group_id).is_some_and(|task_group| task_group.needs_resched())
        || iht::has_pending_work(task_group_id)
}

/// Returns whether local interrupts are enabled for a host-backed runqueue.
pub(crate) fn frame_task_group_virtual_interrupts_enabled(task_group_id: FrameTaskGroupId) -> bool {
    iht::virtual_interrupts_enabled(task_group_id)
}

#[cfg(feature = "host-api")]
pub(crate) fn frame_task_group_current_ostd_task(
    task_group_id: FrameTaskGroupId,
) -> Option<Arc<host_ostd::task::Task>> {
    let current = host_ostd::task::Task::current()?.cloned();
    (super::task_group_id_for_task(&current) == Some(task_group_id)).then_some(current)
}

pub(crate) fn enter_virtual_interrupt_disabled_section() -> Option<VirtualInterruptToken> {
    let task_group_id = super::current_task_group_for_virtual_interrupt()?;
    iht::disable_virtual_interrupts(task_group_id);
    Some(VirtualInterruptToken::new(task_group_id))
}

pub(crate) fn exit_virtual_interrupt_disabled_section(token: VirtualInterruptToken) {
    iht::enable_virtual_interrupts(token.task_group_id);
}

fn register_virtual_timer_callback_on_current_cpu() {
    timer::register_callback_on_cpu(|| {
        let _ = inject_virtual_timer_tick_for_current_task_group();
    });
}

fn inject_virtual_timer_tick_for_current_task_group() -> bool {
    let Some(task_group_id) = super::current_task_group_for_timer_tick() else {
        return false;
    };

    let Some(task_group) = vm::get_task_group_by_id(task_group_id) else {
        return false;
    };
    task_group.inject_timer_tick();
    true
}

pub(crate) fn init_virtual_timer_on_current_cpu() {
    let preempt_guard = disable_preempt();
    let host_cpu_id = u32::from(preempt_guard.current_cpu()) as usize;

    {
        let mut registered_cpus = VIRTUAL_TIMER_DRIVER_CPUS.write();
        if !registered_cpus.insert(host_cpu_id) {
            return;
        }
    }

    register_virtual_timer_callback_on_current_cpu();
}

#[cfg(ktest)]
pub(crate) fn clear_virtual_timer_driver_registered_cpus_for_test() {
    VIRTUAL_TIMER_DRIVER_CPUS.write().clear();
}

#[cfg(ktest)]
pub(crate) fn try_register_virtual_timer_driver_cpu_for_test(host_cpu_id: usize) -> bool {
    VIRTUAL_TIMER_DRIVER_CPUS.write().insert(host_cpu_id)
}

#[cfg(ktest)]
pub(crate) fn virtual_timer_driver_has_registered_cpu_for_test(host_cpu_id: usize) -> bool {
    VIRTUAL_TIMER_DRIVER_CPUS.read().contains(&host_cpu_id)
}

pub(crate) fn dispatch_timer_ticks(task_group_id: FrameTaskGroupId, ticks: u64) {
    if ticks == 0 {
        return;
    }

    crate::timer::advance_timer_ticks(task_group_id, ticks);
    let Some(scheduler) = scheduler_for_vm(task_group_id.vm_id()) else {
        crate::timer::dispatch_registered_callbacks(task_group_id, ticks);
        return;
    };

    dispatch_ticks_on_scheduler(scheduler, task_group_id, ticks);
    #[cfg(feature = "host-api")]
    super::wake_service_tasks_in_frame_task_group(task_group_id);
    crate::timer::dispatch_registered_callbacks(task_group_id, ticks);
}

fn dispatch_ticks_on_scheduler(
    scheduler: &'static dyn Scheduler<Task>,
    task_group_id: FrameTaskGroupId,
    ticks: u64,
) {
    let target_cpu = CpuId::from_raw(task_group_id.vcpu_id() as u32);

    let current_cpu_matches = current_cpu().is_none_or(|cpu_id| cpu_id == target_cpu);
    if current_cpu_matches {
        scheduler.mut_local_rq_with(&mut |rq| dispatch_ticks_on_runqueue(rq, ticks));
    }
}

fn dispatch_ticks_on_runqueue(rq: &mut dyn LocalRunQueue<Task>, ticks: u64) {
    for _ in 0..ticks {
        let _ = rq.update_current(UpdateFlags::Tick);
    }
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn virtual_timer_driver_registration_is_per_host_cpu() {
        clear_virtual_timer_driver_registered_cpus_for_test();

        assert!(try_register_virtual_timer_driver_cpu_for_test(0));
        assert!(!try_register_virtual_timer_driver_cpu_for_test(0));
        assert!(try_register_virtual_timer_driver_cpu_for_test(1));
        assert!(virtual_timer_driver_has_registered_cpu_for_test(0));
        assert!(virtual_timer_driver_has_registered_cpu_for_test(1));

        clear_virtual_timer_driver_registered_cpus_for_test();
    }
}
