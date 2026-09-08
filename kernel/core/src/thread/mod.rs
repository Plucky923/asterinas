// SPDX-License-Identifier: MPL-2.0

//! Posix thread implementation

use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use aster_util::per_cpu_counter::PerCpuCounter;
use ostd::{
    cpu::{AtomicCpuSet, CpuId, CpuSet},
    irq::DisabledLocalIrqGuard,
    sync::Rcu,
    task::Task,
};
use spin::Once;

use crate::{
    prelude::*,
    sched::{self, SchedAttr, SchedPolicy, TaskGroup},
};
mod stats;
use stats::CONTEXT_SWITCH_COUNTER;
pub(crate) use stats::collect_context_switch_count;
pub(crate) mod exception;
mod framevm_task;
pub(crate) mod kernel_thread;
pub(crate) mod oops;
pub(crate) mod task;
pub(crate) mod work_queue;

pub(crate) type Tid = u32;

fn pre_schedule_handler(irq_guard: &DisabledLocalIrqGuard) {
    let Some(task) = Task::current() else {
        return;
    };
    if task
        .as_thread()
        .is_some_and(|thread| thread.framevm_task_state().is_some())
    {
        aster_framevisor::task::dispatch_physical_pre_schedule(irq_guard);
        return;
    }
    let Some(thread_local) = task.as_thread_local() else {
        return;
    };

    thread_local.supp_user_context().before_schedule(irq_guard);
}

fn post_schedule_handler() {
    let task = Task::current().expect("scheduled context must have a current task");
    let carrier = task.cloned();
    if let Some(state) = task
        .as_thread()
        .and_then(|thread| thread.framevm_task_state())
    {
        // Continuation classification reads FrameSchedGroup state protected by
        // virtual-preemption locks. Publish the projection for this exact
        // current carrier first so those locks have a vCPU identity; the
        // classifier immediately below still verifies that the carrier is the
        // committed or staged continuation of the current outer group.
        aster_framevisor::task::install_current_task(&carrier, state);
        match sched::classify_framevm_continuation_arrival(&carrier, state) {
            sched::FrameContinuationArrival::Committed => {
                // This is B's first post-switch action. Only the direct nested
                // processor path can satisfy the exact pending pair, so only it
                // installs the logical Frame current and dispatches logical POST.
                let _ = aster_framevisor::task::dispatch_post_schedule();
            }
            sched::FrameContinuationArrival::OuterResume => {
                // An ordinary Host resume returns to the already-committed A.
                // It restores only private physical Frame runtime state and must
                // not look like a logical service task switch.
                aster_framevisor::task::dispatch_physical_post_schedule();
            }
        }
        CONTEXT_SWITCH_COUNTER
            .get()
            .unwrap()
            .add_on_cpu(CpuId::current_racy(), 1);
        return;
    }
    aster_framevisor::task::clear_current_task();

    // No races because preemption shouldn't happen in post-schedule handlers.
    CONTEXT_SWITCH_COUNTER
        .get()
        .unwrap()
        .add_on_cpu(CpuId::current_racy(), 1);

    let Some(thread_local) = task.as_thread_local() else {
        return;
    };

    let vmar = thread_local.vmar().borrow();
    if let Some(vmar) = vmar.as_ref() {
        vmar.vm_space().activate()
    }
}

pub(super) fn init() {
    CONTEXT_SWITCH_COUNTER.call_once(PerCpuCounter::new);
    ostd::task::inject_pre_schedule_handler(pre_schedule_handler);
    ostd::task::inject_post_schedule_handler(post_schedule_handler);
    ostd::mm::fault::inject_user_page_fault_handler(exception::page_fault_handler);
    framevm_task::init();
}

/// A thread is a wrapper on top of task.
pub(crate) struct Thread {
    // immutable part
    /// Low-level info
    ///
    /// The ordinary constructors bind this while constructing the thread. FrameVM
    /// carriers bind it after their fallible OSTD task construction succeeds, but
    /// before the task can be published to a scheduler.
    task: Once<Weak<Task>>,
    /// Data: Posix thread info/Kernel thread Info
    data: Box<dyn Send + Sync + Any>,

    // mutable part
    /// Thread status
    is_exited: AtomicBool,
    /// Thread CPU affinity
    cpu_affinity: AtomicCpuSet,
    sched_attr: SchedAttr,
    /// The task group this thread belongs to.
    task_group: Rcu<Arc<TaskGroup>>,
}

impl Debug for Thread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Thread")
            .field("is_exited", &self.is_exited)
            .field("cpu_affinity", &self.cpu_affinity)
            .field("sched_attr", &self.sched_attr)
            .finish_non_exhaustive()
    }
}

impl Thread {
    /// Never call these function directly
    pub(crate) fn new(
        task: Weak<Task>,
        data: impl Send + Sync + Any,
        cpu_affinity: CpuSet,
        sched_policy: SchedPolicy,
    ) -> Self {
        let thread = Self::new_unbound(data, cpu_affinity, sched_policy);
        thread.bind_task(task);
        thread
    }

    /// Creates a thread whose task is not bound yet.
    ///
    /// This is only for a task constructor that must first complete a fallible
    /// OSTD task build. The caller must bind the returned thread before making
    /// that task reachable by the scheduler or any other concurrent observer.
    fn new_unbound(
        data: impl Send + Sync + Any,
        cpu_affinity: CpuSet,
        sched_policy: SchedPolicy,
    ) -> Self {
        Thread {
            task: Once::new(),
            data: Box::new(data),
            is_exited: AtomicBool::new(false),
            cpu_affinity: AtomicCpuSet::new(cpu_affinity),
            sched_attr: SchedAttr::new(sched_policy),
            task_group: Rcu::new(sched::root_task_group().clone()),
        }
    }

    /// Binds the OSTD task exactly once during construction.
    fn bind_task(&self, task: Weak<Task>) {
        let mut is_new = false;
        self.task.call_once(|| {
            is_new = true;
            task
        });
        assert!(is_new, "a thread task may only be bound once");
    }

    /// Returns the current thread.
    ///
    /// This function returns `None` if the current task is not associated with
    /// a thread, or if called within the bootstrap context.
    pub(crate) fn current() -> Option<Arc<Self>> {
        Task::current()?.as_thread().cloned()
    }

    /// Returns the task associated with this thread.
    #[expect(dead_code)]
    pub(crate) fn task(&self) -> Arc<Task> {
        self.task
            .get()
            .expect("a thread task must be bound before use")
            .upgrade()
            .unwrap()
    }

    /// Runs this thread at once.
    #[track_caller]
    pub(crate) fn run(&self) {
        self.task
            .get()
            .expect("a thread task must be bound before use")
            .upgrade()
            .unwrap()
            .run();
    }

    /// Returns whether the thread is exited.
    pub(crate) fn is_exited(&self) -> bool {
        self.is_exited.load(Ordering::Acquire)
    }

    pub(super) fn exit(&self) {
        self.is_exited.store(true, Ordering::Release);
    }

    /// Returns the reference to the atomic CPU affinity.
    pub(crate) fn atomic_cpu_affinity(&self) -> &AtomicCpuSet {
        &self.cpu_affinity
    }

    pub(crate) fn sched_attr(&self) -> &SchedAttr {
        &self.sched_attr
    }

    /// Returns the task group this thread belongs to.
    pub fn task_group(&self) -> Arc<TaskGroup> {
        self.task_group.read().get().clone()
    }

    /// Sets the task group for this thread.
    pub(crate) fn set_task_group(&self, task_group: Arc<TaskGroup>) {
        self.task_group.update(task_group);
    }

    /// Yields the execution to another thread.
    ///
    /// This method will return once the current thread is scheduled again.
    #[track_caller]
    pub(crate) fn yield_now() {
        Task::yield_now()
    }

    /// Joins the execution of the thread.
    ///
    /// This method will return after the thread exits.
    #[cfg_attr(not(ktest), expect(dead_code))]
    #[track_caller]
    pub(crate) fn join(&self) {
        while !self.is_exited() {
            Self::yield_now();
        }
    }

    /// Returns the associated data.
    pub(crate) fn data(&self) -> &(dyn Send + Sync + Any) {
        &*self.data
    }
}

/// A trait to provide the `as_thread` method for tasks.
pub(crate) trait AsThread {
    /// Returns the associated [`Thread`].
    fn as_thread(&self) -> Option<&Arc<Thread>>;
}

impl AsThread for Task {
    fn as_thread(&self) -> Option<&Arc<Thread>> {
        self.data().downcast_ref::<Arc<Thread>>()
    }
}
