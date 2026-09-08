// SPDX-License-Identifier: MPL-2.0

//! Exact-main scheduling transitions for Frame tasks.
//!
//! The injected Frame scheduler owns every enqueue, update, dequeue, and
//! pick.  This module mirrors OSTD's generic control flow and replaces only
//! its final `processor::switch_to_task` call with the nested processor seam.
//! In particular, it never asks the Host scheduler to choose, wait, yield, or
//! exit on behalf of an inner task.

use alloc::sync::Arc;

use super::{EnqueueFlags, LocalRunQueue, UpdateFlags};
use crate::{
    task::{self, Task},
    vm::FrameVcpuId,
};

/// Enqueues a newly built Frame task with the exact `Spawn` protocol.
pub(crate) fn run_task(runnable: &Arc<Task>) {
    let state = runnable.state().clone();
    let scheduler = state
        .frame_vm()
        .scheduler()
        .expect("a runnable Frame task must retain its injected scheduler");

    if let Some(preempt_cpu) = scheduler.enqueue(runnable.clone(), EnqueueFlags::Spawn) {
        request_virtual_preemption(&state, preempt_cpu);
    }
    // As in main, spawn reaches the current virtual CPU's ordinary
    // preemption point after publication.  A remote target keeps its request
    // until that vCPU is resumed by its outer group/doorbell mechanism.
    might_preempt();
}

/// Enqueues a woken Frame task with the exact `Wake` protocol.
pub(crate) fn unpark_target(runnable: Arc<Task>) {
    let state = runnable.state().clone();
    let scheduler = state
        .frame_vm()
        .scheduler()
        .expect("a Frame waiter must retain its injected scheduler until wake");

    if let Some(preempt_cpu) = scheduler.enqueue(runnable, EnqueueFlags::Wake) {
        request_virtual_preemption(&state, preempt_cpu);
    }
}

/// Executes main OSTD's `might_preempt` algorithm for the running virtual
/// CPU.  A Frame scheduler's preemption bit is distinct from the Host's bit.
pub(crate) fn might_preempt() {
    let Some(current) = task::current_task_for_scheduler() else {
        return;
    };
    let Some(group) = running_group(&current) else {
        return;
    };
    if !group.take_inner_preempt() {
        return;
    }

    reschedule(|local_rq| match local_rq.try_pick_next() {
        Some(next_task) => ReschedAction::SwitchTo(next_task.clone()),
        None => ReschedAction::DoNothing,
    });
}

/// Applies main OSTD's `Task::yield_now` transition.
pub(crate) fn yield_current() {
    reschedule(|local_rq| {
        let should_pick_next = local_rq.update_current(UpdateFlags::Yield);
        if should_pick_next {
            // `update_current` promises that a successor is available.
            ReschedAction::SwitchTo(local_rq.pick_next().clone())
        } else {
            ReschedAction::DoNothing
        }
    });
}

/// Applies main OSTD's lost-wakeup-safe `park_current` transition.
pub(crate) fn park_current<F>(has_unparked: F)
where
    F: Fn() -> bool,
{
    let mut current = None;
    let mut is_first_try = true;

    reschedule(|local_rq| {
        let next_task = if is_first_try {
            if has_unparked() {
                return ReschedAction::DoNothing;
            }
            is_first_try = false;

            // The final predicate check, `Wait` update, and dequeue are
            // serialized by this same exact local runqueue.  `Wake` can only
            // enqueue after the dequeue has become visible.
            let should_pick_next = local_rq.update_current(UpdateFlags::Wait);
            current = local_rq.dequeue_current();
            should_pick_next.then(|| local_rq.pick_next().clone())
        } else {
            local_rq.try_pick_next().cloned()
        };

        match next_task {
            Some(next_task) if Arc::ptr_eq(current.as_ref().unwrap(), &next_task) => {
                ReschedAction::DoNothing
            }
            Some(next_task) => ReschedAction::SwitchTo(next_task),
            None => ReschedAction::Retry,
        }
    });
}

/// Applies main OSTD's non-returning current-task exit transition.
///
/// A normal inner exit selects another Frame task and crosses the nested
/// processor boundary. If a stopping vCPU has no successor, its bootstrap
/// continuation is the final carrier of the outer group. Release that exact
/// continuation before asking OSTD to retire the carrier as an ordinary Host
/// task; otherwise the Host scheduler could pick the already-finished Frame
/// carrier again.
pub(crate) fn exit_current_task() -> ! {
    let current = task::current_task_for_scheduler()
        .expect("a FrameVM task entry must retain a current Frame task until exit");
    clear_virtual_preemption(&current);

    let scheduler = current
        .state()
        .frame_vm()
        .scheduler()
        .expect("a running FrameVM task must retain its exact scheduler");
    let mut next_task = None;
    scheduler.mut_local_rq_with(&mut |local_rq| {
        let should_pick_next = local_rq.update_current(UpdateFlags::Exit);
        let _current = local_rq.dequeue_current();
        next_task = should_pick_next.then(|| local_rq.pick_next().clone());
    });

    if let Some(next_task) = next_task {
        switch_selected(current, next_task);
        unreachable!("an exited FrameVM task must never resume");
    }

    assert!(
        current.state().frame_vm().status() == crate::vm::VmStatus::Stopping,
        "a live FrameVM vCPU must retain an inner successor after task exit"
    );
    let group = running_group(&current)
        .expect("the final FrameVM task must retain its exact outer group");
    let released = group
        .release_committed_continuation(&current)
        .expect("the final FrameVM task must release its exact outer continuation");
    assert!(
        Arc::ptr_eq(&released, &current),
        "the final FrameVM task must release itself as the outer continuation"
    );
    // OSTD task exit does not unwind this stack. Release every temporary
    // Frame-task owner before entering the Host exit path so the service-image
    // lease can drain once the processor drops the previous carrier.
    drop(released);
    drop(group);
    drop(current);
    host_ostd::task::__private::exit_current_task();
}

/// Mirrors OSTD's `reschedule` helper with a Frame processor backend.
fn reschedule<F>(mut decide: F)
where
    F: FnMut(&mut dyn LocalRunQueue<Task>) -> ReschedAction,
{
    let Some(current) = task::current_task_for_scheduler() else {
        return;
    };
    clear_virtual_preemption(&current);
    let scheduler = current
        .state()
        .frame_vm()
        .scheduler()
        .expect("a FrameVM task entry must retain the injected scheduler for its lifetime");

    let next_task = loop {
        let mut action = ReschedAction::DoNothing;
        scheduler.mut_local_rq_with(&mut |local_rq| {
            action = decide(local_rq);
        });
        match action {
            ReschedAction::DoNothing => return,
            ReschedAction::Retry => continue,
            ReschedAction::SwitchTo(next_task) => break next_task,
        }
    };

    if !Arc::ptr_eq(&current, &next_task) {
        switch_selected(current, next_task);
    }
}

/// Stages a completed inner A -> B choice and crosses the processor boundary.
fn switch_selected(from: Arc<Task>, to: Arc<Task>) {
    let group = running_group(&from)
        .expect("an exact inner switch requires the current outer FrameSchedGroup");
    let target_cpu = to
        .schedule_info()
        .cpu
        .get()
        .expect("an inner-selected FrameVM task must have a virtual CPU");
    let target = FrameVcpuId::new(to.state().frame_vm().id(), target_cpu.as_usize());
    assert_eq!(
        target,
        group.id(),
        "an exact local runqueue may only select its owning vCPU's task"
    );

    group
        .stage_continuation_switch(&from, to.clone())
        .expect("one FrameVM vCPU may stage only its exact current switch");
    let to_host = to.ostd_task().clone();
    // A direct processor switch never unwinds the source stack. The group
    // owns both sides of the staged transition, so these temporary handles
    // must be released before crossing that boundary; otherwise an exited
    // service task would retain its image lease forever.
    drop(to);
    drop(from);
    host_ostd::task::__private::switch_to_task_with_pre_switch(to_host, |guard| {
        // Logical PRE is owned by this direct A -> B processor entry;
        // ordinary Host suspension of the outer group never reaches it.
        let _ = crate::task::dispatch_pre_schedule(guard);
    });
}

fn request_virtual_preemption(state: &crate::task::FrameTaskState, cpu: crate::cpu::CpuId) {
    if let Some(group) = state.frame_vm().sched_group(cpu.as_usize()) {
        group.request_inner_preempt();
    }
}

fn clear_virtual_preemption(current: &Arc<Task>) {
    if let Some(group) = running_group(current) {
        let _ = group.take_inner_preempt();
    }
}

fn running_group(current: &Arc<Task>) -> Option<Arc<crate::vm::FrameSchedGroup>> {
    let current_id = task::current_frame_vcpu_id()?;
    let frame_vm = current.state().frame_vm();
    (current_id.vm_id() == frame_vm.id())
        .then(|| frame_vm.sched_group(current_id.vcpu_index()).cloned())
        .flatten()
}

enum ReschedAction {
    DoNothing,
    Retry,
    SwitchTo(Arc<Task>),
}
