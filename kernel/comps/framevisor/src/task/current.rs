// SPDX-License-Identifier: MPL-2.0

//! The current FrameVM task projection.

use alloc::sync::{Arc, Weak};
use core::cell::RefCell;

use host_ostd::{irq, task::Task as OstdTask};

use super::{FrameTaskLocalData, FrameTaskState};

#[derive(Clone)]
struct CurrentFrameTask {
    carrier: Weak<OstdTask>,
    state: Weak<FrameTaskState>,
}

host_ostd::cpu_local! {
    static CURRENT_FRAME_TASK: RefCell<Option<CurrentFrameTask>> = RefCell::new(None);
}

/// Publishes the current FrameVM carrier after the Host context switch.
pub fn install_current_task(carrier: &Arc<OstdTask>, state: &Arc<FrameTaskState>) {
    let irq_guard = irq::disable_local();
    let current = CURRENT_FRAME_TASK.get_with(&irq_guard);
    *current.borrow_mut() = Some(CurrentFrameTask {
        carrier: Arc::downgrade(carrier),
        state: Arc::downgrade(state),
    });
}

/// Clears the current FrameVM projection after switching to an ordinary Host task.
pub fn clear_current_task() {
    let irq_guard = irq::disable_local();
    let current = CURRENT_FRAME_TASK.get_with(&irq_guard);
    *current.borrow_mut() = None;
}

/// Returns the state for `carrier` only when it is the current FrameVM carrier.
pub(crate) fn current_state(carrier: &Arc<OstdTask>) -> Option<Arc<FrameTaskState>> {
    let irq_guard = irq::disable_local();
    let current = CURRENT_FRAME_TASK.get_with(&irq_guard);
    if let Some(current) = current.borrow().clone()
        && let Some(projected_carrier) = current.carrier.upgrade()
        && Arc::ptr_eq(&projected_carrier, carrier)
        && let Some(state) = current.state.upgrade()
    {
        return Some(state);
    }

    // The projection is maintained around Host scheduler transitions, but a
    // Host-only path may clear it while this exact carrier is still running.
    // Local data travels with the carrier, so it is an exact (rather than
    // CPU-global) fallback for the FrameVM state during that transition.
    let current = OstdTask::current()?;
    Arc::ptr_eq(&current.cloned(), carrier)
        .then(|| current.local_data())
        .and_then(|local_data| local_data.downcast_ref::<FrameTaskLocalData>())
        .map(FrameTaskLocalData::state)
}

/// Returns the state of the current carrier, if it belongs to a FrameVM.
pub(crate) fn current_state_for_current_task() -> Option<Arc<FrameTaskState>> {
    let carrier = OstdTask::current()?.cloned();
    current_state(&carrier)
}

/// Returns the Frame task represented by the physically current carrier.
///
/// Unlike the service-visible [`crate::task::Task::current`], this preserves
/// the private bootstrap continuation. Scheduler composition needs that exact
/// continuation for the one bootstrap-to-idle processor handoff, while public
/// service code must continue to observe no current task during bootstrap.
pub(crate) fn current_task_for_scheduler() -> Option<Arc<super::Task>> {
    let carrier = OstdTask::current()?.cloned();
    let state = current_state(&carrier)?;
    Some(state.task(carrier))
}

/// Returns the FrameVM that owns the current FrameVM task.
pub(crate) fn current_frame_vm() -> Option<Arc<crate::vm::FrameVm>> {
    current_state_for_current_task().map(|state| state.frame_vm())
}

/// Returns the current FrameVM vCPU identity.
pub(crate) fn current_frame_vcpu_id() -> Option<crate::vm::FrameVcpuId> {
    current_state_for_current_task().and_then(|state| state.bound_frame_vcpu_id())
}
