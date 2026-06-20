// SPDX-License-Identifier: MPL-2.0

//! Service-payload virtual interrupt handling.

extern crate alloc;

use alloc::collections::BTreeMap;

use host_ostd::sync::RwLock;

use crate::service_domain::FrameTaskGroupId;

#[derive(Default)]
struct InterruptState {
    disable_depth: u32,
}

static INTERRUPT_STATES: RwLock<BTreeMap<FrameTaskGroupId, InterruptState>> =
    RwLock::new(BTreeMap::new());

/// Service-payload placeholder for an interrupt-handler context.
pub(crate) struct IhtContext;

/// Private marker used only by shared task code to recognize IHT tasks.
pub(crate) struct IhtTaskData {
    task_group_id: FrameTaskGroupId,
}

impl IhtTaskData {
    /// Creates a private marker for an interrupt-handler task.
    pub(crate) const fn new(_cpu_id: usize, task_group_id: FrameTaskGroupId) -> Self {
        Self { task_group_id }
    }

    /// Returns the service CPU identifier.
    pub(crate) const fn vcpu_id(&self) -> usize {
        self.task_group_id.vcpu_id()
    }

    /// Returns the service CPU runqueue identifier.
    pub(crate) const fn task_group_id(&self) -> FrameTaskGroupId {
        self.task_group_id
    }
}

/// Disables local virtual interrupts for a service CPU runqueue.
pub(crate) fn disable_virtual_interrupts(task_group_id: FrameTaskGroupId) {
    let mut states = INTERRUPT_STATES.write();
    let state = states.entry(task_group_id).or_default();
    state.disable_depth = state.disable_depth.saturating_add(1);
}

/// Enables local virtual interrupts for a service CPU runqueue.
pub(crate) fn enable_virtual_interrupts(task_group_id: FrameTaskGroupId) {
    let should_dispatch = {
        let mut states = INTERRUPT_STATES.write();
        let Some(state) = states.get_mut(&task_group_id) else {
            return;
        };

        state.disable_depth = state.disable_depth.saturating_sub(1);
        if state.disable_depth != 0 {
            return;
        }

        states.remove(&task_group_id);
        true
    };

    if should_dispatch {
        drain_and_dispatch_timer_ticks(task_group_id);
    }
}

/// Injects a virtual timer tick into a service CPU runqueue.
pub(crate) fn inject_timer_tick(task_group_id: FrameTaskGroupId) {
    let Some(task_group) = crate::service_domain::get_task_group_by_id(task_group_id) else {
        return;
    };
    task_group.inject_timer_tick();

    if virtual_interrupts_enabled(task_group_id) {
        drain_and_dispatch_timer_ticks(task_group_id);
    }
}

/// Returns whether local virtual interrupts are enabled.
pub(crate) fn virtual_interrupts_enabled(task_group_id: FrameTaskGroupId) -> bool {
    INTERRUPT_STATES
        .read()
        .get(&task_group_id)
        .is_none_or(|state| state.disable_depth == 0)
}

/// Returns whether virtual interrupt-handler work is pending.
pub(crate) fn has_pending_work(task_group_id: FrameTaskGroupId) -> bool {
    crate::service_domain::get_task_group_by_id(task_group_id)
        .is_some_and(|task_group| task_group.has_pending_timer_work())
}

fn drain_and_dispatch_timer_ticks(task_group_id: FrameTaskGroupId) {
    let Some(task_group) = crate::service_domain::get_task_group_by_id(task_group_id) else {
        return;
    };
    let ticks = task_group.take_pending_timer_ticks();
    if ticks != 0 {
        crate::task::scheduler::dispatch_timer_ticks(task_group_id, ticks);
    }
}
