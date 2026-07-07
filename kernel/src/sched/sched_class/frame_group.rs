// SPDX-License-Identifier: MPL-2.0

//! Scheduler-owned state for FrameVM scheduling groups.

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};

use aster_framevisor::{DEFAULT_FRAMEVM_SHARE, FrameSchedGroup, FrameVcpuId};
use ostd::{sync::SpinLock, task::Task};

use super::fair::{FairAttr, WEIGHT_0};

/// Scheduler entity state for one FrameVM vCPU group.
#[derive(Debug)]
pub(super) struct FrameSchedEntityState {
    group: Weak<FrameSchedGroup>,
    fair_attr: FairAttr,
    inflight_task: SpinLock<Option<Arc<Task>>>,
}

impl FrameSchedEntityState {
    fn new(group: &Arc<FrameSchedGroup>, share: u32) -> Self {
        Self {
            group: Arc::downgrade(group),
            fair_attr: FairAttr::from_weight(weight_for_share(share)),
            inflight_task: SpinLock::new(None),
        }
    }

    pub(super) fn group(&self) -> Option<Arc<FrameSchedGroup>> {
        self.group.upgrade()
    }

    pub(super) fn fair_attr(&self) -> &FairAttr {
        &self.fair_attr
    }

    pub(super) fn inflight_task(&self) -> Option<Arc<Task>> {
        self.inflight_task.lock().clone()
    }

    pub(super) fn set_inflight_task(&self, task: Arc<Task>) {
        *self.inflight_task.lock() = Some(task);
    }

    pub(super) fn complete_inflight_task(&self, task: &Arc<Task>) {
        let mut inflight_task = self.inflight_task.lock();
        if inflight_task
            .as_ref()
            .is_some_and(|inflight| Arc::ptr_eq(inflight, task))
        {
            *inflight_task = None;
        }
    }
}

static FRAME_GROUPS: SpinLock<BTreeMap<FrameVcpuId, Arc<FrameSchedEntityState>>> =
    SpinLock::new(BTreeMap::new());

pub(crate) fn register(group: Arc<FrameSchedGroup>, share: u32) {
    let state = Arc::new(FrameSchedEntityState::new(&group, share));
    FRAME_GROUPS.lock().insert(group.id(), state);
}

pub(crate) fn unregister_vm(vm_id: aster_framevisor::VmId) {
    FRAME_GROUPS.lock().retain(|id, _| id.vm_id() != vm_id);
}

pub(super) fn state_for(group: &FrameSchedGroup) -> Option<Arc<FrameSchedEntityState>> {
    FRAME_GROUPS.lock().get(&group.id()).cloned()
}

fn weight_for_share(share: u32) -> u64 {
    u64::from(share).saturating_mul(WEIGHT_0) / u64::from(DEFAULT_FRAMEVM_SHARE)
}
