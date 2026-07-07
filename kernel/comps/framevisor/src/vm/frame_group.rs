// SPDX-License-Identifier: MPL-2.0

//! FrameVM host scheduling domains.

use alloc::sync::Arc;

use host_ostd::{cpu::CpuId as HostCpuId, task::Task as HostTask};

use super::VmId;
use crate::{
    cpu::CpuId,
    iht::IhtContext,
    sync::SpinLock,
    task::{self, FrameTaskKind, scheduler},
};

/// Identifies the host scheduling domain for one FrameVM vCPU.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FrameVcpuId {
    vm_id: VmId,
    vcpu_index: usize,
}

impl FrameVcpuId {
    /// Creates an identifier for one FrameVM vCPU scheduling domain.
    pub const fn new(vm_id: VmId, vcpu_index: usize) -> Self {
        Self { vm_id, vcpu_index }
    }

    /// Returns the owning VM ID.
    pub const fn vm_id(&self) -> VmId {
        self.vm_id
    }

    /// Returns the vCPU index within the owning VM.
    pub const fn vcpu_index(&self) -> usize {
        self.vcpu_index
    }
}

/// Host scheduling domain for one FrameVM vCPU.
pub struct FrameSchedGroup {
    id: FrameVcpuId,
    share: u32,
    host_cpu: SpinLock<HostCpuId>,
    iht_context: Arc<IhtContext>,
    state: SpinLock<RunState>,
}

impl FrameSchedGroup {
    /// Creates a FrameVM host scheduling domain.
    pub fn new(
        id: FrameVcpuId,
        share: u32,
        host_cpu: HostCpuId,
        iht_context: Arc<IhtContext>,
    ) -> Self {
        Self {
            id,
            share,
            host_cpu: SpinLock::new(host_cpu),
            iht_context,
            state: SpinLock::new(RunState::new()),
        }
    }

    /// Returns this scheduling domain's identity.
    pub const fn id(&self) -> FrameVcpuId {
        self.id
    }

    /// Returns the owning VM ID.
    pub const fn vm_id(&self) -> VmId {
        self.id.vm_id()
    }

    /// Returns the vCPU index within the owning VM.
    pub const fn vcpu_index(&self) -> usize {
        self.id.vcpu_index()
    }

    /// Returns the fixed CPU share configured at VM creation.
    pub const fn share(&self) -> u32 {
        self.share
    }

    /// Returns the bound host CPU.
    pub fn host_cpu(&self) -> HostCpuId {
        *self.host_cpu.lock()
    }

    /// Binds this group to one physical host CPU.
    pub fn bind_host_cpu(&self, host_cpu: HostCpuId) {
        *self.host_cpu.lock() = host_cpu;
    }

    /// Returns the associated IHT context.
    pub fn iht_context(&self) -> &Arc<IhtContext> {
        &self.iht_context
    }

    /// Returns whether this group has deliverable IHT work now.
    pub fn has_deliverable_iht_work(&self) -> bool {
        self.iht_context.has_deliverable_work()
    }

    /// Returns whether the FrameVM scheduler has service work for this vCPU.
    pub fn has_service_work(&self) -> bool {
        let Some(vm) = super::get_vm_by_id(self.vm_id()) else {
            return false;
        };
        let Some(scheduler) = vm.scheduler() else {
            return self.has_bootstrap_service_work();
        };
        let mut has_runnable = false;
        scheduler.local_rq_on_cpu_with(CpuId::from_raw(self.vcpu_index() as u32), &mut |rq| {
            has_runnable = rq.has_runnable();
        });
        has_runnable
    }

    /// Returns the derived outer runnable state.
    pub fn has_runnable_work(&self) -> bool {
        self.has_deliverable_iht_work() || self.has_service_work()
    }

    /// Marks a scheduler-bootstrap service task runnable before the service scheduler exists.
    pub(crate) fn enqueue_bootstrap_service_task(&self, task: Arc<HostTask>) {
        self.state.lock().bootstrap_service_task = Some(task);
    }

    /// Clears the scheduler-bootstrap service task after the service scheduler is installed.
    pub(crate) fn clear_bootstrap_service_task(&self) {
        self.state.lock().bootstrap_service_task = None;
    }

    fn has_bootstrap_service_work(&self) -> bool {
        self.state.lock().bootstrap_service_task.is_some()
    }

    /// Records one virtual timer tick for this group's vCPU.
    pub fn record_timer_tick(&self) {
        self.iht_context.record_timer_tick();
    }

    /// Returns whether this group is currently present in the outer runqueue.
    pub fn is_queued(&self) -> bool {
        self.state.lock().queued
    }

    /// Marks this group as no longer queued after host scheduler pick.
    pub fn mark_picked(&self) {
        self.state.lock().queued = false;
    }

    /// Computes the outer queue action for a derived runnable state.
    pub fn refresh_action(&self, runnable: bool, is_current: bool) -> RefreshAction {
        let mut state = self.state.lock();
        match (state.queued, runnable, is_current) {
            (false, true, false) => {
                state.queued = true;
                RefreshAction::Enqueue
            }
            (true, false, _) => {
                state.queued = false;
                RefreshAction::Dequeue
            }
            _ => RefreshAction::None,
        }
    }

    /// Selects inner work for this scheduling group.
    ///
    /// Specification invariant: IHT-first is part of the FrameSchedGroup
    /// contract. IHT owns notification/control work, not normal device data
    /// paths. If service work is delayed by continuous device events, keep this
    /// pick order and fix the IHT event source so it clears or coalesces
    /// notification-level deliverability after waking service work. Do not
    /// change this path to service-first to hide an IHT data-path bug.
    pub fn try_pick_inner(&self) -> InnerPick {
        self.with_cpu_scope(|| {
            if self.iht_context.has_deliverable_work()
                && let Some(task) = self.iht_context.task()
            {
                return InnerPick::Iht(task);
            }

            if let Some(task) = self.try_pick_service() {
                return InnerPick::Service(task);
            }

            InnerPick::NoWork
        })
    }

    fn try_pick_service(&self) -> Option<Arc<HostTask>> {
        let vm = super::get_vm_by_id(self.vm_id())?;
        let Some(scheduler) = vm.scheduler() else {
            let task = self.state.lock().bootstrap_service_task.clone()?;
            self.debug_assert_task_owner(&task, FrameTaskKind::Service);
            return Some(task);
        };
        let mut picked_task = None;

        // Lock order: host scheduler runqueue picks the outer group first, then
        // enters the FrameVM scheduler local runqueue for this scoped vCPU.
        scheduler.mut_local_rq_on_cpu_with(CpuId::from_raw(self.vcpu_index() as u32), &mut |rq| {
            picked_task = rq.try_pick_next().map(|task| task.clone_ostd_task());
        });

        let task = picked_task?;
        self.debug_assert_task_owner(&task, FrameTaskKind::Service);
        Some(task)
    }

    fn debug_assert_task_owner(&self, task: &HostTask, kind: FrameTaskKind) {
        debug_assert_eq!(task::frame_task_kind_for_ostd_task(task), Some(kind));
        debug_assert_eq!(
            task::frame_task_vcpu_index_for_ostd_task(task),
            Some(self.vcpu_index())
        );
        debug_assert_eq!(
            task::frame_sched_group_for_ostd_task(task).map(|group| group.id()),
            Some(self.id())
        );
    }

    /// Runs a closure with this group as the FrameVM CPU identity.
    pub(crate) fn with_cpu_scope<T>(&self, f: impl FnOnce() -> T) -> T {
        let cpu_id = CpuId::from_raw(self.vcpu_index() as u32);
        let _scope = scheduler::enter_frame_cpu_scope(cpu_id);
        f()
    }
}

/// Outer scheduler queue action for a refreshed FrameSchedGroup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshAction {
    Enqueue,
    Dequeue,
    None,
}

/// Inner work selected by a FrameSchedGroup.
pub enum InnerPick {
    Iht(Arc<HostTask>),
    Service(Arc<HostTask>),
    NoWork,
}

struct RunState {
    queued: bool,
    bootstrap_service_task: Option<Arc<HostTask>>,
}

impl RunState {
    const fn new() -> Self {
        Self {
            queued: false,
            bootstrap_service_task: None,
        }
    }
}
