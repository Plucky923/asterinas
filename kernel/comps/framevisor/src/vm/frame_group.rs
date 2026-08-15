// SPDX-License-Identifier: MPL-2.0

//! FrameVM host scheduling domains.

use alloc::{
    collections::BTreeSet,
    sync::{Arc, Weak},
    vec::Vec,
};

use host_ostd::{
    cpu::{CpuId as HostCpuId, PinCurrentCpu},
    sync::{LocalIrqDisabled as HostLocalIrqDisabled, SpinLock as HostSpinLock},
    task::{Task as HostTask, disable_preempt},
    timer,
};

use super::VmId;
use crate::{
    cpu::CpuId,
    irq::InterruptHandler,
    task::scheduler::{self, UpdateFlags},
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
    host_cpu: HostSpinLock<HostCpuId, HostLocalIrqDisabled>,
    interrupt_handler: Arc<InterruptHandler>,
    state: HostSpinLock<RunState, HostLocalIrqDisabled>,
    service_tasks: HostSpinLock<Vec<Weak<HostTask>>, HostLocalIrqDisabled>,
    timer_host_cpus: HostSpinLock<BTreeSet<usize>, HostLocalIrqDisabled>,
}

impl FrameSchedGroup {
    /// Creates a FrameVM host scheduling domain.
    pub fn new(
        id: FrameVcpuId,
        share: u32,
        host_cpu: HostCpuId,
        interrupt_handler: Arc<InterruptHandler>,
    ) -> Self {
        Self {
            id,
            share,
            host_cpu: HostSpinLock::new(host_cpu),
            interrupt_handler,
            state: HostSpinLock::new(RunState::new()),
            service_tasks: HostSpinLock::new(Vec::new()),
            timer_host_cpus: HostSpinLock::new(BTreeSet::new()),
        }
    }

    /// Returns this scheduling domain's identity.
    pub const fn id(&self) -> FrameVcpuId {
        self.id
    }

    /// Returns this group's configured CPU share.
    pub const fn share(&self) -> u32 {
        self.share
    }

    /// Returns the owning VM ID.
    pub(crate) const fn vm_id(&self) -> VmId {
        self.id.vm_id()
    }

    /// Returns the vCPU index within the owning VM.
    pub(crate) const fn vcpu_index(&self) -> usize {
        self.id.vcpu_index()
    }

    /// Returns the bound host CPU.
    pub fn host_cpu(&self) -> HostCpuId {
        *self.host_cpu.lock()
    }

    /// Binds this group to one physical host CPU.
    pub fn bind_host_cpu(&self, host_cpu: HostCpuId) {
        *self.host_cpu.lock() = host_cpu;
    }

    pub(crate) fn enable_timer_on_current_cpu(self: &Arc<Self>) {
        let host_cpu = disable_preempt().current_cpu();
        if host_cpu != self.host_cpu() {
            return;
        }
        if !self
            .timer_host_cpus
            .lock()
            .insert(u32::from(host_cpu) as usize)
        {
            return;
        }

        let group = Arc::downgrade(self);
        timer::register_callback_on_cpu(move || {
            let Some(group) = group.upgrade() else {
                return;
            };
            if group.host_cpu() == host_cpu {
                super::get_vm_by_id(group.vm_id()).map(|vm| vm.record_timer_tick(group.id()));
            }
        });
    }

    fn has_interrupt_work(&self) -> bool {
        self.interrupt_handler.has_deliverable_work()
    }

    fn has_service_work_inner(&self) -> bool {
        let Some(vm) = super::get_vm_by_id(self.vm_id()) else {
            return false;
        };
        let Some(scheduler) = vm.scheduler() else {
            return self.state.lock().bootstrap_service_task.is_some();
        };
        let mut has_runnable = false;
        scheduler.local_rq_on_cpu_with(CpuId::from_raw(self.vcpu_index() as u32), &mut |rq| {
            has_runnable = rq.has_runnable();
        });
        has_runnable || self.state.lock().bootstrap_service_task.is_some()
    }

    /// Returns whether service work can keep this group runnable.
    pub fn has_service_work_for_outer(&self) -> bool {
        let admits_work = self.state.lock().admits_work;
        admits_work && self.has_service_work_inner()
    }

    /// Returns whether this group has work for the Host scheduler.
    pub fn has_runnable_work(&self) -> bool {
        if !self.state.lock().admits_work {
            return self.interrupt_handler.has_deliverable_work() || self.has_service_work_inner();
        }
        self.has_interrupt_work() || self.has_service_work_inner()
    }

    /// Allows service and interrupt work to re-enter the Host scheduler.
    pub(crate) fn open_admission(&self) {
        let mut state = self.state.lock();
        state.admits_work = true;
        state.service_handoff_pending = false;
    }

    /// Prevents inner work from becoming an outer scheduling entity during bootstrap.
    pub(crate) fn begin_bootstrap(&self) {
        let mut state = self.state.lock();
        // The bootstrap task may yield after it installs the service scheduler
        // but before it exits. Give the first service task one handoff before
        // interrupt-first arbitration resumes.
        state.service_handoff_pending = true;
    }

    /// Opens outer scheduling after the bootstrap task finishes.
    pub(crate) fn complete_bootstrap(&self) {
        let mut state = self.state.lock();
        state.bootstrap_service_task = None;
        // Let the initial service task finish startup before interrupt-first arbitration resumes.
        state.service_handoff_pending = true;
    }

    /// Closes admission for new service and interrupt work.
    pub(crate) fn close_admission(&self) {
        {
            let mut state = self.state.lock();
            state.admits_work = false;
            state.service_handoff_pending = false;
        }
        self.wake_service_tasks();
    }

    /// Retains the scheduler-bootstrap task until its entry function returns.
    pub(crate) fn enqueue_bootstrap_service_task(&self, task: Arc<HostTask>) {
        self.state.lock().bootstrap_service_task = Some(task);
    }

    /// Adds a service task that may need a Host wakeup for this vCPU.
    pub(crate) fn add_service_task(&self, task: &Arc<HostTask>) {
        let mut service_tasks = self.service_tasks.lock();
        service_tasks.retain(|weak_task| weak_task.strong_count() != 0);
        let task_ptr = Arc::as_ptr(task);
        if service_tasks
            .iter()
            .any(|weak_task| weak_task.as_ptr() == task_ptr)
        {
            return;
        }

        service_tasks.push(Arc::downgrade(task));
    }

    /// Removes a service task that no longer belongs to this vCPU.
    pub(crate) fn remove_service_task(&self, task: &Arc<HostTask>) {
        let task_ptr = Arc::as_ptr(task);
        self.service_tasks
            .lock()
            .retain(|weak_task| weak_task.strong_count() != 0 && weak_task.as_ptr() != task_ptr);
    }

    /// Returns strong references to service tasks still associated with this vCPU.
    pub(crate) fn service_tasks_snapshot(&self) -> Vec<Arc<HostTask>> {
        let mut service_tasks = self.service_tasks.lock();
        service_tasks.retain(|weak_task| weak_task.strong_count() != 0);
        service_tasks.iter().filter_map(Weak::upgrade).collect()
    }

    /// Publishes service waiters after this vCPU delivers service-owned work.
    pub fn wake_service_tasks(&self) {
        let current_task = HostTask::current().map(|current| current.cloned());
        let tasks = {
            let mut service_tasks = self.service_tasks.lock();
            service_tasks.retain(|weak_task| weak_task.strong_count() != 0);
            service_tasks
                .iter()
                .filter_map(Weak::upgrade)
                .filter(|task| {
                    current_task
                        .as_ref()
                        .is_none_or(|current| !Arc::ptr_eq(current, task))
                })
                .filter(|task| !task.is_completed())
                .collect::<Vec<_>>()
        };

        // Wake the Host backing tasks after releasing the group-local lock. The
        // timer and interrupt paths call this outside the Host runqueue lock.
        for task in tasks {
            task.wake_up();
        }
    }

    /// Requests one service-task handoff after a bounded interrupt batch.
    pub fn request_service_handoff(&self) {
        self.state.lock().service_handoff_pending = true;
    }

    /// Mirrors a Host current-task update into the FrameVM scheduler.
    ///
    /// Returns whether the Host scheduler must select another task for this
    /// group.
    pub fn update_current(&self, task: &Arc<HostTask>, flags: UpdateFlags) -> bool {
        if matches!(flags, UpdateFlags::Wait) {
            let _ = scheduler::park_service_task(task);
        }

        let has_interrupt_work = self.has_interrupt_work();
        let has_runnable_work = matches!(
            flags,
            UpdateFlags::Yield | UpdateFlags::Wait | UpdateFlags::Exit
        ) && self.has_runnable_work();
        has_interrupt_work || has_runnable_work
    }

    /// Selects the next task, giving interrupt delivery priority and handing
    /// off to service work after each delivered interrupt request.
    /// Interrupt-first is part of the FrameSchedGroup notification/control data path contract.
    /// Do not let service selection bypass a runnable interrupt task.
    pub fn pick_task(&self) -> Option<Arc<HostTask>> {
        let (admits_work, service_handoff_required) = {
            let mut state = self.state.lock();
            let service_handoff_required = state.service_handoff_pending;
            state.service_handoff_pending = false;
            (state.admits_work, service_handoff_required)
        };
        if admits_work && service_handoff_required {
            if let Some(task) = self.try_pick_service() {
                return Some(task);
            }
            self.state.lock().service_handoff_pending = true;
        }
        let interrupt_is_runnable = if admits_work {
            self.interrupt_handler.has_deliverable_work()
        } else {
            self.interrupt_handler.has_pending_exit()
        };
        let interrupt_task = interrupt_is_runnable
            .then(|| self.interrupt_handler.task())
            .flatten();
        if let Some(task) = interrupt_task {
            return Some(task);
        }

        if !admits_work {
            let bootstrap_task = self.state.lock().bootstrap_service_task.clone();
            return bootstrap_task.or_else(|| self.try_pick_service());
        }

        if let Some(task) = self.try_pick_service() {
            return Some(task);
        }

        None
    }

    fn try_pick_service(&self) -> Option<Arc<HostTask>> {
        let vm = super::get_vm_by_id(self.vm_id())?;
        let Some(scheduler) = vm.scheduler() else {
            let task = self.state.lock().bootstrap_service_task.clone()?;
            return Some(task);
        };

        let mut picked_task = None;
        // Lock order: the Host scheduler picks the outer group first, then
        // enters the explicitly selected FrameVM vCPU runqueue.
        scheduler.mut_local_rq_on_cpu_with(CpuId::from_raw(self.vcpu_index() as u32), &mut |rq| {
            if !rq.has_runnable() {
                return;
            }
            picked_task = rq
                .current()
                .filter(|task| !task.is_completed())
                .map(|task| task.ostd_task().clone())
                .or_else(|| rq.try_pick_next().map(|task| task.ostd_task().clone()));
        });

        picked_task
            .filter(|task| !task.is_completed())
            .or_else(|| self.state.lock().bootstrap_service_task.clone())
    }
}

struct RunState {
    admits_work: bool,
    bootstrap_service_task: Option<Arc<HostTask>>,
    service_handoff_pending: bool,
}

impl RunState {
    const fn new() -> Self {
        Self {
            admits_work: false,
            bootstrap_service_task: None,
            service_handoff_pending: false,
        }
    }
}
