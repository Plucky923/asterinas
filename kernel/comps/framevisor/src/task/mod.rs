// SPDX-License-Identifier: MPL-2.0

//! Tasks are the unit of code execution.

pub mod atomic_mode;
mod frame_task;
mod preempt;
pub mod scheduler;

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{any::Any, borrow::Borrow, ops::Deref};

pub use frame_task::{FrameTaskData, FrameTaskKind};
#[cfg(target_arch = "x86_64")]
use host_ostd::arch::cpu::context::CpuException;
#[cfg(target_arch = "riscv64")]
use host_ostd::arch::cpu::context::CpuException;
#[cfg(target_arch = "loongarch64")]
use host_ostd::arch::cpu::context::CpuExceptionInfo as CpuException;
use host_ostd::{
    irq::DisabledLocalIrqGuard as OstdDisabledLocalIrqGuard,
    sync::RwLock,
    task::{CurrentTask as OstdCurrentTask, Task as OstdTask},
};
pub use preempt::{DisabledPreemptGuard, disable_preempt};
pub use scheduler::info::{AtomicCpuId, TaskScheduleInfo};

use crate::{
    cpu::CpuId,
    error::Error,
    irq::DisabledLocalIrqGuard,
    prelude::Result,
    sync::Once,
    vm::{self, FrameSchedGroup, FrameVcpuId, VmId},
};

type TaskCreator = fn(
    Box<dyn FnOnce() + Send>,
    Box<dyn Any + Send + Sync>,
    Box<dyn Any + Send>,
    Option<FrameVcpuId>,
) -> Result<Arc<OstdTask>>;
type VcpuBinder = fn(Arc<OstdTask>, FrameVcpuId) -> Result<()>;
type PriorityBooster = fn(Arc<OstdTask>, bool);

/// Function signature for task creator injected from the host kernel.
pub type TaskCreatorFn = fn(
    Box<dyn FnOnce() + Send>,
    Box<dyn Any + Send + Sync>,
    Box<dyn Any + Send>,
    Option<FrameVcpuId>,
) -> Result<Arc<OstdTask>>;
pub type VcpuBinderFn = fn(Arc<OstdTask>, FrameVcpuId) -> Result<()>;
pub type PriorityBoosterFn = fn(Arc<OstdTask>, bool);

type UserPageFaultHandler = fn(&CpuException) -> core::result::Result<(), ()>;
type FrameVcpuKey = u64;

static TASK_CREATOR: Once<TaskCreator> = Once::new();
static VCPU_BINDER: Once<VcpuBinder> = Once::new();
static PRIORITY_BOOSTER: Once<PriorityBooster> = Once::new();

struct FrameVcpuRuntimeBinding {
    task: Weak<OstdTask>,
    frame_vcpu_id: FrameVcpuId,
}

impl FrameVcpuRuntimeBinding {
    fn new(task: &Arc<OstdTask>, frame_vcpu_id: FrameVcpuId) -> Self {
        Self {
            task: Arc::downgrade(task),
            frame_vcpu_id,
        }
    }

    fn task(&self) -> Option<Arc<OstdTask>> {
        self.task.upgrade()
    }

    fn frame_vcpu_id(&self) -> FrameVcpuId {
        self.frame_vcpu_id
    }
}

// Host OSTD injects scheduler and trap hooks through global function entry
// points. These maps are hook-dispatch glue keyed by FrameVcpuId; VM/vCPU
// scheduler state remains owned by `FrameVm`, `FrameSchedGroup`, and `Vcpu`.
static POST_SCHEDULE_HANDLERS: RwLock<BTreeMap<FrameVcpuKey, fn() -> bool>> =
    RwLock::new(BTreeMap::new());
static PRE_SCHEDULE_HANDLERS: RwLock<BTreeMap<FrameVcpuKey, fn(&DisabledLocalIrqGuard)>> =
    RwLock::new(BTreeMap::new());
static PRE_USER_RUN_HANDLERS: RwLock<BTreeMap<FrameVcpuKey, fn(&DisabledLocalIrqGuard)>> =
    RwLock::new(BTreeMap::new());
static USER_PAGE_FAULT_HANDLERS: RwLock<BTreeMap<FrameVcpuKey, UserPageFaultHandler>> =
    RwLock::new(BTreeMap::new());
static FRAME_VCPU_RUNTIME_BINDINGS: RwLock<BTreeMap<usize, Arc<FrameVcpuRuntimeBinding>>> =
    RwLock::new(BTreeMap::new());
static PRIORITY_BOOST_DEPTHS: RwLock<BTreeMap<usize, PriorityBoostState>> =
    RwLock::new(BTreeMap::new());
static TASK_HANDLES: RwLock<BTreeMap<usize, Weak<Task>>> = RwLock::new(BTreeMap::new());

struct PriorityBoostState {
    task: Weak<OstdTask>,
    depth: u32,
}

impl PriorityBoostState {
    fn new(task: &Arc<OstdTask>) -> Self {
        Self {
            task: Arc::downgrade(task),
            depth: 1,
        }
    }
}

/// Inject task creator from kernel.
pub fn inject_task_creator(creator: TaskCreatorFn) {
    TASK_CREATOR.call_once(|| creator);
}

/// Inject task-group binder from kernel.
pub fn inject_vcpu_binder(binder: VcpuBinderFn) {
    VCPU_BINDER.call_once(|| binder);
}

/// Injects host scheduler priority boosting for virtual IRQ-disabled sections.
pub fn inject_priority_booster(booster: PriorityBoosterFn) {
    PRIORITY_BOOSTER.call_once(|| booster);
}

/// Registers a post-schedule handler for the current task.
pub fn inject_post_schedule_handler(handler: fn() -> bool) {
    for task_group_key in current_vm_vcpu_keys() {
        POST_SCHEDULE_HANDLERS
            .write()
            .insert(task_group_key, handler);
    }
}

fn clear_post_schedule_handler() {
    for task_group_key in current_vm_vcpu_keys() {
        POST_SCHEDULE_HANDLERS.write().remove(&task_group_key);
    }
}

/// Registers a pre-schedule handler for the current task.
pub fn inject_pre_schedule_handler(handler: fn(&DisabledLocalIrqGuard)) {
    for task_group_key in current_vm_vcpu_keys() {
        PRE_SCHEDULE_HANDLERS
            .write()
            .insert(task_group_key, handler);
    }
}

fn clear_pre_schedule_handler() {
    for task_group_key in current_vm_vcpu_keys() {
        PRE_SCHEDULE_HANDLERS.write().remove(&task_group_key);
    }
}

/// Registers a pre-user-run handler for the current task.
pub fn inject_pre_user_run_handler(handler: fn(&DisabledLocalIrqGuard)) {
    for task_group_key in current_vm_vcpu_keys() {
        PRE_USER_RUN_HANDLERS
            .write()
            .insert(task_group_key, handler);
    }
}

fn clear_pre_user_run_handler() {
    for task_group_key in current_vm_vcpu_keys() {
        PRE_USER_RUN_HANDLERS.write().remove(&task_group_key);
    }
}

pub(crate) fn inject_user_page_fault_handler(handler: UserPageFaultHandler) {
    for task_group_key in current_vm_vcpu_keys() {
        USER_PAGE_FAULT_HANDLERS
            .write()
            .insert(task_group_key, handler);
    }
}

fn clear_user_page_fault_handler() {
    for task_group_key in current_vm_vcpu_keys() {
        USER_PAGE_FAULT_HANDLERS.write().remove(&task_group_key);
    }
}

pub(crate) fn clear_current_service_hooks() {
    clear_pre_schedule_handler();
    clear_user_page_fault_handler();
    clear_post_schedule_handler();
    clear_pre_user_run_handler();
    clear_dead_task_handles();
    scheduler::clear_scheduler();
}

pub(crate) fn clear_service_hooks_for_vm(vm_id: VmId) {
    for task_group_key in vm_vcpu_keys(vm_id) {
        PRE_SCHEDULE_HANDLERS.write().remove(&task_group_key);
        USER_PAGE_FAULT_HANDLERS.write().remove(&task_group_key);
        POST_SCHEDULE_HANDLERS.write().remove(&task_group_key);
        PRE_USER_RUN_HANDLERS.write().remove(&task_group_key);
    }
    FRAME_VCPU_RUNTIME_BINDINGS
        .write()
        .retain(|_, binding| binding.frame_vcpu_id().vm_id() != vm_id);
    clear_dead_task_handles();
    scheduler::clear_scheduler_for_vm(vm_id);
}

/// Binds the current backing task to a host-backed local runqueue.
pub(crate) fn bind_current_task_to_frame_vcpu(frame_vcpu_id: FrameVcpuId) -> Result<()> {
    let current = OstdTask::current().ok_or(Error::InvalidArgs)?;
    bind_vcpu_runtime_inner(current.cloned(), frame_vcpu_id, true)
}

/// Clears the host-backed local runqueue binding from the current backing task.
pub(crate) fn clear_current_frame_vcpu() {
    if let Some(current) = OstdTask::current() {
        let task_ptr = Arc::as_ptr(&current.cloned()) as usize;
        FRAME_VCPU_RUNTIME_BINDINGS.write().remove(&task_ptr);
    }
}

/// Binds an OSTD backing task to a host-backed local runqueue for runtime accounting.
pub fn bind_ostd_task_to_frame_vcpu(task: Arc<OstdTask>, frame_vcpu_id: FrameVcpuId) -> Result<()> {
    bind_vcpu_runtime(task, frame_vcpu_id)
}

pub(super) fn bind_vcpu_runtime(task: Arc<OstdTask>, frame_vcpu_id: FrameVcpuId) -> Result<()> {
    bind_vcpu_runtime_inner(task, frame_vcpu_id, false)
}

pub(super) fn bind_service_vcpu_runtime(
    task: Arc<OstdTask>,
    frame_vcpu_id: FrameVcpuId,
) -> Result<()> {
    bind_vcpu_runtime_inner(task, frame_vcpu_id, true)
}

fn bind_vcpu_runtime_inner(
    task: Arc<OstdTask>,
    frame_vcpu_id: FrameVcpuId,
    bind_host_scheduler: bool,
) -> Result<()> {
    let Some(frame_vm) = vm::get_vm_by_id(frame_vcpu_id.vm_id()) else {
        return Err(Error::InvalidArgs);
    };
    if frame_vcpu_id.vcpu_index() >= frame_vm.vcpu_count() {
        return Err(Error::InvalidArgs);
    }

    if bind_host_scheduler && let Some(binder) = VCPU_BINDER.get() {
        binder(task.clone(), frame_vcpu_id)?;
    }

    let task_ptr = Arc::as_ptr(&task) as usize;
    FRAME_VCPU_RUNTIME_BINDINGS.write().insert(
        task_ptr,
        Arc::new(FrameVcpuRuntimeBinding::new(&task, frame_vcpu_id)),
    );
    Ok(())
}

fn frame_vcpu_runtime_binding(task: &Arc<OstdTask>) -> Option<Arc<FrameVcpuRuntimeBinding>> {
    let task_ptr = Arc::as_ptr(task) as usize;
    FRAME_VCPU_RUNTIME_BINDINGS.read().get(&task_ptr).cloned()
}

/// Returns live OSTD backing tasks bound to a host-backed local runqueue.
pub fn ostd_tasks_in_frame_vcpu(frame_vcpu_id: FrameVcpuId) -> Vec<Arc<OstdTask>> {
    FRAME_VCPU_RUNTIME_BINDINGS
        .read()
        .values()
        .filter(|binding| binding.frame_vcpu_id() == frame_vcpu_id)
        .filter_map(|binding| binding.task())
        .collect()
}

pub(crate) fn wake_service_tasks_in_frame_vcpu(frame_vcpu_id: FrameVcpuId) {
    let current_task = OstdTask::current().map(|current| current.cloned());
    let tasks = FRAME_VCPU_RUNTIME_BINDINGS
        .read()
        .values()
        .filter(|binding| binding.frame_vcpu_id() == frame_vcpu_id)
        .filter_map(|binding| binding.task())
        .filter(|task| {
            !is_iht_task(task.as_ref())
                && current_task
                    .as_ref()
                    .is_none_or(|current| !Arc::ptr_eq(current, task))
        })
        .collect::<Vec<_>>();

    for task in tasks {
        task.wake_up();
    }
}

fn get_current_frame_vcpu_id() -> Option<FrameVcpuId> {
    let current = OstdTask::current()?;
    let task = current.cloned();
    frame_vcpu_id_for_task(&task)
}

fn frame_vcpu_id_for_task(task: &Arc<OstdTask>) -> Option<FrameVcpuId> {
    if let Some(data) = frame_task_data_for_ostd_task(task) {
        return frame_vcpu_id(data);
    }

    frame_vcpu_runtime_binding(task).map(|binding| binding.frame_vcpu_id())
}

fn frame_vcpu_id(data: &FrameTaskData) -> Option<FrameVcpuId> {
    let group = data.group()?;
    Some(FrameVcpuId::new(group.vm_id(), group.vcpu_index()))
}

fn frame_task_data_for_ostd_task(task: &OstdTask) -> Option<&FrameTaskData> {
    task.extension()
        .downcast_ref::<FrameTaskData>()
        .or_else(|| {
            task.extension()
                .downcast_ref::<TaskPayload>()?
                .extension()
                .downcast_ref::<FrameTaskData>()
        })
}

/// Returns FrameVM task metadata kind for a host OSTD task.
pub fn frame_task_kind_for_ostd_task(task: &OstdTask) -> Option<FrameTaskKind> {
    Some(frame_task_data_for_ostd_task(task)?.kind())
}

/// Returns FrameVM task metadata vCPU index for a host OSTD task.
pub fn frame_task_vcpu_index_for_ostd_task(task: &OstdTask) -> Option<usize> {
    Some(frame_task_data_for_ostd_task(task)?.vcpu_index())
}

/// Returns the owning scheduling group for a host OSTD FrameVM task.
pub fn frame_sched_group_for_ostd_task(task: &OstdTask) -> Option<Arc<FrameSchedGroup>> {
    frame_task_data_for_ostd_task(task)?.group()
}

fn frame_vcpu_key(frame_vcpu_id: FrameVcpuId) -> FrameVcpuKey {
    ((frame_vcpu_id.vm_id() as u64) << 32) | frame_vcpu_id.vcpu_index() as u64
}

fn current_vm_vcpu_keys() -> Vec<FrameVcpuKey> {
    let Some(frame_vcpu_id) = get_current_frame_vcpu_id() else {
        return Vec::new();
    };

    let keys = vm_vcpu_keys(frame_vcpu_id.vm_id());
    if keys.is_empty() {
        Vec::from([frame_vcpu_key(frame_vcpu_id)])
    } else {
        keys
    }
}

fn vm_vcpu_keys(vm_id: VmId) -> Vec<FrameVcpuKey> {
    let Some(frame_vm) = vm::get_vm_by_id(vm_id) else {
        return Vec::new();
    };
    (0..frame_vm.vcpu_count())
        .map(|vcpu_id| frame_vcpu_key(FrameVcpuId::new(vm_id, vcpu_id)))
        .collect()
}

fn is_iht_task(task: &OstdTask) -> bool {
    frame_task_kind_for_ostd_task(task) == Some(FrameTaskKind::Iht)
}

pub(super) fn current_frame_vcpu_for_virtual_interrupt() -> Option<FrameVcpuId> {
    let current = OstdTask::current()?;
    let task = current.cloned();

    if is_iht_task(task.as_ref()) {
        return None;
    }

    frame_vcpu_id_for_task(&task)
}

pub(super) fn enter_virtual_irq_priority_boost() -> Option<usize> {
    let current = OstdTask::current()?;
    let task = current.cloned();

    if is_iht_task(task.as_ref()) || frame_vcpu_id_for_task(&task).is_none() {
        return None;
    }

    let task_key = Arc::as_ptr(&task) as usize;
    let mut depths = PRIORITY_BOOST_DEPTHS.write();
    if let Some(state) = depths.get_mut(&task_key) {
        state.depth = state.depth.saturating_add(1);
        return Some(task_key);
    }

    depths.insert(task_key, PriorityBoostState::new(&task));
    drop(depths);

    if let Some(booster) = PRIORITY_BOOSTER.get() {
        booster(task, true);
    }

    Some(task_key)
}

pub(super) fn exit_virtual_irq_priority_boost(task_key: usize) {
    let task_to_unboost = {
        let mut depths = PRIORITY_BOOST_DEPTHS.write();
        let Some(state) = depths.get_mut(&task_key) else {
            return;
        };

        state.depth = state.depth.saturating_sub(1);
        if state.depth != 0 {
            return;
        }

        depths
            .remove(&task_key)
            .and_then(|state| state.task.upgrade())
    };

    if let Some(task) = task_to_unboost
        && let Some(booster) = PRIORITY_BOOSTER.get()
    {
        booster(task, false);
    }
}

/// Returns the host-backed local runqueue of the current backing task.
pub(crate) fn current_frame_vcpu_id() -> Option<FrameVcpuId> {
    get_current_frame_vcpu_id()
}

/// Dispatches pre-schedule accounting for service backing tasks.
pub fn dispatch_pre_schedule(_guard: &OstdDisabledLocalIrqGuard) -> bool {
    let Some(current) = OstdTask::current() else {
        return false;
    };
    let task = current.cloned();
    let frame_vcpu_id = frame_vcpu_id_for_task(&task);

    if let Some(frame_vcpu_id) = frame_vcpu_id {
        let task_group_key = frame_vcpu_key(frame_vcpu_id);
        if let Some(handler) = PRE_SCHEDULE_HANDLERS.read().get(&task_group_key).copied() {
            let service_guard = crate::irq::disable_local();
            handler(&service_guard);
        }
    }

    if frame_vcpu_runtime_binding(&task).is_some() {
        return true;
    }

    if frame_vcpu_id.is_some() || is_iht_task(task.as_ref()) {
        return true;
    }

    false
}

/// Dispatches a post-schedule handler for managed tasks.
/// Returns true if handler was dispatched.
pub fn dispatch_post_schedule() -> bool {
    if let Some(current) = OstdTask::current() {
        let task = current.cloned();
        let accounted = frame_vcpu_runtime_binding(&task).is_some();
        let frame_vcpu_id = frame_vcpu_id_for_task(&task);
        if accounted || frame_vcpu_id.is_some() {
            scheduler::init_virtual_timer_on_current_cpu();
        }

        if let Some(frame_vcpu_id) = frame_vcpu_id {
            let task_group_key = frame_vcpu_key(frame_vcpu_id);
            if let Some(handler) = POST_SCHEDULE_HANDLERS.read().get(&task_group_key).copied() {
                handler();
            }
            return true;
        }

        if is_iht_task(task.as_ref()) {
            return true;
        }

        return accounted;
    }
    false
}

/// Dispatches a pre-user-run handler for managed tasks.
pub fn dispatch_pre_user_run(_guard: &OstdDisabledLocalIrqGuard) -> bool {
    if let Some(current) = OstdTask::current() {
        let task = current.cloned();
        let Some(frame_vcpu_id) = frame_vcpu_id_for_task(&task) else {
            return false;
        };

        let task_group_key = frame_vcpu_key(frame_vcpu_id);
        if let Some(handler) = PRE_USER_RUN_HANDLERS.read().get(&task_group_key).copied() {
            let service_guard = crate::irq::disable_local();
            handler(&service_guard);
        }
        return true;
    }
    false
}

/// Dispatches a user page fault handler for managed tasks.
pub fn dispatch_user_page_fault(info: &CpuException) -> Option<core::result::Result<(), ()>> {
    let current = OstdTask::current()?;
    let task = current.cloned();
    let frame_vcpu_id = frame_vcpu_id_for_task(&task)?;
    let task_group_key = frame_vcpu_key(frame_vcpu_id);

    let handler = USER_PAGE_FAULT_HANDLERS
        .read()
        .get(&task_group_key)
        .copied();
    Some(handler.map_or(Err(()), |handler| handler(info)))
}

struct TaskPayload {
    data: Option<Box<dyn Any + Send + Sync>>,
    extension: Option<Box<dyn Any + Send + Sync>>,
    schedule_info: TaskScheduleInfo,
}

impl TaskPayload {
    fn new(
        data: Box<dyn Any + Send + Sync>,
        extension: Box<dyn Any + Send + Sync>,
        initial_cpu: Option<CpuId>,
    ) -> Self {
        let schedule_info = TaskScheduleInfo {
            cpu: Default::default(),
        };
        if let Some(cpu_id) = initial_cpu {
            schedule_info.cpu.set_anyway(cpu_id);
        }

        Self {
            data: Some(data),
            extension: Some(extension),
            schedule_info,
        }
    }

    fn data(&self) -> &Box<dyn Any + Send + Sync> {
        self.data
            .as_ref()
            .expect("task payload data has been dropped")
    }

    fn extension(&self) -> &Box<dyn Any + Send + Sync> {
        self.extension
            .as_ref()
            .expect("task payload extension has been dropped")
    }
}

impl Drop for TaskPayload {
    fn drop(&mut self) {
        drop(self.data.take());
        drop(self.extension.take());
    }
}

/// Wrapper for the current task.
pub struct CurrentTask {
    task: Arc<Task>,
    current: OstdCurrentTask,
}

/// A task that executes a function to the end.
#[derive(Debug)]
pub struct Task {
    inner: Arc<OstdTask>,
}

impl Task {
    /// Get the current task if available.
    pub fn current() -> Option<CurrentTask> {
        OstdTask::current().map(|current| CurrentTask {
            task: task_handle_for_ostd_task(current.cloned()),
            current,
        })
    }

    /// Yield the current task.
    pub fn yield_now() {
        OstdTask::yield_now();
    }

    /// Returns the bottom address of the task stack.
    pub fn stack_bottom(&self) -> usize {
        self.ostd_task().stack_bottom()
    }

    /// Returns the top address of the task stack.
    pub fn stack_top(&self) -> usize {
        self.ostd_task().stack_top()
    }

    /// Returns the task data.
    pub fn data(&self) -> &Box<dyn Any + Send + Sync> {
        self.payload()
            .map_or_else(|| self.ostd_task().extension(), TaskPayload::data)
    }

    /// Returns the task extension data.
    pub fn extension(&self) -> &Box<dyn Any + Send + Sync> {
        self.payload()
            .map_or_else(|| self.ostd_task().extension(), TaskPayload::extension)
    }

    /// Returns the task scheduling information.
    pub fn schedule_info(&self) -> &TaskScheduleInfo {
        &self
            .payload()
            .expect("task schedule information is missing")
            .schedule_info
    }

    pub(super) fn try_schedule_info(&self) -> Option<&TaskScheduleInfo> {
        self.payload().map(|payload| &payload.schedule_info)
    }

    fn payload(&self) -> Option<&TaskPayload> {
        self.ostd_task().extension().downcast_ref::<TaskPayload>()
    }

    pub(super) fn ostd_task(&self) -> &Arc<OstdTask> {
        &self.inner
    }

    pub(crate) fn clone_ostd_task(&self) -> Arc<OstdTask> {
        self.inner.clone()
    }

    fn new(task: Arc<OstdTask>) -> Self {
        Self { inner: task }
    }

    /// Run this task.
    pub fn run(self: &Arc<Self>) {
        register_task_handle(self);
        let _ = scheduler::enqueue_task(self.clone(), scheduler::EnqueueFlags::Spawn);
        self.ostd_task().run();
    }

    /// Wakes up the task.
    pub fn wake_up(self: &Arc<Self>) {
        scheduler::unpark_target(self.clone());
    }
}

impl Deref for CurrentTask {
    type Target = Task;

    fn deref(&self) -> &Self::Target {
        self.task.as_ref()
    }
}

impl CurrentTask {
    /// Returns the local data of the current task.
    pub fn local_data(&self) -> &(dyn Any + Send) {
        self.current.local_data()
    }

    /// Returns a cloned task handle.
    pub fn cloned(&self) -> Arc<Task> {
        self.task.clone()
    }
}

impl AsRef<Task> for CurrentTask {
    fn as_ref(&self) -> &Task {
        self
    }
}

impl Borrow<Task> for CurrentTask {
    fn borrow(&self) -> &Task {
        self
    }
}

/// Builder for creating tasks.
pub struct TaskOptions {
    func: Option<Box<dyn FnOnce() + Send>>,
    data: Option<Box<dyn Any + Send + Sync>>,
    extension: Option<Box<dyn Any + Send + Sync>>,
    local_data: Option<Box<dyn Any + Send>>,
}

impl TaskOptions {
    /// Create a new task builder with the given entry function.
    pub fn new<F>(entry: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            func: Some(Box::new(entry)),
            data: None,
            extension: None,
            local_data: None,
        }
    }

    /// Sets the function that represents the entry point of the task.
    pub fn func<F>(mut self, func: F) -> Self
    where
        F: Fn() + Send + 'static,
    {
        self.func = Some(Box::new(func));
        self
    }

    /// Set task-specific data.
    pub fn data<T>(self, data: T) -> Self
    where
        T: Any + Send + Sync + 'static,
    {
        self.data_any(Box::new(data))
    }

    /// Sets task-specific data from an already-boxed value.
    pub fn data_any(mut self, data: Box<dyn Any + Send + Sync>) -> Self {
        self.data = Some(data);
        self
    }

    /// Sets task extension data.
    pub fn extension<T>(self, extension: T) -> Self
    where
        T: Any + Send + Sync + 'static,
    {
        self.extension_any(Box::new(extension))
    }

    /// Sets task extension data from an already-boxed value.
    pub fn extension_any(mut self, extension: Box<dyn Any + Send + Sync>) -> Self {
        self.extension = Some(extension);
        self
    }

    /// Sets current-task local data.
    pub fn local_data<T>(self, local_data: T) -> Self
    where
        T: Any + Send + 'static,
    {
        self.local_data_any(Box::new(local_data))
    }

    /// Sets current-task local data from an already-boxed value.
    pub fn local_data_any(mut self, local_data: Box<dyn Any + Send>) -> Self {
        self.local_data = Some(local_data);
        self
    }

    /// Build and return the task.
    pub fn build(mut self) -> Result<Task> {
        let func = self.func.take().ok_or(Error::InvalidArgs)?;
        let frame_vcpu_id = current_frame_vcpu_id();
        let extension = match frame_vcpu_id {
            Some(id) => {
                let sched_group =
                    vm::get_sched_group_by_id(FrameVcpuId::new(id.vm_id(), id.vcpu_index()))
                        .ok_or(Error::InvalidArgs)?;
                Box::new(FrameTaskData::new(&sched_group, FrameTaskKind::Service))
                    as Box<dyn Any + Send + Sync>
            }
            None => self.extension.take().unwrap_or_else(|| Box::new(())),
        };
        let payload = Box::new(TaskPayload::new(
            self.data.take().unwrap_or_else(|| Box::new(())),
            extension,
            frame_vcpu_id.map(|id| CpuId::from_raw(id.vcpu_index() as u32)),
        ));
        let local_data = self.local_data.take().unwrap_or_else(|| Box::new(()));

        let task_func = Box::new(move || {
            func();
            scheduler::exit_current_task();
        });

        let task = if let Some(creator) = TASK_CREATOR.get() {
            creator(task_func, payload, local_data, frame_vcpu_id)?
        } else {
            // Fallback to bare ostd task
            let options = host_ostd::task::TaskOptions::new(task_func)
                .extension_any(payload)
                .local_data_any(local_data);
            Arc::new(options.build().map_err(Error::from)?)
        };
        Ok(Task::new(task))
    }

    /// Builds a new task and runs it immediately.
    pub fn spawn(self) -> Result<Arc<Task>> {
        let task = Arc::new(self.build()?);
        register_task_handle(&task);
        task.run();
        Ok(task)
    }
}

fn ostd_task_key(task: &Arc<OstdTask>) -> usize {
    Arc::as_ptr(task) as usize
}

fn register_task_handle(task: &Arc<Task>) {
    TASK_HANDLES
        .write()
        .insert(ostd_task_key(task.ostd_task()), Arc::downgrade(task));
}

fn task_handle_for_ostd_task(task: Arc<OstdTask>) -> Arc<Task> {
    let key = ostd_task_key(&task);
    if let Some(task) = TASK_HANDLES.read().get(&key).and_then(Weak::upgrade) {
        return task;
    }

    let task = Arc::new(Task::new(task));
    TASK_HANDLES.write().insert(key, Arc::downgrade(&task));
    task
}

fn clear_dead_task_handles() {
    TASK_HANDLES
        .write()
        .retain(|_, task| task.strong_count() != 0);
}

#[cfg(ktest)]
mod tests {
    use alloc::sync::Arc;

    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn task_handle_registry_returns_registered_handle() {
        let task = Arc::new(TaskOptions::new(|| {}).build().unwrap());

        register_task_handle(&task);
        let found = task_handle_for_ostd_task(task.ostd_task().clone());

        assert!(Arc::ptr_eq(&task, &found));
    }
}

/// Initializes the task subsystem.
pub(crate) fn init_task() {
    // Verify task creation works
    Task::current();
    preempt::init_preempt();
    scheduler::init_virtual_timer_on_current_cpu();
}
