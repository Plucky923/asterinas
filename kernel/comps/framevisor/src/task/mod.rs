// SPDX-License-Identifier: MPL-2.0

//! Tasks are the unit of code execution.

pub mod atomic_mode;
mod preempt;
pub mod scheduler;

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    any::Any,
    borrow::Borrow,
    ops::Deref,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(target_arch = "x86_64")]
use host_ostd::arch::cpu::context::CpuException;
#[cfg(target_arch = "riscv64")]
use host_ostd::arch::cpu::context::CpuException;
#[cfg(target_arch = "loongarch64")]
use host_ostd::arch::cpu::context::CpuExceptionInfo as CpuException;
#[cfg(feature = "host-api")]
use host_ostd::irq::DisabledLocalIrqGuard as OstdDisabledLocalIrqGuard;
use host_ostd::{
    sync::RwLock,
    task::{CurrentTask as OstdCurrentTask, Task as OstdTask},
};
pub use preempt::{DisabledPreemptGuard, disable_preempt};
#[cfg(not(feature = "host-api"))]
use vm::{FrameTaskGroupId, VmId};

#[cfg(not(feature = "host-api"))]
use crate::service_domain as vm;
#[cfg(feature = "host-api")]
use crate::vm::{self, FrameTaskGroupId, VmId};
use crate::{
    error::Error, iht::IhtTaskData, irq::DisabledLocalIrqGuard, prelude::Result, sync::Once,
    task::scheduler::info::TaskScheduleInfo,
};

type TaskCreator = fn(
    Box<dyn FnOnce() + Send>,
    Box<dyn Any + Send + Sync>,
    Box<dyn Any + Send>,
    Option<FrameTaskGroupId>,
) -> Result<Arc<OstdTask>>;
type TaskGroupBinder = fn(Arc<OstdTask>, FrameTaskGroupId) -> Result<()>;
type PriorityBooster = fn(Arc<OstdTask>, bool);
type FrameTaskGroupShareUpdater = fn(FrameTaskGroupId);

/// Function signature for task creator injected from the host kernel.
#[cfg(feature = "host-api")]
pub type TaskCreatorFn = fn(
    Box<dyn FnOnce() + Send>,
    Box<dyn Any + Send + Sync>,
    Box<dyn Any + Send>,
    Option<FrameTaskGroupId>,
) -> Result<Arc<OstdTask>>;
#[cfg(feature = "host-api")]
pub type TaskGroupBinderFn = fn(Arc<OstdTask>, FrameTaskGroupId) -> Result<()>;
#[cfg(feature = "host-api")]
pub type PriorityBoosterFn = fn(Arc<OstdTask>, bool);
#[cfg(feature = "host-api")]
pub type FrameTaskGroupShareUpdaterFn = fn(FrameTaskGroupId);

type UserPageFaultHandler = fn(&CpuException) -> core::result::Result<(), ()>;
type FrameTaskGroupKey = u64;

static TASK_CREATOR: Once<TaskCreator> = Once::new();
static TASK_GROUP_BINDER: Once<TaskGroupBinder> = Once::new();
static PRIORITY_BOOSTER: Once<PriorityBooster> = Once::new();
static FRAME_TASK_GROUP_SHARE_UPDATER: Once<FrameTaskGroupShareUpdater> = Once::new();

struct TaskGroupRuntimeBinding {
    task: Weak<OstdTask>,
    task_group_id: FrameTaskGroupId,
    is_iht: bool,
    last_schedule_in: AtomicU64,
}

impl TaskGroupRuntimeBinding {
    fn new(task: &Arc<OstdTask>, task_group_id: FrameTaskGroupId) -> Self {
        Self {
            task: Arc::downgrade(task),
            task_group_id,
            is_iht: is_iht_task(task.as_ref()),
            last_schedule_in: AtomicU64::new(0),
        }
    }

    fn task(&self) -> Option<Arc<OstdTask>> {
        self.task.upgrade()
    }

    fn task_group_id(&self) -> FrameTaskGroupId {
        self.task_group_id
    }

    fn mark_schedule_in(&self) {
        record_task_group_schedule_in(self.task_group_id, self.is_iht, &self.last_schedule_in);
    }

    fn mark_schedule_out(&self) {
        record_task_group_schedule_out(self.task_group_id, self.is_iht, &self.last_schedule_in);
    }
}

static POST_SCHEDULE_HANDLERS: RwLock<BTreeMap<FrameTaskGroupKey, fn() -> bool>> =
    RwLock::new(BTreeMap::new());
static PRE_SCHEDULE_HANDLERS: RwLock<BTreeMap<FrameTaskGroupKey, fn(&DisabledLocalIrqGuard)>> =
    RwLock::new(BTreeMap::new());
static PRE_USER_RUN_HANDLERS: RwLock<BTreeMap<FrameTaskGroupKey, fn(&DisabledLocalIrqGuard)>> =
    RwLock::new(BTreeMap::new());
static USER_PAGE_FAULT_HANDLERS: RwLock<BTreeMap<FrameTaskGroupKey, UserPageFaultHandler>> =
    RwLock::new(BTreeMap::new());
static TASK_GROUP_RUNTIME_BINDINGS: RwLock<BTreeMap<usize, Arc<TaskGroupRuntimeBinding>>> =
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
#[cfg(feature = "host-api")]
pub fn inject_task_creator(creator: TaskCreatorFn) {
    TASK_CREATOR.call_once(|| creator);
}

/// Inject task-group binder from kernel.
#[cfg(feature = "host-api")]
pub fn inject_task_group_binder(binder: TaskGroupBinderFn) {
    TASK_GROUP_BINDER.call_once(|| binder);
}

/// Injects host scheduler priority boosting for virtual IRQ-disabled sections.
#[cfg(feature = "host-api")]
pub fn inject_priority_booster(booster: PriorityBoosterFn) {
    PRIORITY_BOOSTER.call_once(|| booster);
}

/// Injects host scheduler updates for service task-group share changes.
#[cfg(feature = "host-api")]
pub fn inject_frame_task_group_share_updater(updater: FrameTaskGroupShareUpdaterFn) {
    FRAME_TASK_GROUP_SHARE_UPDATER.call_once(|| updater);
}

#[cfg(feature = "host-api")]
pub(crate) fn update_frame_task_group_share(task_group_id: FrameTaskGroupId) {
    if let Some(updater) = FRAME_TASK_GROUP_SHARE_UPDATER.get().copied() {
        updater(task_group_id);
    }
}

/// Registers a post-schedule handler for the current task.
pub fn inject_post_schedule_handler(handler: fn() -> bool) {
    for task_group_key in current_vm_task_group_keys() {
        POST_SCHEDULE_HANDLERS
            .write()
            .insert(task_group_key, handler);
    }
}

fn clear_post_schedule_handler() {
    for task_group_key in current_vm_task_group_keys() {
        POST_SCHEDULE_HANDLERS.write().remove(&task_group_key);
    }
}

/// Registers a pre-schedule handler for the current task.
pub fn inject_pre_schedule_handler(handler: fn(&DisabledLocalIrqGuard)) {
    for task_group_key in current_vm_task_group_keys() {
        PRE_SCHEDULE_HANDLERS
            .write()
            .insert(task_group_key, handler);
    }
}

fn clear_pre_schedule_handler() {
    for task_group_key in current_vm_task_group_keys() {
        PRE_SCHEDULE_HANDLERS.write().remove(&task_group_key);
    }
}

/// Registers a pre-user-run handler for the current task.
pub fn inject_pre_user_run_handler(handler: fn(&DisabledLocalIrqGuard)) {
    for task_group_key in current_vm_task_group_keys() {
        PRE_USER_RUN_HANDLERS
            .write()
            .insert(task_group_key, handler);
    }
}

fn clear_pre_user_run_handler() {
    for task_group_key in current_vm_task_group_keys() {
        PRE_USER_RUN_HANDLERS.write().remove(&task_group_key);
    }
}

pub(crate) fn inject_user_page_fault_handler(handler: UserPageFaultHandler) {
    for task_group_key in current_vm_task_group_keys() {
        USER_PAGE_FAULT_HANDLERS
            .write()
            .insert(task_group_key, handler);
    }
}

fn clear_user_page_fault_handler() {
    for task_group_key in current_vm_task_group_keys() {
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

#[cfg(feature = "host-api")]
pub(crate) fn clear_service_hooks_for_vm(vm_id: VmId) {
    for task_group_key in vm_task_group_keys(vm_id) {
        PRE_SCHEDULE_HANDLERS.write().remove(&task_group_key);
        USER_PAGE_FAULT_HANDLERS.write().remove(&task_group_key);
        POST_SCHEDULE_HANDLERS.write().remove(&task_group_key);
        PRE_USER_RUN_HANDLERS.write().remove(&task_group_key);
    }
    TASK_GROUP_RUNTIME_BINDINGS
        .write()
        .retain(|_, binding| binding.task_group_id().vm_id() != vm_id);
    clear_dead_task_handles();
    scheduler::clear_scheduler_for_vm(vm_id);
}

/// Binds the current backing task to a host-backed local runqueue.
pub(crate) fn bind_current_task_to_frame_task_group(task_group_id: FrameTaskGroupId) -> Result<()> {
    let current = OstdTask::current().ok_or(Error::InvalidArgs)?;
    bind_task_group_runtime(current.cloned(), task_group_id)
}

/// Clears the host-backed local runqueue binding from the current backing task.
pub(crate) fn clear_current_frame_task_group() {
    if let Some(current) = OstdTask::current() {
        let task_ptr = Arc::as_ptr(&current.cloned()) as usize;
        TASK_GROUP_RUNTIME_BINDINGS.write().remove(&task_ptr);
    }
}

/// Binds an OSTD backing task to a host-backed local runqueue for runtime accounting.
#[cfg(feature = "host-api")]
pub fn bind_ostd_task_to_frame_task_group(
    task: Arc<OstdTask>,
    task_group_id: FrameTaskGroupId,
) -> Result<()> {
    bind_task_group_runtime(task, task_group_id)
}

pub(super) fn bind_task_group_runtime(
    task: Arc<OstdTask>,
    task_group_id: FrameTaskGroupId,
) -> Result<()> {
    bind_task_group_runtime_inner(task, task_group_id, false)
}

pub(super) fn bind_service_task_group_runtime(
    task: Arc<OstdTask>,
    task_group_id: FrameTaskGroupId,
) -> Result<()> {
    bind_task_group_runtime_inner(task, task_group_id, true)
}

fn bind_task_group_runtime_inner(
    task: Arc<OstdTask>,
    task_group_id: FrameTaskGroupId,
    bind_host_scheduler: bool,
) -> Result<()> {
    if vm::get_task_group_by_id(task_group_id).is_none() {
        return Err(Error::InvalidArgs);
    }

    if bind_host_scheduler && let Some(binder) = TASK_GROUP_BINDER.get() {
        binder(task.clone(), task_group_id)?;
    }

    let task_ptr = Arc::as_ptr(&task) as usize;
    TASK_GROUP_RUNTIME_BINDINGS.write().insert(
        task_ptr,
        Arc::new(TaskGroupRuntimeBinding::new(&task, task_group_id)),
    );
    Ok(())
}

fn task_group_runtime_binding(task: &Arc<OstdTask>) -> Option<Arc<TaskGroupRuntimeBinding>> {
    let task_ptr = Arc::as_ptr(task) as usize;
    TASK_GROUP_RUNTIME_BINDINGS.read().get(&task_ptr).cloned()
}

/// Returns live OSTD backing tasks bound to a host-backed local runqueue.
#[cfg(feature = "host-api")]
pub fn ostd_tasks_in_frame_task_group(task_group_id: FrameTaskGroupId) -> Vec<Arc<OstdTask>> {
    TASK_GROUP_RUNTIME_BINDINGS
        .read()
        .values()
        .filter(|binding| binding.task_group_id() == task_group_id)
        .filter_map(|binding| binding.task())
        .collect()
}

#[cfg(feature = "host-api")]
pub(crate) fn wake_service_tasks_in_frame_task_group(task_group_id: FrameTaskGroupId) {
    let current_task = OstdTask::current().map(|current| current.cloned());
    let tasks = TASK_GROUP_RUNTIME_BINDINGS
        .read()
        .values()
        .filter(|binding| binding.task_group_id() == task_group_id)
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

fn get_current_task_group_id() -> Option<FrameTaskGroupId> {
    let current = OstdTask::current()?;
    let task = current.cloned();
    task_group_id_for_task(&task)
}

fn task_group_id_for_task(task: &Arc<OstdTask>) -> Option<FrameTaskGroupId> {
    if let Some(data) = task.extension().downcast_ref::<IhtTaskData>() {
        return Some(data.task_group_id());
    }

    task_group_runtime_binding(task).map(|binding| binding.task_group_id())
}

fn frame_task_group_key(task_group_id: FrameTaskGroupId) -> FrameTaskGroupKey {
    ((task_group_id.vm_id() as u64) << 32) | task_group_id.vcpu_id() as u64
}

fn current_vm_task_group_keys() -> Vec<FrameTaskGroupKey> {
    let Some(task_group_id) = get_current_task_group_id() else {
        return Vec::new();
    };

    let keys = vm_task_group_keys(task_group_id.vm_id());
    if keys.is_empty() {
        Vec::from([frame_task_group_key(task_group_id)])
    } else {
        keys
    }
}

fn vm_task_group_keys(vm_id: VmId) -> Vec<FrameTaskGroupKey> {
    let Some(frame_vm) = vm::get_vm_by_id(vm_id) else {
        return Vec::new();
    };
    (0..frame_vm.vcpu_count())
        .filter_map(|vcpu_id| {
            frame_vm
                .task_group(vcpu_id)
                .map(|task_group| frame_task_group_key(task_group.id()))
        })
        .collect()
}

fn is_iht_task(task: &OstdTask) -> bool {
    task.extension().downcast_ref::<IhtTaskData>().is_some()
}

pub(super) fn current_task_group_for_timer_tick() -> Option<FrameTaskGroupId> {
    let current = OstdTask::current()?;
    let task = current.cloned();

    if is_iht_task(task.as_ref()) {
        return None;
    }

    task_group_id_for_task(&task)
}

pub(super) fn current_task_group_for_virtual_interrupt() -> Option<FrameTaskGroupId> {
    let current = OstdTask::current()?;
    let task = current.cloned();

    if is_iht_task(task.as_ref()) {
        return None;
    }

    task_group_id_for_task(&task)
}

pub(super) fn enter_virtual_irq_priority_boost() -> Option<usize> {
    let current = OstdTask::current()?;
    let task = current.cloned();

    if is_iht_task(task.as_ref()) || task_group_id_for_task(&task).is_none() {
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
pub(crate) fn current_frame_task_group_id() -> Option<FrameTaskGroupId> {
    get_current_task_group_id()
}

pub(crate) fn record_task_group_schedule_in(
    task_group_id: FrameTaskGroupId,
    is_iht: bool,
    last_schedule_in: &AtomicU64,
) {
    let previous = last_schedule_in.swap(host_ostd::arch::read_tsc(), Ordering::AcqRel);
    if previous == 0
        && let Some(task_group) = vm::get_task_group_by_id(task_group_id)
    {
        task_group.record_schedule_in(is_iht);
    }
}

pub(crate) fn record_task_group_schedule_out(
    task_group_id: FrameTaskGroupId,
    is_iht: bool,
    last_schedule_in: &AtomicU64,
) {
    let start_cycles = last_schedule_in.swap(0, Ordering::AcqRel);
    if start_cycles == 0 {
        return;
    }

    if let Some(task_group) = vm::get_task_group_by_id(task_group_id) {
        task_group.record_runtime_cycles(start_cycles, host_ostd::arch::read_tsc(), is_iht);
    }
}

/// Dispatches pre-schedule accounting for service backing tasks.
#[cfg(feature = "host-api")]
pub fn dispatch_pre_schedule(_guard: &OstdDisabledLocalIrqGuard) -> bool {
    let Some(current) = OstdTask::current() else {
        return false;
    };
    let task = current.cloned();
    let task_group_id = task_group_id_for_task(&task);

    if let Some(task_group_id) = task_group_id {
        let task_group_key = frame_task_group_key(task_group_id);
        if let Some(handler) = PRE_SCHEDULE_HANDLERS.read().get(&task_group_key).copied() {
            let service_guard = crate::irq::disable_local();
            handler(&service_guard);
        }
    }

    if let Some(binding) = task_group_runtime_binding(&task) {
        binding.mark_schedule_out();
        return true;
    }

    if task_group_id.is_some() || is_iht_task(task.as_ref()) {
        return true;
    }

    false
}

/// Dispatches a post-schedule handler for managed tasks.
/// Returns true if handler was dispatched.
#[cfg(feature = "host-api")]
pub fn dispatch_post_schedule() -> bool {
    if let Some(current) = OstdTask::current() {
        let task = current.cloned();
        let accounted = if let Some(binding) = task_group_runtime_binding(&task) {
            binding.mark_schedule_in();
            true
        } else {
            false
        };
        let task_group_id = task_group_id_for_task(&task);

        if accounted || task_group_id.is_some() {
            scheduler::init_virtual_timer_on_current_cpu();
        }

        if let Some(task_group_id) = task_group_id {
            let task_group_key = frame_task_group_key(task_group_id);
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
#[cfg(feature = "host-api")]
pub fn dispatch_pre_user_run(_guard: &OstdDisabledLocalIrqGuard) -> bool {
    if let Some(current) = OstdTask::current() {
        let task = current.cloned();
        let Some(task_group_id) = task_group_id_for_task(&task) else {
            return false;
        };

        let task_group_key = frame_task_group_key(task_group_id);
        if let Some(handler) = PRE_USER_RUN_HANDLERS.read().get(&task_group_key).copied() {
            let service_guard = crate::irq::disable_local();
            handler(&service_guard);
        }
        return true;
    }
    false
}

/// Dispatches a user page fault handler for managed tasks.
#[cfg(feature = "host-api")]
pub fn dispatch_user_page_fault(info: &CpuException) -> Option<core::result::Result<(), ()>> {
    let current = OstdTask::current()?;
    let task = current.cloned();
    let task_group_id = task_group_id_for_task(&task)?;
    let task_group_key = frame_task_group_key(task_group_id);

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
    fn new(data: Box<dyn Any + Send + Sync>, extension: Box<dyn Any + Send + Sync>) -> Self {
        Self {
            data: Some(data),
            extension: Some(extension),
            schedule_info: TaskScheduleInfo {
                cpu: Default::default(),
            },
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
        let payload = Box::new(TaskPayload::new(
            self.data.take().unwrap_or_else(|| Box::new(())),
            self.extension.take().unwrap_or_else(|| Box::new(())),
        ));
        let local_data = self.local_data.take().unwrap_or_else(|| Box::new(()));

        let task = if let Some(creator) = TASK_CREATOR.get() {
            creator(func, payload, local_data, current_frame_task_group_id())?
        } else {
            // Fallback to bare ostd task
            let options = host_ostd::task::TaskOptions::new(func)
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
