//! User-task lifecycle, execution, and fault handling for the kernel image.

use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    mem,
    sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering},
};

use align_ext::AlignExt;
use ostd::{
    arch::cpu::context::{
        CpuException, FpuContext, FsBase, GsBase, PageFaultErrorCode, RawPageFaultInfo, UserContext,
    },
    cpu::CpuId,
    irq::DisabledLocalIrqGuard,
    mm::{CachePolicy, FallibleVmWrite, FrameAllocOptions, PageProperty, VmReader, VmSpace},
    sync::{Once, SpinLock as Mutex, WaitQueue},
    task::{Task, TaskOptions, disable_preempt},
    user::{ReturnReason, UserMode},
};

use crate::{
    error::{Errno, Error, Result},
    fd_table::FileTable,
    fs_context::ThreadFsInfo,
    futex,
    process::{
        ProcessIdentity, new_child_process, new_init_process, unregister_process_if_last_reference,
    },
    resource::ResourceLimits,
    robust_list::{self, RobustListHead},
    scheduler,
    signal::SignalActions,
    syscall::handle_syscall,
    vm::{LazyRange, activate_kernel_vm_space, clone_vm_space},
};

const PAGE_SIZE: usize = 4096;
/// Clone flags handled by the trimmed process model.
pub const CLONE_VM: u64 = 0x0000_0100;
pub const CLONE_FILES: u64 = 0x0000_0400;
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
pub const CLONE_VFORK: u64 = 0x0000_4000;
pub const CLONE_THREAD: u64 = 0x0001_0000;
pub const CLONE_SETTLS: u64 = 0x0008_0000;
pub const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
pub const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
const CLONE_NEWTIME: u64 = 0x0000_0080;
const CLONE_NEWNS: u64 = 0x0002_0000;
const CLONE_NEWCGROUP: u64 = 0x0200_0000;
const CLONE_NEWUTS: u64 = 0x0400_0000;
const CLONE_NEWIPC: u64 = 0x0800_0000;
const CLONE_NEWUSER: u64 = 0x1000_0000;
const CLONE_NEWPID: u64 = 0x2000_0000;
const CLONE_NEWNET: u64 = 0x4000_0000;
const CLONE_EXIT_SIGNAL_MASK: u64 = 0xff;
const THREAD_NAME_LEN: usize = 16;
const DEFAULT_TIMER_SLACK_NS: u64 = 50_000;
const UNSUPPORTED_CLONE_FLAGS: u64 = CLONE_NEWTIME
    | CLONE_NEWNS
    | CLONE_NEWCGROUP
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET;

#[derive(Clone, Copy)]
enum UserTaskExitMode {
    ParkAfterExit,
    CompleteAfterExit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserCpuStateLocation {
    InMemory,
    OnCpu,
    Both,
}

#[derive(Clone, Debug)]
struct UserRegSlot<T> {
    reg: T,
    location: UserCpuStateLocation,
}

impl<T> UserRegSlot<T> {
    fn new(reg: T) -> Self {
        Self {
            reg,
            location: UserCpuStateLocation::InMemory,
        }
    }

    fn set(&mut self, reg: T) {
        self.reg = reg;
        self.location = UserCpuStateLocation::InMemory;
    }
}

impl<T: Clone> UserRegSlot<T> {
    fn clone_in_memory(&self) -> Self {
        Self::new(self.reg.clone())
    }
}

/// Supplemental user CPU state owned by a task.
pub struct UserCpuState {
    fpu: Mutex<UserRegSlot<FpuContext>>,
    fs_base: Mutex<UserRegSlot<FsBase>>,
    gs_base: Mutex<UserRegSlot<GsBase>>,
}

impl UserCpuState {
    fn new() -> Self {
        Self {
            fpu: Mutex::new(UserRegSlot::new(FpuContext::new())),
            fs_base: Mutex::new(UserRegSlot::new(FsBase::default())),
            gs_base: Mutex::new(UserRegSlot::new(GsBase::default())),
        }
    }

    fn clone_in_memory(&self) -> Self {
        Self {
            fpu: Mutex::new(self.fpu.lock().clone_in_memory()),
            fs_base: Mutex::new(self.fs_base.lock().clone_in_memory()),
            gs_base: Mutex::new(self.gs_base.lock().clone_in_memory()),
        }
    }

    fn reset_for_exec(&self) {
        self.fpu.lock().set(FpuContext::new());
        self.fs_base.lock().set(FsBase::default());
        self.gs_base.lock().set(GsBase::default());
    }

    fn set_fs_base(&self, addr: usize) {
        self.fs_base.lock().set(FsBase::new(addr));
    }

    fn set_gs_base(&self, addr: usize) {
        self.gs_base.lock().set(GsBase::new(addr));
    }

    fn fs_base(&self) -> usize {
        let mut fs_base = self.fs_base.lock();
        if fs_base.location == UserCpuStateLocation::OnCpu {
            fs_base.reg.save();
            fs_base.location = UserCpuStateLocation::Both;
        }
        fs_base.reg.addr()
    }

    fn gs_base(&self, guard: &DisabledLocalIrqGuard) -> usize {
        let mut gs_base = self.gs_base.lock();
        if gs_base.location == UserCpuStateLocation::OnCpu {
            gs_base.reg.save(guard);
            gs_base.location = UserCpuStateLocation::Both;
        }
        gs_base.reg.addr()
    }

    fn before_schedule(&self, guard: &DisabledLocalIrqGuard) {
        let mut fpu = self.fpu.lock();
        if fpu.location == UserCpuStateLocation::OnCpu {
            fpu.reg.save();
        }
        fpu.location = UserCpuStateLocation::InMemory;
        drop(fpu);

        let mut fs_base = self.fs_base.lock();
        if fs_base.location == UserCpuStateLocation::OnCpu {
            fs_base.reg.save();
        }
        fs_base.location = UserCpuStateLocation::InMemory;
        drop(fs_base);

        let mut gs_base = self.gs_base.lock();
        if gs_base.location == UserCpuStateLocation::OnCpu {
            gs_base.reg.save(guard);
        }
        gs_base.location = UserCpuStateLocation::InMemory;
    }

    fn before_user_exec(&self, guard: &DisabledLocalIrqGuard) {
        let mut fpu = self.fpu.lock();
        if fpu.location == UserCpuStateLocation::InMemory {
            fpu.reg.load();
        }
        fpu.location = UserCpuStateLocation::OnCpu;
        drop(fpu);

        let mut fs_base = self.fs_base.lock();
        if fs_base.location == UserCpuStateLocation::InMemory {
            fs_base.reg.load();
        }
        fs_base.location = UserCpuStateLocation::OnCpu;
        drop(fs_base);

        let mut gs_base = self.gs_base.lock();
        if gs_base.location == UserCpuStateLocation::InMemory {
            gs_base.reg.load(guard);
        }
        gs_base.location = UserCpuStateLocation::OnCpu;
    }
}

/// Next thread ID (TID) allocator.
static NEXT_TID: AtomicU32 = AtomicU32::new(1);
static ACTIVE_USER_TASKS: AtomicU32 = AtomicU32::new(0);
static USER_TASK_WAIT_QUEUE: Once<WaitQueue> = Once::new();
static LIVE_USER_TASKS: Once<Mutex<BTreeMap<u32, Weak<Task>>>> = Once::new();

pub fn alloc_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::Relaxed)
}

fn user_task_wait_queue() -> &'static WaitQueue {
    USER_TASK_WAIT_QUEUE.call_once(WaitQueue::new)
}

fn signal_user_task_completion() {
    let _ = ACTIVE_USER_TASKS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
        count.checked_sub(1)
    });
    user_task_wait_queue().wake_one();
}

fn live_user_tasks() -> &'static Mutex<BTreeMap<u32, Weak<Task>>> {
    LIVE_USER_TASKS.call_once(|| Mutex::new(BTreeMap::new()))
}

fn register_live_user_task(task: &Arc<Task>) {
    let Some(task_data) = task.data().downcast_ref::<UserTaskData>() else {
        return;
    };
    live_user_tasks()
        .lock()
        .insert(task_data.tid, Arc::downgrade(task));
}

fn unregister_live_user_task(tid: u32) {
    live_user_tasks().lock().remove(&tid);
}

fn live_user_task(tid: u32) -> Option<Arc<Task>> {
    let mut tasks = live_user_tasks().lock();
    let task = tasks.get(&tid).and_then(Weak::upgrade);
    if task.is_none() {
        tasks.remove(&tid);
    }
    task
}

/// Returns the process that owns a live user thread.
pub fn process_for_tid(tid: u32) -> Option<Arc<ProcessIdentity>> {
    let task = live_user_task(tid)?;
    task.data()
        .downcast_ref::<UserTaskData>()
        .map(|task_data| task_data.process.clone())
}

/// Returns accumulated CPU runtime for a live user thread.
pub fn thread_cpu_time_cycles_for_tid(tid: u32) -> Option<u64> {
    let task = live_user_task(tid)?;
    task.data()
        .downcast_ref::<UserTaskData>()
        .map(UserTaskData::thread_cpu_time_cycles)
}

/// Returns a live process and its resource limits by process ID.
pub fn process_resource_limits_for_pid(
    pid: u32,
) -> Option<(Arc<ProcessIdentity>, Arc<ResourceLimits>)> {
    let mut tasks = live_user_tasks().lock();
    let mut dead_tids = Vec::new();
    let mut result = None;

    for (tid, task) in tasks.iter() {
        let Some(task) = task.upgrade() else {
            dead_tids.push(*tid);
            continue;
        };
        let Some(task_data) = task.data().downcast_ref::<UserTaskData>() else {
            continue;
        };
        if task_data.process.pid() == pid {
            result = Some((task_data.process.clone(), task_data.resource_limits.clone()));
            break;
        }
    }

    for tid in dead_tids {
        tasks.remove(&tid);
    }

    result
}

fn thread_name_from_executable_path(executable_path: &str) -> [u8; THREAD_NAME_LEN] {
    let file_name = executable_path.split('/').next_back().unwrap_or_default();
    thread_name_from_bytes(file_name.as_bytes())
}

fn thread_name_from_bytes(name: &[u8]) -> [u8; THREAD_NAME_LEN] {
    let mut thread_name = [0u8; THREAD_NAME_LEN];
    let name_len = name.len().min(THREAD_NAME_LEN - 1);
    thread_name[..name_len].copy_from_slice(&name[..name_len]);
    thread_name
}

pub fn wait_for_user_task_to_exit(task: &Arc<Task>) {
    let Some(task_data) = task.data().downcast_ref::<UserTaskData>() else {
        return;
    };

    task_data.finish_queue.wait_until(|| {
        if task_data.finished.load(Ordering::SeqCst) {
            Some(())
        } else {
            None
        }
    });
}

/// Data associated with the user task
pub struct UserTaskData {
    pub vm_space: Mutex<Arc<VmSpace>>,
    pub entry_point: AtomicUsize,
    pub stack_top: AtomicUsize,
    pub lazy_ranges: Mutex<Arc<Vec<LazyRange>>>,
    pub heap_base: AtomicUsize,
    pub brk: AtomicUsize,
    pub cpu_state: UserCpuState,
    pub finished: Arc<AtomicBool>,
    pub finish_queue: Arc<WaitQueue>,
    exec_started: Arc<AtomicBool>,
    exec_queue: Arc<WaitQueue>,
    pub tid: u32,
    pub parent_tid: Option<u32>,
    pub process: Arc<ProcessIdentity>,
    thread_cpu_time_cycles: AtomicU64,
    last_cpu_time_start_cycles: AtomicU64,
    pub cpu_id: CpuId,
    pub initial_context: Option<UserContext>,
    pub exit_code: AtomicI32,
    pub clear_child_tid: AtomicUsize,
    /// Per-thread robust futex list registered by `set_robust_list`.
    pub robust_list: Mutex<Option<RobustListHead>>,
    /// Filesystem context used by path-based syscalls.
    pub fs: Mutex<ThreadFsInfo>,
    /// Per-task reference to the file descriptor table.
    ///
    /// Tasks created with `CLONE_FILES` share the same inner table. Syscalls
    /// such as `close_range(CLOSE_RANGE_UNSHARE)` replace this reference with
    /// a cloned table for the current task.
    fd_table: Mutex<Arc<Mutex<FileTable>>>,
    /// Process-level resource limits.
    pub resource_limits: Arc<ResourceLimits>,
    /// Process-level signal dispositions.
    pub signal_actions: Arc<SignalActions>,
    /// Per-thread signal mask.
    pub signal_mask: AtomicU64,
    /// Thread name exposed through `prctl(PR_GET_NAME)`.
    pub thread_name: Mutex<[u8; THREAD_NAME_LEN]>,
    /// Per-thread timer slack in nanoseconds.
    pub timer_slack_ns: AtomicU64,
    /// Default timer slack used by `prctl(PR_SET_TIMERSLACK, 0)`.
    pub default_timer_slack_ns: AtomicU64,
    pending_child_starts: Mutex<Vec<Arc<Task>>>,
    exit_mode: UserTaskExitMode,
}

impl UserTaskData {
    pub fn vm_space(&self) -> Arc<VmSpace> {
        self.vm_space.lock().clone()
    }

    pub fn lazy_ranges(&self) -> Arc<Vec<LazyRange>> {
        self.lazy_ranges.lock().clone()
    }

    pub fn entry_point(&self) -> usize {
        self.entry_point.load(Ordering::SeqCst)
    }

    pub fn stack_top(&self) -> usize {
        self.stack_top.load(Ordering::SeqCst)
    }

    pub fn heap_base(&self) -> usize {
        self.heap_base.load(Ordering::SeqCst)
    }

    pub(crate) fn fd_table(&self) -> Arc<Mutex<FileTable>> {
        self.fd_table.lock().clone()
    }

    pub(crate) fn unshare_fd_table(&self) {
        let mut fd_table_ref = self.fd_table.lock();
        if Arc::strong_count(&fd_table_ref) == 1 {
            return;
        }

        let cloned_table = fd_table_ref.lock().clone_for_fork();
        *fd_table_ref = Arc::new(Mutex::new(cloned_table));
    }

    pub fn replace_exec_image(
        &self,
        vm_space: Arc<VmSpace>,
        entry_point: usize,
        stack_top: usize,
        heap_base: usize,
        lazy_ranges: Arc<Vec<LazyRange>>,
        executable_path: &str,
    ) {
        *self.vm_space.lock() = vm_space;
        *self.lazy_ranges.lock() = lazy_ranges;
        self.entry_point.store(entry_point, Ordering::SeqCst);
        self.stack_top.store(stack_top, Ordering::SeqCst);
        self.heap_base.store(heap_base, Ordering::SeqCst);
        self.brk.store(heap_base, Ordering::SeqCst);
        self.cpu_state.reset_for_exec();
        self.signal_actions.reset_user_handlers_for_exec();
        *self.thread_name.lock() = thread_name_from_executable_path(executable_path);
    }

    pub fn set_fs_base(&self, addr: usize) {
        self.cpu_state.set_fs_base(addr);
    }

    pub fn set_gs_base(&self, addr: usize) {
        self.cpu_state.set_gs_base(addr);
    }

    pub fn fs_base(&self) -> usize {
        self.cpu_state.fs_base()
    }

    pub fn gs_base(&self, guard: &DisabledLocalIrqGuard) -> usize {
        self.cpu_state.gs_base(guard)
    }

    pub fn save_cpu_state_before_schedule(&self, guard: &DisabledLocalIrqGuard) {
        self.cpu_state.before_schedule(guard);
    }

    pub fn restore_cpu_state_before_user(&self, guard: &DisabledLocalIrqGuard) {
        self.cpu_state.before_user_exec(guard);
    }

    pub fn record_cpu_time_schedule_in(&self) {
        self.last_cpu_time_start_cycles
            .store(ostd::arch::read_tsc(), Ordering::Release);
    }

    pub fn record_cpu_time_schedule_out(&self) {
        let start_cycles = self.last_cpu_time_start_cycles.swap(0, Ordering::AcqRel);
        if start_cycles == 0 {
            return;
        }

        let delta = ostd::arch::read_tsc().saturating_sub(start_cycles);
        self.thread_cpu_time_cycles
            .fetch_add(delta, Ordering::Relaxed);
        self.process.record_cpu_time_cycles(delta);
    }

    pub fn thread_cpu_time_cycles(&self) -> u64 {
        self.cpu_time_cycles_with_current_delta(self.thread_cpu_time_cycles.load(Ordering::Acquire))
    }

    pub fn process_cpu_time_cycles(&self) -> u64 {
        self.cpu_time_cycles_with_current_delta(self.process.cpu_time_cycles())
    }

    fn cpu_time_cycles_with_current_delta(&self, base_cycles: u64) -> u64 {
        let start_cycles = self.last_cpu_time_start_cycles.load(Ordering::Acquire);
        if start_cycles == 0 {
            return base_cycles;
        }

        base_cycles.saturating_add(ostd::arch::read_tsc().saturating_sub(start_cycles))
    }

    pub fn notify_exec_boundary(&self) {
        if !self.exec_started.swap(true, Ordering::SeqCst) {
            self.exec_queue.wake_all();
        }
    }

    fn defer_child_start(&self, task: Arc<Task>) {
        self.pending_child_starts.lock().push(task);
    }

    fn start_pending_children(&self) {
        let children = {
            let mut pending_child_starts = self.pending_child_starts.lock();
            mem::take(&mut *pending_child_starts)
        };

        for child in children {
            child.run();
        }
    }

    fn should_park_after_exit(&self) -> bool {
        matches!(self.exit_mode, UserTaskExitMode::ParkAfterExit)
    }
}

fn prepare_current_task_for_child_wait() {
    let Some(current_task) = Task::current() else {
        return;
    };
    let Some(task_data) = current_task.data().downcast_ref::<UserTaskData>() else {
        return;
    };
    scheduler::block_task(task_data.cpu_id, task_data.tid);
    task_data.start_pending_children();
}

pub fn notify_current_exec_boundary() -> Result<()> {
    let current = Task::current().ok_or(Error::new(Errno::ESRCH))?;
    let task_data = current
        .data()
        .downcast_ref::<UserTaskData>()
        .ok_or(Error::new(Errno::EINVAL))?;
    task_data.notify_exec_boundary();
    Ok(())
}

fn handle_lazy_page_fault(
    vm_space: &VmSpace,
    lazy_ranges: &[LazyRange],
    info: RawPageFaultInfo,
) -> bool {
    if info.error_code.contains(PageFaultErrorCode::PRESENT) {
        return false;
    }

    let addr = info.addr;
    let range = match lazy_ranges.iter().find(|range| range.contains(addr)) {
        Some(range) => range,
        None => return false,
    };

    let page_start = addr.align_down(PAGE_SIZE);
    let page_end = page_start + PAGE_SIZE;
    let map_prop = PageProperty::new_user(range.page_flags(), CachePolicy::Writeback);

    let segment = match FrameAllocOptions::new().alloc_segment(1) {
        Ok(segment) => segment,
        Err(_) => return false,
    };

    let frame = match segment.into_iter().next() {
        Some(frame) => frame,
        None => return false,
    };

    let preempt_guard = disable_preempt();
    let mut cursor = match vm_space.cursor_mut(&preempt_guard, &(page_start..page_end)) {
        Ok(cursor) => cursor,
        Err(_) => return false,
    };
    cursor.map(frame.into(), map_prop);
    true
}

pub fn user_page_fault_handler(exception: &CpuException) -> core::result::Result<(), ()> {
    let CpuException::PageFault(info) = *exception else {
        return Err(());
    };

    let current = Task::current().ok_or(())?;
    let Some(task_data) = current.data().downcast_ref::<UserTaskData>() else {
        ostd::early_println!(
            "[kernel] user page fault without task data: addr=0x{:x}, code={:?}",
            info.addr,
            info.error_code
        );
        return Err(());
    };

    let handled = handle_lazy_page_fault(
        task_data.vm_space().as_ref(),
        task_data.lazy_ranges().as_ref(),
        info,
    );
    ostd::early_println!(
        "[kernel] user page fault: tid={}, addr=0x{:x}, code={:?}, handled={}",
        task_data.tid,
        info.addr,
        info.error_code,
        handled
    );
    if handled { Ok(()) } else { Err(()) }
}

/// Handler called when the task is scheduled
pub fn post_schedule_handler() -> bool {
    if let Some(task) = Task::current() {
        if let Some(user_task_data) = task.data().downcast_ref::<UserTaskData>() {
            user_task_data.record_cpu_time_schedule_in();
            user_task_data.vm_space().activate();
        }
    }
    true
}

/// Saves user CPU state before a task switch.
pub fn pre_schedule_handler(guard: &DisabledLocalIrqGuard) {
    if let Some(task) = Task::current()
        && let Some(user_task_data) = task.data().downcast_ref::<UserTaskData>()
    {
        user_task_data.record_cpu_time_schedule_out();
        user_task_data.save_cpu_state_before_schedule(guard);
    }
}

/// Loads user CPU state before entering user mode.
pub fn pre_user_run_handler(guard: &DisabledLocalIrqGuard) {
    if let Some(task) = Task::current()
        && let Some(user_task_data) = task.data().downcast_ref::<UserTaskData>()
    {
        user_task_data.restore_cpu_state_before_user(guard);
    }
}

/// Creates a user context with entry point and stack
fn create_user_context(entry_point: usize, stack_top: usize) -> UserContext {
    let mut user_ctx = UserContext::default();
    user_ctx.set_rip(entry_point);
    user_ctx.set_rsp(stack_top);
    user_ctx
}

/// Executor for the user task loop
struct UserExecutor {
    user_mode: UserMode,
    vm_space: Arc<VmSpace>,
    lazy_ranges: Arc<Vec<LazyRange>>,
    cpu_id: CpuId,
    tid: u32,
}

impl UserExecutor {
    fn new(
        entry_point: usize,
        stack_top: usize,
        vm_space: Arc<VmSpace>,
        lazy_ranges: Arc<Vec<LazyRange>>,
        cpu_id: CpuId,
        tid: u32,
    ) -> Self {
        let user_ctx = create_user_context(entry_point, stack_top);
        let user_mode = UserMode::new(user_ctx);
        Self {
            user_mode,
            vm_space,
            lazy_ranges,
            cpu_id,
            tid,
        }
    }

    fn from_context(
        context: UserContext,
        vm_space: Arc<VmSpace>,
        lazy_ranges: Arc<Vec<LazyRange>>,
        cpu_id: CpuId,
        tid: u32,
    ) -> Self {
        let user_mode = UserMode::new(context);
        Self {
            user_mode,
            vm_space,
            lazy_ranges,
            cpu_id,
            tid,
        }
    }

    fn run(&mut self) {
        loop {
            scheduler::wait_until_current(self.cpu_id, self.tid);
            self.activate_user_state();

            let cpu_id = self.cpu_id;
            let tid = self.tid;
            let return_reason = self
                .user_mode
                .execute(|| scheduler::has_kernel_event(cpu_id, tid));
            if self.handle_exit_reason(return_reason) {
                break;
            }
        }
    }

    fn activate_user_state(&self) {
        self.vm_space.activate();
    }

    /// Handles the reason for returning from user mode. Returns true if the task should exit.
    fn handle_exit_reason(&mut self, reason: ReturnReason) -> bool {
        match reason {
            ReturnReason::UserSyscall => {
                let user_context = self.user_mode.context_mut();
                let should_exit = handle_syscall(user_context, &self.vm_space);
                if !should_exit {
                    self.sync_after_syscall();
                }
                should_exit
            }
            ReturnReason::UserException => {
                let (exception, rip) = {
                    let user_context = self.user_mode.context_mut();
                    (user_context.take_exception(), user_context.rip())
                };
                if let Some(CpuException::PageFault(info)) = exception {
                    if self.handle_page_fault(info) {
                        return false;
                    }
                }
                ostd::early_println!(
                    "[kernel] user exception occurred: {:?}, RIP: 0x{:x}",
                    exception,
                    rip
                );
                true // Exit on unhandled exception
            }
            ReturnReason::KernelEvent => {
                scheduler::reschedule_current_task(self.cpu_id, self.tid);
                false
            }
        }
    }

    fn handle_page_fault(&self, info: RawPageFaultInfo) -> bool {
        handle_lazy_page_fault(self.vm_space.as_ref(), self.lazy_ranges.as_ref(), info)
    }

    fn sync_after_syscall(&mut self) {
        let Some(current_task) = Task::current() else {
            return;
        };
        let Some(task_data) = current_task.data().downcast_ref::<UserTaskData>() else {
            return;
        };

        let vm_space = task_data.vm_space();
        if !Arc::ptr_eq(&self.vm_space, &vm_space) {
            self.vm_space = vm_space;
            self.lazy_ranges = task_data.lazy_ranges();
        }
    }
}

/// user task
fn user_task_routine() {
    // Retrieve task data
    let Some(current_task) = Task::current() else {
        ostd::early_println!("[kernel] error: current task missing in user task routine");
        signal_user_task_completion();
        return;
    };
    let Some(task_data) = current_task.data().downcast_ref::<UserTaskData>() else {
        ostd::early_println!("[kernel] error: user task data missing in user task routine");
        signal_user_task_completion();
        return;
    };

    scheduler::register_current_task();

    // Initialize and run the executor
    let vm_space = task_data.vm_space();
    let lazy_ranges = task_data.lazy_ranges();
    let mut executor = if let Some(initial_ctx) = task_data.initial_context.as_ref() {
        UserExecutor::from_context(
            initial_ctx.clone(),
            vm_space,
            lazy_ranges,
            task_data.cpu_id,
            task_data.tid,
        )
    } else {
        UserExecutor::new(
            task_data.entry_point(),
            task_data.stack_top(),
            vm_space,
            lazy_ranges,
            task_data.cpu_id,
            task_data.tid,
        )
    };
    executor.run();

    let exit_code = task_data.exit_code.load(Ordering::SeqCst);
    task_data.record_cpu_time_schedule_out();
    task_data.notify_exec_boundary();
    // These cleanup paths access user addresses, so they must run before
    // switching away from the exiting task's address space.
    clear_child_tid_on_exit(task_data);
    robust_list::wake_robust_list(
        task_data.vm_space().as_ref(),
        task_data.robust_list.lock().take(),
        task_data.tid,
    );
    activate_kernel_vm_space();
    drop(executor);

    cleanup_task_fds(task_data);
    unregister_live_user_task(task_data.tid);
    record_task_exit(task_data, exit_code);
    task_data.finished.store(true, Ordering::SeqCst);
    signal_user_task_completion();
    task_data.finish_queue.wake_one();
    if task_data.parent_tid.is_none() && task_data.should_park_after_exit() {
        let park_queue = WaitQueue::new();
        loop {
            park_queue.wait_until(|| None::<()>);
        }
    }
}

fn create_user_task_inner(
    executable_path: &str,
    vm_space: Arc<VmSpace>,
    entry_point: usize,
    stack_top: usize,
    heap_base: usize,
    lazy_ranges: Arc<Vec<LazyRange>>,
    finish_queue: Arc<WaitQueue>,
    cpu_id: CpuId,
    exit_mode: UserTaskExitMode,
) -> Result<Arc<Task>> {
    let tid = alloc_tid();
    let task_data = UserTaskData {
        vm_space: Mutex::new(vm_space),
        entry_point: AtomicUsize::new(entry_point),
        stack_top: AtomicUsize::new(stack_top),
        lazy_ranges: Mutex::new(lazy_ranges),
        heap_base: AtomicUsize::new(heap_base),
        brk: AtomicUsize::new(heap_base),
        cpu_state: UserCpuState::new(),
        finished: Arc::new(AtomicBool::new(false)),
        finish_queue,
        exec_started: Arc::new(AtomicBool::new(false)),
        exec_queue: Arc::new(WaitQueue::new()),
        tid,
        parent_tid: None,
        process: new_init_process(tid),
        thread_cpu_time_cycles: AtomicU64::new(0),
        last_cpu_time_start_cycles: AtomicU64::new(0),
        cpu_id,
        initial_context: None,
        exit_code: AtomicI32::new(0),
        clear_child_tid: AtomicUsize::new(0),
        robust_list: Mutex::new(None),
        fs: Mutex::new(ThreadFsInfo::new_root()),
        fd_table: Mutex::new(Arc::new(Mutex::new(FileTable::new()))),
        resource_limits: Arc::new(ResourceLimits::default()),
        signal_actions: Arc::new(SignalActions::new()),
        signal_mask: AtomicU64::new(0),
        thread_name: Mutex::new(thread_name_from_executable_path(executable_path)),
        timer_slack_ns: AtomicU64::new(DEFAULT_TIMER_SLACK_NS),
        default_timer_slack_ns: AtomicU64::new(DEFAULT_TIMER_SLACK_NS),
        pending_child_starts: Mutex::new(Vec::new()),
        exit_mode,
    };

    let task = TaskOptions::new(user_task_routine)
        .data(task_data)
        .build()
        .map(Arc::new)
        .map_err(|e| Error::from(e))?;

    task.schedule_info().cpu.set_anyway(cpu_id);
    register_live_user_task(&task);
    ACTIVE_USER_TASKS.fetch_add(1, Ordering::SeqCst);
    Ok(task)
}

pub fn create_user_task(
    executable_path: &str,
    vm_space: Arc<VmSpace>,
    entry_point: usize,
    stack_top: usize,
    heap_base: usize,
    lazy_ranges: Arc<Vec<LazyRange>>,
    finish_queue: Arc<WaitQueue>,
    cpu_id: CpuId,
) -> Result<Arc<Task>> {
    create_user_task_inner(
        executable_path,
        vm_space,
        entry_point,
        stack_top,
        heap_base,
        lazy_ranges,
        finish_queue,
        cpu_id,
        UserTaskExitMode::ParkAfterExit,
    )
}

pub fn create_transient_user_task(
    executable_path: &str,
    vm_space: Arc<VmSpace>,
    entry_point: usize,
    stack_top: usize,
    heap_base: usize,
    lazy_ranges: Arc<Vec<LazyRange>>,
    finish_queue: Arc<WaitQueue>,
    cpu_id: CpuId,
) -> Result<Arc<Task>> {
    create_user_task_inner(
        executable_path,
        vm_space,
        entry_point,
        stack_top,
        heap_base,
        lazy_ranges,
        finish_queue,
        cpu_id,
        UserTaskExitMode::CompleteAfterExit,
    )
}

pub fn clone_user_task(
    parent_context: &UserContext,
    child_stack: usize,
    flags: u64,
    parent_tidptr: usize,
    child_tidptr: usize,
    tls: usize,
) -> Result<u32> {
    let current = Task::current().ok_or(Error::new(Errno::ESRCH))?;
    let parent_data = current
        .data()
        .downcast_ref::<UserTaskData>()
        .ok_or(Error::new(Errno::EINVAL))?;

    let guard = ostd::irq::disable_local();
    parent_data.save_cpu_state_before_schedule(&guard);
    drop(guard);

    validate_clone_flags(flags)?;
    let clone_flags = clone_flags_without_exit_signal(flags);

    let thread_style = clone_flags & CLONE_THREAD != 0;
    let fork_style = clone_flags & CLONE_VM == 0;
    let child_vm_space = if fork_style {
        Arc::new(clone_vm_space(parent_data.vm_space().as_ref())?)
    } else {
        parent_data.vm_space()
    };

    let mut child_ctx = parent_context.clone();
    let child_stack_top = if fork_style {
        if child_stack != 0 {
            child_ctx.set_rsp(child_stack);
        }
        parent_data.stack_top()
    } else if child_stack != 0 {
        child_ctx.set_rsp(child_stack);
        child_stack
    } else {
        parent_data.stack_top()
    };

    // Child returns 0 from clone/fork.
    child_ctx.set_rax(0);

    // File descriptor table semantics:
    // - CLONE_FILES: share the same fd table object between parent/child.
    // - otherwise (fork-style): clone descriptor table entries.
    let parent_fd_table = parent_data.fd_table();
    let child_fd_table = if clone_flags & CLONE_FILES != 0 {
        parent_fd_table
    } else {
        let parent_fds = parent_fd_table.lock();
        Arc::new(Mutex::new(parent_fds.clone_for_fork()))
    };
    let child_resource_limits = if fork_style {
        Arc::new(parent_data.resource_limits.as_ref().clone())
    } else {
        parent_data.resource_limits.clone()
    };
    let child_signal_actions = if clone_flags & CLONE_SIGHAND != 0 {
        parent_data.signal_actions.clone()
    } else {
        Arc::new(parent_data.signal_actions.snapshot())
    };
    let child_cpu_state = parent_data.cpu_state.clone_in_memory();
    if clone_flags & CLONE_SETTLS != 0 {
        child_cpu_state.set_fs_base(tls);
    }
    let child_finished = Arc::new(AtomicBool::new(false));
    let child_exec_started = Arc::new(AtomicBool::new(false));
    let child_exec_queue = Arc::new(WaitQueue::new());

    let tid = alloc_tid();
    let set_child_tid_requested = clone_flags & CLONE_CHILD_SETTID != 0;
    let clear_child_tid = if clone_flags & CLONE_CHILD_CLEARTID != 0 {
        child_tidptr
    } else {
        0
    };
    if clone_flags & CLONE_PARENT_SETTID != 0 {
        write_u32_to_user(parent_data.vm_space().as_ref(), parent_tidptr, tid)?;
    }
    if set_child_tid_requested {
        write_u32_to_user(child_vm_space.as_ref(), child_tidptr, tid)?;
    }
    let parent_tid = parent_data.tid;
    let cpu_id = parent_data.cpu_id;
    let parent_timer_slack = parent_data.timer_slack_ns.load(Ordering::SeqCst);
    let child_process = if thread_style {
        parent_data.process.clone()
    } else {
        new_child_process(tid, &parent_data.process)
    };
    let task_data = UserTaskData {
        vm_space: Mutex::new(child_vm_space),
        entry_point: AtomicUsize::new(parent_data.entry_point()),
        stack_top: AtomicUsize::new(child_stack_top),
        lazy_ranges: Mutex::new(parent_data.lazy_ranges()),
        heap_base: AtomicUsize::new(parent_data.heap_base()),
        brk: AtomicUsize::new(parent_data.brk.load(Ordering::SeqCst)),
        cpu_state: child_cpu_state,
        finished: child_finished.clone(),
        finish_queue: parent_data.finish_queue.clone(),
        exec_started: child_exec_started.clone(),
        exec_queue: child_exec_queue.clone(),
        tid,
        parent_tid: Some(parent_tid),
        process: child_process,
        thread_cpu_time_cycles: AtomicU64::new(0),
        last_cpu_time_start_cycles: AtomicU64::new(0),
        cpu_id,
        initial_context: Some(child_ctx),
        exit_code: AtomicI32::new(0),
        clear_child_tid: AtomicUsize::new(clear_child_tid),
        robust_list: Mutex::new(None),
        fs: Mutex::new(parent_data.fs.lock().clone()),
        fd_table: Mutex::new(child_fd_table),
        resource_limits: child_resource_limits,
        signal_actions: child_signal_actions,
        signal_mask: AtomicU64::new(parent_data.signal_mask.load(Ordering::SeqCst)),
        thread_name: Mutex::new(*parent_data.thread_name.lock()),
        timer_slack_ns: AtomicU64::new(parent_timer_slack),
        default_timer_slack_ns: AtomicU64::new(parent_timer_slack),
        pending_child_starts: Mutex::new(Vec::new()),
        exit_mode: UserTaskExitMode::CompleteAfterExit,
    };

    let task = TaskOptions::new(user_task_routine)
        .data(task_data)
        .build()
        .map(Arc::new)
        .map_err(|e| Error::from(e))?;

    task.schedule_info().cpu.set_anyway(cpu_id);
    register_live_user_task(&task);
    register_live_child(parent_tid, tid);
    ACTIVE_USER_TASKS.fetch_add(1, Ordering::SeqCst);
    if clone_flags & CLONE_VFORK != 0 {
        let preempt_guard = disable_preempt();
        task.run();
        drop(preempt_guard);
        child_exec_queue.wait_until(|| {
            (child_exec_started.load(Ordering::SeqCst) || child_finished.load(Ordering::SeqCst))
                .then_some(())
        });
    } else {
        parent_data.defer_child_start(task);
    }
    Ok(tid)
}

pub fn set_current_exit_code(code: i32) {
    if let Some(current) = Task::current() {
        if let Some(data) = current.data().downcast_ref::<UserTaskData>() {
            data.exit_code.store(code, Ordering::SeqCst);
        }
    }
}

fn cleanup_task_fds(task_data: &UserTaskData) {
    let fd_table_ref = task_data.fd_table.lock();

    // Align with Linux CLONE_FILES semantics: only close descriptors when this
    // task owns the last reference to the fd table object.
    if Arc::strong_count(&fd_table_ref) == 1 {
        fd_table_ref.lock().close_all();
    }
}

fn clear_child_tid_on_exit(task_data: &UserTaskData) {
    let clear_child_tid = task_data.clear_child_tid.swap(0, Ordering::SeqCst);
    if clear_child_tid == 0 {
        return;
    }

    if let Err(error) = write_u32_to_user(task_data.vm_space().as_ref(), clear_child_tid, 0) {
        ostd::early_println!("[kernel] exit: cannot clear child tid: {:?}", error);
    }
    if let Err(error) = futex::futex_wake(clear_child_tid, 1) {
        ostd::early_println!(
            "[kernel] exit: cannot wake clear child tid futex: {:?}",
            error
        );
    }
}

#[derive(Clone)]
pub struct ExitInfo {
    pub tid: u32,
    pub parent_tid: Option<u32>,
    pub code: i32,
}

pub enum TryWaitResult {
    Exited(ExitInfo),
    StillRunning,
    NoChild,
}

struct ExitState {
    zombies: Vec<ExitInfo>,
    live_children: BTreeMap<u32, Vec<u32>>,
}

struct ExitQueue {
    state: Mutex<ExitState>,
    wait_queue: WaitQueue,
}

static EXIT_QUEUE: Once<ExitQueue> = Once::new();

fn exit_queue() -> &'static ExitQueue {
    EXIT_QUEUE.call_once(|| ExitQueue {
        state: Mutex::new(ExitState {
            zombies: Vec::new(),
            live_children: BTreeMap::new(),
        }),
        wait_queue: WaitQueue::new(),
    })
}

fn register_live_child(parent_tid: u32, child_tid: u32) {
    let queue = exit_queue();
    let mut state = queue.state.lock();
    state
        .live_children
        .entry(parent_tid)
        .or_default()
        .push(child_tid);
}

pub fn record_task_exit(task_data: &UserTaskData, code: i32) {
    scheduler::mark_task_exiting(task_data.cpu_id, task_data.tid);
    let parent_task = task_data.parent_tid.and_then(live_user_task);
    let queue = exit_queue();
    let mut state = queue.state.lock();
    if let Some(parent_tid) = task_data.parent_tid
        && let Some(children) = state.live_children.get_mut(&parent_tid)
    {
        children.retain(|child_tid| *child_tid != task_data.tid);
        if children.is_empty() {
            state.live_children.remove(&parent_tid);
        }
    }
    state.zombies.push(ExitInfo {
        tid: task_data.tid,
        parent_tid: task_data.parent_tid,
        code,
    });
    drop(state);
    unregister_process_if_last_reference(&task_data.process);
    if let Some(parent_task) = parent_task {
        parent_task.wake_up();
    }
    queue.wait_queue.wake_all();
}

pub fn wait_for_exit(parent_tid: u32, pid: i32) -> Result<ExitInfo> {
    match try_wait_for_exit(parent_tid, pid) {
        TryWaitResult::Exited(exit_info) => return Ok(exit_info),
        TryWaitResult::NoChild => {
            return Err(Error::new(Errno::ECHILD));
        }
        TryWaitResult::StillRunning => {}
    }

    prepare_current_task_for_child_wait();
    let queue = exit_queue();
    let result = queue
        .wait_queue
        .wait_until(|| match try_wait_for_exit(parent_tid, pid) {
            TryWaitResult::Exited(exit_info) => Some(Ok(exit_info)),
            TryWaitResult::NoChild => Some(Err(Error::new(Errno::ECHILD))),
            TryWaitResult::StillRunning => None,
        });
    result
}

pub fn wait_for_exit_no_reap(parent_tid: u32, pid: i32) -> Result<ExitInfo> {
    match peek_wait_for_exit(parent_tid, pid) {
        TryWaitResult::Exited(exit_info) => {
            return Ok(exit_info);
        }
        TryWaitResult::NoChild => {
            return Err(Error::new(Errno::ECHILD));
        }
        TryWaitResult::StillRunning => {}
    }

    prepare_current_task_for_child_wait();
    let queue = exit_queue();
    queue
        .wait_queue
        .wait_until(|| match peek_wait_for_exit(parent_tid, pid) {
            TryWaitResult::Exited(exit_info) => Some(Ok(exit_info)),
            TryWaitResult::NoChild => Some(Err(Error::new(Errno::ECHILD))),
            TryWaitResult::StillRunning => None,
        })
}

pub fn try_wait_for_exit(parent_tid: u32, pid: i32) -> TryWaitResult {
    let queue = exit_queue();
    let mut state = queue.state.lock();
    if let Some(idx) = state
        .zombies
        .iter()
        .position(|zombie| zombie_matches(zombie, parent_tid, pid))
    {
        return TryWaitResult::Exited(state.zombies.remove(idx));
    }

    if has_live_child(&state, parent_tid, pid) {
        TryWaitResult::StillRunning
    } else {
        TryWaitResult::NoChild
    }
}

pub fn peek_wait_for_exit(parent_tid: u32, pid: i32) -> TryWaitResult {
    let queue = exit_queue();
    let state = queue.state.lock();
    if let Some(exit_info) = state
        .zombies
        .iter()
        .find(|zombie| zombie_matches(zombie, parent_tid, pid))
    {
        return TryWaitResult::Exited(exit_info.clone());
    }

    if has_live_child(&state, parent_tid, pid) {
        TryWaitResult::StillRunning
    } else {
        TryWaitResult::NoChild
    }
}

fn zombie_matches(zombie: &ExitInfo, parent_tid: u32, pid: i32) -> bool {
    zombie.parent_tid == Some(parent_tid) && (pid <= 0 || zombie.tid == pid as u32)
}

fn has_live_child(state: &ExitState, parent_tid: u32, pid: i32) -> bool {
    let Some(children) = state.live_children.get(&parent_tid) else {
        return false;
    };
    if pid <= 0 {
        return !children.is_empty();
    }
    children.iter().any(|child_tid| *child_tid == pid as u32)
}

fn validate_clone_flags(flags: u64) -> Result<()> {
    if flags & UNSUPPORTED_CLONE_FLAGS != 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    if flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    if flags & CLONE_THREAD != 0 && flags & (CLONE_VM | CLONE_SIGHAND) != (CLONE_VM | CLONE_SIGHAND)
    {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok(())
}

fn clone_flags_without_exit_signal(flags: u64) -> u64 {
    flags & !CLONE_EXIT_SIGNAL_MASK
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn clone_rejects_namespace_flags() {
        for namespace_flag in [
            CLONE_NEWTIME,
            CLONE_NEWNS,
            CLONE_NEWCGROUP,
            CLONE_NEWUTS,
            CLONE_NEWIPC,
            CLONE_NEWUSER,
            CLONE_NEWPID,
            CLONE_NEWNET,
        ] {
            assert_eq!(
                validate_clone_flags(namespace_flag).unwrap_err().errno(),
                Errno::EINVAL
            );
        }
    }

    #[ktest]
    fn clone_validates_signal_handler_and_thread_dependencies() {
        assert_eq!(
            validate_clone_flags(CLONE_SIGHAND).unwrap_err().errno(),
            Errno::EINVAL
        );
        assert_eq!(
            validate_clone_flags(CLONE_THREAD | CLONE_VM)
                .unwrap_err()
                .errno(),
            Errno::EINVAL
        );

        validate_clone_flags(CLONE_THREAD | CLONE_VM | CLONE_SIGHAND).unwrap();
    }
}

pub(crate) fn current_scheduler_identity() -> Option<(CpuId, u32)> {
    let current = Task::current()?;
    let task_data = current.data().downcast_ref::<UserTaskData>()?;
    Some((task_data.cpu_id, task_data.tid))
}

fn write_u32_to_user(vm_space: &VmSpace, addr: usize, value: u32) -> Result<()> {
    let bytes = value.to_ne_bytes();
    let mut writer = vm_space.writer(addr, bytes.len()).map_err(Error::from)?;
    writer
        .write_fallible(&mut VmReader::from(bytes.as_slice()))
        .map_err(|(error, _)| Error::from(error))?;
    Ok(())
}
