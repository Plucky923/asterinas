//! User-task lifecycle, execution, and fault handling for FrameVM.

use alloc::{sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

use align_ext::AlignExt;
use aster_framevisor::{
    arch::cpu::context::{CpuException, PageFaultErrorCode, RawPageFaultInfo, UserContext},
    mm::{
        CachePolicy, FallibleVmRead, FallibleVmWrite, FrameAllocOptions, PageProperty, VmReader,
        VmSpace, VmWriter,
    },
    sync::WaitQueue,
    task::{Task, TaskOptions, disable_preempt},
    user::{ReturnReason, UserMode},
};
use spin::{Mutex, Once};

use crate::{
    error::{Errno, Error, Result},
    fd_table::FdTable,
    syscall::handle_syscall,
    vm::{LazyRange, USER_STACK_SIZE, allocate_user_stack},
};

const PAGE_SIZE: usize = 4096;
/// Cooperative reschedule interval at syscall boundaries (ns).
///
/// FrameVM tasks do not currently get full Linux-style timer preemption on every
/// workload shape. We keep a small time slice here to avoid long-term starvation
/// across multiple busy user tasks (e.g., multi-connection recv loops).
const SYSCALL_RESCHED_INTERVAL_NS: u64 = 100_000; // 100us
static SYSCALL_RESCHED_INTERVAL_CYCLES: AtomicU64 = AtomicU64::new(0);

#[inline]
fn syscall_resched_interval_cycles() -> u64 {
    let cached = SYSCALL_RESCHED_INTERVAL_CYCLES.load(Ordering::Acquire);
    if cached != 0 {
        return cached;
    }

    let freq = aster_framevisor::arch::tsc_freq();
    let cycles = if freq == 0 {
        1
    } else {
        (((freq as u128) * (SYSCALL_RESCHED_INTERVAL_NS as u128)) / 1_000_000_000u128).max(1) as u64
    };

    let _ = SYSCALL_RESCHED_INTERVAL_CYCLES.compare_exchange(
        0,
        cycles,
        Ordering::AcqRel,
        Ordering::Acquire,
    );
    SYSCALL_RESCHED_INTERVAL_CYCLES.load(Ordering::Acquire)
}

/// Clone flags (simplified)
pub const CLONE_VM: u64 = 0x0000_0100;
pub const CLONE_FILES: u64 = 0x0000_0400;
pub const CLONE_THREAD: u64 = 0x0001_0000;

/// Next thread ID (TID) allocator
static NEXT_TID: AtomicU32 = AtomicU32::new(2);
static ACTIVE_USER_TASKS: AtomicU32 = AtomicU32::new(0);
static USER_TASK_WAIT_QUEUE: Once<WaitQueue> = Once::new();

pub fn alloc_tid() -> u32 {
    NEXT_TID.fetch_add(1, Ordering::Relaxed)
}

pub fn active_user_task_count() -> u32 {
    ACTIVE_USER_TASKS.load(Ordering::SeqCst)
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

pub fn wait_for_all_user_tasks_to_exit() {
    user_task_wait_queue().wait_until(|| {
        if active_user_task_count() == 0 {
            Some(())
        } else {
            None
        }
    });
}

/// Data associated with the user task
pub struct UserTaskData {
    pub vm_space: Arc<VmSpace>,
    pub entry_point: usize,
    pub stack_top: usize,
    pub lazy_ranges: Arc<Vec<LazyRange>>,
    pub finished: Arc<AtomicBool>,
    pub finish_queue: Arc<WaitQueue>,
    pub tid: u32,
    pub initial_context: Option<UserContext>,
    pub exit_code: AtomicI32,
    /// Per-task file descriptor table (cloned on fork)
    pub fd_table: Arc<Mutex<FdTable>>,
}

impl UserTaskData {
    pub fn vm_space(&self) -> Arc<VmSpace> {
        self.vm_space.clone()
    }
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
        return Err(());
    };

    if handle_lazy_page_fault(
        task_data.vm_space.as_ref(),
        task_data.lazy_ranges.as_ref(),
        info,
    ) {
        Ok(())
    } else {
        Err(())
    }
}

/// Handler called when the task is scheduled
pub fn post_schedule_handler() {
    if let Some(task) = Task::current() {
        if let Some(user_task_data) = task.data().downcast_ref::<UserTaskData>() {
            user_task_data.vm_space().activate();
        }
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
    last_syscall_resched_tsc: u64,
}

impl UserExecutor {
    fn new(
        entry_point: usize,
        stack_top: usize,
        vm_space: Arc<VmSpace>,
        lazy_ranges: Arc<Vec<LazyRange>>,
    ) -> Self {
        framevm_logln!("[FrameVM] Creating user context and mode");
        let user_ctx = create_user_context(entry_point, stack_top);
        let user_mode = UserMode::new(user_ctx);
        Self {
            user_mode,
            vm_space,
            lazy_ranges,
            last_syscall_resched_tsc: aster_framevisor::arch::read_tsc(),
        }
    }

    fn from_context(
        context: UserContext,
        vm_space: Arc<VmSpace>,
        lazy_ranges: Arc<Vec<LazyRange>>,
    ) -> Self {
        let user_mode = UserMode::new(context);
        Self {
            user_mode,
            vm_space,
            lazy_ranges,
            last_syscall_resched_tsc: aster_framevisor::arch::read_tsc(),
        }
    }

    fn run(&mut self) {
        framevm_logln!("[FrameVM] Entering user mode execution loop");
        loop {
            // Execute user code until an event occurs (syscall, exception, etc.)
            let return_reason = self.user_mode.execute(|| false);

            if self.handle_exit_reason(return_reason) {
                break;
            }
        }
        framevm_logln!("[FrameVM] User mode execution loop finished");
    }

    /// Handles the reason for returning from user mode. Returns true if the task should exit.
    fn handle_exit_reason(&mut self, reason: ReturnReason) -> bool {
        match reason {
            ReturnReason::UserSyscall => {
                let user_context = self.user_mode.context_mut();
                let should_exit = handle_syscall(user_context, &self.vm_space);
                if !should_exit {
                    self.maybe_resched_after_syscall();
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
                framevm_logln!(
                    "[FrameVM] User exception occurred: {:?}, RIP: 0x{:x}",
                    exception,
                    rip
                );
                true // Exit on unhandled exception
            }
            ReturnReason::KernelEvent => {
                // Kernel event (e.g., timer interrupt).
                // Yield to allow other tasks to run. Without this,
                // a task in a tight syscall loop (e.g., recvfrom)
                // monopolizes the CPU and starves other tasks,
                // causing severe bandwidth unfairness across connections.
                Task::yield_now();
                false
            }
        }
    }

    fn handle_page_fault(&self, info: RawPageFaultInfo) -> bool {
        handle_lazy_page_fault(self.vm_space.as_ref(), self.lazy_ranges.as_ref(), info)
    }

    #[inline]
    fn maybe_resched_after_syscall(&mut self) {
        let interval = syscall_resched_interval_cycles();
        let now = aster_framevisor::arch::read_tsc();
        if now.wrapping_sub(self.last_syscall_resched_tsc) < interval {
            return;
        }

        self.last_syscall_resched_tsc = now;
        Task::yield_now();
    }
}

/// user task
fn user_task_routine() {
    framevm_logln!("[FrameVM] User task started");

    // Retrieve task data
    let Some(current_task) = Task::current() else {
        framevm_logln!("[FrameVM] ERROR: current task missing in user task routine");
        signal_user_task_completion();
        return;
    };
    let Some(task_data) = current_task.data().downcast_ref::<UserTaskData>() else {
        framevm_logln!("[FrameVM] ERROR: user task data missing in user task routine");
        signal_user_task_completion();
        return;
    };

    // Initialize and run the executor
    let vm_space = task_data.vm_space.clone();
    let lazy_ranges = task_data.lazy_ranges.clone();
    let mut executor = if let Some(initial_ctx) = task_data.initial_context.as_ref() {
        UserExecutor::from_context(initial_ctx.clone(), vm_space, lazy_ranges)
    } else {
        UserExecutor::new(
            task_data.entry_point,
            task_data.stack_top,
            vm_space,
            lazy_ranges,
        )
    };
    executor.run();

    // Mark task as finished
    let exit_code = task_data.exit_code.load(Ordering::SeqCst);
    cleanup_task_fds(task_data);
    record_task_exit(task_data.tid, exit_code);
    task_data.finished.store(true, Ordering::SeqCst);
    signal_user_task_completion();
    task_data.finish_queue.wake_one();
}

pub fn create_user_task(
    vm_space: Arc<VmSpace>,
    entry_point: usize,
    stack_top: usize,
    lazy_ranges: Arc<Vec<LazyRange>>,
    finish_queue: Arc<WaitQueue>,
) -> Result<Arc<Task>> {
    framevm_logln!("[FrameVM] Building user task...");

    let task_data = UserTaskData {
        vm_space,
        entry_point,
        stack_top,
        lazy_ranges,
        finished: Arc::new(AtomicBool::new(false)),
        finish_queue,
        tid: 1,
        initial_context: None,
        exit_code: AtomicI32::new(0),
        fd_table: Arc::new(Mutex::new(FdTable::new())),
    };

    let task = TaskOptions::new(user_task_routine)
        .data(task_data)
        .build()
        .map(Arc::new)
        .map_err(|e| Error::from(e))?;

    ACTIVE_USER_TASKS.fetch_add(1, Ordering::SeqCst);
    Ok(task)
}

pub fn clone_user_task(
    parent_context: &UserContext,
    child_stack: usize,
    flags: u64,
) -> Result<u32> {
    if flags & CLONE_VM == 0 {
        return Err(Error::new(Errno::ENOSYS));
    }

    let current = Task::current().ok_or(Error::new(Errno::ESRCH))?;
    let parent_data = current
        .data()
        .downcast_ref::<UserTaskData>()
        .ok_or(Error::new(Errno::EINVAL))?;

    let mut child_ctx = parent_context.clone();
    let child_stack_top;

    if child_stack != 0 {
        child_ctx.set_rsp(child_stack);
        child_stack_top = child_stack;
    } else {
        let (stack_top, child_rsp) = alloc_and_clone_stack(
            parent_data.vm_space.as_ref(),
            parent_data.stack_top,
            parent_context.rsp(),
        )?;
        child_stack_top = stack_top;
        child_ctx.set_rsp(child_rsp);
    }

    // Child returns 0 from clone/fork.
    child_ctx.set_rax(0);

    // File descriptor table semantics:
    // - CLONE_FILES: share the same fd table object between parent/child.
    // - otherwise (fork-style): clone descriptor table entries.
    let child_fd_table = if flags & CLONE_FILES != 0 {
        parent_data.fd_table.clone()
    } else {
        let parent_fds = parent_data.fd_table.lock();
        Arc::new(Mutex::new(parent_fds.clone_for_fork()))
    };

    let tid = alloc_tid();
    let task_data = UserTaskData {
        vm_space: parent_data.vm_space.clone(),
        entry_point: parent_data.entry_point,
        stack_top: child_stack_top,
        lazy_ranges: parent_data.lazy_ranges.clone(),
        finished: Arc::new(AtomicBool::new(false)),
        finish_queue: parent_data.finish_queue.clone(),
        tid,
        initial_context: Some(child_ctx),
        exit_code: AtomicI32::new(0),
        fd_table: child_fd_table,
    };

    let task = TaskOptions::new(user_task_routine)
        .data(task_data)
        .build()
        .map(Arc::new)
        .map_err(|e| Error::from(e))?;

    ACTIVE_USER_TASKS.fetch_add(1, Ordering::SeqCst);
    task.run();
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
    let fd_table_refs = Arc::strong_count(&task_data.fd_table);
    let mut fd_table = task_data.fd_table.lock();

    // Align with Linux CLONE_FILES semantics: only close descriptors when this
    // task owns the last reference to the fd table object.
    if fd_table_refs == 1 {
        fd_table.close_all();
    }
}

pub struct ExitInfo {
    pub tid: u32,
    pub code: i32,
}

struct ExitQueue {
    zombies: Mutex<Vec<ExitInfo>>,
    wait_queue: WaitQueue,
}

static EXIT_QUEUE: Once<ExitQueue> = Once::new();

fn exit_queue() -> &'static ExitQueue {
    EXIT_QUEUE.call_once(|| ExitQueue {
        zombies: Mutex::new(Vec::new()),
        wait_queue: WaitQueue::new(),
    })
}

pub fn record_task_exit(tid: u32, code: i32) {
    let queue = exit_queue();
    queue.zombies.lock().push(ExitInfo { tid, code });
    queue.wait_queue.wake_one();
}

pub fn wait_for_exit(pid: i32) -> ExitInfo {
    let queue = exit_queue();
    queue.wait_queue.wait_until(|| {
        let mut zombies = queue.zombies.lock();
        if pid == -1 {
            if !zombies.is_empty() {
                return Some(zombies.remove(0));
            }
        } else if let Some(idx) = zombies.iter().position(|z| z.tid == pid as u32) {
            return Some(zombies.remove(idx));
        }
        None
    })
}

fn alloc_and_clone_stack(
    vm_space: &VmSpace,
    parent_stack_top: usize,
    parent_rsp: usize,
) -> Result<(usize, usize)> {
    let stack_top = allocate_user_stack(vm_space)?;
    let parent_stack_base = parent_stack_top + 8;
    let parent_stack_bottom = parent_stack_base - USER_STACK_SIZE;
    let child_stack_base = stack_top + 8;
    let child_stack_bottom = child_stack_base - USER_STACK_SIZE;

    if parent_rsp < parent_stack_bottom || parent_rsp > parent_stack_base {
        return Err(Error::new(Errno::EINVAL));
    }

    // Copy the entire stack region so the child can resume safely.
    copy_user_range(
        vm_space,
        parent_stack_bottom,
        child_stack_bottom,
        USER_STACK_SIZE,
    )?;

    let offset_from_top = parent_stack_base - parent_rsp;
    let child_rsp = child_stack_base - offset_from_top;
    Ok((stack_top, child_rsp))
}

fn copy_user_range(vm_space: &VmSpace, src: usize, dst: usize, len: usize) -> Result<()> {
    let mut buf = vec![0u8; len];
    let mut reader = vm_space.reader(src, len).map_err(Error::from)?;
    reader
        .read_fallible(&mut VmWriter::from(&mut buf as &mut [u8]))
        .map_err(Error::from)?;
    let mut writer = vm_space.writer(dst, len).map_err(Error::from)?;
    writer
        .write_fallible(&mut VmReader::from(buf.as_slice()))
        .map_err(|(e, _)| Error::from(e))?;
    Ok(())
}
