// SPDX-License-Identifier: MPL-2.0

use alloc::{format, string::String, sync::Arc};
use core::{
    fmt::{Display, Write},
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};

use aster_framevisor::{start_framevm, stop_framevm};
use log::{debug, error, info, warn};
use ostd::{
    sync::{SpinLock, WaitQueue},
    task::Task,
};

use crate::{
    fs::{
        file_handle::FileLike,
        path::FsPath,
        utils::{AccessMode, InodeMode, OpenArgs},
    },
    prelude::*,
    process::posix_thread::AsThreadLocal,
    thread::kernel_thread::ThreadOptions,
};

/// Guard against concurrent or repeated FrameVM load requests.
///
/// `/proc/framevm` is user-triggered and can be written repeatedly.
/// We reject overlapping loads to avoid lifecycle races.
static FRAMEVM_LOAD_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
static FRAMEVM_LOAD_STATE: AtomicU8 = AtomicU8::new(FrameVmLoadState::Idle as u8);
static FRAMEVM_LAST_ERROR: SpinLock<Option<String>> = SpinLock::new(None);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum FrameVmLoadState {
    Idle = 0,
    ReadingElf = 1,
    ThreadSpawned = 2,
    ThreadStarted = 3,
    StartingFramevisor = 4,
    LoadingModule = 5,
    Running = 6,
    Completed = 7,
    Failed = 8,
}

impl FrameVmLoadState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::ReadingElf => "reading_elf",
            Self::ThreadSpawned => "thread_spawned",
            Self::ThreadStarted => "thread_started",
            Self::StartingFramevisor => "starting_framevisor",
            Self::LoadingModule => "loading_module",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

impl From<u8> for FrameVmLoadState {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::ReadingElf,
            2 => Self::ThreadSpawned,
            3 => Self::ThreadStarted,
            4 => Self::StartingFramevisor,
            5 => Self::LoadingModule,
            6 => Self::Running,
            7 => Self::Completed,
            8 => Self::Failed,
            _ => Self::Idle,
        }
    }
}

struct BackgroundLoadSignal {
    has_started: AtomicBool,
    wait_queue: WaitQueue,
}

impl BackgroundLoadSignal {
    fn new() -> Self {
        Self {
            has_started: AtomicBool::new(false),
            wait_queue: WaitQueue::new(),
        }
    }

    fn signal_started(&self) {
        self.has_started.store(true, Ordering::Release);
        self.wait_queue.wake_all();
    }

    fn wait_until_started(&self) {
        self.wait_queue
            .wait_until(|| self.has_started.load(Ordering::Acquire).then_some(()));
    }
}

fn write_status_line(output: &mut String, key: &str, value: impl Display) {
    let _ = writeln!(output, "{key}: {value}");
}

fn set_framevm_load_state(state: FrameVmLoadState) {
    FRAMEVM_LOAD_STATE.store(state as u8, Ordering::Release);
}

fn clear_framevm_last_error() {
    *FRAMEVM_LAST_ERROR.lock() = None;
    aster_framevisor::clear_framevm_log();
    ostd::loader::clear_last_error();
}

fn record_framevm_last_error(error: &Error) {
    let message = if let Some(loader_error) = ostd::loader::last_error() {
        format!("{:?}: {}", error, loader_error)
    } else {
        format!("{:?}", error)
    };
    *FRAMEVM_LAST_ERROR.lock() = Some(message);
}

fn rollback_failed_framevm_start() {
    if aster_framevisor::framevm_count() == 0 {
        return;
    }

    warn!("[FrameVM] rolling back failed FrameVM startup");
    stop_framevm();
}

pub fn framevm_load_status() -> String {
    let state = FrameVmLoadState::from(FRAMEVM_LOAD_STATE.load(Ordering::Acquire));
    let mut output = String::new();
    write_status_line(&mut output, "state", state.as_str());
    write_status_line(
        &mut output,
        "in_progress",
        u8::from(FRAMEVM_LOAD_IN_PROGRESS.load(Ordering::Acquire)),
    );
    write_status_line(&mut output, "vm_count", aster_framevisor::framevm_count());
    if let Some(last_error) = FRAMEVM_LAST_ERROR.lock().as_ref() {
        write_status_line(&mut output, "last_error", last_error);
    }
    let framevm_log = aster_framevisor::framevm_log_snapshot();
    if !framevm_log.is_empty() {
        write_status_line(&mut output, "output", "");
        output.push_str(&framevm_log);
    }
    output
}

pub fn stop_framevm_instances() {
    stop_framevm();
    clear_framevm_last_error();
    set_framevm_load_state(FrameVmLoadState::Idle);
    end_framevm_load();
}

fn try_begin_framevm_load() -> Result<()> {
    if FRAMEVM_LOAD_IN_PROGRESS
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        warn!("[FrameVM] load rejected: another load is already in progress");
        return Err(Error::with_message(
            Errno::EBUSY,
            "framevm load already in progress",
        ));
    }

    if let Err(error) = ensure_framevm_not_running("load rejected") {
        FRAMEVM_LOAD_IN_PROGRESS.store(false, Ordering::Release);
        return Err(error);
    }

    Ok(())
}

fn ensure_framevm_not_running(rejection_reason: &str) -> Result<()> {
    if aster_framevisor::framevm_count() == 0 {
        return Ok(());
    }

    warn!("[FrameVM] {rejection_reason}: an existing FrameVM instance is still present");
    Err(Error::with_message(
        Errno::EBUSY,
        "framevm is already running",
    ))
}

#[inline]
fn end_framevm_load() {
    FRAMEVM_LOAD_IN_PROGRESS.store(false, Ordering::Release);
}

/// Load and start the FrameVM (synchronous, blocks until FrameVM exits)
///
/// # Arguments
/// * `vcpu_count` - Number of vCPUs to initialize (1-4)
pub fn load_framevm(vcpu_count: usize) -> Result<()> {
    try_begin_framevm_load()?;
    clear_framevm_last_error();
    set_framevm_load_state(FrameVmLoadState::ReadingElf);
    let result = (|| {
        let elf_data = read_framevm_elf()?;
        ensure_framevm_not_running("refusing to load")?;
        set_framevm_load_state(FrameVmLoadState::StartingFramevisor);
        start_framevm(vcpu_count)?;
        set_framevm_load_state(FrameVmLoadState::LoadingModule);
        if let Err(error) = load_framevm_file(&elf_data) {
            rollback_failed_framevm_start();
            return Err(error);
        }
        Ok(())
    })();
    match &result {
        Ok(()) => set_framevm_load_state(FrameVmLoadState::Completed),
        Err(error) => {
            set_framevm_load_state(FrameVmLoadState::Failed);
            record_framevm_last_error(error);
            error!("[FrameVM] FrameVM load error: {:?}", error);
        }
    }
    end_framevm_load();
    result
}

/// Load and start the FrameVM in a background thread.
///
/// This function is designed for `/proc/framevm`: it returns immediately after spawning the
/// background loader thread, so the write syscall can return without blocking the caller shell.
///
/// # Arguments
/// * `vcpu_count` - Number of vCPUs to initialize (1-4)
pub fn load_framevm_background(vcpu_count: usize) -> Result<()> {
    try_begin_framevm_load()?;
    clear_framevm_last_error();
    set_framevm_load_state(FrameVmLoadState::ReadingElf);

    // Read the ELF before spawning the kernel thread.
    // The file handle must be dropped while we still run in a process-backed task,
    // because inode range-lock teardown expects `current!()` to resolve to a process.
    let elf_data = match read_framevm_elf() {
        Ok(data) => data,
        Err(e) => {
            set_framevm_load_state(FrameVmLoadState::Failed);
            record_framevm_last_error(&e);
            end_framevm_load();
            return Err(e);
        }
    };

    set_framevm_load_state(FrameVmLoadState::ThreadSpawned);
    info!(
        "[FrameVM] Spawning FrameVM with {} vCPU(s) in background thread...",
        vcpu_count
    );
    let start_barrier = Arc::new(BackgroundLoadSignal::new());
    let thread_barrier = start_barrier.clone();
    ThreadOptions::new(move || {
        set_framevm_load_state(FrameVmLoadState::ThreadStarted);
        info!("[FrameVM] background loader thread started");
        thread_barrier.signal_started();

        let res: Result<()> = (|| {
            ensure_framevm_not_running("refusing to load in background")?;

            set_framevm_load_state(FrameVmLoadState::StartingFramevisor);
            info!("[FrameVM] starting FrameVisor from loader thread");
            start_framevm(vcpu_count)?;

            set_framevm_load_state(FrameVmLoadState::LoadingModule);
            info!("[FrameVM] loading FrameVM module from loader thread");
            if let Err(error) = load_framevm_file(&elf_data) {
                rollback_failed_framevm_start();
                return Err(error);
            }
            Ok(())
        })();

        match res {
            Ok(()) => {
                set_framevm_load_state(FrameVmLoadState::Completed);
                info!("[FrameVM] background FrameVM load completed");
            }
            Err(e) => {
                set_framevm_load_state(FrameVmLoadState::Failed);
                record_framevm_last_error(&e);
                error!("[FrameVM] FrameVM thread error: {:?}", e);
            }
        }
        end_framevm_load();
    })
    .spawn();

    start_barrier.wait_until_started();

    Ok(())
}

/// Read the FrameVM ELF file from the filesystem
fn read_framevm_elf() -> Result<Vec<u8>> {
    let framevm_file = open_framevm_elf_file()?;

    let file_size = framevm_file.path().inode().size();
    debug!("[FrameVM] framevm object size: {} bytes", file_size);

    let mut elf_data = vec![0u8; file_size];
    let read_len = framevm_file.read_bytes_at(0, &mut elf_data)?;
    if read_len != file_size {
        return Err(Error::with_message(
            Errno::EIO,
            "failed to read the complete FrameVM object file",
        ));
    }

    Ok(elf_data)
}

fn open_framevm_elf_file() -> Result<Arc<dyn FileLike>> {
    debug!("[FrameVM] opening /framevm/framevm.o");
    let task = Task::current()
        .ok_or_else(|| Error::with_message(Errno::ESRCH, "framevm load requires a current task"))?;
    let thread_local = task.as_thread_local().ok_or_else(|| {
        Error::with_message(Errno::EINVAL, "framevm load requires a process-backed task")
    })?;

    let framevm_file: Arc<dyn FileLike> = {
        let fs_ref = thread_local.borrow_fs();
        let fs_resolver = fs_ref.resolver().read();

        let fs_path = FsPath::try_from("/framevm/framevm.o")?;
        let path = fs_resolver.lookup(&fs_path)?;
        let open_args =
            OpenArgs::from_modes(AccessMode::O_RDONLY, InodeMode::from_bits_truncate(0o644));
        let inode_handle = path.open(open_args)?;

        Arc::new(inode_handle)
    };
    debug!("[FrameVM] /framevm/framevm.o opened successfully");
    Ok(framevm_file)
}

/// Load and run FrameVM from ELF data (blocks until FrameVM exits)
fn load_framevm_file(elf_data: &[u8]) -> Result<()> {
    let frame_vm_info = ostd::loader::FrameVmInfo::load_framevm_file(elf_data)?;

    set_framevm_load_state(FrameVmLoadState::Running);

    // Invoke the entry point directly so startup stays on the loader thread;
    // FrameVM sets up its own runtime tasks during initialization.
    frame_vm_info.start_framevm()?;

    Ok(())
}
