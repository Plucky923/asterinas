// SPDX-License-Identifier: MPL-2.0

use alloc::format;
use core::{
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
    time::Duration,
};

use aster_framevisor::boot;
use ostd::{
    arch::{read_tsc, tsc_freq},
    sync::WaitQueue,
    task::Task,
};
use spin::once::Once;

use crate::{
    events::IoEvents,
    fs::{
        file::{AccessMode, FileLike, InodeMode, OpenArgs},
        vfs::path::{FsPath, Path},
    },
    prelude::*,
    process::signal::{PollHandle, Pollee},
    thread::kernel_thread::ThreadOptions,
    time::SystemTime,
};

/// Guard against concurrent or repeated typed FrameVM start requests.
///
/// Short-term procfs startup shims route through this host-control path, so
/// overlapping loads are rejected to avoid lifecycle races.
static FRAMEVM_LOAD_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
static FRAMEVM_LOAD_STATE: AtomicU8 = AtomicU8::new(FrameVmLoadState::Idle as u8);
static FRAMEVM_LAST_ERROR: SpinLock<Option<String>> = SpinLock::new(None);
static FRAMEVM_LIFECYCLES: Once<SpinLock<BTreeMap<aster_framevisor::VmId, Arc<FrameVmLifecycle>>>> =
    Once::new();

const SETUP_PENDING: u8 = 0;
const SETUP_READY: u8 = 1;
const SETUP_FAILED: u8 = 2;

struct FrameVmSetupCompletion {
    state: AtomicU8,
    error: SpinLock<Option<String>>,
    wait_queue: WaitQueue,
}

impl FrameVmSetupCompletion {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU8::new(SETUP_PENDING),
            error: SpinLock::new(None),
            wait_queue: WaitQueue::new(),
        })
    }

    fn complete(&self) {
        self.state.store(SETUP_READY, Ordering::Release);
        self.wait_queue.wake_all();
    }

    fn fail(&self, error: &Error) {
        *self.error.lock() = Some(format!("{:?}", error));
        self.state.store(SETUP_FAILED, Ordering::Release);
        self.wait_queue.wake_all();
    }

    fn wait(&self) -> Result<()> {
        self.wait_queue
            .wait_until(|| match self.state.load(Ordering::Acquire) {
                SETUP_READY => Some(Ok(())),
                SETUP_FAILED => Some(Err(Error::with_message(Errno::EIO, "FrameVM setup failed"))),
                _ => None,
            })
    }
}

/// Host-observable lifecycle state for one FrameVM fd.
///
/// The lifecycle object is owned by the VM fd and passed to the loader path.
/// It records terminal status before wakeups so user-space waiters can observe
/// guest exit without inferring success from console EOF. Service-exit paths
/// publish readiness only after the matching VM/device cleanup has run, so a
/// waiter cannot start a second FrameVM instance while the first registry entry
/// is still being torn down.
pub struct FrameVmLifecycle {
    status: Mutex<FrameVmLifecycleStatus>,
    pending_terminal: Mutex<Option<FrameVmLifecycleStatus>>,
    pollee: Pollee,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum FrameVmLifecycleState {
    Created = 0,
    Starting = 1,
    Running = 2,
    ExitedSuccess = 3,
    ExitedFailure = 4,
    RestartRequested = 5,
    StoppedByHost = 6,
    PanicFailure = 7,
    Destroyed = 8,
}

/// Rust-owned lifecycle status for one FrameVM instance.
///
/// Terminal variants carry their reason and status data in the variant rather
/// than in a parallel mutable field set. The flat C ioctl ABI is derived from
/// this enum at the VM-fd boundary.
#[expect(
    dead_code,
    reason = "the lifecycle ABI defines all terminal states before every service-originated exit path is wired"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameVmLifecycleStatus {
    Created,
    Starting {
        vm_id: Option<aster_framevisor::VmId>,
    },
    Running {
        vm_id: aster_framevisor::VmId,
    },
    ExitedSuccess {
        vm_id: Option<aster_framevisor::VmId>,
        code: i32,
    },
    ExitedFailure {
        vm_id: Option<aster_framevisor::VmId>,
        code: i32,
    },
    RestartRequested {
        vm_id: Option<aster_framevisor::VmId>,
        code: i32,
    },
    StoppedByHost {
        vm_id: Option<aster_framevisor::VmId>,
        reason: FrameVmTerminalReason,
    },
    PanicFailure {
        vm_id: Option<aster_framevisor::VmId>,
        reason: FrameVmTerminalReason,
        code: i32,
        failure_class: FrameVmFailureClass,
    },
    Destroyed {
        vm_id: Option<aster_framevisor::VmId>,
    },
}

impl FrameVmLifecycleStatus {
    /// Returns whether this lifecycle status is terminal.
    pub const fn is_terminal(self) -> bool {
        !matches!(
            self,
            Self::Created | Self::Starting { .. } | Self::Running { .. }
        )
    }

    /// Returns the ioctl-facing state code for this typed status.
    pub const fn state(self) -> FrameVmLifecycleState {
        match self {
            Self::Created => FrameVmLifecycleState::Created,
            Self::Starting { .. } => FrameVmLifecycleState::Starting,
            Self::Running { .. } => FrameVmLifecycleState::Running,
            Self::ExitedSuccess { .. } => FrameVmLifecycleState::ExitedSuccess,
            Self::ExitedFailure { .. } => FrameVmLifecycleState::ExitedFailure,
            Self::RestartRequested { .. } => FrameVmLifecycleState::RestartRequested,
            Self::StoppedByHost { .. } => FrameVmLifecycleState::StoppedByHost,
            Self::PanicFailure { .. } => FrameVmLifecycleState::PanicFailure,
            Self::Destroyed { .. } => FrameVmLifecycleState::Destroyed,
        }
    }

    /// Returns the VM id carried by this status, if a VM has been created.
    pub const fn vm_id(self) -> Option<aster_framevisor::VmId> {
        match self {
            Self::Created => None,
            Self::Starting { vm_id }
            | Self::ExitedSuccess { vm_id, .. }
            | Self::ExitedFailure { vm_id, .. }
            | Self::RestartRequested { vm_id, .. }
            | Self::StoppedByHost { vm_id, .. }
            | Self::PanicFailure { vm_id, .. }
            | Self::Destroyed { vm_id } => vm_id,
            Self::Running { vm_id } => Some(vm_id),
        }
    }

    /// Returns the terminal reason for this status.
    pub const fn terminal_reason(self) -> FrameVmTerminalReason {
        match self {
            Self::Created | Self::Starting { .. } | Self::Running { .. } => {
                FrameVmTerminalReason::None
            }
            Self::ExitedSuccess { .. } | Self::ExitedFailure { .. } => {
                FrameVmTerminalReason::GuestExit
            }
            Self::RestartRequested { .. } => FrameVmTerminalReason::Restart,
            Self::StoppedByHost { reason, .. } | Self::PanicFailure { reason, .. } => reason,
            Self::Destroyed { .. } => FrameVmTerminalReason::HostStop,
        }
    }

    /// Returns the guest or failure status code for this status.
    pub const fn status_code(self) -> i32 {
        match self {
            Self::ExitedSuccess { code, .. }
            | Self::ExitedFailure { code, .. }
            | Self::RestartRequested { code, .. }
            | Self::PanicFailure { code, .. } => code,
            _ => 0,
        }
    }

    /// Returns the failure class for this status.
    pub const fn failure_class(self) -> FrameVmFailureClass {
        match self {
            Self::ExitedFailure { .. } => FrameVmFailureClass::GuestExitCode,
            Self::StoppedByHost { .. } | Self::Destroyed { .. } => FrameVmFailureClass::HostStop,
            Self::PanicFailure { failure_class, .. } => failure_class,
            _ => FrameVmFailureClass::None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum FrameVmTerminalReason {
    None = 0,
    GuestExit = 1,
    Poweroff = 2,
    Restart = 3,
    HostStop = 4,
    FdClose = 5,
    Panic = 6,
    SetupFailed = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum FrameVmFailureClass {
    None = 0,
    GuestExitCode = 1,
    Panic = 2,
    Setup = 3,
    HostStop = 4,
}

impl FrameVmLifecycle {
    /// Creates a lifecycle object in the `Created` state.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            status: Mutex::new(FrameVmLifecycleStatus::Created),
            pending_terminal: Mutex::new(None),
            pollee: Pollee::new(),
        })
    }

    /// Returns the current typed lifecycle status.
    pub fn status(&self) -> FrameVmLifecycleStatus {
        *self.status.lock()
    }

    /// Returns poll readiness for terminal-status observation.
    pub fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee.poll_with(mask, poller, || {
            if self.status().is_terminal() {
                IoEvents::IN | IoEvents::HUP
            } else {
                IoEvents::empty()
            }
        })
    }

    fn mark_starting(&self) {
        let mut status = self.status.lock();
        if status.is_terminal() {
            return;
        }
        *status = FrameVmLifecycleStatus::Starting {
            vm_id: status.vm_id(),
        };
        self.pollee.invalidate();
    }

    fn set_vm_id(&self, vm_id: aster_framevisor::VmId) {
        let mut status = self.status.lock();
        if status.is_terminal() {
            return;
        }
        *status = match *status {
            FrameVmLifecycleStatus::Created | FrameVmLifecycleStatus::Starting { .. } => {
                FrameVmLifecycleStatus::Starting { vm_id: Some(vm_id) }
            }
            FrameVmLifecycleStatus::Running { .. } => FrameVmLifecycleStatus::Running { vm_id },
            terminal_status => terminal_status,
        };
        self.pollee.invalidate();
    }

    fn mark_running(&self) {
        let mut status = self.status.lock();
        if status.is_terminal() {
            return;
        }
        if let Some(vm_id) = status.vm_id() {
            *status = FrameVmLifecycleStatus::Running { vm_id };
        }
        self.pollee.invalidate();
    }

    fn record_terminal_status(&self, terminal_status: FrameVmLifecycleStatus) -> bool {
        debug_assert!(terminal_status.is_terminal());
        let did_record = {
            let mut status = self.status.lock();
            if status.is_terminal() {
                false
            } else {
                let vm_id = status.vm_id();
                *status = match terminal_status {
                    FrameVmLifecycleStatus::ExitedSuccess { code, .. } => {
                        FrameVmLifecycleStatus::ExitedSuccess { vm_id, code }
                    }
                    FrameVmLifecycleStatus::ExitedFailure { code, .. } => {
                        FrameVmLifecycleStatus::ExitedFailure { vm_id, code }
                    }
                    FrameVmLifecycleStatus::RestartRequested { code, .. } => {
                        FrameVmLifecycleStatus::RestartRequested { vm_id, code }
                    }
                    FrameVmLifecycleStatus::StoppedByHost { reason, .. } => {
                        FrameVmLifecycleStatus::StoppedByHost { vm_id, reason }
                    }
                    FrameVmLifecycleStatus::PanicFailure {
                        reason,
                        code,
                        failure_class,
                        ..
                    } => FrameVmLifecycleStatus::PanicFailure {
                        vm_id,
                        reason,
                        code,
                        failure_class,
                    },
                    FrameVmLifecycleStatus::Destroyed { .. } => {
                        FrameVmLifecycleStatus::Destroyed { vm_id }
                    }
                    nonterminal_status => nonterminal_status,
                };
                true
            }
        };

        if did_record {
            let status = self.status();
            info!(
                "[FrameVM] terminal state recorded: {:?}, reason={:?}, status={}",
                status.state(),
                status.terminal_reason(),
                status.status_code()
            );
        }
        did_record
    }

    /// Records terminal status exactly once and wakes VM-fd pollers.
    pub fn record_terminal(&self, terminal_status: FrameVmLifecycleStatus) -> bool {
        let did_record = self.record_terminal_status(terminal_status);
        if did_record {
            self.notify_terminal_waiters();
        }
        did_record
    }

    fn notify_terminal_waiters(&self) {
        self.pollee.notify(IoEvents::IN | IoEvents::HUP);
    }

    fn set_pending_terminal(&self, terminal_status: FrameVmLifecycleStatus) {
        debug_assert!(terminal_status.is_terminal());
        *self.pending_terminal.lock() = Some(terminal_status);
    }

    fn take_pending_terminal(&self) -> Option<FrameVmLifecycleStatus> {
        self.pending_terminal.lock().take()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum FrameVmLoadState {
    Idle = 0,
    ReadingElf = 1,
    StartingFramevisor = 2,
    LoadingModule = 3,
    Running = 4,
    Completed = 5,
    Failed = 6,
}

/// Typed host-control request to start one FrameVM bring-up instance.
pub struct FrameVmStartRequest {
    vcpu_count: usize,
    share: u32,
    drive_image: Option<Arc<dyn aster_framevisor::device::BlockImage>>,
    cmdline_append: Option<String>,
    lifecycle: Option<Arc<FrameVmLifecycle>>,
}

impl FrameVmStartRequest {
    /// Creates a start request with one fd-backed raw block image.
    pub fn new_with_drive_image(
        vcpu_count: usize,
        share: u32,
        drive_image: Arc<dyn aster_framevisor::device::BlockImage>,
    ) -> Result<Self> {
        validate_framevm_vcpu_count(vcpu_count)?;
        aster_framevisor::validate_framevm_share(share)?;
        Ok(Self {
            vcpu_count,
            share,
            drive_image: Some(drive_image),
            cmdline_append: None,
            lifecycle: None,
        })
    }

    /// Appends validated user-provided guest command-line text.
    pub fn with_cmdline_append(mut self, cmdline_append: Option<String>) -> Self {
        self.cmdline_append = cmdline_append;
        self
    }

    /// Associates the start request with a VM-fd lifecycle observer.
    pub fn with_lifecycle(mut self, lifecycle: Arc<FrameVmLifecycle>) -> Self {
        self.lifecycle = Some(lifecycle);
        self
    }

    /// Returns the requested vCPU count.
    pub const fn vcpu_count(&self) -> usize {
        self.vcpu_count
    }

    /// Returns the requested FrameVM scheduler share.
    pub const fn share(&self) -> u32 {
        self.share
    }

    fn drive_image(&self) -> Option<Arc<dyn aster_framevisor::device::BlockImage>> {
        self.drive_image.clone()
    }

    fn cmdline_append(&self) -> Option<String> {
        self.cmdline_append.clone()
    }

    fn lifecycle(&self) -> Option<Arc<FrameVmLifecycle>> {
        self.lifecycle.clone()
    }
}

/// Fd-backed raw image used by FrameVisor block backend.
pub struct FrameVmRawImage {
    path: Path,
    readonly: bool,
    capacity_bytes: u64,
}

impl FrameVmRawImage {
    /// Creates a raw image wrapper around a validated filesystem path.
    pub fn new(path: Path, readonly: bool, capacity_bytes: u64) -> Self {
        Self {
            path,
            readonly,
            capacity_bytes,
        }
    }

    fn map_io_error(error: Error) -> aster_framevisor::device::BlockImageError {
        match error.error() {
            Errno::EROFS | Errno::EPERM | Errno::EACCES | Errno::EBADF => {
                aster_framevisor::device::BlockImageError::Io
            }
            _ => aster_framevisor::device::BlockImageError::Io,
        }
    }
}

impl aster_framevisor::device::BlockImage for FrameVmRawImage {
    fn read_exact_at(
        &self,
        offset_bytes: u64,
        dst: &mut [u8],
    ) -> core::result::Result<(), aster_framevisor::device::BlockImageError> {
        let offset = usize::try_from(offset_bytes)
            .map_err(|_| aster_framevisor::device::BlockImageError::Io)?;
        let read_len = self
            .path
            .inode()
            .read_bytes_at(offset, dst)
            .map_err(Self::map_io_error)?;
        if read_len != dst.len() {
            return Err(aster_framevisor::device::BlockImageError::ShortRead {
                offset_bytes,
                requested_bytes: dst.len(),
                actual_bytes: read_len,
            });
        }
        Ok(())
    }

    fn write_all_at(
        &self,
        offset_bytes: u64,
        src: &[u8],
    ) -> core::result::Result<(), aster_framevisor::device::BlockImageError> {
        if self.readonly {
            return Err(aster_framevisor::device::BlockImageError::Readonly);
        }
        let offset = usize::try_from(offset_bytes)
            .map_err(|_| aster_framevisor::device::BlockImageError::Io)?;
        let written_len = self
            .path
            .inode()
            .write_bytes_at(offset, src)
            .map_err(Self::map_io_error)?;
        if written_len != src.len() {
            return Err(aster_framevisor::device::BlockImageError::ShortWrite {
                offset_bytes,
                requested_bytes: src.len(),
                actual_bytes: written_len,
            });
        }
        Ok(())
    }

    fn flush(&self) -> core::result::Result<(), aster_framevisor::device::BlockImageError> {
        self.path
            .sync_all()
            .map_err(|_| aster_framevisor::device::BlockImageError::Flush)
    }

    fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    fn readonly(&self) -> bool {
        self.readonly
    }
}

/// Typed host-control request to stop all FrameVM bring-up instances.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameVmStopRequest;

impl FrameVmStopRequest {
    /// Creates a stop request.
    pub const fn new() -> Self {
        Self
    }
}

fn set_framevm_load_state(state: FrameVmLoadState) {
    FRAMEVM_LOAD_STATE.store(state as u8, Ordering::Release);
}

fn framevm_lifecycles() -> &'static SpinLock<BTreeMap<aster_framevisor::VmId, Arc<FrameVmLifecycle>>>
{
    FRAMEVM_LIFECYCLES.call_once(|| SpinLock::new(BTreeMap::new()))
}

fn install_framevisor_power_event_handler() {
    aster_framevisor::power::inject_service_power_event_handler(record_service_power_event);
}

fn register_framevm_lifecycle(
    vm_id: aster_framevisor::VmId,
    lifecycle: Option<&Arc<FrameVmLifecycle>>,
) {
    let Some(lifecycle) = lifecycle else {
        return;
    };

    framevm_lifecycles().lock().insert(vm_id, lifecycle.clone());
}

fn unregister_framevm_lifecycle(vm_id: aster_framevisor::VmId) {
    framevm_lifecycles().lock().remove(&vm_id);
}

fn record_service_power_event(
    vm_id: aster_framevisor::VmId,
    action: aster_framevisor::power::PowerAction,
    status_code: i32,
) {
    let lifecycle = framevm_lifecycles().lock().get(&vm_id).cloned();
    let Some(lifecycle) = lifecycle else {
        aster_framevisor::early_println!(
            "[FrameVM] service power event ignored: lifecycle missing vm={}",
            vm_id
        );
        return;
    };

    let terminal_status = match action {
        aster_framevisor::power::PowerAction::Poweroff if status_code == 0 => {
            FrameVmLifecycleStatus::ExitedSuccess {
                vm_id: Some(vm_id),
                code: status_code,
            }
        }
        aster_framevisor::power::PowerAction::Poweroff => FrameVmLifecycleStatus::ExitedFailure {
            vm_id: Some(vm_id),
            code: status_code,
        },
        aster_framevisor::power::PowerAction::Restart => FrameVmLifecycleStatus::RestartRequested {
            vm_id: Some(vm_id),
            code: status_code,
        },
    };
    if lifecycle.record_terminal_status(terminal_status) {
        cleanup_terminal_framevm_instance(Some(&lifecycle));
        lifecycle.notify_terminal_waiters();
    }
}

fn clear_framevm_last_error() {
    *FRAMEVM_LAST_ERROR.lock() = None;
    ostd::loader::clear_last_error();
}

fn register_frame_sched_groups(vm_id: aster_framevisor::VmId) {
    for group in aster_framevisor::vm::get_sched_groups_by_vm_id(vm_id) {
        let share = group.share();
        crate::sched::register_frame_sched_group(group, share);
    }
}

fn bind_loader_to_default_frame_vcpu() -> Result<()> {
    let frame_vcpu_id = aster_framevisor::default_frame_vcpu_id()
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "missing FrameVM vCPU"))?;
    aster_framevisor::bind_current_task_to_frame_vcpu(frame_vcpu_id)?;
    Ok(())
}

fn clear_loader_frame_vcpu() {
    aster_framevisor::clear_current_frame_vcpu();
}

fn restore_current_thread_vm_space() {
    let Some(task) = Task::current() else {
        return;
    };
    let Some(thread_local) = task.as_thread_local() else {
        return;
    };
    let vmar = thread_local.vmar().borrow();
    if let Some(vmar) = vmar.as_ref() {
        vmar.vm_space().activate();
    }
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
    stop_framevm(FrameVmStopRequest::new());
}

fn rollback_framevm_instance(vm_id: aster_framevisor::VmId) {
    unregister_framevm_lifecycle(vm_id);
    aster_framevisor::destroy_framevm(vm_id);
    crate::sched::unregister_frame_sched_groups(vm_id);
}

fn cleanup_terminal_framevm_instance(lifecycle: Option<&Arc<FrameVmLifecycle>>) {
    let vm_id = lifecycle
        .and_then(|lifecycle| lifecycle.status().vm_id())
        .or_else(|| {
            let mut vm_ids = aster_framevisor::list_framevms().into_iter();
            let vm_id = vm_ids.next()?;
            vm_ids.next().is_none().then_some(vm_id)
        });

    let Some(vm_id) = vm_id else {
        return;
    };

    unregister_framevm_lifecycle(vm_id);
    aster_framevisor::destroy_framevm(vm_id);
    crate::sched::unregister_frame_sched_groups(vm_id);
    if aster_framevisor::framevm_count() == 0 {
        boot::clear_boot_info();
        set_framevm_load_state(FrameVmLoadState::Idle);
    }
}

fn clear_framevm_console_output(vm_id: aster_framevisor::VmId) -> Result<()> {
    let vm = aster_framevisor::get_framevm(vm_id)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "FrameVM does not exist"))?;
    vm.devices().console().clear_output_log();
    Ok(())
}

fn framevm_console_output_snapshot(vm_id: aster_framevisor::VmId) -> Result<String> {
    let vm = aster_framevisor::get_framevm(vm_id)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "FrameVM does not exist"))?;
    Ok(vm.devices().console().output_log_snapshot())
}

pub fn stop_framevm(_request: FrameVmStopRequest) {
    for vm_id in aster_framevisor::list_framevms() {
        unregister_framevm_lifecycle(vm_id);
        aster_framevisor::destroy_framevm(vm_id);
        crate::sched::unregister_frame_sched_groups(vm_id);
    }
    boot::clear_boot_info();
    clear_framevm_last_error();
    set_framevm_load_state(FrameVmLoadState::Idle);
    end_framevm_load();
}

fn try_begin_framevm_load() -> Result<()> {
    if FRAMEVM_LOAD_IN_PROGRESS
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        error!("[FrameVM] load rejected: another load is already in progress");
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

    error!(
        "[FrameVM] {rejection_reason}: {} existing FrameVM instance(s) still present",
        aster_framevisor::framevm_count()
    );
    Err(Error::with_message(
        Errno::EBUSY,
        "framevm is already running",
    ))
}

#[inline]
fn end_framevm_load() {
    FRAMEVM_LOAD_IN_PROGRESS.store(false, Ordering::Release);
}

/// Starts FrameVM from the configured service artifact and optional drive.
pub fn start_framevm(request: FrameVmStartRequest) -> Result<()> {
    install_framevisor_power_event_handler();
    try_begin_framevm_load()?;
    clear_framevm_last_error();
    set_framevm_load_state(FrameVmLoadState::ReadingElf);
    if let Some(lifecycle) = request.lifecycle() {
        lifecycle.mark_starting();
    }

    let result = (|| {
        let elf_data = read_framevm_artifacts()?;
        start_framevm_loader_thread(
            request.vcpu_count(),
            request.share(),
            request.drive_image(),
            request.cmdline_append(),
            request.lifecycle(),
            elf_data,
        )
    })();

    if let Err(error) = &result {
        set_framevm_load_state(FrameVmLoadState::Failed);
        record_framevm_last_error(error);
        error!("[FrameVM] FrameVM load error: {:?}", error);
        if let Some(lifecycle) = request.lifecycle() {
            lifecycle.record_terminal(FrameVmLifecycleStatus::PanicFailure {
                vm_id: None,
                reason: FrameVmTerminalReason::SetupFailed,
                code: -1,
                failure_class: FrameVmFailureClass::Setup,
            });
        }
    }
    end_framevm_load();
    result
}

fn start_framevm_loader_thread(
    vcpu_count: usize,
    share: u32,
    drive_image: Option<Arc<dyn aster_framevisor::device::BlockImage>>,
    cmdline_append: Option<String>,
    lifecycle: Option<Arc<FrameVmLifecycle>>,
    elf_data: Vec<u8>,
) -> Result<()> {
    let setup_completion = FrameVmSetupCompletion::new();
    let loader_setup_completion = setup_completion.clone();
    let loader_task_fn = move || {
        let result = run_framevm_loader(
            vcpu_count,
            share,
            drive_image,
            cmdline_append,
            lifecycle,
            elf_data,
            loader_setup_completion,
        );
        match &result {
            Ok(()) => set_framevm_load_state(FrameVmLoadState::Completed),
            Err(error) => {
                set_framevm_load_state(FrameVmLoadState::Failed);
                record_framevm_last_error(error);
                error!("[FrameVM] FrameVM loader thread error: {:?}", error);
            }
        }
    };

    ThreadOptions::new(loader_task_fn).spawn();
    setup_completion.wait()
}

fn read_framevm_artifacts() -> Result<Vec<u8>> {
    // Read the artifacts before spawning the kernel thread.
    // The file handles must be dropped while we still run in a process-backed task,
    // because inode range-lock teardown expects `current!()` to resolve to a process.
    read_framevm_elf()
}

fn run_framevm_loader(
    vcpu_count: usize,
    share: u32,
    drive_image: Option<Arc<dyn aster_framevisor::device::BlockImage>>,
    cmdline_append: Option<String>,
    lifecycle: Option<Arc<FrameVmLifecycle>>,
    elf_data: Vec<u8>,
    setup_completion: Arc<FrameVmSetupCompletion>,
) -> Result<()> {
    ensure_framevm_not_running("refusing to load")?;

    set_framevm_load_state(FrameVmLoadState::StartingFramevisor);
    let framevm_id = match drive_image {
        Some(image) => {
            aster_framevisor::create_framevm_unstarted_with_block_image(vcpu_count, share, image)?
        }
        None => aster_framevisor::create_framevm_unstarted(vcpu_count, share)?,
    };
    if let Some(lifecycle) = &lifecycle {
        lifecycle.set_vm_id(framevm_id);
    }
    register_framevm_lifecycle(framevm_id, lifecycle.as_ref());

    let setup_result = (|| {
        clear_framevm_console_output(framevm_id)?;
        register_frame_sched_groups(framevm_id);
        if let Err(error) = aster_framevisor::start_framevm_by_id(framevm_id) {
            return Err(error.into());
        }
        bind_loader_to_default_frame_vcpu()?;
        let framev_devices = aster_framevisor::framev_device_descriptor_boot_arg(framevm_id)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "missing FrameV descriptor"))?;
        boot::set_boot_info_without_initramfs(framevm_boot_cmdline(
            vcpu_count,
            &framev_devices,
            cmdline_append.as_deref(),
        )?);
        Ok(())
    })();
    if let Err(error) = setup_result {
        setup_completion.fail(&error);
        clear_loader_frame_vcpu();
        restore_current_thread_vm_space();
        rollback_framevm_instance(framevm_id);
        return Err(error);
    }
    set_framevm_load_state(FrameVmLoadState::LoadingModule);
    let load_result = spawn_framevm_service_task(elf_data, lifecycle.clone());
    clear_loader_frame_vcpu();
    restore_current_thread_vm_space();
    match load_result {
        Ok(()) => {
            if let Some(lifecycle) = &lifecycle {
                lifecycle.mark_running();
            }
            setup_completion.complete();
        }
        Err(error) => {
            setup_completion.fail(&error);
            if let Ok(console_output) = framevm_console_output_snapshot(framevm_id) {
                if !console_output.is_empty() {
                    warn!(
                        "[FrameVM] loader console output before rollback: {}",
                        console_output
                    );
                }
            }
            rollback_failed_framevm_start();
            return Err(error);
        }
    }
    Ok(())
}

fn framevm_boot_cmdline(
    vcpu_count: usize,
    framev_devices: &str,
    append: Option<&str>,
) -> Result<String> {
    let realtime_ns = duration_to_ns(
        SystemTime::now()
            .duration_since(&SystemTime::UNIX_EPOCH)
            .map_err(|_| Error::new(Errno::EINVAL))?,
    )?;
    let monotonic_ns = read_host_monotonic_ns()?;

    let mut cmdline = format!(
        "kernel.realtime_base_ns={realtime_ns} kernel.monotonic_base_ns={monotonic_ns} ostd.vcpu_count={vcpu_count} framev.devices={framev_devices}"
    );
    if let Some(append) = append {
        if !append.is_empty() {
            cmdline.push(' ');
            cmdline.push_str(append);
        }
    }

    Ok(cmdline)
}

fn read_host_monotonic_ns() -> Result<u64> {
    const NANOS_PER_SEC: u64 = 1_000_000_000;

    let freq = tsc_freq();
    if freq == 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    let tsc = read_tsc();
    let sec = tsc / freq;
    let nsec = (tsc % freq)
        .checked_mul(NANOS_PER_SEC)
        .and_then(|value| value.checked_div(freq))
        .ok_or(Error::new(Errno::EINVAL))?;
    sec.checked_mul(NANOS_PER_SEC)
        .and_then(|sec_ns| sec_ns.checked_add(nsec))
        .ok_or(Error::new(Errno::EINVAL))
}

fn duration_to_ns(duration: Duration) -> Result<u64> {
    const NANOS_PER_SEC: u128 = 1_000_000_000;

    let nanos = u128::from(duration.as_secs())
        .checked_mul(NANOS_PER_SEC)
        .and_then(|sec_ns| sec_ns.checked_add(u128::from(duration.subsec_nanos())))
        .ok_or(Error::new(Errno::EINVAL))?;
    u64::try_from(nanos).map_err(|_| Error::new(Errno::EINVAL))
}

fn validate_framevm_vcpu_count(vcpu_count: usize) -> Result<()> {
    if (1..=4).contains(&vcpu_count) {
        return Ok(());
    }

    Err(Error::with_message(
        Errno::EINVAL,
        "vcpu count must be between 1 and 4",
    ))
}

/// Read the FrameVM ELF file from the filesystem
fn read_framevm_elf() -> Result<Vec<u8>> {
    let framevm_file = open_framevm_artifact("/framevm/framevm.o")?;

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

fn open_framevm_artifact(pathname: &str) -> Result<Arc<dyn FileLike>> {
    debug!("[FrameVM] opening {}", pathname);
    let task = Task::current()
        .ok_or_else(|| Error::with_message(Errno::ESRCH, "framevm load requires a current task"))?;
    let thread_local = task.as_thread_local().ok_or_else(|| {
        Error::with_message(Errno::EINVAL, "framevm load requires a process-backed task")
    })?;

    let framevm_file: Arc<dyn FileLike> = {
        let fs_ref = thread_local.borrow_fs();
        let fs_resolver = fs_ref.resolver().read();

        let fs_path = FsPath::try_from(pathname)?;
        let path = fs_resolver.lookup(&fs_path)?;
        let open_args =
            OpenArgs::from_modes(AccessMode::O_RDONLY, InodeMode::from_bits_truncate(0o644));
        let inode_handle = path.open(open_args)?;

        Arc::new(inode_handle)
    };
    debug!("[FrameVM] {} opened successfully", pathname);
    Ok(framevm_file)
}

/// Spawns a FrameVM service task from ELF data.
fn spawn_framevm_service_task(
    elf_data: Vec<u8>,
    lifecycle: Option<Arc<FrameVmLifecycle>>,
) -> Result<()> {
    aster_framevisor::default_frame_vcpu_id()
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "missing FrameVM vCPU"))?;
    let service_task_fn = move || {
        let result = run_framevm_service(&elf_data);
        let terminal_status = match &result {
            Ok(()) => {
                set_framevm_load_state(FrameVmLoadState::Completed);
                lifecycle
                    .as_ref()
                    .and_then(|lifecycle| lifecycle.take_pending_terminal())
                    .unwrap_or(FrameVmLifecycleStatus::ExitedSuccess {
                        vm_id: None,
                        code: 0,
                    })
            }
            Err(error) => {
                set_framevm_load_state(FrameVmLoadState::Failed);
                record_framevm_last_error(error);
                error!("[FrameVM] FrameVM service task error: {:?}", error);
                FrameVmLifecycleStatus::PanicFailure {
                    vm_id: None,
                    reason: FrameVmTerminalReason::Panic,
                    code: -1,
                    failure_class: FrameVmFailureClass::Panic,
                }
            }
        };
        if let Some(lifecycle) = &lifecycle {
            let did_record = lifecycle.record_terminal_status(terminal_status);
            cleanup_terminal_framevm_instance(Some(lifecycle));
            if did_record {
                lifecycle.notify_terminal_waiters();
            }
        } else {
            cleanup_terminal_framevm_instance(None);
        }
    };

    let service_task = aster_framevisor::task::TaskOptions::new(service_task_fn).spawn()?;
    // The service scheduler is installed by the service itself. Until then,
    // the first service task is runnable through the FrameSchedGroup bootstrap
    // slot, so give the group a scheduling boundary immediately after spawn.
    service_task.wake_up();
    Task::yield_now();
    set_framevm_load_state(FrameVmLoadState::Running);
    Ok(())
}

/// Loads and runs FrameVM from ELF data.
fn run_framevm_service(elf_data: &[u8]) -> Result<()> {
    let service_module = ostd::loader::ServiceModuleInfo::load_service_module(elf_data)?;

    // Invoke the entry point on the FrameVisor service task;
    // FrameVM sets up its own runtime tasks during initialization.
    if !boot::enter_current_service() {
        return Err(Error::with_message(
            Errno::EINVAL,
            "missing FrameVM service domain",
        ));
    }
    let run_result = service_module.start();
    run_result?;
    if !boot::shutdown_current_service() {
        return Err(Error::with_message(
            Errno::EINVAL,
            "failed to shut down FrameVM service domain",
        ));
    }

    Ok(())
}
