// SPDX-License-Identifier: MPL-2.0

#[cfg(target_arch = "x86_64")]
mod assigned_pci_fault;

use alloc::format;
use core::{
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
    time::Duration,
};

use aster_framevisor::boot;
use ostd::{
    arch::{read_tsc, tsc_freq},
    cpu::CpuSet,
    sync::WaitQueue,
    task::Task,
};

use crate::{
    events::IoEvents,
    fs::{
        cgroupfs::CpuPlacement,
        file::{AccessMode, FileLike, InodeMode, Mappable, OpenArgs},
        vfs::path::FsPath,
    },
    prelude::*,
    process::signal::{PollHandle, Pollee},
    thread::{
        kernel_thread::ThreadOptions,
        work_queue::{self, WorkPriority},
    },
    time::SystemTime,
};

/// Serializes service-module loading while allowing already-started VMs to run.
static FRAMEVM_START_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
/// Initializes deferred containment for assigned PCI DMA faults.
#[cfg(target_arch = "x86_64")]
pub(crate) fn init_assigned_pci_fault_containment() {
    assigned_pci_fault::init();
}

const SETUP_PENDING: u8 = 0;
const SETUP_READY: u8 = 1;
const SETUP_FAILED: u8 = 2;
struct FrameVmSetupCompletion {
    state: AtomicU8,
    error: SpinLock<Option<Error>>,
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
        *self.error.lock() = Some(*error);
        self.state.store(SETUP_FAILED, Ordering::Release);
        self.wait_queue.wake_all();
    }

    fn fail_if_pending(&self, error: &Error) {
        if self.state.load(Ordering::Acquire) == SETUP_PENDING {
            self.fail(error);
        }
    }

    fn wait(&self) -> Result<()> {
        self.wait_queue
            .wait_until(|| match self.state.load(Ordering::Acquire) {
                SETUP_READY => Some(Ok(())),
                SETUP_FAILED => Some(Err(self
                    .error
                    .lock()
                    .unwrap_or_else(|| Error::with_message(Errno::EIO, "FrameVM setup failed")))),
                _ => None,
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameVmState {
    Created,
    Starting,
    Running,
    Exited { code: i32 },
}

impl FrameVmState {
    pub(crate) fn is_terminal(self) -> bool {
        matches!(self, Self::Exited { .. })
    }

    fn code(self) -> i32 {
        match self {
            Self::Exited { code } => code,
            Self::Created | Self::Starting | Self::Running => 0,
        }
    }

    fn abi_code(self) -> u32 {
        match self {
            Self::Created => framevm_abi::FRAMEVM_STATE_CREATED,
            Self::Starting => framevm_abi::FRAMEVM_STATE_STARTING,
            Self::Running => framevm_abi::FRAMEVM_STATE_RUNNING,
            Self::Exited { .. } => framevm_abi::FRAMEVM_STATE_EXITED,
        }
    }
}

struct FrameVmControlState {
    state: FrameVmState,
    vm_id: Option<aster_framevisor::VmId>,
    pending_exit_code: Option<i32>,
}

/// Owns one FrameVM fd's start, stop, terminal publication and retained output.
pub(crate) struct FrameVmControl {
    self_ref: Weak<FrameVmControl>,
    cpu_placement: Arc<CpuPlacement>,
    state: Mutex<FrameVmControlState>,
    cleanup_task: Mutex<Option<Arc<Task>>>,
    cleanup_queued: AtomicBool,
    cleanup_started: AtomicBool,
    retained_console_output: Mutex<Option<RetainedConsoleOutput>>,
    terminal_pollee: Pollee,
}

struct RetainedConsoleOutput {
    start_offset: u64,
    bytes: Vec<u8>,
}
impl FrameVmControl {
    /// Creates one control object in the `Created` state.
    pub(crate) fn new(cpu_placement: Arc<CpuPlacement>) -> Arc<Self> {
        Arc::new_cyclic(|self_ref| Self {
            self_ref: self_ref.clone(),
            cpu_placement,
            state: Mutex::new(FrameVmControlState {
                state: FrameVmState::Created,
                vm_id: None,
                pending_exit_code: None,
            }),
            cleanup_task: Mutex::new(None),
            cleanup_queued: AtomicBool::new(false),
            cleanup_started: AtomicBool::new(false),
            retained_console_output: Mutex::new(None),
            terminal_pollee: Pollee::new(),
        })
    }

    pub(crate) fn state(&self) -> FrameVmState {
        self.state.lock().state
    }

    pub(crate) fn vm_id(&self) -> Option<aster_framevisor::VmId> {
        self.state.lock().vm_id
    }

    pub(crate) fn status(&self) -> framevm_abi::FrameVmStatus {
        let state = self.state.lock().state;
        framevm_abi::FrameVmStatus::new(state.abi_code(), state.code())
    }

    pub(crate) fn begin_start(&self) -> bool {
        let mut control = self.state.lock();
        if control.state != FrameVmState::Created {
            return false;
        }
        control.state = FrameVmState::Starting;
        true
    }

    fn set_vm_id(&self, vm_id: aster_framevisor::VmId) -> bool {
        let mut control = self.state.lock();
        if control.state != FrameVmState::Starting || control.vm_id.is_some() {
            return false;
        }
        control.vm_id = Some(vm_id);
        true
    }

    fn mark_running(&self) -> bool {
        let mut control = self.state.lock();
        if control.state != FrameVmState::Starting || control.vm_id.is_none() {
            return false;
        }
        control.state = FrameVmState::Running;
        true
    }

    pub(crate) fn publish_terminal(&self, code: i32) -> bool {
        let did_publish = {
            let mut control = self.state.lock();
            if control.state.is_terminal() {
                false
            } else {
                control.state = FrameVmState::Exited { code };
                true
            }
        };
        if did_publish {
            self.terminal_pollee.notify(IoEvents::IN | IoEvents::HUP);
        }
        did_publish
    }

    fn set_pending_exit(&self, code: i32) -> bool {
        let did_set = {
            let mut control = self.state.lock();
            if control.state.is_terminal() || control.pending_exit_code.is_some() {
                false
            } else {
                control.pending_exit_code = Some(code);
                true
            }
        };
        if did_set {
            info!(
                "[FrameVM] terminal event accepted: code={}, current_task={}",
                code,
                Task::current().is_some()
            );
        }
        did_set
    }

    fn set_pending_failure(&self, code: i32) -> bool {
        if self.cleanup_started.load(Ordering::Acquire) {
            return false;
        }
        let can_set = {
            let mut control = self.state.lock();
            if control.state.is_terminal() {
                false
            } else {
                control.pending_exit_code = Some(code);
                true
            }
        };
        can_set
    }

    fn take_pending_exit(&self) -> Option<i32> {
        let mut control = self.state.lock();
        control.pending_exit_code.take()
    }

    pub(crate) fn retain_console_output(&self, vm: &aster_framevisor::vm::FrameVm) {
        let output = vm.devices().console().read_output_from(0, usize::MAX);
        let next_offset = output.next_offset();
        let bytes = output.into_bytes();
        let start_offset = next_offset.saturating_sub(bytes.len() as u64);
        *self.retained_console_output.lock() = Some(RetainedConsoleOutput {
            start_offset,
            bytes,
        });
    }

    pub(crate) fn read_retained_console_output(
        &self,
        cursor: &mut u64,
        writer: &mut VmWriter,
    ) -> Option<Result<usize>> {
        let retained = self.retained_console_output.lock();
        let retained = retained.as_ref()?;
        if *cursor < retained.start_offset {
            *cursor = retained.start_offset;
        }
        let relative_offset = cursor.saturating_sub(retained.start_offset);
        let Ok(relative_offset) = usize::try_from(relative_offset) else {
            return Some(Ok(0));
        };
        if relative_offset >= retained.bytes.len() {
            return Some(Ok(0));
        }

        let end_offset = relative_offset
            .saturating_add(writer.avail())
            .min(retained.bytes.len());
        let mut reader = VmReader::from(&retained.bytes[relative_offset..end_offset]);
        let initial_avail = writer.avail();
        let result = writer.write_fallible(&mut reader);
        let written = initial_avail - writer.avail();
        *cursor = cursor.saturating_add(written as u64);
        Some((|| -> Result<usize> {
            result?;
            Ok(written)
        })())
    }

    /// Returns poll readiness for terminal status observation.
    pub fn poll_terminal(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.terminal_pollee.poll_with(mask, poller, || {
            if self.state().is_terminal() {
                IoEvents::IN | IoEvents::HUP
            } else {
                IoEvents::empty()
            }
        })
    }

    /// Prepares the terminal cleanup task in Host allocation context.
    ///
    /// The terminal event originates from a FrameVM service task. Building the
    /// Host cleanup task there would charge its stack to the terminating VM,
    /// so teardown could release the stack that is performing the cleanup.
    fn prepare_terminal_cleanup(&self) {
        if self.cleanup_task.lock().is_some() {
            return;
        }

        let control_ref = self.self_ref.clone();
        let task = ThreadOptions::new(move || {
            if let Some(control) = control_ref.upgrade() {
                complete_terminal_framevm_cleanup(&control);
            }
        })
        .build();

        let mut cleanup_task = self.cleanup_task.lock();
        if cleanup_task.is_none() {
            *cleanup_task = Some(task);
        }
    }

    /// Schedules the prebuilt Host task that completes terminal cleanup.
    fn start_terminal_cleanup(&self) {
        let cleanup_task = self.cleanup_task.lock().take();
        let Some(cleanup_task) = cleanup_task else {
            warn!("[FrameVM] terminal cleanup task is unavailable");
            return;
        };
        info!("[FrameVM] starting terminal cleanup task");
        cleanup_task.run();
    }

    /// Defers cleanup to a normal Host worker.
    ///
    /// The worker may begin before the reporting carrier leaves the CPU, but
    /// it blocks on service-image ownership before it can tear down the VM.
    /// Keeping submission outside the carrier-exit path avoids scheduling
    /// work after OSTD has already dequeued that carrier.
    fn queue_terminal_cleanup(&self) {
        if self
            .cleanup_queued
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let control_ref = self.self_ref.clone();
        work_queue::submit_work_func(
            move || {
                if let Some(control) = control_ref.upgrade() {
                    control.start_terminal_cleanup();
                }
            },
            // The reporting service carrier must run its non-returning exit
            // path before this worker claims stop cleanup. A high-priority
            // worker can preempt that carrier on a uniprocessor Host and then
            // wait for the very service-image ownership it prevented from
            // retiring.
            WorkPriority::Normal,
        );
    }

    fn begin_cleanup(&self) -> bool {
        self.cleanup_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

impl aster_framevisor::vm::FrameVmEventSink for FrameVmControl {
    fn on_power_event(&self, action: aster_framevisor::power::PowerAction, code: i32) {
        info!(
            "[FrameVM] service requested {:?} with exit code {}",
            action, code
        );
        let code = match action {
            aster_framevisor::power::PowerAction::Poweroff => code,
            aster_framevisor::power::PowerAction::Restart => code.max(1),
        };
        if self.set_pending_exit(code) {
            // A service has reached its non-returning power path, so the
            // FrameVM control operation is complete even if its Host cleanup
            // task must wait for service-owned state to drain. Publishing now
            // lets a `framevmm` caller observe the terminal result and avoids
            // making that result depend on the carrier it is retiring.
            self.publish_terminal(code);
            self.queue_terminal_cleanup();
        }
    }

    fn on_assigned_device_failure(&self) {
        if let Some(vm_id) = self.vm_id()
            && let Some(frame_vm) = aster_framevisor::get_framevm(vm_id)
        {
            // The cleanup worker waits for the service task to exit. Request
            // that exit before waking the worker, otherwise a device-fault
            // callback can deadlock forever behind the still-runnable task.
            frame_vm.force_stop();
        }
        if self.set_pending_failure(-5) {
            self.start_terminal_cleanup();
        }
    }
}

/// Fd-backed raw image used by FrameVisor block backend.
pub struct FrameVmRawImage {
    file: Arc<dyn FileLike>,
    readonly: bool,
    capacity_bytes: u64,
}

impl FrameVmRawImage {
    /// Creates a raw image wrapper around a captured file.
    pub fn new(file: Arc<dyn FileLike>, readonly: bool, capacity_bytes: u64) -> Self {
        Self {
            file,
            readonly,
            capacity_bytes,
        }
    }
}

impl aster_framevisor::device::BlockImage for FrameVmRawImage {
    fn read_exact_at(
        &self,
        offset_bytes: u64,
        destinations: &mut aster_framevisor::device::BlockDestinations<'_>,
    ) -> core::result::Result<(), aster_framevisor::device::BlockImageError> {
        let mut offset = usize::try_from(offset_bytes)
            .map_err(|_| aster_framevisor::device::BlockImageError::Io)?;
        let requested_bytes = destinations.byte_len();
        let requested_bytes_u64 = u64::try_from(requested_bytes)
            .map_err(|_| aster_framevisor::device::BlockImageError::Io)?;
        let end_offset = offset_bytes
            .checked_add(requested_bytes_u64)
            .ok_or(aster_framevisor::device::BlockImageError::Io)?;
        if end_offset > self.capacity_bytes {
            return Err(aster_framevisor::device::BlockImageError::Io);
        }
        let mut actual_bytes = 0_usize;
        for writer in destinations.writers_mut() {
            let extent_len = writer.avail();
            let read_len = self
                .file
                .read_at(offset, writer)
                .map_err(|_| aster_framevisor::device::BlockImageError::Io)?;
            actual_bytes = actual_bytes
                .checked_add(read_len)
                .ok_or(aster_framevisor::device::BlockImageError::Io)?;
            if read_len != extent_len {
                return Err(aster_framevisor::device::BlockImageError::ShortRead {
                    offset_bytes,
                    requested_bytes,
                    actual_bytes,
                });
            }
            offset = offset
                .checked_add(read_len)
                .ok_or(aster_framevisor::device::BlockImageError::Io)?;
        }
        Ok(())
    }

    fn write_all_at(
        &self,
        offset_bytes: u64,
        sources: &mut aster_framevisor::device::BlockSources<'_>,
    ) -> core::result::Result<(), aster_framevisor::device::BlockImageError> {
        if self.readonly {
            return Err(aster_framevisor::device::BlockImageError::Readonly);
        }
        let mut offset = usize::try_from(offset_bytes)
            .map_err(|_| aster_framevisor::device::BlockImageError::Io)?;
        let requested_bytes = sources.byte_len();
        let requested_bytes_u64 = u64::try_from(requested_bytes)
            .map_err(|_| aster_framevisor::device::BlockImageError::Io)?;
        let end_offset = offset_bytes
            .checked_add(requested_bytes_u64)
            .ok_or(aster_framevisor::device::BlockImageError::Io)?;
        if end_offset > self.capacity_bytes {
            return Err(aster_framevisor::device::BlockImageError::Io);
        }
        if let Ok(Mappable::Vmo(vmo)) = self.file.mappable() {
            vmo.write_readers(offset, sources.readers_mut())
                .map_err(|_| aster_framevisor::device::BlockImageError::Io)?;
            let remaining_bytes = sources
                .readers_mut()
                .iter()
                .map(VmReader::remain)
                .sum::<usize>();
            if remaining_bytes != 0 {
                return Err(aster_framevisor::device::BlockImageError::ShortWrite {
                    offset_bytes,
                    requested_bytes,
                    actual_bytes: requested_bytes - remaining_bytes,
                });
            }
            return Ok(());
        }

        let mut actual_bytes = 0_usize;
        for reader in sources.readers_mut() {
            let extent_len = reader.remain();
            let written_len = self
                .file
                .write_at(offset, reader)
                .map_err(|_| aster_framevisor::device::BlockImageError::Io)?;
            actual_bytes = actual_bytes
                .checked_add(written_len)
                .ok_or(aster_framevisor::device::BlockImageError::Io)?;
            if written_len != extent_len {
                return Err(aster_framevisor::device::BlockImageError::ShortWrite {
                    offset_bytes,
                    requested_bytes,
                    actual_bytes,
                });
            }
            offset = offset
                .checked_add(written_len)
                .ok_or(aster_framevisor::device::BlockImageError::Io)?;
        }
        Ok(())
    }

    fn flush(&self) -> core::result::Result<(), aster_framevisor::device::BlockImageError> {
        self.file
            .path()
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

fn complete_terminal_framevm_cleanup(control: &Arc<FrameVmControl>) {
    if !control.begin_cleanup() {
        return;
    }

    info!("[FrameVM] terminal cleanup entered");
    let exit_code = control.take_pending_exit().unwrap_or(0);
    let exit_code = if cleanup_terminal_framevm_instance(control) {
        -5
    } else {
        exit_code
    };
    control.publish_terminal(exit_code);
}

fn register_frame_sched_groups(
    vm_id: aster_framevisor::VmId,
    task_group: &Arc<crate::sched::TaskGroup>,
    cpu_affinity: &CpuSet,
) {
    for group in aster_framevisor::vm::get_sched_groups_by_vm_id(vm_id) {
        crate::sched::register_frame_sched_group(group, task_group.clone(), cpu_affinity);
    }
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

fn destroy_stopped_framevm(vm_id: aster_framevisor::VmId) -> bool {
    let Some(framevm) = aster_framevisor::get_framevm(vm_id) else {
        return false;
    };
    if framevm.status() == aster_framevisor::vm::VmStatus::Stopping {
        framevm.release_stopped_memory();
    }
    if framevm.status() != aster_framevisor::vm::VmStatus::Stopped {
        // A stopped request can leave a VM quarantined when a service, DMA,
        // or typed-frame reference still owns domain memory.  Keep the VM and
        // its ID registered so no new instance can observe stale ownership.
        warn!(
            "[FrameVM] keeping VM {} quarantined; memory ownership has not drained",
            vm_id
        );
        return false;
    }
    crate::sched::unregister_frame_sched_groups(vm_id);
    boot::release_service_resources(vm_id);
    drop(framevm);
    aster_framevisor::destroy_framevm(vm_id)
}

fn cleanup_terminal_framevm_instance(control: &Arc<FrameVmControl>) -> bool {
    let Some(vm_id) = control.vm_id() else {
        return false;
    };

    let Some(framevm) = aster_framevisor::get_framevm(vm_id) else {
        return false;
    };
    info!("[FrameVM] terminal cleanup stopping VM {}", vm_id);
    control.retain_console_output(&framevm);
    let assigned_pci_failed = framevm.force_stop();
    info!("[FrameVM] terminal cleanup finished VM stop for {}", vm_id);
    drop(framevm);
    let destroyed = destroy_stopped_framevm(vm_id);
    if destroyed {
        control.cpu_placement.unsubscribe_framevm(vm_id);
    }
    assigned_pci_failed
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

/// Stops and destroys one FrameVM after draining admitted service I/O.
pub(crate) fn stop_framevm_orderly(
    vm_id: aster_framevisor::VmId,
    control: &FrameVmControl,
) -> bool {
    let Some(framevm) = aster_framevisor::get_framevm(vm_id) else {
        return false;
    };
    let assigned_pci_failed = framevm.stop();
    drop(framevm);
    if destroy_stopped_framevm(vm_id) {
        control.cpu_placement.unsubscribe_framevm(vm_id);
    }
    assigned_pci_failed
}

/// Stops and destroys one FrameVM without waiting for persistence work.
pub(crate) fn stop_framevm_forced(vm_id: aster_framevisor::VmId, control: &FrameVmControl) -> bool {
    let Some(framevm) = aster_framevisor::get_framevm(vm_id) else {
        return false;
    };
    let assigned_pci_failed = framevm.force_stop();
    drop(framevm);
    if destroy_stopped_framevm(vm_id) {
        control.cpu_placement.unsubscribe_framevm(vm_id);
    }
    assigned_pci_failed
}

fn try_begin_framevm_start() -> Result<()> {
    if FRAMEVM_START_IN_PROGRESS
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        error!("[FrameVM] start rejected: another start is already in progress");
        return Err(Error::with_message(
            Errno::EBUSY,
            "another FrameVM start is already in progress",
        ));
    }
    Ok(())
}

#[inline]
fn end_framevm_start() {
    FRAMEVM_START_IN_PROGRESS.store(false, Ordering::Release);
}

/// Starts FrameVM from the configured service artifact and optional drive.
pub(crate) fn start_framevm(
    config: aster_framevisor::FrameVmConfig,
    control: Arc<FrameVmControl>,
    task_group: Arc<crate::sched::TaskGroup>,
) -> Result<()> {
    validate_framevm_vcpu_count(config.vcpu_count)?;
    aster_framevisor::validate_framevm_share(config.share)?;
    validate_framevm_memory_limit(config.memory_limit_bytes)?;
    try_begin_framevm_start()?;
    if !control.begin_start() {
        end_framevm_start();
        return Err(Error::with_message(
            Errno::EBUSY,
            "FrameVM is not ready to start",
        ));
    }

    let framevm_task_group = crate::sched::create_framevm_task_group(&task_group, config.share);
    let result = start_framevm_loader_thread(config, control.clone(), framevm_task_group);

    if let Err(error) = &result {
        error!("[FrameVM] FrameVM load error: {:?}", error);
        control.publish_terminal(-1);
    }
    end_framevm_start();
    result
}

#[cfg(ktest)]
mod control_tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn control_publishes_one_terminal_result() {
        let control = FrameVmControl::new(crate::fs::cgroupfs::root_cpu_placement());
        assert_eq!(control.state(), FrameVmState::Created);
        assert!(control.begin_start());
        assert!(!control.begin_start());
        assert!(control.set_vm_id(aster_framevisor::VmId::new(8)));
        assert!(control.mark_running());
        assert!(!control.mark_running());
        assert!(control.publish_terminal(7));
        assert!(!control.publish_terminal(9));
        assert_eq!(control.status().state(), framevm_abi::FRAMEVM_STATE_EXITED);
        assert_eq!(control.status().code(), 7);
    }

    #[ktest]
    fn start_failure_is_terminal() {
        let control = FrameVmControl::new(crate::fs::cgroupfs::root_cpu_placement());
        assert!(control.begin_start());
        assert!(control.publish_terminal(-1));
        assert_eq!(control.state(), FrameVmState::Exited { code: -1 });
    }

    #[ktest]
    fn vcpu_count_validation_accepts_only_the_flat_supported_range() {
        for vcpu_count in 1..=4 {
            assert!(validate_framevm_vcpu_count(vcpu_count).is_ok());
        }

        for vcpu_count in [0, 5, usize::MAX] {
            let error = validate_framevm_vcpu_count(vcpu_count).unwrap_err();
            assert_eq!(error.error(), Errno::EINVAL);
        }
    }
}

fn start_framevm_loader_thread(
    config: aster_framevisor::FrameVmConfig,
    control: Arc<FrameVmControl>,
    task_group: Arc<crate::sched::TaskGroup>,
) -> Result<()> {
    let setup_completion = FrameVmSetupCompletion::new();
    let loader_setup_completion = setup_completion.clone();
    let loader_task_fn = move || {
        let returned_setup_completion = loader_setup_completion.clone();
        let result = run_framevm_loader(config, control, task_group, loader_setup_completion);
        if let Err(error) = &result {
            returned_setup_completion.fail_if_pending(error);
            error!("[FrameVM] FrameVM loader thread error: {:?}", error);
        }
    };

    ThreadOptions::new(loader_task_fn).spawn();
    setup_completion.wait()
}

fn run_framevm_loader(
    config: aster_framevisor::FrameVmConfig,
    control: Arc<FrameVmControl>,
    task_group: Arc<crate::sched::TaskGroup>,
    setup_completion: Arc<FrameVmSetupCompletion>,
) -> Result<()> {
    control.prepare_terminal_cleanup();

    let vcpu_count = config.vcpu_count;
    let cmdline_append = config.cmdline_append.clone();
    let framevm_id = aster_framevisor::create_framevm_unstarted(config).map_err(|error| {
        let error: Error = error.into();
        Error::with_message(error.error(), "FrameVM instance creation failed")
    })?;
    if !control.set_vm_id(framevm_id) {
        let _ = stop_framevm_forced(framevm_id, &control);
        return Err(Error::with_message(
            Errno::ECANCELED,
            "FrameVM state changed during startup",
        ));
    }
    let Some(framevm) = aster_framevisor::get_framevm(framevm_id) else {
        let _ = stop_framevm_forced(framevm_id, &control);
        return Err(Error::with_message(
            Errno::EIO,
            "FrameVM instance disappeared",
        ));
    };
    if let Err(error) = framevm.install_event_sink(control.clone()) {
        let error: Error = error.into();
        let error = Error::with_message(error.error(), "FrameVM event-sink installation failed");
        let _ = stop_framevm_forced(framevm_id, &control);
        return Err(error);
    }

    let setup_result = (|| {
        clear_framevm_console_output(framevm_id)
            .map_err(|error| Error::with_message(error.error(), "FrameVM console setup failed"))?;
        let cpu_affinity = control.cpu_placement.effective_cpu_set();
        register_frame_sched_groups(framevm_id, &task_group, &cpu_affinity);
        control.cpu_placement.subscribe_framevm(framevm_id);
        if let Err(error) = aster_framevisor::start_framevm_by_id(framevm_id) {
            let error: Error = error.into();
            return Err(Error::with_message(
                error.error(),
                "FrameVM vCPU startup failed",
            ));
        }
        let boot_cmdline =
            framevm_boot_cmdline(vcpu_count, cmdline_append.as_deref()).map_err(|error| {
                Error::with_message(error.error(), "FrameVM boot-command-line setup failed")
            })?;
        boot::set_boot_info_without_initramfs(framevm_id, boot_cmdline).map_err(|error| {
            let error: Error = error.into();
            Error::with_message(error.error(), "FrameVM boot-information setup failed")
        })?;
        Ok(())
    })();
    if let Err(error) = setup_result {
        restore_current_thread_vm_space();
        stop_framevm_forced(framevm_id, &control);
        setup_completion.fail(&error);
        return Err(error);
    }
    let bootstrap_group = framevm.sched_group(0).ok_or_else(|| {
        Error::with_message(
            Errno::EINVAL,
            "FrameVM bootstrap scheduling group is unavailable",
        )
    });
    let bootstrap_host_cpu = bootstrap_group
        .as_ref()
        .map(|group| group.host_cpu())
        .map_err(|error| *error);
    let service_startup = framevm.begin_task_startup().ok_or_else(|| {
        Error::with_message(Errno::EINVAL, "FrameVM service startup is unavailable")
    });
    let service_task = bootstrap_group.and_then(|bootstrap_group| {
        service_startup.and_then(|service_startup| {
            let service_control = control.clone();
            aster_framevisor::task::build_bootstrap_task(&framevm, bootstrap_group, move || {
                let load_result = (|| {
                    let elf_data = aster_framevisor::get_framevm(framevm_id)
                        .and_then(|framevm| framevm.take_service_image())
                        .ok_or_else(|| {
                            Error::with_message(
                                Errno::EINVAL,
                                "FrameVM service image is unavailable",
                            )
                        })?;
                    let result = load_framevm_service(framevm_id, &elf_data);
                    drop(elf_data);
                    result
                })();
                match load_result {
                    Ok(()) => {
                        // A successful service entry transfers execution to
                        // the first inner task before its bootstrap function
                        // can return. Complete startup before that handoff so
                        // the Host-side `framevmm` request does not wait for
                        // the service's eventual shutdown.
                        service_startup.complete();
                        if let Err(error) = start_framevm_service(framevm_id) {
                            error!("[FrameVM] FrameVM service task error: {:?}", error);
                            let _ = service_control.set_pending_exit(-1);
                        }
                    }
                    Err(error) => {
                        error!("[FrameVM] FrameVM service load error: {:?}", error);
                        service_startup.fail();
                        let _ = service_control.set_pending_exit(-1);
                    }
                }
            })
            .map(Arc::new)
            .map_err(|error| {
                let error: Error = error.into();
                Error::with_message(error.error(), "FrameVM service task startup failed")
            })
        })
    });
    restore_current_thread_vm_space();
    match service_task.and_then(|service_task| {
        bootstrap_host_cpu.map(|bootstrap_host_cpu| (service_task, bootstrap_host_cpu))
    }) {
        Ok((service_task, bootstrap_host_cpu)) => {
            if control.mark_running() {
                setup_completion.complete();
                // The Host class scheduler owns this vCPU group on one
                // physical CPU. Starting its first continuation from a worker
                // on that same CPU avoids a synchronous remote-preemption
                // handshake before the group has a runnable carrier.
                work_queue::submit_work_func_on_cpu(
                    bootstrap_host_cpu,
                    move || service_task.run(),
                    WorkPriority::Normal,
                );
            } else {
                let error = Error::with_message(
                    Errno::ECANCELED,
                    "FrameVM state changed during service startup",
                );
                warn!("[FrameVM] state changed before service became running");
                stop_framevm_forced(framevm_id, &control);
                setup_completion.fail(&error);
                return Err(error);
            }
        }
        Err(error) => {
            if let Ok(console_output) = framevm_console_output_snapshot(framevm_id)
                && !console_output.is_empty()
            {
                warn!(
                    "[FrameVM] loader console output before rollback: {}",
                    console_output
                );
            }
            warn!("[FrameVM] rolling back failed FrameVM startup");
            stop_framevm_forced(framevm_id, &control);
            setup_completion.fail(&error);
            return Err(error);
        }
    }
    Ok(())
}

fn framevm_boot_cmdline(vcpu_count: usize, append: Option<&str>) -> Result<String> {
    let realtime_ns = duration_to_ns(
        SystemTime::now()
            .duration_since(&SystemTime::UNIX_EPOCH)
            .map_err(|_| Error::new(Errno::EINVAL))?,
    )?;
    let monotonic_ns = read_host_monotonic_ns()?;

    let mut cmdline = format!(
        "kernel.realtime_base_ns={realtime_ns} kernel.monotonic_base_ns={monotonic_ns} ostd.vcpu_count={vcpu_count}"
    );
    if let Some(append) = append
        && !append.is_empty()
    {
        cmdline.push(' ');
        cmdline.push_str(append);
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

fn validate_framevm_memory_limit(memory_limit_bytes: usize) -> Result<()> {
    if memory_limit_bytes != 0 && memory_limit_bytes.is_multiple_of(PAGE_SIZE) {
        return Ok(());
    }

    Err(Error::with_message(
        Errno::EINVAL,
        "FrameVM memory limit must be nonzero and page aligned",
    ))
}

/// Reads the packaged FrameVM artifact before untrusted userspace starts.
pub(crate) fn read_packaged_framevm_artifact() -> Result<Vec<u8>> {
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

/// Loads the FrameVM service program from ELF data.
fn load_framevm_service(vm_id: aster_framevisor::VmId, elf_data: &[u8]) -> Result<()> {
    let frame_vm = aster_framevisor::get_framevm(vm_id)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "missing FrameVM instance"))?;
    let allocate_segment =
        |pages| aster_framevisor::mm::alloc_service_segment(frame_vm.id(), pages);
    let resolve_symbol = |symbol_name: &[u8]| {
        frame_vm
            .resolve_service_symbol(symbol_name)
            .or_else(|| ostd::symbols::framevm_symbol_addr_by_name(symbol_name))
            .map(|addr| addr as u64)
    };
    let observe_symbol = |symbol: &ostd::loader::DefinedSymbol<'_>| {
        frame_vm.observe_service_symbol(symbol).map_err(|error| {
            error!(
                "[FrameVM] rejected service provider symbol {:?}: {:?}",
                symbol.name(),
                error
            );
            ostd::Error::InvalidArgs
        })
    };
    let load_context = ostd::loader::FrameVmLoadContext::new(
        &allocate_segment,
        &resolve_symbol,
        &aster_framevisor::vm::FrameVm::should_defer_service_symbol,
        &observe_symbol,
    );
    let service_program = match ostd::loader::Program::load_with_context(elf_data, &load_context) {
        Ok(program) => program,
        Err(error) => {
            error!("[FrameVM] failed to load the service image: {:?}", error);
            frame_vm.abort_service_load();
            return Err(error.into());
        }
    };
    if let Err(error) = frame_vm.install_program(service_program) {
        error!("[FrameVM] failed to install the service image: {:?}", error);
        frame_vm.abort_service_load();
        return Err(error.into());
    }

    Ok(())
}

/// Runs a previously loaded FrameVM service program.
fn start_framevm_service(vm_id: aster_framevisor::VmId) -> Result<()> {
    let frame_vm = aster_framevisor::get_framevm(vm_id)
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "missing FrameVM instance"))?;
    // Invoke the entry point on the FrameVisor service task;
    // FrameVM sets up its own runtime tasks during initialization.
    if aster_framevisor::current_frame_vcpu_id().is_none() {
        frame_vm.abort_service_load();
        return Err(Error::with_message(
            Errno::EINVAL,
            "missing FrameVM service domain",
        ));
    }
    frame_vm
        .start_program()
        .map_err(|_| Error::with_message(Errno::EIO, "FrameVM service entry failed"))
}
