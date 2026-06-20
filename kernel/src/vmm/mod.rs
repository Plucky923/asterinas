// SPDX-License-Identifier: MPL-2.0

use alloc::format;
use core::{
    fmt::{Display, Write},
    sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering},
    time::Duration,
};

use aster_framevisor::{
    DEFAULT_FRAME_TASK_GROUP_SHARE, FrameTaskGroupSnapshot,
    boot::{self, BootMode},
    create_framevm_unstarted, start_framevm, start_framevm_by_id, stop_framevm,
};
use libflate::gzip::Decoder as GZipDecoder;
use no_std_io2::io::Read;
use ostd::{
    arch::{read_tsc, tsc_freq},
    cpu::{CpuId, CpuSet},
    sync::WaitQueue,
    task::Task,
};

use crate::{
    fs::{
        file::{AccessMode, FileLike, InodeMode, OpenArgs},
        vfs::path::FsPath,
    },
    prelude::*,
    thread::kernel_thread::ThreadOptions,
    time::SystemTime,
};

/// Guard against concurrent or repeated FrameVM load requests.
///
/// `/proc/framevm` is user-triggered and can be written repeatedly.
/// We reject overlapping loads to avoid lifecycle races.
static FRAMEVM_LOAD_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
static FRAMEVM_LOAD_STATE: AtomicU8 = AtomicU8::new(FrameVmLoadState::Idle as u8);
static FRAMEVM_TASK_GROUP_SHARE: AtomicU32 = AtomicU32::new(DEFAULT_FRAME_TASK_GROUP_SHARE);
static FRAMEVM_LAST_ERROR: SpinLock<Option<String>> = SpinLock::new(None);
static FRAMEVM_LAST_SHARE_TEST: SpinLock<Option<FrameVmShareTestReport>> = SpinLock::new(None);
static FRAMEVM_LAST_BUSYBOX_SMOKE: SpinLock<Option<FrameVmBusyBoxSmokeReport>> =
    SpinLock::new(None);

const FRAMEVM_BUSYBOX_SMOKE_VCPU_COUNT: usize = 1;
const FRAMEVM_SHARE_TEST_VCPU_COUNT: usize = 2;
const FRAMEVM_SHARE_TEST_TOLERANCE_PER_MILLE: u64 = 200;
const FRAMEVM_SHARE_TEST_REQUIRED_SHARE_UPDATES: u64 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum FrameVmLoadState {
    Idle = 0,
    ReadingElf = 1,
    ReadingRootfs = 2,
    ThreadSpawned = 3,
    ThreadStarted = 4,
    StartingFramevisor = 5,
    LoadingModule = 6,
    Running = 7,
    Completed = 8,
    Failed = 9,
}

impl FrameVmLoadState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::ReadingElf => "reading_elf",
            Self::ReadingRootfs => "reading_rootfs",
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
            2 => Self::ReadingRootfs,
            3 => Self::ThreadSpawned,
            4 => Self::ThreadStarted,
            5 => Self::StartingFramevisor,
            6 => Self::LoadingModule,
            7 => Self::Running,
            8 => Self::Completed,
            9 => Self::Failed,
            _ => Self::Idle,
        }
    }
}

#[derive(Clone, Debug)]
struct FrameVmShareTestReport {
    group0_share: u32,
    group1_share: u32,
    duration_ms: u64,
    dynamic_share_update: bool,
    host_scheduler_path_exercised: bool,
    host_weight_matches_share: bool,
    group0_host_weight: u32,
    group1_host_weight: u32,
    group0_actual_host_weight: u64,
    group1_actual_host_weight: u64,
    group0_parent_pick_count: u64,
    group1_parent_pick_count: u64,
    group0_parent_pick_with_peer_count: u64,
    group1_parent_pick_with_peer_count: u64,
    group0_parent_entity_dequeue_count: u64,
    group1_parent_entity_dequeue_count: u64,
    group0_current_compete_count: u64,
    group1_current_compete_count: u64,
    group0_current_requeue_count: u64,
    group1_current_requeue_count: u64,
    group0_schedule_in_bound_count: u64,
    group1_schedule_in_bound_count: u64,
    group0_schedule_in_unbound_count: u64,
    group1_schedule_in_unbound_count: u64,
    share_update_count: u64,
    group0_runtime_cycles: u64,
    group1_runtime_cycles: u64,
    group0_loops: u64,
    group1_loops: u64,
    expected_group1_per_mille: u64,
    actual_runtime_group1_per_mille: u64,
    actual_loop_group1_per_mille: u64,
    tolerance_per_mille: u64,
    passed: bool,
}

#[derive(Clone, Debug)]
struct FrameVmBusyBoxSmokeReport {
    found_pwd_root: bool,
    found_cwd_tmp: bool,
    found_cwd_file: bool,
    found_rootfs_marker: bool,
    found_vfs_marker: bool,
    found_mounts: bool,
    found_vsock_probe: bool,
    found_success_marker: bool,
    exited_to_host: bool,
    passed: bool,
}

struct FrameVmLoadSignal {
    has_started: AtomicBool,
    wait_queue: WaitQueue,
}

impl FrameVmLoadSignal {
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
    *FRAMEVM_LAST_SHARE_TEST.lock() = None;
    *FRAMEVM_LAST_BUSYBOX_SMOKE.lock() = None;
    aster_framevisor::clear_framevm_log();
    ostd::loader::clear_last_error();
}

pub fn set_framevm_task_group_share(share: u32) -> Result<()> {
    aster_framevisor::validate_frame_task_group_share(share)?;
    FRAMEVM_TASK_GROUP_SHARE.store(share, Ordering::Release);

    if aster_framevisor::framevm_count() > 0 {
        apply_configured_frame_task_group_share()?;
    }

    Ok(())
}

fn configured_frame_task_group_share() -> u32 {
    FRAMEVM_TASK_GROUP_SHARE.load(Ordering::Acquire)
}

fn apply_configured_frame_task_group_share() -> Result<()> {
    let share = configured_frame_task_group_share();
    for snapshot in aster_framevisor::frame_task_group_snapshots() {
        aster_framevisor::set_frame_task_group_share(snapshot.id(), share)?;
    }
    Ok(())
}

fn bind_loader_to_default_frame_task_group() -> Result<()> {
    let task_group_id = aster_framevisor::default_frame_task_group_id()
        .ok_or_else(|| Error::with_message(Errno::EINVAL, "missing FrameVM task group"))?;
    aster_framevisor::bind_current_task_to_frame_task_group(task_group_id)?;
    crate::thread::framevm_task::bind_current_thread_to_frame_task_group(task_group_id);
    Ok(())
}

fn clear_loader_frame_task_group() {
    crate::thread::framevm_task::clear_current_thread_frame_task_group();
    aster_framevisor::clear_current_frame_task_group();
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
    write_status_line(
        &mut output,
        "configured_task_group_share",
        configured_frame_task_group_share(),
    );
    write_frame_task_group_status(&mut output);
    write_busybox_smoke_status(&mut output);
    write_share_test_status(&mut output);
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

fn write_busybox_smoke_status(output: &mut String) {
    let Some(report) = FRAMEVM_LAST_BUSYBOX_SMOKE.lock().clone() else {
        return;
    };

    let _ = writeln!(
        output,
        "busybox_smoke: passed={} found_pwd_root={} found_cwd_tmp={} found_cwd_file={} found_rootfs_marker={} found_vfs_marker={} found_mounts={} found_vsock_probe={} found_success_marker={} exited_to_host={}",
        u8::from(report.passed),
        u8::from(report.found_pwd_root),
        u8::from(report.found_cwd_tmp),
        u8::from(report.found_cwd_file),
        u8::from(report.found_rootfs_marker),
        u8::from(report.found_vfs_marker),
        u8::from(report.found_mounts),
        u8::from(report.found_vsock_probe),
        u8::from(report.found_success_marker),
        u8::from(report.exited_to_host)
    );
}

fn write_share_test_status(output: &mut String) {
    let Some(report) = FRAMEVM_LAST_SHARE_TEST.lock().clone() else {
        return;
    };

    let _ = writeln!(
        output,
        "share_test: passed={} dynamic_share_update={} host_scheduler_path_exercised={} host_weight_matches_share={} group0_share={} group1_share={} duration_ms={} group0_host_weight={} group1_host_weight={} group0_actual_host_weight={} group1_actual_host_weight={} group0_parent_pick_count={} group1_parent_pick_count={} group0_parent_pick_with_peer_count={} group1_parent_pick_with_peer_count={} group0_parent_entity_dequeue_count={} group1_parent_entity_dequeue_count={} group0_current_compete_count={} group1_current_compete_count={} group0_current_requeue_count={} group1_current_requeue_count={} group0_schedule_in_bound_count={} group1_schedule_in_bound_count={} group0_schedule_in_unbound_count={} group1_schedule_in_unbound_count={} share_update_count={} group0_runtime_cycles={} group1_runtime_cycles={} group0_loops={} group1_loops={} expected_group1_per_mille={} actual_runtime_group1_per_mille={} actual_loop_group1_per_mille={} tolerance_per_mille={}",
        u8::from(report.passed),
        u8::from(report.dynamic_share_update),
        u8::from(report.host_scheduler_path_exercised),
        u8::from(report.host_weight_matches_share),
        report.group0_share,
        report.group1_share,
        report.duration_ms,
        report.group0_host_weight,
        report.group1_host_weight,
        report.group0_actual_host_weight,
        report.group1_actual_host_weight,
        report.group0_parent_pick_count,
        report.group1_parent_pick_count,
        report.group0_parent_pick_with_peer_count,
        report.group1_parent_pick_with_peer_count,
        report.group0_parent_entity_dequeue_count,
        report.group1_parent_entity_dequeue_count,
        report.group0_current_compete_count,
        report.group1_current_compete_count,
        report.group0_current_requeue_count,
        report.group1_current_requeue_count,
        report.group0_schedule_in_bound_count,
        report.group1_schedule_in_bound_count,
        report.group0_schedule_in_unbound_count,
        report.group1_schedule_in_unbound_count,
        report.share_update_count,
        report.group0_runtime_cycles,
        report.group1_runtime_cycles,
        report.group0_loops,
        report.group1_loops,
        report.expected_group1_per_mille,
        report.actual_runtime_group1_per_mille,
        report.actual_loop_group1_per_mille,
        report.tolerance_per_mille
    );
}

fn write_frame_task_group_status(output: &mut String) {
    let snapshots = aster_framevisor::frame_task_group_snapshots();
    write_status_line(output, "task_group_count", snapshots.len());
    for snapshot in snapshots {
        let id = snapshot.id();
        let host_sched =
            crate::thread::framevm_task::frame_task_group_host_sched_snapshot(id, snapshot.share());
        let host_weight = host_sched.map_or(0, |snapshot| snapshot.weight);
        let actual_host_weight = host_sched.map_or(0, |snapshot| snapshot.actual_weight);
        let host_vruntime = host_sched.map_or(0, |snapshot| snapshot.vruntime);
        let bound_task_count = host_sched.map_or(0, |snapshot| snapshot.bound_task_count);
        let scheduler_bound_task_count =
            host_sched.map_or(0, |snapshot| snapshot.scheduler_bound_task_count);
        let bind_count = host_sched.map_or(0, |snapshot| snapshot.bind_count);
        let service_bind_count = host_sched.map_or(0, |snapshot| snapshot.service_bind_count);
        let iht_bind_count = host_sched.map_or(0, |snapshot| snapshot.iht_bind_count);
        let schedule_in_bound_count =
            host_sched.map_or(0, |snapshot| snapshot.schedule_in_bound_count);
        let schedule_in_unbound_count =
            host_sched.map_or(0, |snapshot| snapshot.schedule_in_unbound_count);
        let parent_pick_count = host_sched.map_or(0, |snapshot| snapshot.parent_pick_count);
        let parent_pick_with_any_peer_count =
            host_sched.map_or(0, |snapshot| snapshot.parent_pick_with_any_peer_count);
        let parent_pick_with_peer_count =
            host_sched.map_or(0, |snapshot| snapshot.parent_pick_with_peer_count);
        let parent_pick_child_empty_count =
            host_sched.map_or(0, |snapshot| snapshot.parent_pick_child_empty_count);
        let parent_pick_empty_no_task_count =
            host_sched.map_or(0, |snapshot| snapshot.parent_pick_empty_no_task_count);
        let current_compete_count = host_sched.map_or(0, |snapshot| snapshot.current_compete_count);
        let current_requeue_count = host_sched.map_or(0, |snapshot| snapshot.current_requeue_count);
        let current_dequeue_empty_count =
            host_sched.map_or(0, |snapshot| snapshot.current_dequeue_empty_count);
        let queued_dequeue_empty_count =
            host_sched.map_or(0, |snapshot| snapshot.queued_dequeue_empty_count);
        let share_update_count = host_sched.map_or(0, |snapshot| snapshot.share_update_count);
        let _ = writeln!(
            output,
            "task_group: vm={} vcpu={} share={} nice={} host_weight={} actual_host_weight={} host_vruntime={} bound_tasks={} scheduler_bound_tasks={} bind_count={} service_bind_count={} iht_bind_count={} schedule_in_bound_count={} schedule_in_unbound_count={} parent_pick_count={} parent_pick_with_any_peer_count={} parent_pick_with_peer_count={} parent_pick_child_empty_count={} parent_pick_empty_no_task_count={} parent_entity_dequeue_count={} current_compete_count={} current_requeue_count={} current_dequeue_empty_count={} queued_dequeue_empty_count={} share_update_count={} schedule_count={} runtime_cycles={} service_schedule_count={} service_runtime_cycles={} iht_schedule_count={} iht_runtime_cycles={} schedule_cpu_mask={} last_schedule_cpu={} pending_timer_ticks={} delivered_timer_ticks={} last_host_deadline={} needs_resched={}",
            id.vm_id(),
            id.vcpu_id(),
            snapshot.share(),
            snapshot.nice_hint(),
            host_weight,
            actual_host_weight,
            host_vruntime,
            bound_task_count,
            scheduler_bound_task_count,
            bind_count,
            service_bind_count,
            iht_bind_count,
            schedule_in_bound_count,
            schedule_in_unbound_count,
            parent_pick_count,
            parent_pick_with_any_peer_count,
            parent_pick_with_peer_count,
            parent_pick_child_empty_count,
            parent_pick_empty_no_task_count,
            host_sched.map_or(0, |snapshot| snapshot.parent_entity_dequeue_count),
            current_compete_count,
            current_requeue_count,
            current_dequeue_empty_count,
            queued_dequeue_empty_count,
            share_update_count,
            snapshot.schedule_count(),
            snapshot.runtime_cycles(),
            snapshot.service_schedule_count(),
            snapshot.service_runtime_cycles(),
            snapshot.iht_schedule_count(),
            snapshot.iht_runtime_cycles(),
            snapshot.schedule_cpu_mask(),
            snapshot.last_schedule_cpu(),
            snapshot.pending_timer_ticks(),
            snapshot.delivered_timer_ticks(),
            snapshot.last_host_deadline(),
            u8::from(snapshot.needs_resched())
        );
    }
}

pub fn stop_framevm_instances() {
    stop_framevm();
    clear_framevm_last_error();
    set_framevm_load_state(FrameVmLoadState::Idle);
    end_framevm_load();
}

pub fn inject_framevm_console_input(input: &str) -> Result<()> {
    aster_framevisor::inject_framevm_console_input(input.as_bytes())?;
    Ok(())
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
        let (elf_data, rootfs_data) = read_framevm_artifacts()?;
        run_framevm_loader(vcpu_count, &elf_data, rootfs_data)
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

/// Runs a foreground FrameVM BusyBox/rootfs smoke test and records the result.
pub fn run_framevm_busybox_smoke() -> Result<()> {
    ostd::early_println!("[FrameVM] busybox smoke: begin");
    try_begin_framevm_load()?;
    clear_framevm_last_error();
    set_framevm_load_state(FrameVmLoadState::ReadingElf);

    let result = (|| {
        ostd::early_println!("[FrameVM] busybox smoke: read elf");
        let elf_data = read_framevm_elf()?;
        set_framevm_load_state(FrameVmLoadState::ReadingRootfs);
        ostd::early_println!("[FrameVM] busybox smoke: read rootfs");
        let rootfs_data = read_framevm_rootfs()?;
        ensure_framevm_not_running("refusing to run BusyBox smoke test")?;
        set_framevm_load_state(FrameVmLoadState::StartingFramevisor);
        ostd::early_println!("[FrameVM] busybox smoke: start framevisor");
        start_framevm(FRAMEVM_BUSYBOX_SMOKE_VCPU_COUNT)?;
        aster_framevisor::clear_framevm_log();
        ostd::early_println!("[FrameVM] busybox smoke: configure task group");
        apply_configured_frame_task_group_share()?;
        bind_loader_to_default_frame_task_group()?;
        ostd::early_println!("[FrameVM] busybox smoke: set boot info");
        boot::set_boot_info_with_mode_and_extra(
            rootfs_data,
            BootMode::BusyBoxSmoke,
            framevm_boot_cmdline(FRAMEVM_BUSYBOX_SMOKE_VCPU_COUNT)?,
        );
        set_framevm_load_state(FrameVmLoadState::LoadingModule);
        ostd::early_println!("[FrameVM] busybox smoke: load module");
        let load_result = load_framevm_file(&elf_data);
        ostd::early_println!("[FrameVM] busybox smoke: module returned");
        clear_loader_frame_task_group();
        restore_current_thread_vm_space();
        if let Err(error) = load_result {
            rollback_failed_framevm_start();
            return Err(error);
        }

        let report = build_busybox_smoke_report();
        let passed = report.passed;
        *FRAMEVM_LAST_BUSYBOX_SMOKE.lock() = Some(report);
        if !passed {
            return Err(Error::with_message(
                Errno::EIO,
                "FrameVM BusyBox smoke test did not produce the expected output",
            ));
        }

        Ok(())
    })();
    match &result {
        Ok(()) => set_framevm_load_state(FrameVmLoadState::Completed),
        Err(error) => {
            set_framevm_load_state(FrameVmLoadState::Failed);
            record_framevm_last_error(error);
            error!("[FrameVM] FrameVM BusyBox smoke test error: {:?}", error);
        }
    }
    end_framevm_load();
    result
}

fn build_busybox_smoke_report() -> FrameVmBusyBoxSmokeReport {
    let log = aster_framevisor::framevm_log_snapshot();
    let found_pwd_root = log.lines().any(|line| line.trim() == "/");
    let found_cwd_tmp = log.lines().any(|line| line.trim() == "/tmp");
    let found_cwd_file = log.contains("framevm-cwd-ok");
    let found_rootfs_marker = log.contains("kernel-busybox-rootfs ok");
    let found_vfs_marker = log.contains("kernel-busybox-vfs ok");
    let found_mounts = log.contains("rootfs / rootfs rw,relatime 0 0");
    let found_vsock_probe = log.contains("vsock-probe passed");
    let found_success_marker = log.contains("kernel-busybox-smoke passed");
    let exited_to_host = aster_framevisor::framevm_count() == 0;
    let passed = found_pwd_root
        && found_cwd_tmp
        && found_cwd_file
        && found_rootfs_marker
        && found_vfs_marker
        && found_mounts
        && found_vsock_probe
        && found_success_marker
        && exited_to_host;

    FrameVmBusyBoxSmokeReport {
        found_pwd_root,
        found_cwd_tmp,
        found_cwd_file,
        found_rootfs_marker,
        found_vfs_marker,
        found_mounts,
        found_vsock_probe,
        found_success_marker,
        exited_to_host,
        passed,
    }
}

/// Runs a foreground FrameVM CPU-share benchmark and records the result.
pub fn run_framevm_share_test(
    group0_share: u32,
    group1_share: u32,
    duration_ms: u64,
) -> Result<()> {
    validate_share_test_args(group0_share, group1_share, duration_ms)?;
    try_begin_framevm_load()?;
    clear_framevm_last_error();
    set_framevm_load_state(FrameVmLoadState::ReadingElf);

    let result = (|| {
        let elf_data = read_framevm_elf()?;
        set_framevm_load_state(FrameVmLoadState::ReadingRootfs);
        let rootfs_data = read_framevm_rootfs()?;
        ensure_framevm_not_running("refusing to run share test")?;
        set_framevm_load_state(FrameVmLoadState::StartingFramevisor);
        let vm_id = create_framevm_unstarted(FRAMEVM_SHARE_TEST_VCPU_COUNT)?;
        apply_share_test_task_group_shares(group0_share, group0_share)?;
        let group1_task_group_id = find_share_test_snapshot(1)?.id();
        let dynamic_share_update =
            update_share_test_task_group_share(group1_task_group_id, group1_share);
        start_framevm_by_id(vm_id)?;
        aster_framevisor::clear_framevm_log();
        bind_loader_to_default_frame_task_group()?;
        boot::set_boot_info_with_mode_and_extra(
            rootfs_data,
            BootMode::ShareBenchmark { duration_ms },
            framevm_boot_cmdline(FRAMEVM_SHARE_TEST_VCPU_COUNT)?,
        );
        set_framevm_load_state(FrameVmLoadState::LoadingModule);
        let load_result = load_framevm_file(&elf_data);
        clear_loader_frame_task_group();
        restore_current_thread_vm_space();
        if let Err(error) = load_result {
            rollback_failed_framevm_start();
            return Err(error);
        }

        let report = build_share_test_report(
            group0_share,
            group1_share,
            duration_ms,
            dynamic_share_update,
        )?;
        let passed = report.passed;
        *FRAMEVM_LAST_SHARE_TEST.lock() = Some(report);
        if !passed {
            return Err(Error::with_message(
                Errno::EIO,
                "FrameVM CPU share benchmark did not meet the expected ratio",
            ));
        }

        Ok(())
    })();
    match &result {
        Ok(()) => set_framevm_load_state(FrameVmLoadState::Completed),
        Err(error) => {
            set_framevm_load_state(FrameVmLoadState::Failed);
            record_framevm_last_error(error);
            error!("[FrameVM] FrameVM share test error: {:?}", error);
        }
    }
    crate::thread::framevm_task::clear_frame_task_group_cpu_affinity_overrides();
    end_framevm_load();
    result
}

fn validate_share_test_args(group0_share: u32, group1_share: u32, duration_ms: u64) -> Result<()> {
    aster_framevisor::validate_frame_task_group_share(group0_share)?;
    aster_framevisor::validate_frame_task_group_share(group1_share)?;
    if duration_ms == 0 {
        return Err(Error::with_message(
            Errno::EINVAL,
            "FrameVM share test duration must be non-zero",
        ));
    }

    Ok(())
}

fn apply_share_test_task_group_shares(group0_share: u32, group1_share: u32) -> Result<()> {
    let cpu_affinity = share_test_cpu_affinity();
    for snapshot in aster_framevisor::frame_task_group_snapshots() {
        let share = match snapshot.id().vcpu_id() {
            0 => group0_share,
            1 => group1_share,
            _ => continue,
        };
        aster_framevisor::reset_frame_task_group_accounting(snapshot.id())?;
        aster_framevisor::set_frame_task_group_share(snapshot.id(), share)?;
        crate::thread::framevm_task::set_frame_task_group_cpu_affinity(
            snapshot.id(),
            cpu_affinity.clone(),
        );
    }
    Ok(())
}

fn update_share_test_task_group_share(
    task_group_id: aster_framevisor::FrameTaskGroupId,
    target_share: u32,
) -> bool {
    match aster_framevisor::set_frame_task_group_share(task_group_id, target_share) {
        Ok(()) => true,
        Err(error) => {
            error!(
                "[FrameVM] failed to dynamically update share test task group: {:?}",
                error
            );
            false
        }
    }
}

fn share_test_cpu_affinity() -> CpuSet {
    let mut cpu_set = CpuSet::new_empty();
    cpu_set.add(CpuId::bsp());
    cpu_set
}

fn build_share_test_report(
    group0_share: u32,
    group1_share: u32,
    duration_ms: u64,
    dynamic_share_update: bool,
) -> Result<FrameVmShareTestReport> {
    let group0 = find_share_test_snapshot(0)?;
    let group1 = find_share_test_snapshot(1)?;
    let group0_host = crate::thread::framevm_task::frame_task_group_host_sched_snapshot(
        group0.id(),
        group0.share(),
    )
    .ok_or_else(|| {
        Error::with_message(
            Errno::EIO,
            "missing host scheduler state for FrameVM share test group0",
        )
    })?;
    let group1_host = crate::thread::framevm_task::frame_task_group_host_sched_snapshot(
        group1.id(),
        group1.share(),
    )
    .ok_or_else(|| {
        Error::with_message(
            Errno::EIO,
            "missing host scheduler state for FrameVM share test group1",
        )
    })?;
    let group0_runtime_cycles = group0.runtime_cycles();
    let group1_runtime_cycles = group1.runtime_cycles();
    let total_runtime_cycles = group0_runtime_cycles.saturating_add(group1_runtime_cycles);
    if total_runtime_cycles == 0 {
        return Err(Error::with_message(
            Errno::EIO,
            "FrameVM share test produced no runtime samples",
        ));
    }
    let (group0_loops, group1_loops) = parse_share_benchmark_loops()?;
    let total_loops = group0_loops.saturating_add(group1_loops);
    if total_loops == 0 {
        return Err(Error::with_message(
            Errno::EIO,
            "FrameVM share test produced no workload samples",
        ));
    }

    let expected_group1_per_mille =
        u64::from(group1_share) * 1000 / u64::from(group0_share.saturating_add(group1_share));
    let actual_runtime_group1_per_mille = group1_runtime_cycles * 1000 / total_runtime_cycles;
    let actual_loop_group1_per_mille = group1_loops * 1000 / total_loops;
    let parent_pick_count = group0_host
        .parent_pick_count
        .saturating_add(group1_host.parent_pick_count);
    let parent_pick_with_peer_count = group0_host
        .parent_pick_with_peer_count
        .saturating_add(group1_host.parent_pick_with_peer_count);
    let schedule_in_bound_count = group0_host
        .schedule_in_bound_count
        .saturating_add(group1_host.schedule_in_bound_count);
    let schedule_in_unbound_count = group0_host
        .schedule_in_unbound_count
        .saturating_add(group1_host.schedule_in_unbound_count);
    let share_update_count = group0_host
        .share_update_count
        .max(group1_host.share_update_count);
    let host_scheduler_path_exercised = parent_pick_count != 0
        && parent_pick_with_peer_count != 0
        && schedule_in_bound_count != 0
        && schedule_in_unbound_count == 0
        && share_update_count >= FRAMEVM_SHARE_TEST_REQUIRED_SHARE_UPDATES;
    let host_weight_matches_share = share_order_matches_runtime(
        group0_share,
        group1_share,
        group0_host.actual_weight,
        group1_host.actual_weight,
    );
    let passed = dynamic_share_update
        && host_scheduler_path_exercised
        && host_weight_matches_share
        && share_ratio_is_within_tolerance(
            actual_runtime_group1_per_mille,
            expected_group1_per_mille,
        )
        && share_ratio_is_within_tolerance(actual_loop_group1_per_mille, expected_group1_per_mille)
        && share_order_matches_runtime(group0_share, group1_share, group0_loops, group1_loops)
        && share_order_matches_runtime(
            group0_share,
            group1_share,
            group0_runtime_cycles,
            group1_runtime_cycles,
        );

    Ok(FrameVmShareTestReport {
        group0_share,
        group1_share,
        duration_ms,
        dynamic_share_update,
        host_scheduler_path_exercised,
        host_weight_matches_share,
        group0_host_weight: group0_host.weight,
        group1_host_weight: group1_host.weight,
        group0_actual_host_weight: group0_host.actual_weight,
        group1_actual_host_weight: group1_host.actual_weight,
        group0_parent_pick_count: group0_host.parent_pick_count,
        group1_parent_pick_count: group1_host.parent_pick_count,
        group0_parent_pick_with_peer_count: group0_host.parent_pick_with_peer_count,
        group1_parent_pick_with_peer_count: group1_host.parent_pick_with_peer_count,
        group0_parent_entity_dequeue_count: group0_host.parent_entity_dequeue_count,
        group1_parent_entity_dequeue_count: group1_host.parent_entity_dequeue_count,
        group0_current_compete_count: group0_host.current_compete_count,
        group1_current_compete_count: group1_host.current_compete_count,
        group0_current_requeue_count: group0_host.current_requeue_count,
        group1_current_requeue_count: group1_host.current_requeue_count,
        group0_schedule_in_bound_count: group0_host.schedule_in_bound_count,
        group1_schedule_in_bound_count: group1_host.schedule_in_bound_count,
        group0_schedule_in_unbound_count: group0_host.schedule_in_unbound_count,
        group1_schedule_in_unbound_count: group1_host.schedule_in_unbound_count,
        share_update_count,
        group0_runtime_cycles,
        group1_runtime_cycles,
        group0_loops,
        group1_loops,
        expected_group1_per_mille,
        actual_runtime_group1_per_mille,
        actual_loop_group1_per_mille,
        tolerance_per_mille: FRAMEVM_SHARE_TEST_TOLERANCE_PER_MILLE,
        passed,
    })
}

fn share_ratio_is_within_tolerance(actual_per_mille: u64, expected_per_mille: u64) -> bool {
    let lower_bound = expected_per_mille.saturating_sub(FRAMEVM_SHARE_TEST_TOLERANCE_PER_MILLE);
    let upper_bound = (expected_per_mille + FRAMEVM_SHARE_TEST_TOLERANCE_PER_MILLE).min(1000);
    (lower_bound..=upper_bound).contains(&actual_per_mille)
}

fn parse_share_benchmark_loops() -> Result<(u64, u64)> {
    let log = aster_framevisor::framevm_log_snapshot();
    let group0_loops = parse_burn_loops(&log, "worker0").ok_or_else(|| {
        Error::with_message(Errno::EIO, "missing FrameVM share test worker0 loop count")
    })?;
    let group1_loops = parse_burn_loops(&log, "worker1").ok_or_else(|| {
        Error::with_message(Errno::EIO, "missing FrameVM share test worker1 loop count")
    })?;
    Ok((group0_loops, group1_loops))
}

fn parse_burn_loops(log: &str, label: &str) -> Option<u64> {
    let mut loops = None;
    for (index, _) in log.match_indices(label) {
        if let Some(parsed_loops) = parse_burn_loops_after_label(&log[index + label.len()..]) {
            loops = Some(parsed_loops);
        }
    }
    loops
}

fn parse_burn_loops_after_label(log_after_label: &str) -> Option<u64> {
    let loops = log_after_label
        .split_whitespace()
        .find_map(|field| field.strip_prefix("loops="))?;
    parse_u64_decimal(loops)
}

fn parse_u64_decimal(value: &str) -> Option<u64> {
    let mut number = 0u64;
    for byte in value.bytes() {
        if !byte.is_ascii_digit() {
            return None;
        }
        number = number
            .checked_mul(10)?
            .checked_add(u64::from(byte - b'0'))?;
    }
    Some(number)
}

fn find_share_test_snapshot(vcpu_id: usize) -> Result<FrameTaskGroupSnapshot> {
    aster_framevisor::frame_task_group_snapshots()
        .into_iter()
        .find(|snapshot| snapshot.id().vcpu_id() == vcpu_id)
        .ok_or_else(|| Error::with_message(Errno::EIO, "missing FrameVM share test snapshot"))
}

fn share_order_matches_runtime(
    group0_share: u32,
    group1_share: u32,
    group0_runtime_cycles: u64,
    group1_runtime_cycles: u64,
) -> bool {
    match group1_share.cmp(&group0_share) {
        core::cmp::Ordering::Greater => group1_runtime_cycles > group0_runtime_cycles,
        core::cmp::Ordering::Less => group1_runtime_cycles < group0_runtime_cycles,
        core::cmp::Ordering::Equal => true,
    }
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

    let (elf_data, rootfs_data) = match read_framevm_artifacts() {
        Ok(artifacts) => artifacts,
        Err(error) => {
            fail_framevm_load(error);
            return Err(error);
        }
    };

    spawn_framevm_loader(vcpu_count, elf_data, rootfs_data);
    Ok(())
}

fn read_framevm_artifacts() -> Result<(Vec<u8>, Vec<u8>)> {
    // Read the artifacts before spawning the kernel thread.
    // The file handles must be dropped while we still run in a process-backed task,
    // because inode range-lock teardown expects `current!()` to resolve to a process.
    let elf_data = read_framevm_elf()?;
    set_framevm_load_state(FrameVmLoadState::ReadingRootfs);
    let rootfs_data = read_framevm_rootfs()?;
    Ok((elf_data, rootfs_data))
}

fn fail_framevm_load(error: Error) {
    set_framevm_load_state(FrameVmLoadState::Failed);
    record_framevm_last_error(&error);
    error!("[FrameVM] FrameVM load error: {:?}", error);
    end_framevm_load();
}

fn spawn_framevm_loader(
    vcpu_count: usize,
    elf_data: Vec<u8>,
    rootfs_data: Vec<u8>,
) -> Arc<FrameVmLoadSignal> {
    set_framevm_load_state(FrameVmLoadState::ThreadSpawned);
    info!(
        "[FrameVM] Spawning FrameVM with {} vCPU(s) in loader thread...",
        vcpu_count
    );
    let load_signal = Arc::new(FrameVmLoadSignal::new());
    let thread_signal = load_signal.clone();
    ThreadOptions::new(move || {
        set_framevm_load_state(FrameVmLoadState::ThreadStarted);
        info!("[FrameVM] loader thread started");
        thread_signal.signal_started();

        let res = run_framevm_loader(vcpu_count, &elf_data, rootfs_data);

        match res {
            Ok(()) => {
                set_framevm_load_state(FrameVmLoadState::Completed);
                info!("[FrameVM] FrameVM load completed");
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

    load_signal.wait_until_started();
    load_signal
}

fn run_framevm_loader(vcpu_count: usize, elf_data: &[u8], rootfs_data: Vec<u8>) -> Result<()> {
    ensure_framevm_not_running("refusing to load")?;

    set_framevm_load_state(FrameVmLoadState::StartingFramevisor);
    info!("[FrameVM] starting FrameVisor from loader thread");
    start_framevm(vcpu_count)?;
    aster_framevisor::clear_framevm_log();
    apply_configured_frame_task_group_share()?;
    bind_loader_to_default_frame_task_group()?;
    boot::set_boot_info_with_extra(rootfs_data, framevm_boot_cmdline(vcpu_count)?);

    set_framevm_load_state(FrameVmLoadState::LoadingModule);
    info!("[FrameVM] loading FrameVM module from loader thread");
    let load_result = load_framevm_file(elf_data);
    clear_loader_frame_task_group();
    restore_current_thread_vm_space();
    if let Err(error) = load_result {
        rollback_failed_framevm_start();
        return Err(error);
    }
    Ok(())
}

fn framevm_boot_cmdline(vcpu_count: usize) -> Result<String> {
    let realtime_ns = duration_to_ns(
        SystemTime::now()
            .duration_since(&SystemTime::UNIX_EPOCH)
            .map_err(|_| Error::new(Errno::EINVAL))?,
    )?;
    let monotonic_ns = read_host_monotonic_ns()?;

    Ok(format!(
        "kernel.realtime_base_ns={realtime_ns} kernel.monotonic_base_ns={monotonic_ns} ostd.vcpu_count={vcpu_count}"
    ))
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

/// Read the FrameVM ELF file from the filesystem
fn read_framevm_elf() -> Result<Vec<u8>> {
    ostd::early_println!("[FrameVM] read elf: open");
    let framevm_file = open_framevm_artifact("/framevm/framevm.o")?;

    let file_size = framevm_file.path().inode().size();
    ostd::early_println!("[FrameVM] read elf: size={}", file_size);
    debug!("[FrameVM] framevm object size: {} bytes", file_size);

    let mut elf_data = vec![0u8; file_size];
    let read_len = framevm_file.read_bytes_at(0, &mut elf_data)?;
    if read_len != file_size {
        return Err(Error::with_message(
            Errno::EIO,
            "failed to read the complete FrameVM object file",
        ));
    }

    ostd::early_println!("[FrameVM] read elf: done");
    Ok(elf_data)
}

fn read_framevm_rootfs() -> Result<Vec<u8>> {
    ostd::early_println!("[FrameVM] read rootfs: open");
    let rootfs_file = open_framevm_artifact("/framevm/rootfs.cpio.gz")
        .or_else(|_| open_framevm_artifact("/framevm/rootfs.cpio"))?;

    let file_size = rootfs_file.path().inode().size();
    ostd::early_println!("[FrameVM] read rootfs: size={}", file_size);
    debug!("[FrameVM] framevm rootfs size: {} bytes", file_size);

    let mut rootfs_data = vec![0u8; file_size];
    let read_len = rootfs_file.read_bytes_at(0, &mut rootfs_data)?;
    if read_len != file_size {
        return Err(Error::with_message(
            Errno::EIO,
            "failed to read the complete FrameVM rootfs file",
        ));
    }

    ostd::early_println!("[FrameVM] read rootfs: decode");
    decode_framevm_rootfs(rootfs_data)
}

fn decode_framevm_rootfs(rootfs_data: Vec<u8>) -> Result<Vec<u8>> {
    if !matches!(rootfs_data.get(..2), Some([0x1F, 0x8B])) {
        return Ok(rootfs_data);
    }

    let mut gzip_decoder = GZipDecoder::new(rootfs_data.as_slice())
        .map_err(|_| Error::with_message(Errno::EINVAL, "invalid FrameVM gzip rootfs"))?;
    let mut decoded = Vec::new();
    gzip_decoder
        .read_to_end(&mut decoded)
        .map_err(|_| Error::with_message(Errno::EINVAL, "failed to decompress FrameVM rootfs"))?;
    Ok(decoded)
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

/// Load and run FrameVM from ELF data (blocks until FrameVM exits)
fn load_framevm_file(elf_data: &[u8]) -> Result<()> {
    ostd::early_println!("[FrameVM] loader: parse module");
    let service_module = ostd::loader::ServiceModuleInfo::load_service_module(elf_data)?;

    set_framevm_load_state(FrameVmLoadState::Running);

    // Invoke the entry point directly so startup stays on the loader thread;
    // FrameVM sets up its own runtime tasks during initialization.
    ostd::early_println!("[FrameVM] loader: enter service domain");
    if !boot::enter_current_service() {
        return Err(Error::with_message(
            Errno::EINVAL,
            "missing FrameVM service domain",
        ));
    }
    ostd::early_println!("[FrameVM] loader: call service");
    let run_result = service_module.start();
    ostd::early_println!("[FrameVM] loader: shutdown service domain");
    let did_shutdown = boot::shutdown_current_service();
    if did_shutdown {
        info!("[FrameVM] IHT tasks stopped");
    }
    run_result?;

    Ok(())
}
