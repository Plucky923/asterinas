// SPDX-License-Identifier: MPL-2.0

use core::fmt::Display;

use ostd::task::Task;

use super::{console_file::FrameVmConsoleFile, ioctl_defs};
use crate::{
    events::IoEvents,
    fs::{
        file::{AccessMode, CreationFlags, FileLike, file_table::FdFlags},
        pseudofs::AnonInodeFs,
        vfs::path::Path,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
    util::ioctl::{RawIoctl, dispatch_ioctl},
    vmm::{
        FrameVmLifecycle, FrameVmLifecycleStatus, FrameVmRawImage, FrameVmStartRequest,
        FrameVmStopRequest, FrameVmTerminalReason,
    },
};

const FRAMEVM_DRIVE_SECTOR_SIZE: usize = 512;

struct VmInner {
    vcpu_count: usize,
    share: u32,
    drive_file: Option<FrameVmDriveFile>,
    cmdline_append: Option<String>,
    lifecycle: Arc<FrameVmLifecycle>,
}

#[derive(Clone)]
pub(super) struct FrameVmDriveFile {
    file: Arc<dyn FileLike>,
    readonly: bool,
    capacity_bytes: usize,
}

impl FrameVmDriveFile {
    pub(super) fn new(file: Arc<dyn FileLike>, readonly: bool) -> Result<Self> {
        if !file.path().metadata().type_.is_regular_file() {
            return_errno_with_message!(Errno::EINVAL, "FrameVM drive must be a regular file");
        }

        let access_mode = file.access_mode();
        if !access_mode.is_readable() || (!readonly && !access_mode.is_writable()) {
            return_errno_with_message!(
                Errno::EBADF,
                "FrameVM drive fd access mode does not match requested mode"
            );
        }
        let capacity_bytes = file.path().size();
        if capacity_bytes == 0 || !capacity_bytes.is_multiple_of(FRAMEVM_DRIVE_SECTOR_SIZE) {
            return_errno_with_message!(
                Errno::EINVAL,
                "FrameVM drive capacity must be nonzero and 512-byte aligned"
            );
        }

        Ok(Self {
            file,
            readonly,
            capacity_bytes,
        })
    }

    fn readonly(&self) -> bool {
        self.readonly
    }

    fn access_mode(&self) -> AccessMode {
        self.file.access_mode()
    }

    fn raw_image(&self) -> Arc<dyn aster_framevisor::device::BlockImage> {
        Arc::new(FrameVmRawImage::new(
            self.file.path().clone(),
            self.readonly,
            self.capacity_bytes as u64,
        ))
    }
}

pub(super) struct FrameVmFile {
    inner: Mutex<VmInner>,
    pseudo_path: Path,
}

impl FrameVmFile {
    pub(super) fn new(
        vcpu_count: usize,
        share: u32,
        drive_file: Option<FrameVmDriveFile>,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(VmInner {
                vcpu_count,
                share,
                drive_file,
                cmdline_append: None,
                lifecycle: FrameVmLifecycle::new(),
            }),
            pseudo_path: AnonInodeFs::new_path(|_| "anon_inode:[framevm-vm]".to_string()),
        })
    }

    fn try_lock_inner(&self) -> Result<MutexGuard<'_, VmInner>> {
        self.inner.try_lock().ok_or_else(|| {
            error!("[FrameVM] VM fd lifecycle lock is already held");
            Error::with_message(Errno::EBUSY, "a FrameVM lifecycle operation is in progress")
        })
    }

    fn start(&self) -> Result<i32> {
        let inner = self.try_lock_inner()?;
        match inner.lifecycle.status() {
            FrameVmLifecycleStatus::Created => {}
            FrameVmLifecycleStatus::Starting { .. } => {
                error!("[FrameVM] VM fd start rejected because lifecycle transition is active");
                return_errno_with_message!(Errno::EBUSY, "FrameVM lifecycle transition is active")
            }
            FrameVmLifecycleStatus::Running { .. } => {
                return_errno_with_message!(Errno::EALREADY, "FrameVM is running")
            }
            FrameVmLifecycleStatus::ExitedSuccess { .. }
            | FrameVmLifecycleStatus::ExitedFailure { .. }
            | FrameVmLifecycleStatus::RestartRequested { .. }
            | FrameVmLifecycleStatus::StoppedByHost { .. }
            | FrameVmLifecycleStatus::PanicFailure { .. }
            | FrameVmLifecycleStatus::Destroyed { .. } => {
                return_errno_with_message!(Errno::EINVAL, "FrameVM is already terminal")
            }
        }

        let Some(drive_file) = &inner.drive_file else {
            inner
                .lifecycle
                .record_terminal(FrameVmLifecycleStatus::PanicFailure {
                    vm_id: None,
                    reason: FrameVmTerminalReason::SetupFailed,
                    code: -1,
                    failure_class: crate::vmm::FrameVmFailureClass::Setup,
                });
            return_errno_with_message!(Errno::EINVAL, "FrameVM start requires a drive image");
        };

        let request = FrameVmStartRequest::new_with_drive_image(
            inner.vcpu_count,
            inner.share,
            drive_file.raw_image(),
        )?
        .with_cmdline_append(inner.cmdline_append.clone())
        .with_lifecycle(inner.lifecycle.clone());
        match crate::vmm::start_framevm(request) {
            Ok(()) => Ok(0),
            Err(error) => {
                error!("[FrameVM] VM fd start failed: {:?}", error);
                Err(error)
            }
        }
    }

    fn set_cmdline(&self, request: ioctl_defs::FrameVmCmdline) -> Result<i32> {
        let append = request.read_append()?;
        let mut inner = self.try_lock_inner()?;
        match inner.lifecycle.status() {
            FrameVmLifecycleStatus::Created => {}
            FrameVmLifecycleStatus::Starting { .. } => {
                return_errno_with_message!(Errno::EBUSY, "FrameVM lifecycle transition is active")
            }
            FrameVmLifecycleStatus::Running { .. } => {
                return_errno_with_message!(Errno::EBUSY, "FrameVM is already running")
            }
            FrameVmLifecycleStatus::ExitedSuccess { .. }
            | FrameVmLifecycleStatus::ExitedFailure { .. }
            | FrameVmLifecycleStatus::RestartRequested { .. }
            | FrameVmLifecycleStatus::StoppedByHost { .. }
            | FrameVmLifecycleStatus::PanicFailure { .. }
            | FrameVmLifecycleStatus::Destroyed { .. } => {
                return_errno_with_message!(Errno::EINVAL, "FrameVM is already terminal")
            }
        }

        inner.cmdline_append = append;
        Ok(0)
    }

    fn stop(&self) -> Result<i32> {
        let lifecycle = {
            let inner = self.try_lock_inner()?;
            match inner.lifecycle.status() {
                FrameVmLifecycleStatus::Created => {
                    inner
                        .lifecycle
                        .record_terminal(FrameVmLifecycleStatus::StoppedByHost {
                            vm_id: None,
                            reason: FrameVmTerminalReason::HostStop,
                        });
                    return Ok(0);
                }
                FrameVmLifecycleStatus::Running { .. } => inner.lifecycle.clone(),
                FrameVmLifecycleStatus::Starting { .. } => {
                    return_errno_with_message!(
                        Errno::EBUSY,
                        "FrameVM lifecycle transition is active"
                    )
                }
                FrameVmLifecycleStatus::ExitedSuccess { .. }
                | FrameVmLifecycleStatus::ExitedFailure { .. }
                | FrameVmLifecycleStatus::RestartRequested { .. }
                | FrameVmLifecycleStatus::StoppedByHost { .. }
                | FrameVmLifecycleStatus::PanicFailure { .. }
                | FrameVmLifecycleStatus::Destroyed { .. } => return Ok(0),
            }
        };

        crate::vmm::stop_framevm(FrameVmStopRequest::new());
        lifecycle.record_terminal(FrameVmLifecycleStatus::StoppedByHost {
            vm_id: None,
            reason: FrameVmTerminalReason::HostStop,
        });
        Ok(0)
    }

    fn status(&self) -> ioctl_defs::FrameVmStatus {
        let inner = self.inner.lock();
        inner.lifecycle.status().into()
    }

    fn get_console_fd(&self) -> Result<i32> {
        let inner = self.try_lock_inner()?;
        match inner.lifecycle.status() {
            FrameVmLifecycleStatus::Created | FrameVmLifecycleStatus::Running { .. } => {
                let current_task = Task::current().ok_or_else(|| {
                    Error::with_message(Errno::ESRCH, "FrameVM console fd requires a task")
                })?;
                let thread_local = current_task.as_thread_local().ok_or_else(|| {
                    Error::with_message(
                        Errno::EINVAL,
                        "FrameVM console fd requires a process-backed task",
                    )
                })?;

                let cursor = current_console_tail_offset()?;
                let console_file = FrameVmConsoleFile::new(cursor);
                let fd = {
                    let file_table = thread_local.borrow_file_table();
                    let file_table = file_table.as_ref().ok_or_else(|| {
                        Error::with_message(
                            Errno::EINVAL,
                            "FrameVM console fd requires a file table",
                        )
                    })?;
                    let mut file_table_locked = file_table.write();
                    file_table_locked.insert(console_file, FdFlags::empty())
                };
                Ok(fd.into())
            }
            FrameVmLifecycleStatus::Starting { .. } => {
                return_errno_with_message!(Errno::EBUSY, "FrameVM lifecycle transition is active")
            }
            FrameVmLifecycleStatus::ExitedSuccess { .. }
            | FrameVmLifecycleStatus::ExitedFailure { .. }
            | FrameVmLifecycleStatus::RestartRequested { .. }
            | FrameVmLifecycleStatus::StoppedByHost { .. }
            | FrameVmLifecycleStatus::PanicFailure { .. }
            | FrameVmLifecycleStatus::Destroyed { .. } => {
                return_errno_with_message!(Errno::EINVAL, "FrameVM is already terminal")
            }
        }
    }

    fn stop_on_close(&self) {
        let lifecycle = {
            let inner = self.inner.lock();
            match inner.lifecycle.status() {
                FrameVmLifecycleStatus::Created => {
                    inner
                        .lifecycle
                        .record_terminal(FrameVmLifecycleStatus::StoppedByHost {
                            vm_id: None,
                            reason: FrameVmTerminalReason::FdClose,
                        });
                    return;
                }
                FrameVmLifecycleStatus::Starting { .. }
                | FrameVmLifecycleStatus::Running { .. } => Some(inner.lifecycle.clone()),
                FrameVmLifecycleStatus::ExitedSuccess { .. }
                | FrameVmLifecycleStatus::ExitedFailure { .. }
                | FrameVmLifecycleStatus::RestartRequested { .. }
                | FrameVmLifecycleStatus::StoppedByHost { .. }
                | FrameVmLifecycleStatus::PanicFailure { .. }
                | FrameVmLifecycleStatus::Destroyed { .. } => None,
            }
        };

        if let Some(lifecycle) = lifecycle {
            crate::vmm::stop_framevm(FrameVmStopRequest::new());
            lifecycle.record_terminal(FrameVmLifecycleStatus::StoppedByHost {
                vm_id: None,
                reason: FrameVmTerminalReason::FdClose,
            });
        }
    }
}

fn current_console_tail_offset() -> Result<u64> {
    let framevms = aster_framevisor::list_framevms();
    match framevms.as_slice() {
        [] => Ok(0),
        [vm_id] => {
            let vm = aster_framevisor::get_framevm(*vm_id)
                .ok_or_else(|| Error::with_message(Errno::EINVAL, "FrameVM does not exist"))?;
            Ok(vm.devices().console().output_tail_offset())
        }
        _ => return_errno_with_message!(Errno::EBUSY, "multiple FrameVM consoles exist"),
    }
}

impl Drop for FrameVmFile {
    fn drop(&mut self) {
        self.stop_on_close();
    }
}

impl Pollable for FrameVmFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        let lifecycle = {
            let inner = self.inner.lock();
            inner.lifecycle.clone()
        };
        lifecycle.poll(mask, poller)
    }
}

impl FileLike for FrameVmFile {
    fn read(&self, _writer: &mut VmWriter) -> Result<usize> {
        return_errno_with_message!(Errno::EINVAL, "the FrameVM VM fd is not readable")
    }

    fn write(&self, _reader: &mut VmReader) -> Result<usize> {
        return_errno_with_message!(Errno::EINVAL, "the FrameVM VM fd is not writable")
    }

    fn ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        use ioctl_defs::*;

        dispatch_ioctl!(match raw_ioctl {
            StartVm => {
                return self.start();
            }
            StopVm => {
                return self.stop();
            }
            GetConsoleFd => {
                return self.get_console_fd();
            }
            cmd @ SetCmdline => {
                return self.set_cmdline(cmd.read()?);
            }
            cmd @ GetStatus => {
                cmd.write(&self.status())?;
                return Ok(0);
            }
            CreateVm => {
                return_errno_with_message!(
                    Errno::ENOTTY,
                    "the ioctl command is invalid for this fd"
                )
            }
            _ => return_errno_with_message!(Errno::ENOTTY, "the ioctl command is unknown"),
        })
    }

    fn access_mode(&self) -> AccessMode {
        AccessMode::O_RDWR
    }

    fn path(&self) -> &Path {
        &self.pseudo_path
    }

    fn dump_proc_fdinfo(self: Arc<Self>, fd_flags: FdFlags) -> Box<dyn Display> {
        struct FdInfo {
            inner: Arc<FrameVmFile>,
            fd_flags: FdFlags,
        }

        impl Display for FdInfo {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let inner = self.inner.inner.lock();
                let mut flags = self.inner.access_mode() as u32;
                if self.fd_flags.contains(FdFlags::CLOEXEC) {
                    flags |= CreationFlags::O_CLOEXEC.bits();
                }
                let lifecycle_status = inner.lifecycle.status();

                writeln!(formatter, "pos:\t{}", 0)?;
                writeln!(formatter, "flags:\t0{:o}", flags)?;
                writeln!(formatter, "state:\t{:?}", lifecycle_status.state())?;
                writeln!(
                    formatter,
                    "terminal_reason:\t{:?}",
                    lifecycle_status.terminal_reason()
                )?;
                writeln!(formatter, "vcpu_count:\t{}", inner.vcpu_count)?;
                writeln!(formatter, "share:\t{}", inner.share)?;
                match &inner.drive_file {
                    Some(drive_file) => writeln!(
                        formatter,
                        "drive:\t{},access={:?}",
                        if drive_file.readonly() {
                            "readonly"
                        } else {
                            "writable"
                        },
                        drive_file.access_mode()
                    ),
                    None => writeln!(formatter, "drive:\tnone"),
                }
            }
        }

        Box::new(FdInfo {
            inner: self,
            fd_flags,
        })
    }
}
