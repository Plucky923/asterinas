// SPDX-License-Identifier: MPL-2.0

use ostd::task::Task;

use super::{
    ioctl_defs,
    vm_file::{FrameVmDriveFile, FrameVmFile},
};
use crate::{
    events::IoEvents,
    fs::{
        file::{PerOpenFileOps, StatusFlags, file_table::FdFlags},
        vfs::inode::FileOps,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
    util::ioctl::{RawIoctl, dispatch_ioctl},
};

pub(super) struct FrameVmControllerFile;

impl FrameVmControllerFile {
    fn insert_vm_file(request: ioctl_defs::FrameVmCreateVm) -> Result<i32> {
        let current_task = Task::current()
            .ok_or_else(|| Error::with_message(Errno::ESRCH, "FrameVM create requires a task"))?;
        let thread_local = current_task.as_thread_local().ok_or_else(|| {
            Error::with_message(
                Errno::EINVAL,
                "FrameVM create requires a process-backed task",
            )
        })?;

        let fd = {
            let file_table = thread_local.borrow_file_table();
            let file_table = file_table.as_ref().ok_or_else(|| {
                Error::with_message(Errno::EINVAL, "FrameVM create requires a file table")
            })?;
            let mut file_table_locked = file_table.write();
            let drive_file = match request.drive_fd()? {
                Some(drive_fd) => Some(FrameVmDriveFile::new(
                    file_table_locked.get_file(drive_fd)?.clone(),
                    request.drive_readonly(),
                )?),
                None => None,
            };
            let vm_file = FrameVmFile::new(request.vcpu_count(), request.share(), drive_file);
            file_table_locked.insert(vm_file, FdFlags::empty())
        };
        Ok(fd.into())
    }
}

impl Pollable for FrameVmControllerFile {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        IoEvents::empty() & mask
    }
}

impl FileOps for FrameVmControllerFile {
    fn read_at(
        &self,
        _offset: usize,
        _writer: &mut VmWriter,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        return_errno_with_message!(Errno::EINVAL, "the FrameVM controller is not readable")
    }

    fn write_at(
        &self,
        _offset: usize,
        _reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        return_errno_with_message!(Errno::EINVAL, "the FrameVM controller is not writable")
    }
}

impl PerOpenFileOps for FrameVmControllerFile {
    fn check_seekable(&self) -> Result<()> {
        return_errno_with_message!(Errno::ESPIPE, "seek is not supported")
    }

    fn is_offset_aware(&self) -> bool {
        false
    }

    fn ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        use ioctl_defs::*;

        dispatch_ioctl!(match raw_ioctl {
            cmd @ CreateVm => {
                let request = cmd.read()?;
                request.validate()?;
                return Self::insert_vm_file(request);
            }
            StartVm | StopVm | GetConsoleFd | GetStatus => {
                return_errno_with_message!(
                    Errno::ENOTTY,
                    "the ioctl command is invalid for this fd"
                )
            }
            _ => return_errno_with_message!(Errno::ENOTTY, "the ioctl command is unknown"),
        })
    }
}
