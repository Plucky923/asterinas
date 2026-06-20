// SPDX-License-Identifier: MPL-2.0

//! Pipe creation syscalls.

use ostd::{mm::VmSpace, sync::SpinLock};

use super::{
    Errno, Error, FdFlags, O_CLOEXEC, Result, StatusFlags, current_fd_table, current_nofile_limit,
    write_to_user,
};
use crate::fd_table::{FileDesc, FileTable, RawFileDesc};

pub(super) fn sys_pipe(pipefd_addr: usize, vm_space: &VmSpace) -> Result<isize> {
    create_pipe_to_user(vm_space, pipefd_addr, 0)
}

pub(super) fn sys_pipe2(pipefd_addr: usize, flags: usize, vm_space: &VmSpace) -> Result<isize> {
    create_pipe_to_user(vm_space, pipefd_addr, flags)
}

fn create_pipe_to_user(vm_space: &VmSpace, pipefd_addr: usize, flags: usize) -> Result<isize> {
    let flags = u32::try_from(flags).map_err(|_| Error::new(Errno::EINVAL))?;
    let allowed_flags = O_CLOEXEC | StatusFlags::O_NONBLOCK.bits() | StatusFlags::O_DIRECT.bits();
    if flags & !allowed_flags != 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    if flags & StatusFlags::O_DIRECT.bits() != 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    let fd_flags = if flags & O_CLOEXEC != 0 {
        FdFlags::CLOEXEC
    } else {
        FdFlags::empty()
    };
    let status_flags = StatusFlags::from_bits_truncate(flags);
    let fd_table = current_fd_table()?;
    let nofile_limit = current_nofile_limit()?;
    let (read_fd, write_fd) = fd_table
        .lock()
        .alloc_pipe(status_flags, fd_flags, nofile_limit)?;
    let mut pipe_fds = [0u8; 8];
    pipe_fds[..4].copy_from_slice(&read_fd.to_ne_bytes());
    pipe_fds[4..].copy_from_slice(&write_fd.to_ne_bytes());
    if let Err(error) = write_to_user(vm_space, pipefd_addr, &pipe_fds) {
        close_allocated_pipe_fds(&fd_table, read_fd, write_fd);
        return Err(error);
    }
    Ok(0)
}

fn close_allocated_pipe_fds(
    fd_table: &SpinLock<FileTable>,
    read_fd: RawFileDesc,
    write_fd: RawFileDesc,
) {
    let (read_file, write_file) = {
        let mut fd_table = fd_table.lock();
        let read_file = FileDesc::try_from(read_fd)
            .ok()
            .and_then(|read_fd| fd_table.close_file(read_fd));
        let write_file = FileDesc::try_from(write_fd)
            .ok()
            .and_then(|write_fd| fd_table.close_file(write_fd));
        (read_file, write_file)
    };
    drop(read_file);
    drop(write_file);
}
