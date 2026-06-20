// SPDX-License-Identifier: MPL-2.0

//! File synchronization syscalls.

use super::{Errno, Error, Result, current_fd_file};

pub(super) fn sys_fsync(fd: i32) -> Result<isize> {
    let file = current_fd_file(fd)?.ok_or(Error::new(Errno::EBADF))?;
    file.sync()?;
    Ok(0)
}

pub(super) fn sys_fdatasync(fd: i32) -> Result<isize> {
    let file = current_fd_file(fd)?.ok_or(Error::new(Errno::EBADF))?;
    file.sync_data()?;
    Ok(0)
}
