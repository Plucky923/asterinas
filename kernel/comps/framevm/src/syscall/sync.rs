// SPDX-License-Identifier: MPL-2.0

//! Global filesystem synchronization syscalls.

use super::{Errno, Error, Result, RootFs, current_fd_file};

pub(super) fn sys_sync() -> Result<isize> {
    RootFs::get()?.sync()?;
    Ok(0)
}

pub(super) fn sys_syncfs(fd: i32) -> Result<isize> {
    let file = current_fd_file(fd)?.ok_or(Error::new(Errno::EBADF))?;
    file.sync()?;
    Ok(0)
}
