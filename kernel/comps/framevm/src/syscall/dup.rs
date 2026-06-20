// SPDX-License-Identifier: MPL-2.0

//! File-descriptor duplication syscalls.

use super::{
    Errno, Error, FdFlags, O_CLOEXEC, RawFileDesc, Result, current_fd_table, current_nofile_limit,
};
use crate::fd_table::FileDesc;

pub(super) fn sys_dup(old_fd_raw: RawFileDesc) -> Result<isize> {
    let old_fd = FileDesc::try_from(old_fd_raw)?;
    let nofile_limit = current_nofile_limit()?;
    let fd_table = current_fd_table()?;
    Ok(fd_table
        .lock()
        .dup_ceil(old_fd, FileDesc::ZERO, FdFlags::empty(), nofile_limit)?
        .into())
}

pub(super) fn sys_dup2(old_fd_raw: RawFileDesc, new_fd_raw: RawFileDesc) -> Result<isize> {
    let old_fd = FileDesc::try_from(old_fd_raw)?;
    let new_fd = FileDesc::try_from(new_fd_raw)?;
    if old_fd == new_fd {
        let fd_table = current_fd_table()?;
        fd_table.lock().get_file(old_fd)?;
        return Ok(new_fd.into());
    }

    let fd_table = current_fd_table()?;
    let nofile_limit = current_nofile_limit()?;
    if !new_fd.is_below_nofile_limit(nofile_limit) {
        return Err(Error::new(Errno::EBADF));
    }
    let _replaced_handle = fd_table
        .lock()
        .dup_exact(old_fd, new_fd, FdFlags::empty())?;
    Ok(new_fd.into())
}

pub(super) fn sys_dup3(
    old_fd_raw: RawFileDesc,
    new_fd_raw: RawFileDesc,
    flags_raw: usize,
) -> Result<isize> {
    let old_fd = FileDesc::try_from(old_fd_raw)?;
    let new_fd = FileDesc::try_from(new_fd_raw)?;
    let flags = match flags_raw {
        0 => FdFlags::empty(),
        flag if flag == O_CLOEXEC as usize => FdFlags::CLOEXEC,
        _ => return Err(Error::new(Errno::EINVAL)),
    };
    if old_fd == new_fd {
        return Err(Error::new(Errno::EINVAL));
    }

    let fd_table = current_fd_table()?;
    let nofile_limit = current_nofile_limit()?;
    if !new_fd.is_below_nofile_limit(nofile_limit) {
        return Err(Error::new(Errno::EBADF));
    }
    let _replaced_handle = fd_table.lock().dup_exact(old_fd, new_fd, flags)?;
    Ok(new_fd.into())
}
