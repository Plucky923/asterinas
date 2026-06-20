// SPDX-License-Identifier: MPL-2.0

//! File truncation syscalls.

use ostd::mm::VmSpace;

use super::{
    AT_FDCWD, EmptyPathStr, Errno, Error, ResourceType, Result, RootFs, current_fd_file,
    current_resource_limits, read_c_string, resolve_guest_path_at,
};

pub(super) fn sys_truncate(pathname_addr: usize, len: isize, vm_space: &VmSpace) -> Result<isize> {
    let len = checked_truncate_len(len)?;
    let raw_pathname = read_c_string(vm_space, pathname_addr)?;
    let pathname = resolve_guest_path_at(AT_FDCWD, &raw_pathname, EmptyPathStr::Reject)?;
    RootFs::get()?.truncate(&pathname, len)?;
    Ok(0)
}

pub(super) fn sys_ftruncate(fd: i32, len: isize) -> Result<isize> {
    let len = checked_truncate_len(len)?;
    let file = current_fd_file(fd)?.ok_or(Error::new(Errno::EBADF))?;
    file.truncate(len)?;
    Ok(0)
}

fn checked_truncate_len(len: isize) -> Result<usize> {
    let len = usize::try_from(len).map_err(|_| Error::new(Errno::EINVAL))?;
    let len_u64 = u64::try_from(len).map_err(|_| Error::new(Errno::EFBIG))?;
    let max_file_size = current_resource_limits()?
        .get_rlimit(ResourceType::FileSize)
        .get_cur();
    if len_u64 > max_file_size {
        return Err(Error::new(Errno::EFBIG));
    }
    Ok(len)
}
