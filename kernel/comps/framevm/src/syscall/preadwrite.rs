// SPDX-License-Identifier: MPL-2.0

//! Positioned file I/O syscalls.

use alloc::vec;

use ostd::mm::VmSpace;

use super::{
    Errno, Error, Result, current_fd_file, reactivate_current_vm_space, read_from_user_to_vec,
    write_to_user,
};

/// Reads from a file descriptor at a fixed offset.
pub(super) fn sys_pread64(
    fd: i32,
    user_buf_addr: usize,
    user_buf_len: usize,
    offset: i64,
    vm_space: &VmSpace,
) -> Result<isize> {
    check_nonnegative_offset(offset)?;
    let file = current_fd_file(fd)?.ok_or(Error::new(Errno::EBADF))?;
    let offset = checked_offset_from_user(offset, user_buf_len)?;

    let mut buf = vec![0u8; user_buf_len];
    let read_len = file.read_at(offset, &mut buf)?;
    reactivate_current_vm_space()?;
    write_to_user(vm_space, user_buf_addr, &buf[..read_len])?;
    Ok(read_len as isize)
}

/// Writes to a file descriptor at a fixed offset.
pub(super) fn sys_pwrite64(
    fd: i32,
    user_buf_addr: usize,
    user_buf_len: usize,
    offset: i64,
    vm_space: &VmSpace,
) -> Result<isize> {
    check_nonnegative_offset(offset)?;
    let file = current_fd_file(fd)?.ok_or(Error::new(Errno::EBADF))?;
    let offset = checked_offset_from_user(offset, user_buf_len)?;
    let buf = read_from_user_to_vec(vm_space, user_buf_addr, user_buf_len)?;

    let write_len = file.write_at(offset, &buf)?;
    Ok(write_len as isize)
}

fn check_nonnegative_offset(offset: i64) -> Result<()> {
    if offset < 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok(())
}

fn checked_offset_from_user(offset: i64, len: usize) -> Result<usize> {
    let len = i64::try_from(len).map_err(|_| Error::new(Errno::EINVAL))?;
    offset.checked_add(len).ok_or(Error::new(Errno::EINVAL))?;
    usize::try_from(offset).map_err(|_| Error::new(Errno::EINVAL))
}
