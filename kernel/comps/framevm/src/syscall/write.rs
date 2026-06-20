// SPDX-License-Identifier: MPL-2.0

use alloc::vec::Vec;

use ostd::mm::VmSpace;

use super::{Errno, Error, Result, current_fd_file, read_from_user_to_vec, read_usize_from_user};

const IOV_MAX: usize = 1024;
const IOV_ENTRY_SIZE: usize = size_of::<usize>() * 2;
const IOV_LEN_OFFSET: usize = size_of::<usize>();

/// Writes to a file descriptor.
pub(super) fn sys_write(
    fd: i32,
    user_buf_addr: usize,
    user_buf_len: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    if let Some(file) = current_fd_file(fd)? {
        if user_buf_len == 0 {
            return Ok(file.write(&[])? as isize);
        }
        let buf = read_from_user_to_vec(vm_space, user_buf_addr, user_buf_len)?;
        return Ok(file.write(&buf)? as isize);
    }

    Err(Error::new(Errno::EBADF))
}

/// Writes multiple buffers to a file descriptor.
pub(super) fn sys_writev(
    fd: i32,
    iov_addr: usize,
    iovcnt: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let file = current_fd_file(fd)?.ok_or(Error::new(Errno::EBADF))?;
    if iovcnt > IOV_MAX {
        return Err(Error::new(Errno::EINVAL));
    }

    let buffers = read_iovec_buffers(iov_addr, iovcnt, vm_space)?;
    let mut total = 0usize;

    for buffer in buffers {
        match file.write(&buffer) {
            Ok(write_len) => {
                total = total
                    .checked_add(write_len)
                    .ok_or(Error::new(Errno::EINVAL))?;
                if write_len < buffer.len() {
                    break;
                }
            }
            Err(_) if total > 0 => break,
            Err(error) => return Err(error),
        }
    }

    Ok(total as isize)
}

fn read_iovec_buffers(iov_addr: usize, iovcnt: usize, vm_space: &VmSpace) -> Result<Vec<Vec<u8>>> {
    let mut total_len = 0usize;
    let mut buffers = Vec::new();

    for idx in 0..iovcnt {
        let entry_offset = idx
            .checked_mul(IOV_ENTRY_SIZE)
            .ok_or(Error::new(Errno::EFAULT))?;
        let entry_addr = iov_addr
            .checked_add(entry_offset)
            .ok_or(Error::new(Errno::EFAULT))?;
        let base = read_usize_from_user(vm_space, entry_addr)?;
        let len_addr = entry_addr
            .checked_add(IOV_LEN_OFFSET)
            .ok_or(Error::new(Errno::EFAULT))?;
        let len = read_usize_from_user(vm_space, len_addr)?;
        total_len = total_len
            .checked_add(len)
            .ok_or(Error::new(Errno::EINVAL))?;
        if total_len > isize::MAX as usize {
            return Err(Error::new(Errno::EINVAL));
        }
        if len == 0 {
            continue;
        }
        buffers.push(read_from_user_to_vec(vm_space, base, len)?);
    }

    Ok(buffers)
}
