// SPDX-License-Identifier: MPL-2.0

use alloc::vec;

use ostd::mm::VmSpace;

use super::{Errno, Error, Result, current_fd_file, reactivate_current_vm_space, write_to_user};

/// Reads from a file descriptor.
pub(super) fn sys_read(
    fd: i32,
    user_buf_addr: usize,
    user_buf_len: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    if let Some(file) = current_fd_file(fd)? {
        if user_buf_len == 0 {
            if !file.access_mode().is_readable() {
                return Err(Error::new(Errno::EBADF));
            }
            return Ok(0);
        }

        let mut buf = vec![0u8; user_buf_len];
        let read_len = file.read(&mut buf)?;
        reactivate_current_vm_space()?;
        write_to_user(vm_space, user_buf_addr, &buf[..read_len])?;
        return Ok(read_len as isize);
    }

    Err(Error::new(Errno::EBADF))
}
