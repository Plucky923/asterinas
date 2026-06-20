// SPDX-License-Identifier: MPL-2.0

//! File offset syscall.

use super::{Result, current_fd_table};

pub(super) fn sys_lseek(fd: i32, offset: isize, whence: i32) -> Result<isize> {
    let fd_table = current_fd_table()?;
    let file = fd_table.lock().get(fd)?;
    Ok(file.seek(offset, whence)? as isize)
}
