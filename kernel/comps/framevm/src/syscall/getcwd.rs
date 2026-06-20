// SPDX-License-Identifier: MPL-2.0

//! Current working directory syscall.

use ostd::mm::VmSpace;

use super::{Result, current_working_directory, write_to_user};

pub(super) fn sys_getcwd(buf_addr: usize, size: usize, vm_space: &VmSpace) -> Result<isize> {
    let cwd = current_working_directory()?;
    let mut bytes = cwd.into_bytes();
    bytes.push(0);
    let write_len = size.min(bytes.len());
    write_to_user(vm_space, buf_addr, &bytes[..write_len])?;
    Ok(write_len as isize)
}
