// SPDX-License-Identifier: MPL-2.0

//! Directory removal syscalls.

use ostd::mm::VmSpace;

use super::{AT_FDCWD, EmptyPathStr, Result, RootFs, read_c_string, resolve_guest_path_at};

pub(super) fn sys_rmdir(pathname_addr: usize, vm_space: &VmSpace) -> Result<isize> {
    sys_rmdirat(AT_FDCWD, pathname_addr, vm_space)
}

pub(super) fn sys_rmdirat(dirfd: i32, pathname_addr: usize, vm_space: &VmSpace) -> Result<isize> {
    let pathname = read_c_string(vm_space, pathname_addr)?;
    let path = resolve_guest_path_at(dirfd, &pathname, EmptyPathStr::Reject)?;
    RootFs::get()?.rmdir(&path)?;
    Ok(0)
}
