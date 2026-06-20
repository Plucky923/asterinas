// SPDX-License-Identifier: MPL-2.0

//! Directory creation syscalls.

use ostd::mm::VmSpace;

use super::{
    AT_FDCWD, EmptyPathStr, Result, RootFs, read_c_string, resolve_guest_path_at,
    with_current_fs_info,
};

pub(super) fn sys_mkdir(pathname_addr: usize, mode: usize, vm_space: &VmSpace) -> Result<isize> {
    sys_mkdirat(AT_FDCWD, pathname_addr, mode, vm_space)
}

pub(super) fn sys_mkdirat(
    dirfd: i32,
    pathname_addr: usize,
    mode: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let pathname = read_c_string(vm_space, pathname_addr)?;
    let path = resolve_guest_path_at(dirfd, &pathname, EmptyPathStr::Reject)?;
    let umask = with_current_fs_info(|fs| Ok(fs.umask().get()))?;
    RootFs::get()?.mkdir(&path, ((mode as u16) & 0o7777) & !umask)?;
    Ok(0)
}
