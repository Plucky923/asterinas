// SPDX-License-Identifier: MPL-2.0

//! Current working directory update syscalls.

use ostd::mm::VmSpace;

use super::{Result, RootFs, directory_path_from_fd, read_c_string, with_current_fs_info};

pub(super) fn sys_chdir(pathname_addr: usize, vm_space: &VmSpace) -> Result<isize> {
    let pathname = read_c_string(vm_space, pathname_addr)?;
    let rootfs = RootFs::get()?;
    with_current_fs_info(|fs| fs.chdir(rootfs.as_ref(), &pathname))?;
    Ok(0)
}

pub(super) fn sys_fchdir(fd: i32) -> Result<isize> {
    let pathname = directory_path_from_fd(fd)?;
    let rootfs = RootFs::get()?;
    with_current_fs_info(|fs| fs.chdir(rootfs.as_ref(), &pathname))?;
    Ok(0)
}
