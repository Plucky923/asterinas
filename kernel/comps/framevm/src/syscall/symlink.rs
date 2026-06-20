// SPDX-License-Identifier: MPL-2.0

//! Symbolic-link creation syscalls.

use ostd::mm::VmSpace;

use super::{
    AT_FDCWD, EmptyPathStr, Errno, Error, Result, RootFs, read_c_string, resolve_guest_path_at,
};

pub(super) fn sys_symlink(
    target_addr: usize,
    linkpath_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    sys_symlinkat(target_addr, AT_FDCWD, linkpath_addr, vm_space)
}

pub(super) fn sys_symlinkat(
    target_addr: usize,
    dirfd: i32,
    linkpath_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let target = read_c_string(vm_space, target_addr)?;
    if target.is_empty() {
        return Err(Error::new(Errno::ENOENT));
    }

    let linkpath = read_c_string(vm_space, linkpath_addr)?;
    let linkpath = resolve_guest_path_at(dirfd, &linkpath, EmptyPathStr::Reject)?;
    RootFs::get()?.symlink(&target, &linkpath)?;
    Ok(0)
}
