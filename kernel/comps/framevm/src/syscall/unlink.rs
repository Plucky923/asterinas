// SPDX-License-Identifier: MPL-2.0

//! Directory entry unlink syscalls.

use ostd::mm::VmSpace;

use super::{
    AT_FDCWD, EmptyPathStr, Errno, Error, Result, RootFs, read_c_string, resolve_guest_path_at,
    rmdir::sys_rmdirat,
};

const AT_REMOVEDIR: u32 = 0x200;

pub(super) fn sys_unlink(pathname_addr: usize, vm_space: &VmSpace) -> Result<isize> {
    sys_unlinkat(AT_FDCWD, pathname_addr, 0, vm_space)
}

pub(super) fn sys_unlinkat(
    dirfd: i32,
    pathname_addr: usize,
    flags: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let flags = u32::try_from(flags).map_err(|_| Error::new(Errno::EINVAL))?;
    if flags & !AT_REMOVEDIR != 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    if flags & AT_REMOVEDIR != 0 {
        return sys_rmdirat(dirfd, pathname_addr, vm_space);
    }

    let pathname = read_c_string(vm_space, pathname_addr)?;
    let path = resolve_guest_path_at(dirfd, &pathname, EmptyPathStr::Reject)?;
    RootFs::get()?.unlink(&path)?;
    Ok(0)
}
