// SPDX-License-Identifier: MPL-2.0

//! File mode update syscalls.

use ostd::mm::VmSpace;

use super::{
    AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, EmptyPathStr, Errno, Error, Result, RootFs,
    current_fd_file, read_c_string, resolve_guest_path_at,
};

const VALID_FCHMODAT2_FLAGS: u32 = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW;

pub(super) fn sys_chmod(pathname_addr: usize, mode: usize, vm_space: &VmSpace) -> Result<isize> {
    sys_fchmodat2(AT_FDCWD, pathname_addr, mode, 0, vm_space)
}

pub(super) fn sys_fchmod(fd: i32, mode: usize) -> Result<isize> {
    let file = current_fd_file(fd)?.ok_or(Error::new(Errno::EBADF))?;
    let path = file.path().ok_or(Error::new(Errno::EINVAL))?;
    RootFs::get()?.chmod(&path, mode as u16, true)?;
    Ok(0)
}

pub(super) fn sys_fchmodat(
    dirfd: i32,
    pathname_addr: usize,
    mode: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    sys_fchmodat2(dirfd, pathname_addr, mode, 0, vm_space)
}

pub(super) fn sys_fchmodat2(
    dirfd: i32,
    pathname_addr: usize,
    mode: usize,
    flags: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let flags = u32::try_from(flags).map_err(|_| Error::new(Errno::EINVAL))?;
    if flags & !VALID_FCHMODAT2_FLAGS != 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    let raw_pathname = read_c_string(vm_space, pathname_addr)?;
    if raw_pathname.is_empty() && flags & AT_EMPTY_PATH != 0 {
        return sys_fchmod(dirfd, mode);
    }

    let pathname = resolve_guest_path_at(dirfd, &raw_pathname, EmptyPathStr::Reject)?;
    let follow_tail_link = flags & AT_SYMLINK_NOFOLLOW == 0;
    RootFs::get()?.chmod(&pathname, mode as u16, follow_tail_link)?;
    Ok(0)
}
