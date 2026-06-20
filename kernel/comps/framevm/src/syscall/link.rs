// SPDX-License-Identifier: MPL-2.0

//! Hard-link creation syscalls.

use ostd::mm::VmSpace;

use super::{
    AT_FDCWD, EmptyPathStr, Errno, Error, Result, RootFs, read_c_string, resolve_guest_path_at,
};

const AT_EMPTY_PATH: u32 = 0x1000;
const AT_SYMLINK_FOLLOW: u32 = 0x400;
const VALID_LINK_FLAGS: u32 = AT_EMPTY_PATH | AT_SYMLINK_FOLLOW;

pub(super) fn sys_link(
    old_pathname_addr: usize,
    new_pathname_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    sys_linkat(
        AT_FDCWD,
        old_pathname_addr,
        AT_FDCWD,
        new_pathname_addr,
        0,
        vm_space,
    )
}

pub(super) fn sys_linkat(
    old_dirfd: i32,
    old_pathname_addr: usize,
    new_dirfd: i32,
    new_pathname_addr: usize,
    flags: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let flags = u32::try_from(flags).map_err(|_| Error::new(Errno::EINVAL))?;
    if flags & !VALID_LINK_FLAGS != 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    let old_raw_pathname = read_c_string(vm_space, old_pathname_addr)?;
    let new_raw_pathname = read_c_string(vm_space, new_pathname_addr)?;
    let old_empty_path_policy = EmptyPathStr::AllowIfFlag(flags & AT_EMPTY_PATH);
    let old_path = resolve_guest_path_at(old_dirfd, &old_raw_pathname, old_empty_path_policy)?;
    let new_path = resolve_guest_path_at(new_dirfd, &new_raw_pathname, EmptyPathStr::Reject)?;
    let follow_old_tail_link = flags & AT_SYMLINK_FOLLOW != 0;
    RootFs::get()?.link(&old_path, &new_path, follow_old_tail_link)?;
    Ok(0)
}
