// SPDX-License-Identifier: MPL-2.0

//! Directory entry rename syscalls.

use ostd::mm::VmSpace;

use super::{
    AT_FDCWD, EmptyPathStr, Errno, Error, FileKind, Result, RootFs, read_c_string,
    resolve_guest_path_at,
};

const RENAME_NOREPLACE: u32 = 1 << 0;
const RENAME_EXCHANGE: u32 = 1 << 1;
const RENAME_WHITEOUT: u32 = 1 << 2;
const VALID_RENAME_FLAGS: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT;

pub(super) fn sys_rename(
    old_pathname_addr: usize,
    new_pathname_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    sys_renameat2(
        AT_FDCWD,
        old_pathname_addr,
        AT_FDCWD,
        new_pathname_addr,
        0,
        vm_space,
    )
}

pub(super) fn sys_renameat(
    old_dirfd: i32,
    old_pathname_addr: usize,
    new_dirfd: i32,
    new_pathname_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    sys_renameat2(
        old_dirfd,
        old_pathname_addr,
        new_dirfd,
        new_pathname_addr,
        0,
        vm_space,
    )
}

pub(super) fn sys_renameat2(
    old_dirfd: i32,
    old_pathname_addr: usize,
    new_dirfd: i32,
    new_pathname_addr: usize,
    flags: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let flags = u32::try_from(flags).map_err(|_| Error::new(Errno::EINVAL))?;
    if flags & !VALID_RENAME_FLAGS != 0 || flags != 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    let old_raw_pathname = read_c_string(vm_space, old_pathname_addr)?;
    let new_raw_pathname = read_c_string(vm_space, new_pathname_addr)?;
    let old_path = resolve_guest_path_at(old_dirfd, &old_raw_pathname, EmptyPathStr::Reject)?;
    let new_path = resolve_guest_path_at(new_dirfd, &new_raw_pathname, EmptyPathStr::Reject)?;

    let rootfs = RootFs::get()?;
    let old_metadata = rootfs.metadata_no_follow(&old_path)?;
    if old_metadata.kind != FileKind::Directory && old_raw_pathname.ends_with('/') {
        return Err(Error::new(Errno::ENOTDIR));
    }
    if old_metadata.kind != FileKind::Directory && new_raw_pathname.ends_with('/') {
        return Err(Error::new(Errno::EISDIR));
    }

    rootfs.rename(&old_path, &new_path)?;
    Ok(0)
}
