// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmSpace;

use super::{
    AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, EmptyPathStr, Errno, Error, FileMetadata, Result,
    metadata_for_path, metadata_from_fd, read_c_string, resolve_guest_path_at,
};

/// Checks path permissions.
pub(super) fn sys_access(pathname_addr: usize, mode: u16, vm_space: &VmSpace) -> Result<isize> {
    do_faccessat(AT_FDCWD, pathname_addr, mode, 0, vm_space)
}

/// Checks permissions relative to `dirfd`.
pub(super) fn sys_faccessat(
    dirfd: i32,
    pathname_addr: usize,
    mode: u16,
    vm_space: &VmSpace,
) -> Result<isize> {
    do_faccessat(dirfd, pathname_addr, mode, 0, vm_space)
}

/// Checks permissions relative to `dirfd` with Linux `faccessat2` flags.
pub(super) fn sys_faccessat2(
    dirfd: i32,
    pathname_addr: usize,
    mode: u16,
    flags: u32,
    vm_space: &VmSpace,
) -> Result<isize> {
    do_faccessat(dirfd, pathname_addr, mode, flags, vm_space)
}

fn do_faccessat(
    dirfd: i32,
    pathname_addr: usize,
    mode: u16,
    flags: u32,
    vm_space: &VmSpace,
) -> Result<isize> {
    validate_access_mode(mode)?;
    validate_access_flags(flags)?;

    let raw_pathname = read_c_string(vm_space, pathname_addr)?;
    let metadata = if raw_pathname.is_empty() && flags & AT_EMPTY_PATH != 0 {
        metadata_from_fd(dirfd)?
    } else {
        let pathname =
            resolve_guest_path_at(dirfd, &raw_pathname, EmptyPathStr::AllowIfFlag(flags))?;
        let follow_tail_link = flags & AT_SYMLINK_NOFOLLOW == 0;
        metadata_for_path(&pathname, follow_tail_link)?
    };

    check_access_mode(&metadata, mode)?;
    Ok(0)
}

fn validate_access_flags(flags: u32) -> Result<()> {
    const AT_EACCESS: u32 = 0x200;
    const VALID_FLAGS: u32 = AT_EMPTY_PATH | AT_EACCESS | AT_SYMLINK_NOFOLLOW;
    if flags & !VALID_FLAGS != 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok(())
}

fn validate_access_mode(mode: u16) -> Result<()> {
    const R_OK: u16 = 0x4;
    const W_OK: u16 = 0x2;
    const X_OK: u16 = 0x1;
    if mode & !(R_OK | W_OK | X_OK) != 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok(())
}

fn check_access_mode(metadata: &FileMetadata, mode: u16) -> Result<()> {
    const R_OK: u16 = 0x4;
    const W_OK: u16 = 0x2;
    const X_OK: u16 = 0x1;

    if mode == 0 {
        return Ok(());
    }

    if mode & R_OK != 0 && metadata.mode & 0o444 == 0 {
        return Err(Error::new(Errno::EACCES));
    }
    if mode & W_OK != 0 && metadata.mode & 0o222 == 0 {
        return Err(Error::new(Errno::EACCES));
    }
    if mode & X_OK != 0 && metadata.mode & 0o111 == 0 {
        return Err(Error::new(Errno::EACCES));
    }
    Ok(())
}
