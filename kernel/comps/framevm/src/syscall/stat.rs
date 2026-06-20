// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmSpace;

use super::{
    AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW, EmptyPathStr, FileKind, FileMetadata, Result,
    metadata_for_path, metadata_from_fd, read_c_string, resolve_guest_path, resolve_guest_path_at,
    validate_stat_flags, write_to_user,
};

/// Gets file status by path.
pub(super) fn sys_stat(
    pathname_addr: usize,
    stat_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let pathname = resolve_guest_path(&read_c_string(vm_space, pathname_addr)?)?;
    let metadata = metadata_for_path(&pathname, true)?;
    write_stat(vm_space, stat_addr, &metadata)
}

/// Gets file status by path without following the final link.
pub(super) fn sys_lstat(
    pathname_addr: usize,
    stat_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let pathname = resolve_guest_path(&read_c_string(vm_space, pathname_addr)?)?;
    let metadata = metadata_for_path(&pathname, false)?;
    write_stat(vm_space, stat_addr, &metadata)
}

/// Gets file status by file descriptor.
pub(super) fn sys_fstat(fd: i32, stat_addr: usize, vm_space: &VmSpace) -> Result<isize> {
    let metadata = metadata_from_fd(fd)?;
    write_stat(vm_space, stat_addr, &metadata)
}

/// Gets file status relative to `dirfd`.
pub(super) fn sys_newfstatat(
    dirfd: i32,
    pathname_addr: usize,
    stat_addr: usize,
    flags: u32,
    vm_space: &VmSpace,
) -> Result<isize> {
    let flags = validate_stat_flags(flags)?;
    let raw_pathname = read_c_string(vm_space, pathname_addr)?;
    if raw_pathname.is_empty() && flags & AT_EMPTY_PATH != 0 {
        let metadata = metadata_from_fd(dirfd)?;
        return write_stat(vm_space, stat_addr, &metadata);
    }

    let pathname = resolve_guest_path_at(dirfd, &raw_pathname, EmptyPathStr::AllowIfFlag(flags))?;
    let follow_tail_link = flags & AT_SYMLINK_NOFOLLOW == 0;
    let metadata = metadata_for_path(&pathname, follow_tail_link)?;
    write_stat(vm_space, stat_addr, &metadata)
}

fn write_stat(vm_space: &VmSpace, stat_addr: usize, metadata: &FileMetadata) -> Result<isize> {
    const STAT_SIZE: usize = 144;
    const S_IFREG: u32 = 0o100000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFLNK: u32 = 0o120000;
    const S_IFCHR: u32 = 0o020000;

    let file_type = match metadata.kind {
        FileKind::File => S_IFREG,
        FileKind::Directory => S_IFDIR,
        FileKind::Symlink => S_IFLNK,
        FileKind::Special => S_IFCHR,
    };
    let mode = file_type | u32::from(metadata.mode & 0o7777);

    let mut stat = [0u8; STAT_SIZE];
    write_u64_ne(&mut stat, 8, 1);
    write_u64_ne(&mut stat, 16, u64::from(metadata.nlink));
    write_u32_ne(&mut stat, 24, mode);
    write_u64_ne(&mut stat, 48, metadata.size as u64);
    write_u64_ne(&mut stat, 56, 4096);
    write_u64_ne(&mut stat, 64, metadata.size.div_ceil(512) as u64);
    write_to_user(vm_space, stat_addr, &stat)?;
    Ok(0)
}

fn write_u64_ne(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}

fn write_u32_ne(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}
