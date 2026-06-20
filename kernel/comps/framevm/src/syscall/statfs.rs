// SPDX-License-Identifier: MPL-2.0

//! Filesystem-stat syscalls.

use ostd::mm::VmSpace;

use super::{
    Result, RootFs, metadata_for_path, metadata_from_fd, read_c_string, resolve_guest_path,
    write_to_user,
};
use crate::rootfs::RootFsStat;

const STATFS_SIZE: usize = 120;

/// Gets filesystem statistics by path.
pub(super) fn sys_statfs(
    pathname_addr: usize,
    statfs_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let pathname = resolve_guest_path(&read_c_string(vm_space, pathname_addr)?)?;
    let _ = metadata_for_path(&pathname, true)?;
    write_rootfs_statfs(vm_space, statfs_addr, RootFs::get()?.statfs())
}

/// Gets filesystem statistics by file descriptor.
pub(super) fn sys_fstatfs(fd: i32, statfs_addr: usize, vm_space: &VmSpace) -> Result<isize> {
    let _ = metadata_from_fd(fd)?;
    write_rootfs_statfs(vm_space, statfs_addr, RootFs::get()?.statfs())
}

fn write_rootfs_statfs(vm_space: &VmSpace, statfs_addr: usize, stat: RootFsStat) -> Result<isize> {
    let mut statfs = [0u8; STATFS_SIZE];
    write_u64_ne(&mut statfs, 0, stat.magic);
    write_u64_ne(&mut statfs, 8, stat.block_size);
    write_u64_ne(&mut statfs, 16, stat.blocks);
    write_u64_ne(&mut statfs, 24, stat.free_blocks);
    write_u64_ne(&mut statfs, 32, stat.available_blocks);
    write_u64_ne(&mut statfs, 40, stat.files);
    write_u64_ne(&mut statfs, 48, stat.free_files);
    write_u64_ne(&mut statfs, 56, stat.fsid);
    write_u64_ne(&mut statfs, 64, stat.name_max);
    write_u64_ne(&mut statfs, 72, stat.fragment_size);
    write_u64_ne(&mut statfs, 80, stat.flags);
    write_to_user(vm_space, statfs_addr, &statfs)?;
    Ok(0)
}

fn write_u64_ne(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}
