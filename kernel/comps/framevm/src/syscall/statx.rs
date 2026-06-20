// SPDX-License-Identifier: MPL-2.0

//! `statx(2)` support backed by kernel rootfs metadata.

use ostd::mm::VmSpace;

use super::{
    AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_SYMLINK_NOFOLLOW, EmptyPathStr, Errno, Error, FileKind,
    FileMetadata, Result, metadata_for_path, metadata_from_fd, read_c_string,
    resolve_guest_path_at, write_to_user,
};

const STATX_SIZE: usize = 256;
const STATX_BASIC_STATS: u32 = 0x0000_07ff;
const STATX_BTIME: u32 = 0x0000_0800;
const STATX_MNT_ID: u32 = 0x0000_1000;
const STATX_RESERVED: u32 = 0x8000_0000;
const STATX_ATTR_MOUNT_ROOT: u64 = 0x0000_2000;

const AT_STATX_FORCE_SYNC: u32 = 1 << 13;
const AT_STATX_DONT_SYNC: u32 = 1 << 14;
const VALID_STATX_FLAGS: u32 = AT_EMPTY_PATH
    | AT_NO_AUTOMOUNT
    | AT_SYMLINK_NOFOLLOW
    | AT_STATX_FORCE_SYNC
    | AT_STATX_DONT_SYNC;

/// Gets extended file status relative to `dirfd`.
pub(super) fn sys_statx(
    dirfd: i32,
    pathname_addr: usize,
    flags: u32,
    mask: u32,
    statx_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    validate_statx_args(flags, mask)?;

    let raw_pathname = read_c_string(vm_space, pathname_addr)?;
    let metadata = if raw_pathname.is_empty() && flags & AT_EMPTY_PATH != 0 {
        metadata_from_fd(dirfd)?
    } else {
        let pathname = resolve_guest_path_at(
            dirfd,
            &raw_pathname,
            EmptyPathStr::AllowIfFlag(flags & AT_EMPTY_PATH),
        )?;
        let follow_tail_link = flags & AT_SYMLINK_NOFOLLOW == 0;
        metadata_for_path(&pathname, follow_tail_link)?
    };

    write_statx(vm_space, statx_addr, &metadata)
}

fn validate_statx_args(flags: u32, mask: u32) -> Result<()> {
    if flags & !VALID_STATX_FLAGS != 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    if flags & AT_STATX_FORCE_SYNC != 0 && flags & AT_STATX_DONT_SYNC != 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    if mask & STATX_RESERVED != 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok(())
}

fn write_statx(vm_space: &VmSpace, statx_addr: usize, metadata: &FileMetadata) -> Result<isize> {
    const S_IFREG: u16 = 0o100000;
    const S_IFDIR: u16 = 0o040000;
    const S_IFLNK: u16 = 0o120000;
    const S_IFCHR: u16 = 0o020000;

    let file_type = match metadata.kind {
        FileKind::File => S_IFREG,
        FileKind::Directory => S_IFDIR,
        FileKind::Symlink => S_IFLNK,
        FileKind::Special => S_IFCHR,
    };
    let mode = file_type | u16::from(metadata.mode & 0o7777);

    let mut statx = [0u8; STATX_SIZE];
    write_u32_ne(
        &mut statx,
        0,
        STATX_BASIC_STATS | STATX_BTIME | STATX_MNT_ID,
    );
    write_u32_ne(&mut statx, 4, 4096);
    write_u64_ne(&mut statx, 8, 0);
    write_u32_ne(&mut statx, 16, metadata.nlink);
    write_u16_ne(&mut statx, 28, mode);
    write_u64_ne(&mut statx, 32, 1);
    write_u64_ne(&mut statx, 40, metadata.size as u64);
    write_u64_ne(&mut statx, 48, metadata.size.div_ceil(512) as u64);
    write_u64_ne(&mut statx, 56, STATX_ATTR_MOUNT_ROOT);
    write_u64_ne(&mut statx, 144, 1);
    write_to_user(vm_space, statx_addr, &statx)?;
    Ok(0)
}

fn write_u64_ne(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}

fn write_u32_ne(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn write_u16_ne(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_ne_bytes());
}
