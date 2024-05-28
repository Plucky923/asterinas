// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    device::get_device, fs::{
        file_table::FileDesc,
        fs_resolver::{FsPath, AT_FDCWD},
        utils::{InodeMode, InodeType},
    }, prelude::*, syscall::{constants::MAX_FILENAME_LEN, stat::Mode}, util::read_cstring_from_user
};

pub fn sys_mknodat(
    dirfd: FileDesc,
    path_addr: Vaddr,
    mode: u16,
    dev: usize,
) -> Result<SyscallReturn> {
    let path = read_cstring_from_user(path_addr, MAX_FILENAME_LEN)?;
    debug!(
        "dirfd = {}, path = {:?}, mode = {}, dev = {}",
        dirfd, path, mode, dev
    );
    
    let current = current!();
    let (dir_dentry, name) = {
        let path = path.to_string_lossy();
        if path.is_empty() {
            return_errno_with_message!(Errno::ENOENT, "path is empty");
        }
        let fs_path = FsPath::new(dirfd, path.as_ref())?;
        current.fs().read().lookup_dir_and_base_name(&fs_path)?
    };

    let inode_mode = {
        let mask_mode = mode & !current.umask().read().get();
        InodeMode::from_bits_truncate(mask_mode)
    };
    let mknod_mode = Mode::from_bits_truncate(mode);
    if mknod_mode.contains(Mode::S_IFREG) {
        let _ = dir_dentry.new_fs_child(name.trim_end_matches('/'), InodeType::File, inode_mode)?;
    } else if mknod_mode.contains(Mode::S_IFCHR) || mknod_mode.contains(Mode::S_IFBLK) {
        let _ = dir_dentry.mknod(name.trim_end_matches('/'), inode_mode , get_device(dev)?)?;
    } else if mknod_mode.contains(Mode::S_IFIFO) || mknod_mode.contains(Mode::S_IFSOCK) {
        return_errno_with_message!(Errno::EINVAL, "invalid mode");
    } else {
        return_errno_with_message!(Errno::EINVAL, "invalid mode");
    }

    Ok(SyscallReturn::Return(0))
}

pub fn sys_mknod(path_addr: Vaddr, mode: u16, dev: usize) -> Result<SyscallReturn> {
    self::sys_mknodat(AT_FDCWD, path_addr, mode, dev)
}
