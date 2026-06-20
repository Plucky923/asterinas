// SPDX-License-Identifier: MPL-2.0

use ostd::mm::VmSpace;

use super::{
    AT_FDCWD, AccessMode, EmptyPathStr, Errno, Error, FdFlags, FileKind, O_CLOEXEC,
    O_CREAT as RAW_O_CREAT, O_DIRECTORY as RAW_O_DIRECTORY, O_EXCL as RAW_O_EXCL,
    O_NOFOLLOW as RAW_O_NOFOLLOW, O_TMPFILE as RAW_O_TMPFILE, O_TRUNC as RAW_O_TRUNC, Result,
    RootFs, StatusFlags, current_fd_table, current_nofile_limit, is_console_path, is_null_path,
    read_c_string, resolve_guest_path_at, with_current_fs_info,
};

/// Opens a path relative to the current working directory.
pub(super) fn sys_open(
    pathname_addr: usize,
    flags: usize,
    mode: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    open_rootfs_path(vm_space, AT_FDCWD, pathname_addr, flags, mode)
}

/// Opens a path relative to `dirfd`.
pub(super) fn sys_openat(
    dirfd: i32,
    pathname_addr: usize,
    flags: usize,
    mode: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    open_rootfs_path(vm_space, dirfd, pathname_addr, flags, mode)
}

fn open_rootfs_path(
    vm_space: &VmSpace,
    dirfd: i32,
    pathname_addr: usize,
    flags: usize,
    mode: usize,
) -> Result<isize> {
    let open_flags = OpenFlags::from_raw(flags, mode)?;
    let raw_path = read_c_string(vm_space, pathname_addr)?;
    let path = resolve_guest_path_at(dirfd, &raw_path, EmptyPathStr::Reject)?;
    let nofile_limit = current_nofile_limit()?;

    if is_console_path(&path) {
        let fd_table = current_fd_table()?;
        return Ok(fd_table.lock().alloc_console(
            open_flags.access_mode,
            open_flags.status_flags,
            open_flags.fd_flags,
            nofile_limit,
        )? as isize);
    }

    if is_null_path(&path) {
        let fd_table = current_fd_table()?;
        return Ok(fd_table.lock().alloc_null(
            open_flags.access_mode,
            open_flags.status_flags,
            open_flags.fd_flags,
            nofile_limit,
        )? as isize);
    }

    let rootfs = RootFs::get()?;
    let metadata = match open_flags.metadata(rootfs.as_ref(), &path) {
        Ok(metadata) => Some(metadata),
        Err(error)
            if error.errno() == Errno::ENOENT
                && open_flags.creation_flags.contains(CreationFlags::O_CREAT) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    if open_flags.is_path_open() {
        let Some(metadata) = metadata else {
            return Err(Error::new(Errno::ENOENT));
        };
        let fd_table = current_fd_table()?;
        return Ok(fd_table.lock().alloc_path(
            path,
            metadata,
            open_flags.status_flags,
            open_flags.fd_flags,
            nofile_limit,
        )? as isize);
    }

    if open_flags.creation_flags.contains(CreationFlags::O_TMPFILE) {
        return Err(Error::new(Errno::EOPNOTSUPP));
    }

    if open_flags.creation_flags.contains(CreationFlags::O_CREAT)
        && open_flags
            .creation_flags
            .contains(CreationFlags::O_DIRECTORY)
    {
        return Err(Error::new(Errno::EINVAL));
    }

    if open_flags
        .creation_flags
        .contains(CreationFlags::O_NOFOLLOW)
        && metadata.is_some_and(|metadata| metadata.kind == FileKind::Symlink)
        && !open_flags.exclusive_create()
    {
        return Err(Error::new(Errno::ELOOP));
    }

    if let Some(metadata) = metadata {
        if open_flags.raw & RAW_O_DIRECTORY != 0 && metadata.kind != FileKind::Directory {
            return Err(Error::new(Errno::ENOTDIR));
        }
        if metadata.kind == FileKind::Directory {
            if open_flags.access_mode.is_writable() {
                return Err(Error::new(Errno::EISDIR));
            }
            let directory = rootfs.open_dir(&path)?;
            let fd_table = current_fd_table()?;
            return Ok(fd_table.lock().alloc_dir(
                directory,
                open_flags.access_mode,
                open_flags.status_flags,
                open_flags.fd_flags,
                nofile_limit,
            )? as isize);
        }
    } else if open_flags.raw & RAW_O_DIRECTORY != 0 {
        return Err(Error::new(Errno::ENOENT));
    }

    if open_flags.creation_flags.contains(CreationFlags::O_TRUNC)
        && !open_flags.access_mode.is_writable()
    {
        return Err(Error::new(Errno::EACCES));
    }

    let file = rootfs.open_file_with_options(
        &path,
        open_flags.mode,
        open_flags.creation_flags.contains(CreationFlags::O_CREAT),
        open_flags.creation_flags.contains(CreationFlags::O_EXCL),
        open_flags.creation_flags.contains(CreationFlags::O_TRUNC),
    )?;
    let fd_table = current_fd_table()?;
    Ok(fd_table.lock().alloc_file(
        file,
        open_flags.access_mode,
        open_flags.status_flags,
        open_flags.fd_flags,
        nofile_limit,
    )? as isize)
}

struct OpenFlags {
    raw: u32,
    creation_flags: CreationFlags,
    access_mode: AccessMode,
    status_flags: StatusFlags,
    fd_flags: FdFlags,
    mode: u16,
}

impl OpenFlags {
    fn from_raw(flags: usize, mode: usize) -> Result<Self> {
        let raw = u32::try_from(flags).map_err(|_| Error::new(Errno::EINVAL))?;
        let creation_flags = CreationFlags::from_bits_truncate(raw);
        let status_flags = StatusFlags::from_bits_truncate(raw);
        let access_mode = AccessMode::from_u32(raw)?;
        validate_tmpfile_flags(creation_flags, status_flags, access_mode)?;
        let umask = with_current_fs_info(|fs| Ok(fs.umask().get()))?;
        let fd_flags = if raw & O_CLOEXEC != 0 {
            FdFlags::CLOEXEC
        } else {
            FdFlags::empty()
        };

        Ok(Self {
            raw,
            creation_flags,
            access_mode,
            status_flags,
            fd_flags,
            mode: ((mode as u16) & 0o7777) & !umask,
        })
    }

    fn is_path_open(&self) -> bool {
        self.status_flags.contains(StatusFlags::O_PATH)
    }

    fn follow_tail_link(&self) -> bool {
        !(self.creation_flags.contains(CreationFlags::O_NOFOLLOW) || self.exclusive_create())
    }

    fn metadata(&self, rootfs: &RootFs, path: &str) -> Result<crate::rootfs::FileMetadata> {
        if self.follow_tail_link() {
            rootfs.metadata(path)
        } else {
            rootfs.metadata_no_follow(path)
        }
    }

    fn exclusive_create(&self) -> bool {
        self.creation_flags.contains(CreationFlags::O_CREAT)
            && self.creation_flags.contains(CreationFlags::O_EXCL)
    }
}

fn validate_tmpfile_flags(
    creation_flags: CreationFlags,
    status_flags: StatusFlags,
    access_mode: AccessMode,
) -> Result<()> {
    if !creation_flags.contains(CreationFlags::O_TMPFILE)
        || status_flags.contains(StatusFlags::O_PATH)
    {
        return Ok(());
    }
    if !creation_flags.contains(CreationFlags::O_DIRECTORY) {
        return Err(Error::new(Errno::EINVAL));
    }
    if !access_mode.is_writable() {
        return Err(Error::new(Errno::EINVAL));
    }
    if creation_flags.contains(CreationFlags::O_CREAT) {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok(())
}

bitflags::bitflags! {
    struct CreationFlags: u32 {
        const O_CREAT = RAW_O_CREAT;
        const O_EXCL = RAW_O_EXCL;
        const O_TRUNC = RAW_O_TRUNC;
        const O_DIRECTORY = RAW_O_DIRECTORY;
        const O_NOFOLLOW = RAW_O_NOFOLLOW;
        const O_TMPFILE = RAW_O_TMPFILE;
    }
}
