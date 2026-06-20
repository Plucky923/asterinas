// SPDX-License-Identifier: MPL-2.0

//! Per-thread filesystem context for the kernel image.

use alloc::string::String;

use crate::{
    error::{Errno, Error, Result},
    rootfs::{FileKind, RootFs, join_path, normalize_path},
};

/// File descriptor marker for resolving paths relative to the current working directory.
pub const AT_FDCWD: i32 = -100;

/// The `AT_EMPTY_PATH` flag bit, as defined by Linux.
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// Policy for how `*at`-style path resolution treats an empty pathname.
///
/// This mirrors the kernel `EmptyPathStr` policy so syscall call sites make the
/// Linux empty-path rule explicit instead of open-coding it locally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmptyPathStr {
    /// Always reject an empty pathname with `ENOENT`.
    Reject,
    /// Accept an empty pathname iff `AT_EMPTY_PATH` is set in the raw flags.
    AllowIfFlag(u32),
    /// Accept an empty pathname only when `dirfd` is a real file descriptor.
    Allow,
}

/// Filesystem context associated with a POSIX thread.
#[derive(Clone)]
pub struct ThreadFsInfo {
    cwd: String,
    umask: FileCreationMask,
}

impl ThreadFsInfo {
    /// Creates filesystem context rooted at `/`.
    pub fn new_root() -> Self {
        Self {
            cwd: String::from("/"),
            umask: FileCreationMask::default(),
        }
    }

    /// Returns the current working directory path.
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// Returns the file creation mask.
    pub fn umask(&self) -> FileCreationMask {
        self.umask
    }

    /// Sets a new file creation mask and returns the old one.
    pub fn swap_umask(&mut self, new_mask: FileCreationMask) -> FileCreationMask {
        let old_mask = self.umask;
        self.umask = new_mask;
        old_mask
    }

    /// Resolves an absolute or cwd-relative path.
    pub fn resolve_path(&self, path: &str) -> Result<String> {
        self.resolve_path_at_with_base(AT_FDCWD, path, None, EmptyPathStr::Reject)
    }

    /// Resolves a path using Linux `*at` semantics and a pre-resolved `dirfd` base.
    pub(crate) fn resolve_path_at_with_base(
        &self,
        dirfd: i32,
        path: &str,
        dirfd_base: Option<&str>,
        empty_path_policy: EmptyPathStr,
    ) -> Result<String> {
        if path.is_empty() {
            let allowed = match empty_path_policy {
                EmptyPathStr::Reject => false,
                EmptyPathStr::AllowIfFlag(flags) => flags & AT_EMPTY_PATH != 0,
                EmptyPathStr::Allow => dirfd != AT_FDCWD,
            };
            if !allowed {
                return Err(Error::new(Errno::ENOENT));
            }
            if dirfd == AT_FDCWD {
                return Ok(self.cwd.clone());
            }
            let Some(dirfd_base) = dirfd_base else {
                return Err(Error::new(Errno::EBADF));
            };
            return Ok(normalize_path(dirfd_base));
        }

        if path.starts_with('/') {
            return Ok(normalize_path(path));
        }

        if dirfd == AT_FDCWD {
            return Ok(join_path(&self.cwd, path));
        }

        let Some(dirfd_base) = dirfd_base else {
            return Err(Error::new(Errno::EBADF));
        };
        Ok(join_path(dirfd_base, path))
    }

    /// Changes the current working directory after validating it in the rootfs.
    pub fn chdir(&mut self, rootfs: &RootFs, path: &str) -> Result<()> {
        let path = self.resolve_path(path)?;
        let metadata = rootfs.metadata(&path)?;
        if metadata.kind != FileKind::Directory {
            return Err(Error::new(Errno::ENOTDIR));
        }

        self.cwd = path;
        Ok(())
    }
}

/// A mask for the mode of a newly-created file or directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileCreationMask(u16);

impl FileCreationMask {
    const MASK: u16 = 0o777;

    /// Returns the raw mask bits.
    pub fn get(self) -> u16 {
        self.0
    }
}

impl Default for FileCreationMask {
    fn default() -> Self {
        Self(0o022)
    }
}

impl TryFrom<u16> for FileCreationMask {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        if value & !Self::MASK != 0 {
            return Err(Error::new(Errno::EINVAL));
        }
        Ok(Self(value))
    }
}
