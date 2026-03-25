// SPDX-License-Identifier: MPL-2.0

#![expect(unused_variables)]

//! Opened File Handle

use core::fmt::Display;

use ostd::io::IoMem;

use super::{
    AccessMode, FileMode, InodeHandle, StatusFlags, file_table::FdFlags, inode_handle::SeekFrom,
};
use crate::{
    fs::vfs::{inode::FallocMode, path::Path},
    net::socket::Socket,
    prelude::*,
    process::signal::Pollable,
    util::{VmReaderArray, VmWriterArray, ioctl::RawIoctl},
    vm::vmo::Vmo,
};

/// The basic operations defined on a file
pub trait FileLike: Pollable + Send + Sync + Any {
    fn read(&self, writer: &mut VmWriter) -> Result<usize> {
        return_errno_with_message!(Errno::EBADF, "the file is not valid for reading");
    }

    fn write(&self, reader: &mut VmReader) -> Result<usize> {
        return_errno_with_message!(Errno::EBADF, "the file is not valid for writing");
    }

    /// Read at the given file offset.
    ///
    /// The file must be seekable to support `read_at`.
    /// Unsupported offset-based I/O should be rejected even for zero-length requests so that the
    /// `pread`/`preadv` family returns the Linux-compatible errno.
    /// Unlike [`read`], `read_at` will not change the file offset.
    ///
    /// [`read`]: FileLike::read
    fn read_at(&self, offset: usize, writer: &mut VmWriter) -> Result<usize> {
        return_errno_with_message!(Errno::ESPIPE, "read_at is not supported");
    }

    /// Reads into a collection of buffers at the given file offset.
    ///
    /// The default implementation issues one or more [`read_at`] calls in order. When the buffer
    /// collection is empty, it still delegates to [`read_at`] with a zero-length writer so that
    /// the `preadv` family keeps returning the Linux-compatible errno for unsupported files.
    ///
    /// [`read_at`]: FileLike::read_at
    fn read_at_array(&self, offset: usize, writers: &mut VmWriterArray) -> Result<usize> {
        if writers.writers_mut().is_empty() {
            let mut empty = [0u8; 0];
            let mut writer = VmWriter::from(empty.as_mut_slice()).to_fallible();
            return self.read_at(offset, &mut writer);
        }

        let mut total_len = 0;
        let mut cur_offset = offset;
        for writer in writers.writers_mut() {
            debug_assert!(writer.has_avail());

            match self.read_at(cur_offset, writer) {
                Ok(read_len) => {
                    total_len += read_len;
                    cur_offset += read_len;
                }
                Err(_) if total_len > 0 => break,
                Err(err) => return Err(err),
            }
            if writer.has_avail() {
                break;
            }
        }

        Ok(total_len)
    }

    /// Write at the given file offset.
    ///
    /// The file must be seekable to support `write_at`.
    /// Unsupported offset-based I/O should be rejected even for zero-length requests so that the
    /// `pwrite`/`pwritev` family returns the Linux-compatible errno.
    /// Unlike [`write`], `write_at` will not change the file offset.
    /// If the file is append-only, the `offset` will be ignored.
    ///
    /// [`write`]: FileLike::write
    fn write_at(&self, offset: usize, reader: &mut VmReader) -> Result<usize> {
        return_errno_with_message!(Errno::ESPIPE, "write_at is not supported");
    }

    /// Writes from a collection of buffers at the given file offset.
    ///
    /// The default implementation issues one or more [`write_at`] calls in order. When the buffer
    /// collection is empty, it still delegates to [`write_at`] with a zero-length reader so that
    /// the `pwritev` family keeps returning the Linux-compatible errno for unsupported files.
    ///
    /// [`write_at`]: FileLike::write_at
    fn write_at_array(&self, offset: usize, readers: &mut VmReaderArray) -> Result<usize> {
        if readers.readers_mut().is_empty() {
            let empty = [0u8; 0];
            let mut reader = VmReader::from(empty.as_slice()).to_fallible();
            return self.write_at(offset, &mut reader);
        }

        let mut total_len = 0;
        let mut cur_offset = offset;
        for reader in readers.readers_mut() {
            debug_assert!(reader.has_remain());

            match self.write_at(cur_offset, reader) {
                Ok(write_len) => {
                    total_len += write_len;
                    cur_offset += write_len;
                }
                Err(_) if total_len > 0 => break,
                Err(err) => return Err(err),
            }
            if reader.has_remain() {
                break;
            }
        }

        Ok(total_len)
    }

    fn ioctl(&self, raw_ioctl: RawIoctl) -> Result<i32> {
        // `ENOTTY` means that "The specified operation does not apply to the kind of object that
        // the file descriptor references".
        // Reference: <https://man7.org/linux/man-pages/man2/ioctl.2.html>.
        return_errno_with_message!(Errno::ENOTTY, "ioctl is not supported");
    }

    /// Obtains the mappable object to map this file into the user address space.
    ///
    /// If this file has a corresponding mappable object of [`Mappable`],
    /// then it can be either an inode or an MMIO region.
    fn mappable(&self) -> Result<Mappable> {
        // `ENODEV` means that "The underlying filesystem of the specified file does not support
        // memory mapping".
        // Reference: <https://man7.org/linux/man-pages/man2/mmap.2.html>.
        return_errno_with_message!(Errno::ENODEV, "the file is not mappable");
    }

    fn resize(&self, new_size: usize) -> Result<()> {
        return_errno_with_message!(Errno::EINVAL, "resize is not supported");
    }

    fn status_flags(&self) -> StatusFlags {
        StatusFlags::empty()
    }

    fn set_status_flags(&self, _new_flags: StatusFlags) -> Result<()> {
        return_errno_with_message!(Errno::EINVAL, "set_status_flags is not supported");
    }

    fn mode(&self) -> FileMode {
        FileMode::from(self.access_mode())
    }

    fn access_mode(&self) -> AccessMode {
        AccessMode::O_RDWR
    }

    fn seek(&self, seek_from: SeekFrom) -> Result<usize> {
        return_errno_with_message!(Errno::ESPIPE, "seek is not supported");
    }

    fn fallocate(&self, mode: FallocMode, offset: usize, len: usize) -> Result<()> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "fallocate is not supported");
    }

    fn as_socket(&self) -> Option<&dyn Socket> {
        None
    }

    fn path(&self) -> &Path;

    /// Dumps information to appear in the `fdinfo` file under procfs.
    ///
    /// This method must not break atomic mode because it will be called with the file table's spin
    /// lock held. There are two strategies for implementing this method:
    ///  - If the necessary information can be obtained without breaking atomic mode, the method
    ///    can collect and return the information directly. `Arc<Self>` should be dropped and
    ///    should not appear in the returned `Box<dyn Display>`.
    ///  - Otherwise, if the file can be dropped asynchronously in another process, the method can
    ///    return a `Box<dyn Display>` containing the `Arc<Self>`, so that the information can be
    ///    collected later in its `Display::display()` method, after dropping the file table's spin
    ///    lock.
    fn dump_proc_fdinfo(self: Arc<Self>, fd_flags: FdFlags) -> Box<dyn Display>;
}

impl dyn FileLike {
    pub fn downcast_ref<T: FileLike>(&self) -> Option<&T> {
        (self as &dyn Any).downcast_ref::<T>()
    }

    pub fn read_bytes(&self, buf: &mut [u8]) -> Result<usize> {
        let mut writer = VmWriter::from(buf).to_fallible();
        self.read(&mut writer)
    }

    pub fn write_bytes(&self, buf: &[u8]) -> Result<usize> {
        let mut reader = VmReader::from(buf).to_fallible();
        self.write(&mut reader)
    }

    pub fn read_bytes_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        let mut writer = VmWriter::from(buf).to_fallible();
        self.read_at(offset, &mut writer)
    }

    #[expect(dead_code)]
    pub fn write_bytes_at(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        let mut reader = VmReader::from(buf).to_fallible();
        self.write_at(offset, &mut reader)
    }

    pub fn as_socket_or_err(&self) -> Result<&dyn Socket> {
        self.as_socket()
            .ok_or_else(|| Error::with_message(Errno::ENOTSOCK, "the file is not a socket"))
    }

    pub fn as_inode_handle_or_err(&self) -> Result<&InodeHandle> {
        self.downcast_ref().ok_or_else(|| {
            Error::with_message(Errno::EINVAL, "the file is not related to an inode")
        })
    }
}

/// An object that may be memory mapped into the user address space.
#[derive(Debug, Clone)]
pub enum Mappable {
    /// A VMO (i.e., page cache).
    Vmo(Arc<Vmo>),
    /// An MMIO region.
    IoMem(IoMem),
}
