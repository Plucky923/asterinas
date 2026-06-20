// SPDX-License-Identifier: MPL-2.0

//! Per-task file descriptor table for the kernel image.
//!
//! This is the kernel-local counterpart of the kernel file table. Descriptor
//! entries point to rootfs files, pipes, or console endpoints.

use alloc::{
    collections::VecDeque,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    fmt::Display,
    sync::atomic::{AtomicU8, AtomicU32, Ordering},
};

use bitflags::bitflags;
use ostd::sync::{SpinLock, WaitQueue};

use crate::{
    console,
    error::{Errno, Error, Result},
    events::IoEvents,
    net::socket::Socket,
    pollee::{PollHandle, Pollee},
    process::Pid,
    rootfs::{FileKind, FileMetadata, RootDir, RootDirEntry, RootFile, RootFs},
};

const PIPE_CAPACITY: usize = 64 * 1024;

/// A raw file descriptor as received from or returned to user space.
///
/// This is the `int` type from Linux syscall signatures. It may hold negative
/// sentinel values such as `AT_FDCWD`; convert it to [`FileDesc`] before using
/// it as an index into the descriptor table.
pub type RawFileDesc = i32;

/// Represents a validated, non-negative file descriptor.
///
/// The value is guaranteed to be in the range `[0, i32::MAX]`.
/// Use [`RawFileDesc`] at syscall boundaries, then convert to `FileDesc`
/// via `TryFrom` for kernel-internal use.
///
/// Some system calls reinterpret values of types other than [`RawFileDesc`]
/// as file descriptors. Linux typically truncates the high bits without
/// checking whether the full argument fits in range. To avoid accidental
/// misuse, wider arguments should first be converted to a [`RawFileDesc`] in
/// syscall-specific code, and then converted to a `FileDesc`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FileDesc(u32);

impl FileDesc {
    /// File descriptor 0.
    pub const ZERO: Self = Self::from_u32_const(0);

    const fn from_u32_const(value: u32) -> Self {
        assert!(value <= i32::MAX as u32);
        Self(value)
    }

    fn next(self) -> Result<Self> {
        let next = self.0.checked_add(1).ok_or(Error::new(Errno::EMFILE))?;
        if next > i32::MAX as u32 {
            return Err(Error::new(Errno::EMFILE));
        }
        Ok(Self(next))
    }

    /// Returns whether this fd is below the supplied `RLIMIT_NOFILE` value.
    pub const fn is_below_nofile_limit(self, limit: u64) -> bool {
        (self.0 as u64) < limit
    }
}

impl Display for FileDesc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<FileDesc> for RawFileDesc {
    fn from(value: FileDesc) -> Self {
        value.0 as _
    }
}

impl From<FileDesc> for isize {
    fn from(value: FileDesc) -> Self {
        value.0 as _
    }
}

impl From<FileDesc> for u32 {
    fn from(value: FileDesc) -> Self {
        value.0
    }
}

impl From<FileDesc> for u64 {
    fn from(value: FileDesc) -> Self {
        value.0 as _
    }
}

impl From<FileDesc> for usize {
    fn from(value: FileDesc) -> Self {
        value.0 as _
    }
}

impl TryFrom<RawFileDesc> for FileDesc {
    type Error = Error;

    fn try_from(value: RawFileDesc) -> Result<Self> {
        if value < 0 {
            return Err(Error::new(Errno::EBADF));
        }
        Ok(Self(value.cast_unsigned()))
    }
}

#[derive(Clone, Debug)]
struct SlotVec<T> {
    slots: Vec<Option<T>>,
    len: usize,
}

impl<T> SlotVec<T> {
    const fn new() -> Self {
        Self {
            slots: Vec::new(),
            len: 0,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn slots_len(&self) -> usize {
        self.slots.len()
    }

    fn get(&self, idx: usize) -> Option<&T> {
        self.slots.get(idx)?.as_ref()
    }

    fn put_at(&mut self, idx: usize, item: T) -> Option<T> {
        if idx >= self.slots.len() {
            self.slots.resize_with(idx + 1, Default::default);
        }
        let old_item = self.slots[idx].replace(item);
        if old_item.is_none() {
            self.len += 1;
        }
        old_item
    }

    fn remove(&mut self, idx: usize) -> Option<T> {
        let slot = self.slots.get_mut(idx)?;
        let old_item = slot.take();
        if old_item.is_some() {
            self.len -= 1;
        }
        old_item
    }

    fn idxes_and_items(&self) -> impl Iterator<Item = (usize, &T)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(idx, item)| Some((idx, item.as_ref()?)))
    }
}

bitflags! {
    /// Descriptor flags stored in a file-table entry.
    pub struct FdFlags: u8 {
        /// Close this descriptor during `exec`.
        const CLOEXEC = 1;
    }
}

/// The access mode stored in an open file description.
#[expect(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessMode {
    /// Read only.
    O_RDONLY = 0,
    /// Write only.
    O_WRONLY = 1,
    /// Read/write.
    O_RDWR = 2,
}

impl AccessMode {
    /// Creates an access mode from Linux open flags.
    pub fn from_u32(flags: u32) -> Result<Self> {
        match (flags & 0b11) as u8 {
            0 => Ok(Self::O_RDONLY),
            1 => Ok(Self::O_WRONLY),
            2 => Ok(Self::O_RDWR),
            _ => Err(Error::new(Errno::EINVAL)),
        }
    }

    /// Returns the raw Linux flag bits.
    pub const fn bits(self) -> u32 {
        self as u32
    }

    /// Returns whether this mode allows reads.
    pub const fn is_readable(self) -> bool {
        matches!(self, Self::O_RDONLY | Self::O_RDWR)
    }

    /// Returns whether this mode allows writes.
    pub const fn is_writable(self) -> bool {
        matches!(self, Self::O_WRONLY | Self::O_RDWR)
    }
}

bitflags! {
    /// File status flags stored in an open file description.
    pub struct StatusFlags: u32 {
        /// Append on each write.
        const O_APPEND = 1 << 10;
        /// Nonblocking I/O.
        const O_NONBLOCK = 1 << 11;
        /// Synchronized I/O, data only.
        const O_DSYNC = 1 << 12;
        /// Signal-driven I/O.
        const O_ASYNC = 1 << 13;
        /// Direct I/O.
        const O_DIRECT = 1 << 14;
        /// Do not update access time.
        const O_NOATIME = 1 << 18;
        /// Synchronized I/O, data and metadata.
        const O_SYNC = 1 << 20;
        /// Open a path without read/write rights.
        const O_PATH = 1 << 21;
    }
}

/// A kernel-local open file object.
///
/// This intentionally mirrors the kernel's descriptor-table shape: syscall
/// code receives an opaque open file object and dispatches through file
/// operations instead of matching on concrete file kinds.
pub trait FileLike: Send + Sync {
    /// Reads data from this file.
    fn read(&self, _output: &mut [u8]) -> Result<usize> {
        if !self.access_mode().is_readable() {
            return Err(Error::new(Errno::EBADF));
        }
        Err(Error::new(Errno::EINVAL))
    }

    /// Writes data to this file.
    fn write(&self, _input: &[u8]) -> Result<usize> {
        if !self.access_mode().is_writable() {
            return Err(Error::new(Errno::EBADF));
        }
        Err(Error::new(Errno::EINVAL))
    }

    /// Reads data from this file at a fixed offset.
    fn read_at(&self, _offset: usize, _output: &mut [u8]) -> Result<usize> {
        if !self.access_mode().is_readable() {
            return Err(Error::new(Errno::EBADF));
        }
        Err(Error::new(Errno::ESPIPE))
    }

    /// Writes data to this file at a fixed offset.
    fn write_at(&self, _offset: usize, _input: &[u8]) -> Result<usize> {
        if !self.access_mode().is_writable() {
            return Err(Error::new(Errno::EBADF));
        }
        Err(Error::new(Errno::ESPIPE))
    }

    /// Seeks the current file offset.
    fn seek(&self, _offset: isize, _whence: i32) -> Result<usize> {
        Err(Error::new(Errno::EINVAL))
    }

    /// Collects directory entries that fit in `max_bytes`.
    fn collect_dir_entries(
        &self,
        _max_bytes: usize,
        _record_len_fn: &mut dyn FnMut(&RootDirEntry) -> usize,
    ) -> Result<Vec<(usize, RootDirEntry)>> {
        Err(Error::new(Errno::ENOTDIR))
    }

    /// Returns file metadata when the object supports stat-like queries.
    fn metadata(&self) -> Option<FileMetadata> {
        None
    }

    /// Resizes this file.
    fn truncate(&self, _len: usize) -> Result<()> {
        Err(Error::new(Errno::EINVAL))
    }

    /// Synchronizes file state to stable storage when applicable.
    fn sync(&self) -> Result<()> {
        Err(Error::new(Errno::EINVAL))
    }

    /// Synchronizes file data to stable storage when applicable.
    fn sync_data(&self) -> Result<()> {
        self.sync()
    }

    /// Polls readiness for this file.
    fn poll_revents(&self, _events: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        IoEvents::empty()
    }

    /// Returns the number of bytes that can be read without blocking.
    fn bytes_to_read(&self) -> Result<usize> {
        Err(Error::new(Errno::ENOTTY))
    }

    /// Returns the access mode of this open file description.
    fn access_mode(&self) -> AccessMode;

    /// Returns file status flags.
    fn status_flags(&self) -> StatusFlags;

    /// Updates file status flags.
    fn set_status_flags(&self, status_flags: StatusFlags) -> Result<()>;

    /// Returns the directory path for directory file objects.
    fn directory_path(&self) -> Option<String> {
        None
    }

    /// Returns the rootfs path for file objects backed by a named rootfs node.
    fn path(&self) -> Option<String> {
        None
    }

    /// Returns whether this file object is a terminal endpoint.
    fn is_terminal(&self) -> bool {
        false
    }

    /// Returns this object as a socket when applicable.
    fn as_socket(&self) -> Option<&dyn Socket> {
        None
    }

    /// Returns this object as a socket or reports `ENOTSOCK`.
    fn as_socket_or_err(&self) -> Result<&dyn Socket> {
        self.as_socket().ok_or_else(|| Error::new(Errno::ENOTSOCK))
    }
}

struct OpenFileState {
    access_mode: AccessMode,
    status_flags: AtomicU32,
}

impl OpenFileState {
    fn new(access_mode: AccessMode, status_flags: StatusFlags) -> Self {
        Self {
            access_mode,
            status_flags: AtomicU32::new(status_flags.bits()),
        }
    }

    const fn access_mode(&self) -> AccessMode {
        self.access_mode
    }

    fn status_flags(&self) -> StatusFlags {
        StatusFlags::from_bits_truncate(self.status_flags.load(Ordering::Relaxed))
    }

    fn set_status_flags(&self, status_flags: StatusFlags) {
        self.status_flags
            .store(status_flags.bits(), Ordering::Relaxed);
    }

    fn is_nonblocking(&self) -> bool {
        self.status_flags().contains(StatusFlags::O_NONBLOCK)
    }
}

/// A kernel-local descriptor table entry.
pub struct FileTableEntry {
    file: Arc<dyn FileLike>,
    flags: AtomicU8,
    owner: AtomicU32,
}

impl FileTableEntry {
    fn new(file: Arc<dyn FileLike>, flags: FdFlags) -> Self {
        Self {
            file,
            flags: AtomicU8::new(flags.bits()),
            owner: AtomicU32::new(0),
        }
    }

    /// Returns the open file description referenced by this entry.
    pub fn file(&self) -> &Arc<dyn FileLike> {
        &self.file
    }

    /// Returns the descriptor flags.
    pub fn flags(&self) -> FdFlags {
        FdFlags::from_bits_truncate(self.flags.load(Ordering::Relaxed))
    }

    /// Sets the descriptor flags.
    pub fn set_flags(&self, flags: FdFlags) {
        self.flags.store(flags.bits(), Ordering::Relaxed);
    }

    /// Returns the descriptor owner used by signal-driven I/O.
    pub fn owner(&self) -> Option<Pid> {
        match self.owner.load(Ordering::Relaxed) {
            0 => None,
            pid => Some(pid),
        }
    }

    /// Sets the descriptor owner used by signal-driven I/O.
    pub fn set_owner(&self, owner: Option<Pid>) {
        self.owner.store(owner.unwrap_or(0), Ordering::Relaxed);
    }
}

impl Clone for FileTableEntry {
    fn clone(&self) -> Self {
        Self {
            file: self.file.clone(),
            flags: AtomicU8::new(self.flags.load(Ordering::Relaxed)),
            owner: AtomicU32::new(0),
        }
    }
}

struct ConsoleFile {
    state: OpenFileState,
}

impl ConsoleFile {
    fn new(access_mode: AccessMode, status_flags: StatusFlags) -> Self {
        Self {
            state: OpenFileState::new(access_mode, status_flags),
        }
    }
}

struct NullFile {
    state: OpenFileState,
}

impl NullFile {
    fn new(access_mode: AccessMode, status_flags: StatusFlags) -> Self {
        Self {
            state: OpenFileState::new(access_mode, status_flags),
        }
    }
}

struct RootDirectoryFile {
    state: OpenFileState,
    path: String,
    entries: Arc<[RootDirEntry]>,
    mode: u16,
    offset: SpinLock<usize>,
}

impl RootDirectoryFile {
    fn new(directory: RootDir, access_mode: AccessMode, status_flags: StatusFlags) -> Self {
        Self {
            state: OpenFileState::new(access_mode, status_flags),
            path: directory.path().to_string(),
            entries: directory.entries(),
            mode: directory.mode(),
            offset: SpinLock::new(0),
        }
    }
}

struct RootRegularFile {
    state: OpenFileState,
    file: RootFile,
    offset: SpinLock<usize>,
}

impl RootRegularFile {
    fn new(file: RootFile, access_mode: AccessMode, status_flags: StatusFlags) -> Self {
        Self {
            state: OpenFileState::new(access_mode, status_flags),
            file,
            offset: SpinLock::new(0),
        }
    }
}

struct RootPathFile {
    state: OpenFileState,
    path: String,
    metadata: FileMetadata,
}

impl RootPathFile {
    fn new(path: String, metadata: FileMetadata, status_flags: StatusFlags) -> Self {
        Self {
            state: OpenFileState::new(AccessMode::O_RDONLY, status_flags),
            path,
            metadata,
        }
    }
}

struct PipeReaderFile {
    state: OpenFileState,
    pipe: Arc<Pipe>,
}

impl PipeReaderFile {
    fn new(pipe: Arc<Pipe>, status_flags: StatusFlags) -> Self {
        Self {
            state: OpenFileState::new(AccessMode::O_RDONLY, status_flags),
            pipe,
        }
    }
}

struct PipeWriterFile {
    state: OpenFileState,
    pipe: Arc<Pipe>,
}

impl PipeWriterFile {
    fn new(pipe: Arc<Pipe>, status_flags: StatusFlags) -> Self {
        Self {
            state: OpenFileState::new(AccessMode::O_WRONLY, status_flags),
            pipe,
        }
    }
}

pub struct Pipe {
    state: SpinLock<PipeState>,
    reader_pollee: Pollee,
    writer_pollee: Pollee,
    wait_queue: WaitQueue,
}

struct PipeState {
    buffer: VecDeque<u8>,
    readers: usize,
    writers: usize,
}

impl Pipe {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: SpinLock::new(PipeState {
                buffer: VecDeque::new(),
                readers: 1,
                writers: 1,
            }),
            reader_pollee: Pollee::new(),
            writer_pollee: Pollee::new(),
            wait_queue: WaitQueue::new(),
        })
    }

    pub fn read(&self, output: &mut [u8], nonblocking: bool) -> Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }

        if nonblocking {
            let read_len = {
                let mut state = self.state.lock();
                if state.buffer.is_empty() {
                    if state.writers == 0 {
                        0
                    } else {
                        return Err(Error::new(Errno::EAGAIN));
                    }
                } else {
                    Self::read_locked(&mut state, output)
                }
            };
            self.wait_queue.wake_all();
            self.reader_pollee.invalidate();
            self.writer_pollee.notify(IoEvents::OUT);
            return Ok(read_len);
        }

        let read_len = self.wait_queue.wait_until(|| {
            let mut state = self.state.lock();
            if state.buffer.is_empty() {
                return if state.writers == 0 { Some(0) } else { None };
            }

            Some(Self::read_locked(&mut state, output))
        });
        self.wait_queue.wake_all();
        self.reader_pollee.invalidate();
        self.writer_pollee.notify(IoEvents::OUT);
        Ok(read_len)
    }

    pub fn write(&self, input: &[u8], nonblocking: bool) -> Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }

        if nonblocking {
            let write_result = {
                let mut state = self.state.lock();
                if state.readers == 0 {
                    Err(Error::new(Errno::EPIPE))
                } else {
                    let available = PIPE_CAPACITY.saturating_sub(state.buffer.len());
                    if available == 0 {
                        Err(Error::new(Errno::EAGAIN))
                    } else {
                        Ok(Self::write_locked(&mut state, input))
                    }
                }
            };
            if write_result.is_ok() {
                self.wait_queue.wake_all();
                self.reader_pollee.notify(IoEvents::IN | IoEvents::RDNORM);
                self.writer_pollee.invalidate();
            }
            return write_result;
        }

        let write_len = self.wait_queue.wait_until(|| {
            let mut state = self.state.lock();
            if state.readers == 0 {
                return Some(Err(Error::new(Errno::EPIPE)));
            }

            let available = PIPE_CAPACITY.saturating_sub(state.buffer.len());
            if available == 0 {
                return None;
            }

            Some(Ok(Self::write_locked(&mut state, input)))
        })?;
        self.wait_queue.wake_all();
        self.reader_pollee.notify(IoEvents::IN | IoEvents::RDNORM);
        self.writer_pollee.invalidate();
        Ok(write_len)
    }

    fn read_locked(state: &mut PipeState, output: &mut [u8]) -> usize {
        let read_len = output.len().min(state.buffer.len());
        for byte in &mut output[..read_len] {
            if let Some(next_byte) = state.buffer.pop_front() {
                *byte = next_byte;
            }
        }
        read_len
    }

    fn write_locked(state: &mut PipeState, input: &[u8]) -> usize {
        let available = PIPE_CAPACITY.saturating_sub(state.buffer.len());
        let write_len = input.len().min(available);
        state.buffer.extend(&input[..write_len]);
        write_len
    }

    fn drop_reader(&self) {
        let mut state = self.state.lock();
        state.readers = state.readers.saturating_sub(1);
        drop(state);
        self.wait_queue.wake_all();
        self.writer_pollee.notify(IoEvents::ERR | IoEvents::OUT);
    }

    fn drop_writer(&self) {
        let mut state = self.state.lock();
        state.writers = state.writers.saturating_sub(1);
        drop(state);
        self.wait_queue.wake_all();
        self.reader_pollee
            .notify(IoEvents::HUP | IoEvents::IN | IoEvents::RDNORM);
    }

    fn reader_revents(&self, events: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.reader_pollee.poll_with(events, poller, || {
            let state = self.state.lock();
            let mut revents = IoEvents::empty();
            if !state.buffer.is_empty() || state.writers == 0 {
                revents |= IoEvents::IN | IoEvents::RDNORM;
            }
            if state.writers == 0 {
                revents |= IoEvents::HUP;
            }
            revents
        })
    }

    fn writer_revents(&self, events: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.writer_pollee.poll_with(events, poller, || {
            let state = self.state.lock();
            if state.readers == 0 {
                return IoEvents::ERR | IoEvents::OUT;
            }
            if state.buffer.len() < PIPE_CAPACITY {
                IoEvents::OUT
            } else {
                IoEvents::empty()
            }
        })
    }

    fn bytes_to_read(&self) -> usize {
        self.state.lock().buffer.len()
    }
}

fn seek_offset(position: &mut usize, len: usize, offset: isize, whence: i32) -> Result<usize> {
    let base = match whence {
        0 => 0isize,
        1 => isize::try_from(*position).map_err(|_| Error::new(Errno::EINVAL))?,
        2 => isize::try_from(len).map_err(|_| Error::new(Errno::EINVAL))?,
        _ => return Err(Error::new(Errno::EINVAL)),
    };
    let new_position = base.checked_add(offset).ok_or(Error::new(Errno::EINVAL))?;
    if new_position < 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    *position = new_position as usize;
    Ok(*position)
}

impl FileLike for ConsoleFile {
    fn read(&self, output: &mut [u8]) -> Result<usize> {
        if !self.access_mode().is_readable() {
            return Err(Error::new(Errno::EBADF));
        }
        if self.state.is_nonblocking() && !console::has_input() {
            return Err(Error::new(Errno::EAGAIN));
        }
        console::read(output)
    }

    fn write(&self, input: &[u8]) -> Result<usize> {
        if !self.access_mode().is_writable() {
            return Err(Error::new(Errno::EBADF));
        }
        console::write(input)
    }

    fn metadata(&self) -> Option<FileMetadata> {
        Some(FileMetadata {
            mode: 0o666,
            size: 0,
            kind: FileKind::Special,
            nlink: 1,
        })
    }

    fn poll_revents(&self, events: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        console::poll_revents(events, poller)
    }

    fn bytes_to_read(&self) -> Result<usize> {
        console::input_len()
    }

    fn access_mode(&self) -> AccessMode {
        self.state.access_mode()
    }

    fn status_flags(&self) -> StatusFlags {
        self.state.status_flags()
    }

    fn set_status_flags(&self, status_flags: StatusFlags) -> Result<()> {
        self.state.set_status_flags(status_flags);
        Ok(())
    }

    fn is_terminal(&self) -> bool {
        true
    }
}

impl FileLike for NullFile {
    fn read(&self, _output: &mut [u8]) -> Result<usize> {
        if !self.access_mode().is_readable() {
            return Err(Error::new(Errno::EBADF));
        }
        Ok(0)
    }

    fn write(&self, input: &[u8]) -> Result<usize> {
        if !self.access_mode().is_writable() {
            return Err(Error::new(Errno::EBADF));
        }
        Ok(input.len())
    }

    fn metadata(&self) -> Option<FileMetadata> {
        Some(FileMetadata {
            mode: 0o666,
            size: 0,
            kind: FileKind::Special,
            nlink: 1,
        })
    }

    fn poll_revents(&self, events: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        events & (IoEvents::IN | IoEvents::OUT | IoEvents::RDNORM)
    }

    fn access_mode(&self) -> AccessMode {
        self.state.access_mode()
    }

    fn status_flags(&self) -> StatusFlags {
        self.state.status_flags()
    }

    fn set_status_flags(&self, status_flags: StatusFlags) -> Result<()> {
        self.state.set_status_flags(status_flags);
        Ok(())
    }
}

impl FileLike for RootDirectoryFile {
    fn read(&self, _output: &mut [u8]) -> Result<usize> {
        if !self.access_mode().is_readable() {
            return Err(Error::new(Errno::EBADF));
        }
        Err(Error::new(Errno::EISDIR))
    }

    fn seek(&self, offset: isize, whence: i32) -> Result<usize> {
        let mut position = self.offset.lock();
        seek_offset(&mut position, self.entries.len(), offset, whence)
    }

    fn collect_dir_entries(
        &self,
        max_bytes: usize,
        record_len_fn: &mut dyn FnMut(&RootDirEntry) -> usize,
    ) -> Result<Vec<(usize, RootDirEntry)>> {
        let mut offset = self.offset.lock();
        let mut selected = Vec::new();
        let mut used = 0usize;
        for (entry_index, entry) in self.entries.iter().enumerate().skip(*offset) {
            let record_len = record_len_fn(entry);
            if record_len > max_bytes.saturating_sub(used) {
                break;
            }
            selected.push((entry_index + 1, entry.clone()));
            used += record_len;
        }
        *offset += selected.len();
        Ok(selected)
    }

    fn metadata(&self) -> Option<FileMetadata> {
        Some(FileMetadata {
            mode: self.mode,
            size: 0,
            kind: FileKind::Directory,
            nlink: 1,
        })
    }

    fn sync(&self) -> Result<()> {
        RootFs::get()?.sync()
    }

    fn poll_revents(&self, events: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        events & (IoEvents::IN | IoEvents::OUT | IoEvents::RDNORM)
    }

    fn access_mode(&self) -> AccessMode {
        self.state.access_mode()
    }

    fn status_flags(&self) -> StatusFlags {
        self.state.status_flags()
    }

    fn set_status_flags(&self, status_flags: StatusFlags) -> Result<()> {
        self.state.set_status_flags(status_flags);
        Ok(())
    }

    fn directory_path(&self) -> Option<String> {
        Some(self.path.clone())
    }

    fn path(&self) -> Option<String> {
        Some(self.path.clone())
    }
}

impl FileLike for RootRegularFile {
    fn read(&self, output: &mut [u8]) -> Result<usize> {
        if !self.access_mode().is_readable() {
            return Err(Error::new(Errno::EBADF));
        }

        let mut offset = self.offset.lock();
        let read_len = self.file.read_at(*offset, output)?;
        *offset += read_len;
        Ok(read_len)
    }

    fn write(&self, input: &[u8]) -> Result<usize> {
        if !self.access_mode().is_writable() {
            return Err(Error::new(Errno::EBADF));
        }

        let mut offset = self.offset.lock();
        if self.status_flags().contains(StatusFlags::O_APPEND) {
            *offset = self.file.len();
        }
        let write_len = self.file.write_at(*offset, input)?;
        *offset += write_len;
        Ok(write_len)
    }

    fn read_at(&self, offset: usize, output: &mut [u8]) -> Result<usize> {
        if !self.access_mode().is_readable() {
            return Err(Error::new(Errno::EBADF));
        }
        self.file.read_at(offset, output)
    }

    fn write_at(&self, offset: usize, input: &[u8]) -> Result<usize> {
        if !self.access_mode().is_writable() {
            return Err(Error::new(Errno::EBADF));
        }
        let offset = if self.status_flags().contains(StatusFlags::O_APPEND) {
            self.file.len()
        } else {
            offset
        };
        self.file.write_at(offset, input)
    }

    fn seek(&self, offset: isize, whence: i32) -> Result<usize> {
        let mut position = self.offset.lock();
        seek_offset(&mut position, self.file.len(), offset, whence)
    }

    fn metadata(&self) -> Option<FileMetadata> {
        Some(self.file.metadata())
    }

    fn truncate(&self, len: usize) -> Result<()> {
        if !self.access_mode().is_writable() {
            return Err(Error::new(Errno::EINVAL));
        }
        self.file.truncate(len)
    }

    fn sync(&self) -> Result<()> {
        Ok(())
    }

    fn poll_revents(&self, events: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        events & (IoEvents::IN | IoEvents::OUT | IoEvents::RDNORM)
    }

    fn access_mode(&self) -> AccessMode {
        self.state.access_mode()
    }

    fn status_flags(&self) -> StatusFlags {
        self.state.status_flags()
    }

    fn set_status_flags(&self, status_flags: StatusFlags) -> Result<()> {
        self.state.set_status_flags(status_flags);
        Ok(())
    }

    fn path(&self) -> Option<String> {
        Some(self.file.path().to_string())
    }
}

impl FileLike for RootPathFile {
    fn read(&self, _output: &mut [u8]) -> Result<usize> {
        Err(Error::new(Errno::EBADF))
    }

    fn write(&self, _input: &[u8]) -> Result<usize> {
        Err(Error::new(Errno::EBADF))
    }

    fn seek(&self, _offset: isize, _whence: i32) -> Result<usize> {
        Err(Error::new(Errno::EBADF))
    }

    fn collect_dir_entries(
        &self,
        _max_bytes: usize,
        _record_len_fn: &mut dyn FnMut(&RootDirEntry) -> usize,
    ) -> Result<Vec<(usize, RootDirEntry)>> {
        Err(Error::new(Errno::EBADF))
    }

    fn metadata(&self) -> Option<FileMetadata> {
        Some(self.metadata.clone())
    }

    fn sync(&self) -> Result<()> {
        RootFs::get()?.sync()
    }

    fn access_mode(&self) -> AccessMode {
        self.state.access_mode()
    }

    fn status_flags(&self) -> StatusFlags {
        self.state.status_flags()
    }

    fn set_status_flags(&self, status_flags: StatusFlags) -> Result<()> {
        self.state.set_status_flags(status_flags);
        Ok(())
    }

    fn directory_path(&self) -> Option<String> {
        if self.metadata.kind == FileKind::Directory {
            Some(self.path.clone())
        } else {
            None
        }
    }

    fn path(&self) -> Option<String> {
        Some(self.path.clone())
    }
}

fn check_pipe_status_flags(status_flags: StatusFlags) -> Result<()> {
    if status_flags.contains(StatusFlags::O_DIRECT) {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok(())
}

impl FileLike for PipeReaderFile {
    fn read(&self, output: &mut [u8]) -> Result<usize> {
        if !self.access_mode().is_readable() {
            return Err(Error::new(Errno::EBADF));
        }
        self.pipe.read(output, self.state.is_nonblocking())
    }

    fn metadata(&self) -> Option<FileMetadata> {
        Some(FileMetadata {
            mode: 0o600,
            size: 0,
            kind: FileKind::Special,
            nlink: 1,
        })
    }

    fn poll_revents(&self, events: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pipe.reader_revents(events, poller)
    }

    fn bytes_to_read(&self) -> Result<usize> {
        Ok(self.pipe.bytes_to_read())
    }

    fn access_mode(&self) -> AccessMode {
        self.state.access_mode()
    }

    fn status_flags(&self) -> StatusFlags {
        self.state.status_flags()
    }

    fn set_status_flags(&self, status_flags: StatusFlags) -> Result<()> {
        check_pipe_status_flags(status_flags)?;
        self.state.set_status_flags(status_flags);
        Ok(())
    }
}

impl Drop for PipeReaderFile {
    fn drop(&mut self) {
        self.pipe.drop_reader();
    }
}

impl FileLike for PipeWriterFile {
    fn write(&self, input: &[u8]) -> Result<usize> {
        if !self.access_mode().is_writable() {
            return Err(Error::new(Errno::EBADF));
        }
        self.pipe.write(input, self.state.is_nonblocking())
    }

    fn metadata(&self) -> Option<FileMetadata> {
        Some(FileMetadata {
            mode: 0o600,
            size: 0,
            kind: FileKind::Special,
            nlink: 1,
        })
    }

    fn poll_revents(&self, events: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pipe.writer_revents(events, poller)
    }

    fn bytes_to_read(&self) -> Result<usize> {
        Ok(self.pipe.bytes_to_read())
    }

    fn access_mode(&self) -> AccessMode {
        self.state.access_mode()
    }

    fn status_flags(&self) -> StatusFlags {
        self.state.status_flags()
    }

    fn set_status_flags(&self, status_flags: StatusFlags) -> Result<()> {
        check_pipe_status_flags(status_flags)?;
        self.state.set_status_flags(status_flags);
        Ok(())
    }
}

impl Drop for PipeWriterFile {
    fn drop(&mut self) {
        self.pipe.drop_writer();
    }
}

/// Per-task file descriptor table.
///
/// File descriptors 0, 1, and 2 are reserved for stdio.
pub struct FileTable {
    /// Map of fd to kernel-local file description.
    table: SlotVec<FileTableEntry>,
}

impl FileTable {
    /// Creates a new fd table with stdio connected to the console.
    pub fn new() -> Self {
        let mut table = Self {
            table: SlotVec::new(),
        };
        table.insert_stdio(FileDesc::from_u32_const(0));
        table.insert_stdio(FileDesc::from_u32_const(1));
        table.insert_stdio(FileDesc::from_u32_const(2));
        table
    }

    /// Returns the number of descriptor slots in the table.
    pub fn len(&self) -> usize {
        self.table.slots_len()
    }

    fn insert_stdio(&mut self, fd: FileDesc) {
        self.table.put_at(fd.into(), Self::stdio_entry());
    }

    fn stdio_entry() -> FileTableEntry {
        let file: Arc<dyn FileLike> =
            Arc::new(ConsoleFile::new(AccessMode::O_RDWR, StatusFlags::empty()));
        FileTableEntry::new(file, FdFlags::empty())
    }

    /// Allocates a new fd for a regular rootfs file.
    pub fn alloc_file(
        &mut self,
        file: RootFile,
        access_mode: AccessMode,
        status_flags: StatusFlags,
        fd_flags: FdFlags,
        nofile_limit: u64,
    ) -> Result<RawFileDesc> {
        let file: Arc<dyn FileLike> =
            Arc::new(RootRegularFile::new(file, access_mode, status_flags));
        Ok(self.insert_file(file, fd_flags, nofile_limit)?.into())
    }

    /// Allocates a new fd for a rootfs directory.
    pub fn alloc_dir(
        &mut self,
        directory: RootDir,
        access_mode: AccessMode,
        status_flags: StatusFlags,
        fd_flags: FdFlags,
        nofile_limit: u64,
    ) -> Result<RawFileDesc> {
        let file: Arc<dyn FileLike> =
            Arc::new(RootDirectoryFile::new(directory, access_mode, status_flags));
        Ok(self.insert_file(file, fd_flags, nofile_limit)?.into())
    }

    /// Allocates a new fd for an `O_PATH` rootfs entry.
    pub fn alloc_path(
        &mut self,
        path: String,
        metadata: FileMetadata,
        status_flags: StatusFlags,
        fd_flags: FdFlags,
        nofile_limit: u64,
    ) -> Result<RawFileDesc> {
        let file: Arc<dyn FileLike> = Arc::new(RootPathFile::new(path, metadata, status_flags));
        Ok(self.insert_file(file, fd_flags, nofile_limit)?.into())
    }

    /// Allocates a read end and a write end for an in-memory pipe.
    pub fn alloc_pipe(
        &mut self,
        status_flags: StatusFlags,
        fd_flags: FdFlags,
        nofile_limit: u64,
    ) -> Result<(RawFileDesc, RawFileDesc)> {
        check_pipe_status_flags(status_flags)?;
        let pipe = Pipe::new();
        let read_file: Arc<dyn FileLike> =
            Arc::new(PipeReaderFile::new(pipe.clone(), status_flags));
        let read_fd = self.insert_file(read_file, fd_flags, nofile_limit)?;
        let write_file: Arc<dyn FileLike> = Arc::new(PipeWriterFile::new(pipe, status_flags));
        let write_fd = match self.insert_file(write_file, fd_flags, nofile_limit) {
            Ok(write_fd) => write_fd,
            Err(error) => {
                let _ = self.close_file(read_fd);
                return Err(error);
            }
        };
        Ok((read_fd.into(), write_fd.into()))
    }

    /// Allocates a new fd for the console endpoint.
    pub fn alloc_console(
        &mut self,
        access_mode: AccessMode,
        status_flags: StatusFlags,
        fd_flags: FdFlags,
        nofile_limit: u64,
    ) -> Result<RawFileDesc> {
        let file: Arc<dyn FileLike> = Arc::new(ConsoleFile::new(access_mode, status_flags));
        Ok(self.insert_file(file, fd_flags, nofile_limit)?.into())
    }

    /// Allocates a new fd for `/dev/null`.
    pub fn alloc_null(
        &mut self,
        access_mode: AccessMode,
        status_flags: StatusFlags,
        fd_flags: FdFlags,
        nofile_limit: u64,
    ) -> Result<RawFileDesc> {
        let file: Arc<dyn FileLike> = Arc::new(NullFile::new(access_mode, status_flags));
        Ok(self.insert_file(file, fd_flags, nofile_limit)?.into())
    }

    /// Inserts an open file description and returns its descriptor.
    pub fn insert_file(
        &mut self,
        file: Arc<dyn FileLike>,
        flags: FdFlags,
        nofile_limit: u64,
    ) -> Result<FileDesc> {
        let fd = self.next_available_fd(FileDesc::ZERO, nofile_limit)?;
        self.table
            .put_at(fd.into(), FileTableEntry::new(file, flags));
        Ok(fd)
    }

    /// Returns a clone of the open file description referenced by `fd`.
    pub fn get_file(&self, fd: FileDesc) -> Result<Arc<dyn FileLike>> {
        self.table
            .get(fd.into())
            .map(|entry| entry.file().clone())
            .ok_or_else(|| Error::new(Errno::EBADF))
    }

    /// Returns the file-table entry referenced by `fd`.
    pub fn get_entry(&self, fd: FileDesc) -> Result<&FileTableEntry> {
        self.table
            .get(fd.into())
            .ok_or_else(|| Error::new(Errno::EBADF))
    }

    /// Returns a clone of the open file description referenced by raw `fd`.
    pub fn get(&self, fd: RawFileDesc) -> Result<Arc<dyn FileLike>> {
        self.get_file(fd.try_into()?)
    }

    /// Returns a descriptor if the table contains it.
    pub fn get_optional(&self, fd: RawFileDesc) -> Option<Arc<dyn FileLike>> {
        self.get_file(fd.try_into().ok()?).ok()
    }

    /// Duplicates `fd` onto the lowest-numbered available descriptor equal to
    /// or greater than `ceil_fd`.
    pub fn dup_ceil(
        &mut self,
        fd: FileDesc,
        ceil_fd: FileDesc,
        flags: FdFlags,
        nofile_limit: u64,
    ) -> Result<FileDesc> {
        let entry = self.duplicate_entry(fd, flags)?;
        let new_fd = self.next_available_fd(ceil_fd, nofile_limit)?;
        self.table.put_at(new_fd.into(), entry);
        Ok(new_fd)
    }

    /// Duplicates `fd` onto the exact descriptor number `new_fd`.
    pub fn dup_exact(
        &mut self,
        fd: FileDesc,
        new_fd: FileDesc,
        flags: FdFlags,
    ) -> Result<Option<Arc<dyn FileLike>>> {
        let entry = self.duplicate_entry(fd, flags)?;
        let closed_handle = self.close_file(new_fd);
        self.table.put_at(new_fd.into(), entry);
        Ok(closed_handle)
    }

    fn duplicate_entry(&self, fd: FileDesc, flags: FdFlags) -> Result<FileTableEntry> {
        let handle = self.get_file(fd)?;
        Ok(FileTableEntry::new(handle, flags))
    }

    fn next_available_fd(&self, min_fd: FileDesc, nofile_limit: u64) -> Result<FileDesc> {
        let mut fd = min_fd;
        if !fd.is_below_nofile_limit(nofile_limit) {
            return Err(Error::new(Errno::EMFILE));
        }
        while self.table.get(fd.into()).is_some() {
            fd = fd.next()?;
            if !fd.is_below_nofile_limit(nofile_limit) {
                return Err(Error::new(Errno::EMFILE));
            }
        }
        Ok(fd)
    }

    /// Closes `fd` and returns the removed open file description if present.
    pub fn close_file(&mut self, fd: FileDesc) -> Option<Arc<dyn FileLike>> {
        self.table.remove(fd.into()).map(|entry| entry.file)
    }

    /// Closes raw `fd` and returns the removed open file description.
    pub fn remove(&mut self, fd: RawFileDesc) -> Result<Arc<dyn FileLike>> {
        self.close_file(fd.try_into()?)
            .ok_or_else(|| Error::new(Errno::EBADF))
    }

    /// Closes all descriptors marked close-on-exec.
    pub fn close_files_on_exec(&mut self) -> Vec<Arc<dyn FileLike>> {
        let closed_fds: Vec<FileDesc> = self
            .table
            .idxes_and_items()
            .filter_map(|(idx, entry)| {
                if entry.flags().contains(FdFlags::CLOEXEC) {
                    FileDesc::try_from(idx as RawFileDesc).ok()
                } else {
                    None
                }
            })
            .collect();

        let mut closed_files = Vec::new();
        for fd in closed_fds {
            if let Some(closed_file) = self.close_file(fd) {
                closed_files.push(closed_file);
            }
        }
        closed_files
    }

    /// Clones fd table state for fork-style task creation.
    ///
    /// Creates a new fd table with the same mappings. Each open file
    /// description's Arc refcount is incremented, so parent and child share
    /// file offsets and pipe endpoints.
    pub fn clone_for_fork(&self) -> Self {
        Self {
            table: self.table.clone(),
        }
    }

    /// Close all descriptors in this table.
    ///
    /// Clearing the map drops descriptor entries. The underlying object is
    /// closed when the last shared open file description goes away.
    pub fn close_all(&mut self) -> usize {
        let count = self.table.len();
        self.table = SlotVec::new();
        count
    }
}

impl Default for FileTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn dup_ceil_respects_nofile_limit() {
        let mut table = FileTable::new();
        let new_fd = table
            .dup_ceil(FileDesc::ZERO, FileDesc::ZERO, FdFlags::empty(), 4)
            .unwrap();

        assert_eq!(new_fd, FileDesc::from_u32_const(3));
    }

    #[ktest]
    fn dup_ceil_returns_emfile_when_no_fd_is_below_limit() {
        let mut table = FileTable::new();

        assert_eq!(
            table
                .dup_ceil(FileDesc::ZERO, FileDesc::ZERO, FdFlags::empty(), 3,)
                .unwrap_err()
                .errno(),
            Errno::EMFILE
        );
    }
}
