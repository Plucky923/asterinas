// SPDX-License-Identifier: MPL-2.0

//! Per-task file descriptor table for FrameVM
//!
//! Each task has its own fd table. When fork() is called, the fd table is
//! cloned (with Arc refcounts incremented for each socket). This allows
//! independent close() operations per task while sharing the underlying
//! socket objects.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use crate::{
    error::{Errno, Error, Result},
    vsock::socket::FrameVsockSocket,
};

/// Per-fd handle for a socket.
///
/// This wraps the underlying socket and ensures that when the last handle
/// is dropped, the socket is closed and unregistered.
pub struct SocketHandle {
    socket: Arc<FrameVsockSocket>,
}

impl SocketHandle {
    pub fn new(socket: Arc<FrameVsockSocket>) -> Self {
        Self { socket }
    }

    pub fn socket(&self) -> Arc<FrameVsockSocket> {
        self.socket.clone()
    }
}

impl Drop for SocketHandle {
    fn drop(&mut self) {
        let _ = self.socket.close();
    }
}

/// Per-task file descriptor table
///
/// Maps file descriptors (i32) to socket objects (Arc<FrameVsockSocket>).
/// File descriptors 0, 1, 2 are reserved for stdio.
pub struct FdTable {
    /// Map of fd -> socket
    fds: BTreeMap<i32, Arc<SocketHandle>>,
    /// Next fd to allocate
    next_fd: i32,
}

impl FdTable {
    /// Create a new empty fd table
    pub fn new() -> Self {
        Self {
            fds: BTreeMap::new(),
            next_fd: 3, // 0, 1, 2 reserved for stdio
        }
    }

    /// Allocate a new fd for a socket
    ///
    /// Returns the allocated fd number.
    pub fn alloc(&mut self, socket: Arc<FrameVsockSocket>) -> i32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.fds.insert(fd, Arc::new(SocketHandle::new(socket)));
        fd
    }

    /// Get socket by fd
    ///
    /// Returns a clone of the Arc (increments refcount).
    pub fn get(&self, fd: i32) -> Result<Arc<SocketHandle>> {
        self.fds
            .get(&fd)
            .cloned()
            .ok_or_else(|| Error::new(Errno::EBADF))
    }

    /// Remove and return socket by fd
    ///
    /// The socket is removed from this fd table, but may still exist
    /// in other fd tables (after fork) due to Arc sharing.
    pub fn remove(&mut self, fd: i32) -> Result<Arc<SocketHandle>> {
        self.fds.remove(&fd).ok_or_else(|| Error::new(Errno::EBADF))
    }

    /// Clone fd table for fork
    ///
    /// Creates a new fd table with the same mappings. Each socket's
    /// Arc refcount is incremented, so both parent and child share
    /// the same underlying socket objects.
    pub fn clone_for_fork(&self) -> Self {
        Self {
            fds: self.fds.clone(), // Arc::clone for each socket
            next_fd: self.next_fd,
        }
    }

    /// Check if fd exists
    pub fn contains(&self, fd: i32) -> bool {
        self.fds.contains_key(&fd)
    }

    /// Get the number of open fds
    #[expect(dead_code, reason = "kept for targeted debug and future assertions")]
    pub fn len(&self) -> usize {
        self.fds.len()
    }

    /// Return up to `limit` FDs for debug logging.
    pub fn debug_fds(&self, limit: usize) -> Vec<i32> {
        self.fds.keys().take(limit).copied().collect()
    }

    /// Close all descriptors in this table.
    ///
    /// Clearing the map drops `SocketHandle`s, which triggers socket close
    /// when the last shared handle goes away.
    pub fn close_all(&mut self) -> usize {
        let count = self.fds.len();
        self.fds.clear();
        count
    }

    /// Check if fd table is empty
    #[expect(dead_code, reason = "kept for targeted debug and future assertions")]
    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}
