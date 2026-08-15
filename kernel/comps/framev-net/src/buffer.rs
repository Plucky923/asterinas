// SPDX-License-Identifier: MPL-2.0

use alloc::{boxed::Box, vec::Vec};

/// A move-only token whose release function runs in the allocator domain that
/// created an auxiliary buffer resource.
///
/// The token contains no heap allocation. It can therefore move with
/// [`OwnedNetworkBuffer`] between Host and FrameVM without asking the
/// receiving image to drop a Host-owned `Box` or `Arc`.
pub struct BufferDropGuard {
    token: usize,
    release_fn: fn(usize),
}

impl BufferDropGuard {
    /// Creates a guard that delegates release to `release_fn` with `token`.
    pub const fn new(token: usize, release_fn: fn(usize)) -> Self {
        Self { token, release_fn }
    }

    fn token_if_released_by(&self, release_fn: fn(usize)) -> Option<usize> {
        core::ptr::fn_addr_eq(self.release_fn, release_fn).then_some(self.token)
    }

    fn release(self) {
        (self.release_fn)(self.token);
    }
}

/// Owns CPU-accessible storage for one FrameV-net receive buffer.
pub struct OwnedNetworkBuffer {
    bytes: Option<Box<[u8]>>,
    reclaimer_fn: fn(Box<[u8]>),
    drop_guard: Option<BufferDropGuard>,
}

impl OwnedNetworkBuffer {
    /// Creates a buffer owned by the image that allocates `bytes`.
    ///
    /// A buffer created this way must not be retained by Host after a service
    /// boundary call. Host-owned buffers use
    /// [`Self::from_boxed_slice_with_drop_guard`] and are admitted by the Host
    /// allocation registry.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self::from_boxed_slice(bytes.into_boxed_slice())
    }

    /// Creates a buffer from a boxed slice and carries one auxiliary release
    /// guard with it.
    ///
    /// The boxed storage and guard are both moved into the returned value, so
    /// the guard is released exactly once when that value is dropped. Host
    /// uses this constructor only after registering the boxed allocation and
    /// binds admission to the registered allocation identity.
    pub fn from_boxed_slice_with_drop_guard(
        bytes: Box<[u8]>,
        drop_guard: BufferDropGuard,
    ) -> Self {
        Self {
            bytes: Some(bytes),
            reclaimer_fn: release_owned_bytes,
            drop_guard: Some(drop_guard),
        }
    }

    fn from_boxed_slice(bytes: Box<[u8]>) -> Self {
        Self {
            bytes: Some(bytes),
            reclaimer_fn: release_owned_bytes,
            drop_guard: None,
        }
    }

    /// Returns the storage length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.as_ref().map_or(0, |bytes| bytes.len())
    }

    /// Returns the storage as immutable bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
            .as_deref()
            .expect("a live network buffer always owns storage")
    }

    /// Returns the storage as mutable bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.bytes
            .as_deref_mut()
            .expect("a live network buffer always owns storage")
    }

    /// Returns the guard token only when `release_fn` is the guard's owner.
    ///
    /// This lets an allocator domain authenticate its own opaque storage
    /// token without exposing the token or release callback as mutable state.
    pub fn token_if_released_by(&self, release_fn: fn(usize)) -> Option<usize> {
        self.drop_guard
            .as_ref()
            .and_then(|guard| guard.token_if_released_by(release_fn))
    }
}

impl Drop for OwnedNetworkBuffer {
    fn drop(&mut self) {
        // Release auxiliary ownership before deallocating the boxed storage.
        // Host binds the unique guard token to the allocation address; removing
        // that token first closes the record before the address can be reused.
        if let Some(drop_guard) = self.drop_guard.take() {
            drop_guard.release();
        }
        if let Some(bytes) = self.bytes.take() {
            (self.reclaimer_fn)(bytes);
        }
    }
}

// The constructor is compiled in the image that creates the boxed storage,
// so this function pointer remains in that image when the buffer crosses the
// Host/FrameVM boundary. No caller can substitute a reclaimer for a foreign
// allocator domain.
fn release_owned_bytes(bytes: Box<[u8]>) {
    drop(bytes);
}
