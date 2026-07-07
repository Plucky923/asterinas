// SPDX-License-Identifier: MPL-2.0

//! Mutex exposed through the OSTD-compatible surface.

use core::{
    fmt,
    ops::{Deref, DerefMut},
};

use super::{PreemptDisabled, SpinLock, SpinLockGuard};

/// A mutex.
pub struct Mutex<T: ?Sized> {
    inner: SpinLock<T, PreemptDisabled>,
}

impl<T> Mutex<T> {
    /// Creates a new mutex.
    pub const fn new(value: T) -> Self {
        Self {
            inner: SpinLock::new(value),
        }
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Acquires the mutex.
    #[track_caller]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        MutexGuard {
            mutex: self,
            inner: self.inner.lock(),
        }
    }

    /// Tries to acquire the mutex.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        Some(MutexGuard {
            mutex: self,
            inner: self.inner.try_lock()?,
        })
    }

    /// Returns mutable access to the protected value.
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for Mutex<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

/// A mutex guard.
#[must_use]
pub struct MutexGuard<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
    inner: SpinLockGuard<'a, T, PreemptDisabled>,
}

impl<'a, T: ?Sized> MutexGuard<'a, T> {
    /// Returns the mutex associated with this guard.
    pub fn get_lock(guard: &MutexGuard<'a, T>) -> &'a Mutex<T> {
        guard.mutex
    }
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for MutexGuard<'_, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, formatter)
    }
}
