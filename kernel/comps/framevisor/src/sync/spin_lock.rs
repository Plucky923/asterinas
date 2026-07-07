// SPDX-License-Identifier: MPL-2.0

//! Spin lock wrapper with virtual preemption and IRQ guard policies.

use core::{
    fmt,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use host_ostd::task::atomic_mode::{
    AsAtomicModeGuard as OstdAsAtomicModeGuard, InAtomicMode as OstdInAtomicMode,
};
use spin::{Mutex, MutexGuard};

use super::{LocalIrqDisabled, PreemptDisabled, SpinGuardian};
use crate::task::atomic_mode::AsAtomicModeGuard;

/// A spin lock whose guard policy controls virtual preemption or local IRQ delivery.
pub struct SpinLock<T: ?Sized, G = PreemptDisabled> {
    phantom: PhantomData<G>,
    inner: Mutex<T>,
}

/// A borrowed spin lock with a different guard policy.
pub struct SpinLockRef<'a, T: ?Sized, G> {
    inner: &'a Mutex<T>,
    phantom: PhantomData<G>,
}

impl<T, G> SpinLock<T, G> {
    /// Creates a spin lock.
    pub const fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
            phantom: PhantomData,
        }
    }
}

impl<T: ?Sized> SpinLock<T, PreemptDisabled> {
    /// Borrows this lock with virtual local IRQ delivery disabled while held.
    pub fn disable_irq(&self) -> SpinLockRef<'_, T, LocalIrqDisabled> {
        SpinLockRef {
            inner: &self.inner,
            phantom: PhantomData,
        }
    }
}

impl<T: ?Sized, G: SpinGuardian> SpinLock<T, G> {
    /// Acquires the spin lock.
    pub fn lock(&self) -> SpinLockGuard<'_, T, G> {
        let guard = G::guard();
        let inner = self.inner.lock();
        SpinLockGuard { inner, guard }
    }

    /// Tries to acquire the spin lock.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T, G>> {
        let guard = G::guard();
        let inner = self.inner.try_lock()?;
        Some(SpinLockGuard { inner, guard })
    }
}

impl<T: ?Sized, G> SpinLock<T, G> {
    /// Returns mutable access to the protected value.
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }
}

impl<'a, T: ?Sized, G: SpinGuardian> SpinLockRef<'a, T, G> {
    /// Acquires the borrowed spin lock.
    pub fn lock(&self) -> SpinLockGuard<'a, T, G> {
        let guard = G::guard();
        let inner = self.inner.lock();
        SpinLockGuard { inner, guard }
    }

    /// Tries to acquire the borrowed spin lock.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'a, T, G>> {
        let guard = G::guard();
        let inner = self.inner.try_lock()?;
        Some(SpinLockGuard { inner, guard })
    }
}

impl<T: ?Sized + fmt::Debug, G> fmt::Debug for SpinLock<T, G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

/// A guard that releases the spin lock and guard policy when dropped.
#[must_use]
pub struct SpinLockGuard<'a, T: ?Sized, G: SpinGuardian> {
    inner: MutexGuard<'a, T>,
    guard: G::Guard,
}

impl<T: ?Sized, G: SpinGuardian> OstdAsAtomicModeGuard for SpinLockGuard<'_, T, G> {
    fn as_atomic_mode_guard(&self) -> &dyn OstdInAtomicMode {
        self.get_inner().as_atomic_mode_guard()
    }
}

impl<T: ?Sized, G: SpinGuardian> AsAtomicModeGuard for SpinLockGuard<'_, T, G> {
    type Inner = <G::Guard as AsAtomicModeGuard>::Inner;

    fn get_inner(&self) -> &Self::Inner {
        self.guard.get_inner()
    }
}

impl<T: ?Sized, G: SpinGuardian> Deref for SpinLockGuard<'_, T, G> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: ?Sized, G: SpinGuardian> DerefMut for SpinLockGuard<'_, T, G> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: ?Sized + fmt::Debug, G: SpinGuardian> fmt::Debug for SpinLockGuard<'_, T, G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}
