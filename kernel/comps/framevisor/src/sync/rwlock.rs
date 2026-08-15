// SPDX-License-Identifier: MPL-2.0

//! Read-write lock exposed through the OSTD-compatible surface.

use core::{
    fmt,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use host_ostd::task::atomic_mode::{
    AsAtomicModeGuard as OstdAsAtomicModeGuard, InAtomicMode as OstdInAtomicMode,
};
use spin::{
    RwLock as RawRwLock,
    rwlock::{
        RwLockReadGuard as RawRwLockReadGuard, RwLockUpgradableGuard as RawRwLockUpgradableGuard,
        RwLockWriteGuard as RawRwLockWriteGuard,
    },
};

use super::{PreemptDisabled, SpinGuardian};
use crate::task::atomic_mode::AsAtomicModeGuard;

/// A read-write spin lock.
pub struct RwLock<T: ?Sized, G = PreemptDisabled> {
    guard: PhantomData<G>,
    inner: RawRwLock<T>,
}

impl<T, G> RwLock<T, G> {
    /// Creates a new read-write lock.
    pub const fn new(value: T) -> Self {
        Self {
            guard: PhantomData,
            inner: RawRwLock::new(value),
        }
    }
}

impl<T: ?Sized, G: SpinGuardian> RwLock<T, G> {
    /// Acquires a read lock.
    #[track_caller]
    pub fn read(&self) -> RwLockReadGuard<'_, T, G> {
        let guard = G::read_guard();
        let inner = self.inner.read();
        RwLockReadGuard { guard, inner }
    }

    /// Acquires a write lock.
    #[track_caller]
    pub fn write(&self) -> RwLockWriteGuard<'_, T, G> {
        let guard = G::guard();
        let inner = self.inner.write();
        RwLockWriteGuard { guard, inner }
    }

    /// Acquires an upgradeable read lock.
    #[track_caller]
    pub fn upread(&self) -> RwLockUpgradeableGuard<'_, T, G> {
        let guard = G::guard();
        let inner = self.inner.upgradeable_read();
        RwLockUpgradeableGuard { guard, inner }
    }

    /// Tries to acquire a read lock.
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T, G>> {
        let guard = G::read_guard();
        let inner = self.inner.try_read()?;
        Some(RwLockReadGuard { guard, inner })
    }

    /// Tries to acquire a write lock.
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T, G>> {
        let guard = G::guard();
        let inner = self.inner.try_write()?;
        Some(RwLockWriteGuard { guard, inner })
    }

    /// Tries to acquire an upgradeable read lock.
    pub fn try_upread(&self) -> Option<RwLockUpgradeableGuard<'_, T, G>> {
        let guard = G::guard();
        let inner = self.inner.try_upgradeable_read()?;
        Some(RwLockUpgradeableGuard { guard, inner })
    }

    /// Returns mutable access to the protected value.
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }
}

impl<T: ?Sized + fmt::Debug, G> fmt::Debug for RwLock<T, G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(formatter)
    }
}

/// A read lock guard.
#[must_use]
pub struct RwLockReadGuard<'a, T: ?Sized, G: SpinGuardian> {
    guard: G::ReadGuard,
    inner: RawRwLockReadGuard<'a, T>,
}

impl<T: ?Sized, G: SpinGuardian> AsAtomicModeGuard for RwLockReadGuard<'_, T, G> {
    type Inner = <G::ReadGuard as AsAtomicModeGuard>::Inner;

    fn get_inner(&self) -> &Self::Inner {
        self.guard.get_inner()
    }
}

impl<T: ?Sized, G: SpinGuardian> OstdAsAtomicModeGuard for RwLockReadGuard<'_, T, G> {
    fn as_atomic_mode_guard(&self) -> &dyn OstdInAtomicMode {
        self.get_inner().as_atomic_mode_guard()
    }
}

impl<T: ?Sized, G: SpinGuardian> Deref for RwLockReadGuard<'_, T, G> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: ?Sized + fmt::Debug, G: SpinGuardian> fmt::Debug for RwLockReadGuard<'_, T, G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, formatter)
    }
}

/// A write lock guard.
#[must_use]
pub struct RwLockWriteGuard<'a, T: ?Sized, G: SpinGuardian> {
    guard: G::Guard,
    inner: RawRwLockWriteGuard<'a, T>,
}

impl<T: ?Sized, G: SpinGuardian> AsAtomicModeGuard for RwLockWriteGuard<'_, T, G> {
    type Inner = <G::Guard as AsAtomicModeGuard>::Inner;

    fn get_inner(&self) -> &Self::Inner {
        self.guard.get_inner()
    }
}

impl<T: ?Sized, G: SpinGuardian> OstdAsAtomicModeGuard for RwLockWriteGuard<'_, T, G> {
    fn as_atomic_mode_guard(&self) -> &dyn OstdInAtomicMode {
        self.get_inner().as_atomic_mode_guard()
    }
}

impl<T: ?Sized, G: SpinGuardian> Deref for RwLockWriteGuard<'_, T, G> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: ?Sized, G: SpinGuardian> DerefMut for RwLockWriteGuard<'_, T, G> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: ?Sized + fmt::Debug, G: SpinGuardian> fmt::Debug for RwLockWriteGuard<'_, T, G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, formatter)
    }
}

/// An upgradeable read lock guard.
#[must_use]
pub struct RwLockUpgradeableGuard<'a, T: ?Sized, G: SpinGuardian> {
    guard: G::Guard,
    inner: RawRwLockUpgradableGuard<'a, T>,
}

impl<'a, T: ?Sized, G: SpinGuardian> RwLockUpgradeableGuard<'a, T, G> {
    /// Upgrades this guard to a write guard.
    #[track_caller]
    pub fn upgrade(self) -> RwLockWriteGuard<'a, T, G> {
        let Self { guard, inner } = self;
        RwLockWriteGuard {
            guard,
            inner: inner.upgrade(),
        }
    }
}

impl<T: ?Sized, G: SpinGuardian> AsAtomicModeGuard for RwLockUpgradeableGuard<'_, T, G> {
    type Inner = <G::Guard as AsAtomicModeGuard>::Inner;

    fn get_inner(&self) -> &Self::Inner {
        self.guard.get_inner()
    }
}

impl<T: ?Sized, G: SpinGuardian> OstdAsAtomicModeGuard for RwLockUpgradeableGuard<'_, T, G> {
    fn as_atomic_mode_guard(&self) -> &dyn OstdInAtomicMode {
        self.get_inner().as_atomic_mode_guard()
    }
}

impl<T: ?Sized, G: SpinGuardian> Deref for RwLockUpgradeableGuard<'_, T, G> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: ?Sized + fmt::Debug, G: SpinGuardian> fmt::Debug for RwLockUpgradeableGuard<'_, T, G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, formatter)
    }
}
