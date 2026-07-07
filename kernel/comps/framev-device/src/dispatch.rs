//! Bounded synchronous dispatch state.
//!
//! This module defines the common guard used to defer recursive same-ring
//! frontend-to-backend dispatch.

use core::cell::Cell;

/// Same-ring synchronous dispatch entry outcome.
#[derive(Debug)]
pub enum DispatchEnter<'a> {
    Entered(SynchronousDispatchGuard<'a>),
    Deferred,
}

/// Tracks bounded synchronous dispatch for one ring.
#[derive(Debug)]
pub struct SynchronousDispatchState {
    active: Cell<bool>,
    deferred: Cell<bool>,
}

impl SynchronousDispatchState {
    /// Creates an idle dispatch state.
    pub const fn new() -> Self {
        Self {
            active: Cell::new(false),
            deferred: Cell::new(false),
        }
    }

    /// Enters synchronous dispatch or defers recursive same-ring work.
    pub fn enter(&self) -> DispatchEnter<'_> {
        if self.active.get() {
            self.deferred.set(true);
            return DispatchEnter::Deferred;
        }

        self.active.set(true);
        DispatchEnter::Entered(SynchronousDispatchGuard { state: self })
    }

    /// Returns whether dispatch is active.
    pub fn is_active(&self) -> bool {
        self.active.get()
    }

    /// Returns whether recursive work was deferred.
    pub fn has_deferred_work(&self) -> bool {
        self.deferred.get()
    }

    /// Clears the deferred-work hint after scheduling later processing.
    pub fn clear_deferred_work(&self) {
        self.deferred.set(false);
    }
}

/// RAII guard for one active synchronous dispatch entry.
#[derive(Debug)]
pub struct SynchronousDispatchGuard<'a> {
    state: &'a SynchronousDispatchState,
}

impl Drop for SynchronousDispatchGuard<'_> {
    fn drop(&mut self) {
        self.state.active.set(false);
    }
}
