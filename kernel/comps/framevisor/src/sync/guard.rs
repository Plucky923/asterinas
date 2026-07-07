// SPDX-License-Identifier: MPL-2.0

//! Guard policies for spin-based locks on the OSTD-compatible surface.

use crate::{
    irq::{DisabledLocalIrqGuard, disable_local},
    task::{DisabledPreemptGuard, atomic_mode::AsAtomicModeGuard, disable_preempt},
};

/// The guard can be transferred atomically.
pub trait GuardTransfer {
    /// Atomically transfers the current guard to a new instance.
    fn transfer_to(&mut self) -> Self;
}

/// A guardian that denotes the guard behavior for holding a spin-based lock.
pub trait SpinGuardian {
    /// The guard type for holding a spin lock or spin-based write lock.
    type Guard: AsAtomicModeGuard + GuardTransfer;

    /// The guard type for holding a spin-based read lock.
    type ReadGuard: AsAtomicModeGuard + GuardTransfer;

    /// Creates a new guard.
    fn guard() -> Self::Guard;

    /// Creates a new read guard.
    fn read_guard() -> Self::ReadGuard;
}

/// A guardian that disables virtual task preemption while holding a lock.
pub enum PreemptDisabled {}

impl SpinGuardian for PreemptDisabled {
    type Guard = DisabledPreemptGuard;
    type ReadGuard = DisabledPreemptGuard;

    fn guard() -> Self::Guard {
        disable_preempt()
    }

    fn read_guard() -> Self::ReadGuard {
        disable_preempt()
    }
}

/// A guardian that disables virtual local IRQ delivery while holding a lock.
pub enum LocalIrqDisabled {}

impl SpinGuardian for LocalIrqDisabled {
    type Guard = DisabledLocalIrqGuard;
    type ReadGuard = DisabledLocalIrqGuard;

    fn guard() -> Self::Guard {
        disable_local()
    }

    fn read_guard() -> Self::ReadGuard {
        disable_local()
    }
}

/// A guardian that disables virtual local IRQ delivery for writers.
pub enum WriteIrqDisabled {}

impl SpinGuardian for WriteIrqDisabled {
    type Guard = DisabledLocalIrqGuard;
    type ReadGuard = DisabledPreemptGuard;

    fn guard() -> Self::Guard {
        disable_local()
    }

    fn read_guard() -> Self::ReadGuard {
        disable_preempt()
    }
}
