// SPDX-License-Identifier: MPL-2.0

//! Synchronization primitives.

mod guard;
mod mutex;
mod rwlock;
mod spin_lock;
mod wait_queue;

pub use ::spin::Once;
pub use guard::{GuardTransfer, LocalIrqDisabled, PreemptDisabled, SpinGuardian, WriteIrqDisabled};
pub use mutex::{Mutex, MutexGuard};
pub use rwlock::{RwLock, RwLockReadGuard, RwLockUpgradeableGuard, RwLockWriteGuard};
pub use spin_lock::{SpinLock, SpinLockGuard};
pub use wait_queue::{WaitQueue, Waiter, Waker};
