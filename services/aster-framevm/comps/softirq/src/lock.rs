// SPDX-License-Identifier: MPL-2.0

#[cfg(ktest)]
use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(not(ktest))]
use ostd::{
    cpu_local_cell,
    irq::{InterruptLevel, disable_local},
};
use ostd::{
    sync::{GuardTransfer, SpinGuardian},
    task::{DisabledPreemptGuard, atomic_mode::AsAtomicModeGuard, disable_preempt},
};

#[cfg(not(ktest))]
use crate::process_all_pending;

#[cfg(not(ktest))]
cpu_local_cell! {
    static DISABLE_SOFTIRQ_COUNT: u8 = 0;
}

// Kernel-mode component tests execute on the Host test task rather than a
// FrameVM vCPU. Keep their lock-guardian accounting local to the test image;
// production code must continue to require a FrameVM CPU-local slot.
#[cfg(ktest)]
static DISABLE_SOFTIRQ_COUNT: AtomicU8 = AtomicU8::new(0);

/// Returns whether softirq is enabled on local CPU.
pub(super) fn is_softirq_enabled() -> bool {
    disable_count() == 0
}

#[inline]
fn disable_count() -> u8 {
    #[cfg(ktest)]
    {
        return DISABLE_SOFTIRQ_COUNT.load(Ordering::Acquire);
    }

    #[cfg(not(ktest))]
    {
        DISABLE_SOFTIRQ_COUNT.load()
    }
}

#[inline]
fn increment_disable_count() {
    #[cfg(ktest)]
    {
        DISABLE_SOFTIRQ_COUNT.fetch_add(1, Ordering::AcqRel);
    }

    #[cfg(not(ktest))]
    {
        DISABLE_SOFTIRQ_COUNT.add_assign(1);
    }
}

#[inline]
fn decrement_disable_count() {
    #[cfg(ktest)]
    {
        DISABLE_SOFTIRQ_COUNT.fetch_sub(1, Ordering::AcqRel);
    }

    #[cfg(not(ktest))]
    {
        DISABLE_SOFTIRQ_COUNT.sub_assign(1);
    }
}

/// A guardian that disables bottom half while holding a lock.
pub enum BottomHalfDisabled {}

/// A guard for disabled local softirqs.
pub struct DisableLocalBottomHalfGuard {
    preempt: DisabledPreemptGuard,
}

impl AsAtomicModeGuard for DisableLocalBottomHalfGuard {
    type Inner = <DisabledPreemptGuard as AsAtomicModeGuard>::Inner;

    fn get_inner(&self) -> &Self::Inner {
        self.preempt.get_inner()
    }
}

impl Drop for DisableLocalBottomHalfGuard {
    fn drop(&mut self) {
        #[cfg(ktest)]
        {
            decrement_disable_count();
            return;
        }

        #[cfg(not(ktest))]
        self.drop_in_framevm();
    }
}

impl DisableLocalBottomHalfGuard {
    #[cfg(not(ktest))]
    fn drop_in_framevm(&mut self) {
        let in_task_context = InterruptLevel::current().is_task_context();
        // Once the guard is dropped, we will process pending items within
        // the current thread's context if softirq is going to be enabled.
        // This behavior is similar to how Linux handles pending softirqs.
        if disable_count() == 1 && in_task_context {
            // Preemption and softirq are not really enabled at the moment,
            // so we can guarantee that we'll process any pending softirqs for the current CPU.
            let irq_guard = disable_local();
            let irq_guard = process_all_pending(irq_guard);

            // To avoid race conditions, we should decrease the softirq count first,
            // then drop the IRQ guard.
            decrement_disable_count();
            drop(irq_guard);
            return;
        }

        decrement_disable_count();
    }
}

#[must_use]
fn disable_local_bottom_half() -> DisableLocalBottomHalfGuard {
    // When disabling softirq, we must also disable preemption
    // to avoid the task to be scheduled to other CPUs.
    let preempt = disable_preempt();
    increment_disable_count();
    DisableLocalBottomHalfGuard { preempt }
}

impl GuardTransfer for DisableLocalBottomHalfGuard {
    fn transfer_to(&mut self) -> Self {
        disable_local_bottom_half()
    }
}

impl SpinGuardian for BottomHalfDisabled {
    type Guard = DisableLocalBottomHalfGuard;
    type ReadGuard = DisableLocalBottomHalfGuard;

    fn read_guard() -> Self::ReadGuard {
        disable_local_bottom_half()
    }

    fn guard() -> Self::Guard {
        disable_local_bottom_half()
    }
}

#[cfg(ktest)]
mod test {
    use ostd::{
        prelude::*,
        sync::{RwLock, SpinLock},
    };

    use super::*;

    #[ktest]
    fn spinlock_disable_bh() {
        let lock = SpinLock::<(), BottomHalfDisabled>::new(());

        assert!(is_softirq_enabled());

        let guard = lock.lock();
        assert!(!is_softirq_enabled());

        drop(guard);
        assert!(is_softirq_enabled());
    }

    #[ktest]
    fn nested_spin_lock_disable_bh() {
        let lock1 = SpinLock::<(), BottomHalfDisabled>::new(());
        let lock2 = SpinLock::<(), BottomHalfDisabled>::new(());

        assert!(is_softirq_enabled());

        let guard1 = lock1.lock();
        let guard2 = lock2.lock();
        assert!(!is_softirq_enabled());

        drop(guard1);
        assert!(!is_softirq_enabled());

        drop(guard2);
        assert!(is_softirq_enabled());
    }

    #[ktest]
    fn rwlock_disable_bh() {
        let rwlock: RwLock<(), BottomHalfDisabled> = RwLock::new(());

        assert!(is_softirq_enabled());

        let write_guard = rwlock.write();
        assert!(!is_softirq_enabled());

        drop(write_guard);
        assert!(is_softirq_enabled());
    }

    #[ktest]
    fn nested_rwlock_disable_bh() {
        let rwlock: RwLock<(), BottomHalfDisabled> = RwLock::new(());

        assert!(is_softirq_enabled());

        let read_guard1 = rwlock.read();
        let read_guard2 = rwlock.read();
        assert!(!is_softirq_enabled());

        drop(read_guard1);
        assert!(!is_softirq_enabled());

        drop(read_guard2);
        assert!(is_softirq_enabled());
    }

    #[test]
    fn upgradable_rwlock_disable_bh() {
        let rwlock: RwLock<(), BottomHalfDisabled> = RwLock::new(());

        assert!(is_softirq_enabled());

        let upgrade_guard = rwlock.upread();
        assert!(!is_softirq_enabled());

        let write_guard = upgrade_guard.upgrade();
        assert!(!is_softirq_enabled());

        let read_guard = write_guard.downgrade();
        assert!(!is_softirq_enabled());

        drop(read_guard);
        assert!(is_softirq_enabled());
    }
}
