// SPDX-License-Identifier: MPL-2.0

use crate::{sync::GuardTransfer, task::atomic_mode::InAtomicMode};

/// A guard for disable preempt.
#[clippy::has_significant_drop]
#[must_use]
#[derive(Debug)]
pub struct DisabledPreemptGuard {
    // This private field prevents user from constructing values of this type directly.
    _private: (),
}

impl !Send for DisabledPreemptGuard {}

// Required by `InAtomicMode`. See the safety section of its doc comments.
impl !Sync for DisabledPreemptGuard {}

// SAFETY:
// 1. The guard disables preemptions;
// 2. The guard cannot be moved to or used by other tasks.
unsafe impl InAtomicMode for DisabledPreemptGuard {}

impl DisabledPreemptGuard {
    fn new() -> Self {
        // Keep the image-local and shared counts consistent across virtual IRQ
        // delivery, which may switch to another task on this vCPU.
        #[cfg(feature = "kernelet")]
        {
            let irq_guard = crate::irq::disable_local();
            let access = crate::arch::cpu::local::CpuLocalAccess::new(&irq_guard);
            super::cpu_local::inc_guard_count_with(&access);
            crate::kernelet::entry::enter_preempt_guard(access.record());
        }
        #[cfg(not(feature = "kernelet"))]
        super::cpu_local::inc_guard_count();
        Self { _private: () }
    }
}

impl GuardTransfer for DisabledPreemptGuard {
    fn transfer_to(&mut self) -> Self {
        disable_preempt()
    }
}

impl Drop for DisabledPreemptGuard {
    fn drop(&mut self) {
        // Native guard release keeps upstream scheduling boundaries. Carriers
        // enter the Host scheduler through dedicated service points.
        #[cfg(feature = "kernelet")]
        {
            let irq_guard = crate::irq::disable_local();
            let access = crate::arch::cpu::local::CpuLocalAccess::new(&irq_guard);
            super::cpu_local::dec_guard_count_with(&access);
            crate::kernelet::entry::leave_preempt_guard(access.record());
        }
        #[cfg(not(feature = "kernelet"))]
        super::cpu_local::dec_guard_count();
    }
}

/// Disables preemption.
pub fn disable_preempt() -> DisabledPreemptGuard {
    DisabledPreemptGuard::new()
}
