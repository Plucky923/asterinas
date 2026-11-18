// SPDX-License-Identifier: MPL-2.0

//! The IRQ disabling guard.

use crate::{arch::irq as arch_irq, sync::GuardTransfer, task::atomic_mode::InAtomicMode};

/// Disables all IRQs on the current CPU (i.e., locally).
///
/// This function returns a guard object, which will automatically enable local IRQs again when
/// it is dropped. This function works correctly even when it is called in a _nested_ way.
/// The local IRQs shall only be re-enabled when the most outer guard is dropped.
///
/// This function can play nicely with [`SpinLock`] as the type uses this function internally.
/// One can invoke this function even after acquiring a spin lock. And the reversed order is also ok.
///
/// [`SpinLock`]: crate::sync::SpinLock
///
/// # Examples
///
/// ```rust
/// # fn work_with_irq_disabled() {}
/// #
/// use ostd::irq;
///
/// let guard = irq::disable_local();
/// // Do something with IRQs disabled.
/// work_with_irq_disabled();
/// // Re-enable IRQs if they were previously enabled.
/// drop(guard);
/// ```
pub fn disable_local() -> DisabledLocalIrqGuard {
    DisabledLocalIrqGuard::new()
}

/// A guard for disabled local IRQs.
#[clippy::has_significant_drop]
#[must_use]
#[derive(Debug)]
pub struct DisabledLocalIrqGuard {
    was_enabled: bool,
}

impl !Send for DisabledLocalIrqGuard {}

// Required by `InAtomicMode`. See the safety section of its doc comments.
impl !Sync for DisabledLocalIrqGuard {}

// SAFETY:
// 1. The guard disables local IRQs;
// 2. The guard cannot be moved to or used by other tasks.
unsafe impl InAtomicMode for DisabledLocalIrqGuard {}

impl DisabledLocalIrqGuard {
    fn new() -> Self {
        #[cfg(feature = "kernelet")]
        let was_enabled = arch_irq::disable_local_save();
        #[cfg(not(feature = "kernelet"))]
        let was_enabled = {
            let was_enabled = arch_irq::is_local_enabled();
            if was_enabled {
                arch_irq::disable_local();
            }
            was_enabled
        };
        Self { was_enabled }
    }

    /// Borrows an IRQ-disabled entry without changing its mask on Drop.
    ///
    /// # Safety
    ///
    /// Local IRQs must already be disabled and remain so while this guard is used.
    #[cfg(feature = "kernelet")]
    pub(crate) unsafe fn from_disabled() -> Self {
        debug_assert!(!arch_irq::is_local_enabled());
        Self { was_enabled: false }
    }

    /// Masks virtual IRQs for the handoff to the Host.
    ///
    /// The guard leaves IRQs masked on drop. The Host resumes delivery on user return.
    #[cfg(feature = "kernelet")]
    #[inline(always)]
    pub(crate) fn disable_for_user_return(current_task: &crate::task::CurrentTask) -> Self {
        arch_irq::disable_local_for_user_return(current_task);
        Self { was_enabled: false }
    }
}

impl GuardTransfer for DisabledLocalIrqGuard {
    fn transfer_to(&mut self) -> Self {
        let was_enabled = self.was_enabled;
        self.was_enabled = false;
        Self { was_enabled }
    }
}

impl Drop for DisabledLocalIrqGuard {
    fn drop(&mut self) {
        if self.was_enabled {
            arch_irq::enable_local();
        }
    }
}
