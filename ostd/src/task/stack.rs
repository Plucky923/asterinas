// SPDX-License-Identifier: MPL-2.0

//! Stack checking and switching utilities.
//!
//! This module provides functionality to:
//! - Check if the current stack has sufficient space
//! - Switch to a service stack when needed
//!
//! # Security Model
//!
//! When an untrusted domain (e.g., FrameVM) calls a trusted domain's API
//! (e.g., FrameVisor), the untrusted domain could maliciously exhaust its
//! stack before making the call. The `ensure_stack!` macro protects against
//! this by checking stack space and switching to a safe service stack if needed.

use core::sync::atomic::{AtomicUsize, Ordering};

use super::Task;

/// Safety margin to keep when checking stack space (1KB).
const STACK_SAFETY_MARGIN: usize = 1024;

/// Boot stack bottom address (used before tasks are created).
static BOOT_STACK_BOTTOM: AtomicUsize = AtomicUsize::new(0);

/// Sets the boot stack bottom address.
///
/// This should be called during early boot before any stack checks.
pub fn set_boot_stack_bottom(addr: usize) {
    BOOT_STACK_BOTTOM.store(addr, Ordering::Release);
}

/// Gets the current stack pointer.
#[inline(always)]
pub fn current_stack_pointer() -> usize {
    let rsp: usize;
    // SAFETY: Reading RSP is a safe operation.
    unsafe {
        core::arch::asm!(
            "mov {}, rsp",
            out(reg) rsp,
            options(nomem, nostack, preserves_flags)
        );
    }
    rsp
}

/// Gets the current task's stack bottom address.
///
/// Returns the boot stack bottom if no task is currently running.
pub fn get_current_stack_bottom() -> usize {
    if let Some(task) = Task::current() {
        task.stack_bottom()
    } else {
        // Bootstrap context or no task
        BOOT_STACK_BOTTOM.load(Ordering::Acquire)
    }
}

/// Returns the remaining stack space in bytes.
#[inline(always)]
pub fn remaining_stack_space() -> usize {
    let current_rsp = current_stack_pointer();
    let stack_bottom = get_current_stack_bottom();
    current_rsp.saturating_sub(stack_bottom)
}

/// Checks if the current stack has at least `required` bytes of space.
///
/// This function adds a safety margin to the required space to account
/// for function call overhead and other stack usage.
///
/// # Arguments
///
/// * `required` - The minimum required stack space in bytes.
///
/// # Returns
///
/// `true` if the stack has sufficient space, `false` otherwise.
#[inline(always)]
pub fn has_sufficient_stack(required: usize) -> bool {
    let remaining = remaining_stack_space();
    remaining >= required.saturating_add(STACK_SAFETY_MARGIN)
}

/// Ensures sufficient stack space before executing code.
///
/// If the current stack has enough space, the code is executed directly
/// (fast path with zero overhead). Otherwise, execution switches to a
/// service stack (slow path).
///
/// # Arguments
///
/// * `$required` - The minimum required stack space in bytes.
/// * `$body` - The code block to execute.
///
/// # Example
///
/// ```ignore
/// use ostd::ensure_stack_impl;
///
/// pub fn api_function(data: &[u8]) -> Result<()> {
///     ensure_stack_impl!(4096, {
///         // This code is guaranteed to have at least 4KB of stack space
///         process_data(data)
///     })
/// }
/// ```
///
/// Note: Prefer using the `#[ostd::ensure_stack(size)]` proc macro attribute
/// on functions instead of this macro directly.
#[macro_export]
macro_rules! ensure_stack_impl {
    ($required:expr, $body:expr) => {{
        if $crate::task::stack::has_sufficient_stack($required) {
            // Fast path: stack space is sufficient, execute directly
            $body
        } else {
            // Slow path: switch to service stack
            $crate::task::stack::with_service_stack(|| $body)
        }
    }};
}

// Re-export the service stack functionality
pub use super::service_stack::with_service_stack;

#[cfg(ktest)]
mod test {
    use super::*;

    #[ktest]
    fn test_remaining_stack_space() {
        let remaining = remaining_stack_space();
        // Should have some stack space
        assert!(remaining > 0);
        // Should be reasonable (less than 1MB)
        assert!(remaining < 1024 * 1024);
    }

    #[ktest]
    fn test_has_sufficient_stack() {
        // Should have enough for small amounts
        assert!(has_sufficient_stack(1024));
        // Should not have enough for huge amounts
        assert!(!has_sufficient_stack(usize::MAX));
    }
}
