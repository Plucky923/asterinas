// SPDX-License-Identifier: MPL-2.0

//! IRQ notification policy for FrameVsock.
//!
//! FrameVsock follows the kernel vsock socket layer for wait/poll readiness.
//! This module only keeps the backend IRQ coalescing policy used when packets
//! are placed onto a vCPU queue.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Interrupt injection strategy for batching and coalescing
///
/// This reduces interrupt overhead during high-throughput scenarios
/// by batching multiple events before injecting an interrupt.
///
/// # Dual-Threshold Design
/// The strategy uses **both** count and time thresholds:
/// - **Count threshold**: Inject after N packets (high throughput optimization)
/// - **Time threshold**: Inject after T nanoseconds (low latency guarantee)
///
/// Whichever threshold is reached first triggers the interrupt.
/// This ensures:
/// - High throughput: Batch many packets, reduce interrupt overhead
/// - Low latency: Never wait too long, even for sparse traffic
pub struct InterruptStrategy {
    /// Number of events since last interrupt
    pending_count: AtomicU32,
    /// Batch threshold - inject after this many events
    batch_threshold: AtomicU32,
    /// Timestamp of first pending event (nanoseconds since boot)
    first_pending_time_ns: AtomicU64,
    /// Time threshold in nanoseconds - inject if first event is older than this
    time_threshold_ns: AtomicU64,
    /// Flag indicating if there are pending events with timestamp recorded
    has_pending: AtomicBool,
}

impl InterruptStrategy {
    /// Create a new interrupt strategy
    ///
    /// # Arguments
    /// - `batch_threshold`: Number of events to accumulate before forcing interrupt
    pub const fn new(batch_threshold: u32) -> Self {
        Self {
            pending_count: AtomicU32::new(0),
            batch_threshold: AtomicU32::new(batch_threshold),
            first_pending_time_ns: AtomicU64::new(0),
            // Default: 50 microseconds (50,000 ns) - balance between latency and throughput
            time_threshold_ns: AtomicU64::new(50_000),
            has_pending: AtomicBool::new(false),
        }
    }

    /// Create a new interrupt strategy with custom time threshold
    ///
    /// # Arguments
    /// - `batch_threshold`: Number of events to accumulate before forcing interrupt
    /// - `time_threshold_us`: Maximum wait time in microseconds
    pub const fn with_time_threshold(batch_threshold: u32, time_threshold_us: u64) -> Self {
        Self {
            pending_count: AtomicU32::new(0),
            batch_threshold: AtomicU32::new(batch_threshold),
            first_pending_time_ns: AtomicU64::new(0),
            time_threshold_ns: AtomicU64::new(time_threshold_us * 1000),
            has_pending: AtomicBool::new(false),
        }
    }

    /// Update batch/time thresholds at runtime.
    #[inline]
    pub fn set_thresholds(&self, batch_threshold: u32, time_threshold_us: u64) {
        let batch_threshold = batch_threshold.max(1);
        self.batch_threshold
            .store(batch_threshold, Ordering::Relaxed);
        self.time_threshold_ns
            .store(time_threshold_us.saturating_mul(1000), Ordering::Relaxed);
    }

    /// Get current batch threshold.
    #[inline]
    pub fn batch_threshold(&self) -> u32 {
        self.batch_threshold.load(Ordering::Relaxed)
    }

    /// Get current time threshold in nanoseconds.
    #[inline]
    pub fn time_threshold_ns(&self) -> u64 {
        self.time_threshold_ns.load(Ordering::Relaxed)
    }

    /// Check if an interrupt should be injected
    ///
    /// # Arguments
    /// - `is_urgent`: If true, always inject (e.g., for control packets)
    /// - `has_waiters`: If true, more aggressive injection
    /// - `current_time_ns`: Current timestamp in nanoseconds (0 to skip time check)
    ///
    /// Returns `true` if interrupt should be injected
    #[inline]
    pub fn should_inject_with_time(
        &self,
        is_urgent: bool,
        has_waiters: bool,
        current_time_ns: u64,
    ) -> bool {
        // Urgent events always trigger immediately
        if is_urgent {
            self.reset();
            return true;
        }

        // No waiters means no need to inject
        if !has_waiters {
            return false;
        }

        // Increment pending count
        let count = self.pending_count.fetch_add(1, Ordering::Relaxed) + 1;

        // Record first pending time if this is the first event
        if !self.has_pending.swap(true, Ordering::AcqRel) {
            self.first_pending_time_ns
                .store(current_time_ns, Ordering::Relaxed);
        }

        // Check count threshold
        let batch_threshold = self.batch_threshold.load(Ordering::Relaxed);
        if count >= batch_threshold {
            self.reset();
            return true;
        }

        // Check time threshold (only if current_time_ns is provided)
        if current_time_ns > 0 {
            let first_time = self.first_pending_time_ns.load(Ordering::Relaxed);
            let time_threshold_ns = self.time_threshold_ns.load(Ordering::Relaxed);
            if time_threshold_ns > 0 {
                if first_time > 0 && current_time_ns.saturating_sub(first_time) >= time_threshold_ns
                {
                    self.reset();
                    return true;
                }
            }
        }

        false
    }

    /// Reset the pending count and timestamp
    #[inline]
    pub fn reset(&self) {
        self.pending_count.store(0, Ordering::Relaxed);
        self.first_pending_time_ns.store(0, Ordering::Relaxed);
        self.has_pending.store(false, Ordering::Release);
    }
}

impl Default for InterruptStrategy {
    fn default() -> Self {
        // Default: inject every 8 events or after 50us, whichever comes first
        Self::new(8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interrupt_strategy() {
        let strategy = InterruptStrategy::new(3);

        // Urgent always injects
        assert!(strategy.should_inject_with_time(true, false, 0));

        // Without waiters, never inject
        assert!(!strategy.should_inject_with_time(false, false, 1));

        // With waiters, inject after threshold
        assert!(!strategy.should_inject_with_time(false, true, 1)); // count = 1
        assert!(!strategy.should_inject_with_time(false, true, 2)); // count = 2
        assert!(strategy.should_inject_with_time(false, true, 3)); // count = 3, inject!
        assert!(!strategy.should_inject_with_time(false, true, 4)); // count reset to 1
    }
}
