// SPDX-License-Identifier: MPL-2.0

//! Unified Notification Controller for FrameVsock
//!
//! This module provides atomic notification state management to avoid
//! race conditions between wait and notify operations.
//!
//! # Problem Solved
//!
//! The classic wait-notify race condition:
//! ```text
//! T1: Guest checks queue.is_empty() -> true
//! T2: Host delivers packet to queue
//! T3: Host checks recv_waiters -> 0 (Guest not yet waiting)
//! T4: Host decides not to inject interrupt
//! T5: Guest enters wait_queue.wait() and blocks forever
//! ```
//!
//! # Solution
//!
//! Use atomic state machine to ensure notification is never lost:
//! - Register wait BEFORE checking condition
//! - Notify checks state atomically
//! - State transitions are atomic compare-exchange operations

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

/// Notification state machine states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NotifyState {
    /// No waiters, no pending notification
    Idle = 0,
    /// Waiter registered, waiting for notification
    Waiting = 1,
    /// Currently processing events (suppress new interrupts)
    Processing = 2,
    /// Notification pending, waiter should wake up
    Notified = 3,
}

impl From<u8> for NotifyState {
    fn from(val: u8) -> Self {
        match val {
            0 => NotifyState::Idle,
            1 => NotifyState::Waiting,
            2 => NotifyState::Processing,
            3 => NotifyState::Notified,
            _ => NotifyState::Idle,
        }
    }
}

/// I/O event flags (compatible with IoEvents)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Events(u32);

impl Events {
    pub const EMPTY: Self = Self(0);
    pub const IN: Self = Self(1 << 0);
    pub const OUT: Self = Self(1 << 1);
    pub const ERR: Self = Self(1 << 2);
    pub const HUP: Self = Self(1 << 3);

    #[inline]
    pub const fn bits(&self) -> u32 {
        self.0
    }

    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    #[inline]
    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for Events {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for Events {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Atomic notification controller
///
/// Provides race-free wait/notify synchronization using atomic state machine.
///
/// # Usage
///
/// ```ignore
/// // Waiter side (before blocking):
/// controller.register_wait();
/// if condition_met {
///     controller.unregister_wait();
///     return; // fast path
/// }
/// // ... block and wait ...
/// controller.unregister_wait();
///
/// // Notifier side (when event occurs):
/// if controller.try_notify(Events::IN) {
///     inject_interrupt();
/// }
/// ```
pub struct NotifyController {
    state: AtomicU8,
    pending_events: AtomicU32,
    waiter_count: AtomicU32,
}

impl NotifyController {
    /// Create a new notification controller
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(NotifyState::Idle as u8),
            pending_events: AtomicU32::new(0),
            waiter_count: AtomicU32::new(0),
        }
    }

    /// Register as a waiter (call BEFORE checking condition)
    ///
    /// This ensures that any notification after this point will be visible.
    /// Returns the previous waiter count.
    #[inline]
    pub fn register_wait(&self) -> u32 {
        let prev = self.waiter_count.fetch_add(1, Ordering::AcqRel);

        // Try to transition from Idle to Waiting
        let _ = self.state.compare_exchange(
            NotifyState::Idle as u8,
            NotifyState::Waiting as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        prev
    }

    /// Unregister as a waiter (call AFTER waking up or fast-path exit)
    #[inline]
    pub fn unregister_wait(&self) {
        let prev = self.waiter_count.fetch_sub(1, Ordering::AcqRel);

        // If we were the last waiter, try to transition back to Idle
        if prev == 1 {
            let _ = self.state.compare_exchange(
                NotifyState::Waiting as u8,
                NotifyState::Idle as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }

    /// Check if there are any waiters
    #[inline]
    pub fn has_waiters(&self) -> bool {
        self.waiter_count.load(Ordering::Acquire) > 0
    }

    /// Get the current waiter count
    #[inline]
    pub fn waiter_count(&self) -> u32 {
        self.waiter_count.load(Ordering::Acquire)
    }

    /// Try to notify waiters
    ///
    /// Returns `true` if an interrupt should be injected (there are waiters
    /// that need to be woken up), `false` otherwise.
    #[inline]
    pub fn try_notify(&self, events: Events) -> bool {
        // Always record the events
        self.pending_events.fetch_or(events.bits(), Ordering::Release);

        // Check if there are waiters
        if self.waiter_count.load(Ordering::Acquire) > 0 {
            // Try to transition from Waiting to Notified
            match self.state.compare_exchange(
                NotifyState::Waiting as u8,
                NotifyState::Notified as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => true, // Successfully notified, need interrupt
                Err(current) => {
                    // If currently processing, events are recorded but no interrupt needed
                    // If already notified, no additional interrupt needed
                    // If idle (shouldn't happen with waiters), try again
                    if current == NotifyState::Idle as u8 {
                        // Race: waiter just left, but events are recorded
                        true
                    } else {
                        false
                    }
                }
            }
        } else {
            // No waiters, events are recorded for later
            false
        }
    }

    /// Begin processing events (suppresses interrupts during processing)
    #[inline]
    pub fn begin_processing(&self) {
        self.state.store(NotifyState::Processing as u8, Ordering::Release);
    }

    /// End processing and check for new events
    ///
    /// Returns the pending events if any arrived during processing.
    #[inline]
    pub fn end_processing(&self) -> Option<Events> {
        let events = self.pending_events.swap(0, Ordering::AcqRel);

        // Transition based on waiter count
        let new_state = if self.waiter_count.load(Ordering::Acquire) > 0 {
            NotifyState::Waiting as u8
        } else {
            NotifyState::Idle as u8
        };
        self.state.store(new_state, Ordering::Release);

        if events != 0 {
            Some(Events::from_bits(events))
        } else {
            None
        }
    }

    /// Get current state
    #[inline]
    pub fn state(&self) -> NotifyState {
        NotifyState::from(self.state.load(Ordering::Acquire))
    }

    /// Get pending events without clearing
    #[inline]
    pub fn pending_events(&self) -> Events {
        Events::from_bits(self.pending_events.load(Ordering::Acquire))
    }

    /// Clear pending events and return them
    #[inline]
    pub fn take_pending_events(&self) -> Events {
        Events::from_bits(self.pending_events.swap(0, Ordering::AcqRel))
    }
}

impl Default for NotifyController {
    fn default() -> Self {
        Self::new()
    }
}

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
    batch_threshold: u32,
    /// Timestamp of first pending event (nanoseconds since boot)
    first_pending_time_ns: AtomicU64,
    /// Time threshold in nanoseconds - inject if first event is older than this
    time_threshold_ns: u64,
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
            batch_threshold,
            first_pending_time_ns: AtomicU64::new(0),
            // Default: 50 microseconds (50,000 ns) - balance between latency and throughput
            time_threshold_ns: 50_000,
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
            batch_threshold,
            first_pending_time_ns: AtomicU64::new(0),
            time_threshold_ns: time_threshold_us * 1000,
            has_pending: AtomicBool::new(false),
        }
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
        if count >= self.batch_threshold {
            self.reset();
            return true;
        }

        // Check time threshold (only if current_time_ns is provided)
        if current_time_ns > 0 {
            let first_time = self.first_pending_time_ns.load(Ordering::Relaxed);
            if first_time > 0 && current_time_ns.saturating_sub(first_time) >= self.time_threshold_ns
            {
                self.reset();
                return true;
            }
        }

        false
    }

    /// Check if an interrupt should be injected (simplified, no time check)
    ///
    /// # Arguments
    /// - `is_urgent`: If true, always inject (e.g., for control packets)
    /// - `has_waiters`: If true and threshold reached, inject
    ///
    /// Returns `true` if interrupt should be injected
    #[inline]
    pub fn should_inject(&self, is_urgent: bool, has_waiters: bool) -> bool {
        if is_urgent {
            self.pending_count.store(0, Ordering::Relaxed);
            return true;
        }

        if !has_waiters {
            return false;
        }

        let count = self.pending_count.fetch_add(1, Ordering::Relaxed);
        if count >= self.batch_threshold {
            self.pending_count.store(0, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Reset the pending count and timestamp
    #[inline]
    pub fn reset(&self) {
        self.pending_count.store(0, Ordering::Relaxed);
        self.first_pending_time_ns.store(0, Ordering::Relaxed);
        self.has_pending.store(false, Ordering::Release);
    }

    /// Force injection on next call
    #[inline]
    pub fn force_next(&self) {
        self.pending_count
            .store(self.batch_threshold, Ordering::Relaxed);
    }

    /// Check if time threshold exceeded (for external timer-based checks)
    ///
    /// This can be called by a periodic timer to ensure latency bounds
    /// even when the caller doesn't have access to timestamps.
    #[inline]
    pub fn check_time_expired(&self, current_time_ns: u64) -> bool {
        if !self.has_pending.load(Ordering::Acquire) {
            return false;
        }

        let first_time = self.first_pending_time_ns.load(Ordering::Relaxed);
        if first_time > 0 && current_time_ns.saturating_sub(first_time) >= self.time_threshold_ns {
            self.reset();
            return true;
        }

        false
    }

    /// Get pending count (for debugging/monitoring)
    #[inline]
    pub fn pending_count(&self) -> u32 {
        self.pending_count.load(Ordering::Relaxed)
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
    fn test_notify_controller_basic() {
        let ctrl = NotifyController::new();

        // Initially idle with no waiters
        assert_eq!(ctrl.state(), NotifyState::Idle);
        assert!(!ctrl.has_waiters());

        // Notify without waiters should return false
        assert!(!ctrl.try_notify(Events::IN));

        // Register waiter
        ctrl.register_wait();
        assert!(ctrl.has_waiters());
        assert_eq!(ctrl.state(), NotifyState::Waiting);

        // Notify with waiter should return true
        assert!(ctrl.try_notify(Events::IN));
        assert_eq!(ctrl.state(), NotifyState::Notified);

        // Unregister waiter
        ctrl.unregister_wait();
        assert!(!ctrl.has_waiters());
    }

    #[test]
    fn test_interrupt_strategy() {
        let strategy = InterruptStrategy::new(3);

        // Urgent always injects
        assert!(strategy.should_inject(true, false));

        // Without waiters, never inject
        assert!(!strategy.should_inject(false, false));

        // With waiters, inject after threshold
        assert!(!strategy.should_inject(false, true)); // count = 1
        assert!(!strategy.should_inject(false, true)); // count = 2
        assert!(strategy.should_inject(false, true));  // count = 3, inject!
        assert!(!strategy.should_inject(false, true)); // count reset to 1
    }
}
