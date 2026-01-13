// SPDX-License-Identifier: MPL-2.0

//! Simplified Pollee for FrameVM
//!
//! Provides a WaitQueue-based event waiting and waking mechanism
//! for FrameVM socket blocking operations.

use aster_framevisor::sync::WaitQueue;

/// Event waiter for blocking socket operations.
pub struct Pollee {
    wait_queue: WaitQueue,
}

impl Pollee {
    /// Create a new Pollee.
    pub fn new() -> Self {
        Self {
            wait_queue: WaitQueue::new(),
        }
    }

    /// Notify that an event has occurred, waking all waiting tasks.
    pub fn notify(&self) {
        self.wait_queue.wake_all();
    }

    /// Wait until the condition is satisfied.
    pub fn wait_until<F, R>(&self, cond: F) -> R
    where
        F: FnMut() -> Option<R>,
    {
        self.wait_queue.wait_until(cond)
    }
}

impl Default for Pollee {
    fn default() -> Self {
        Self::new()
    }
}
