// SPDX-License-Identifier: MPL-2.0

//! Callback Pool for IHT
//!
//! Pre-allocates callback slots to avoid heap allocation in the hot path.
//! This significantly reduces tail latency caused by allocator contention.

use alloc::{boxed::Box, collections::VecDeque, vec::Vec};

use ostd::sync::SpinLock;

/// Default pool capacity per vCPU
pub const DEFAULT_POOL_CAPACITY: usize = 256;

/// Callback slot ID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallbackSlotId(usize);

/// Callback trait object type
pub type CallbackFn = Box<dyn FnOnce() + Send + 'static>;

/// Callback entry that can be either pooled or heap-allocated
pub enum CallbackEntry {
    /// Callback stored in pool slot
    Pooled(CallbackSlotId),
    /// Fallback: heap-allocated callback (when pool is exhausted)
    Boxed(CallbackFn),
}

/// Pre-allocated callback pool (Safe Rust implementation)
///
/// # Design
///
/// - Pre-allocates `capacity` slots at initialization
/// - Allocation is O(1): pop from free list
/// - Deallocation is O(1): push to free list
/// - Falls back to Box::new when pool is exhausted
///
/// # Thread Safety
///
/// Uses SpinLock for thread-safe access. Each vCPU should have its own pool
/// to minimize contention.
pub struct CallbackPool {
    /// Callback storage slots
    slots: SpinLock<Vec<Option<CallbackFn>>>,
    /// Free slot indices (LIFO for cache locality)
    free_list: SpinLock<VecDeque<usize>>,
    /// Pool capacity
    capacity: usize,
}

impl CallbackPool {
    /// Create a new callback pool with pre-allocated slots.
    pub fn new(capacity: usize) -> Self {
        let mut slots = Vec::with_capacity(capacity);
        let mut free_list = VecDeque::with_capacity(capacity);

        // Pre-allocate all slots
        for i in 0..capacity {
            slots.push(None);
            free_list.push_back(i);
        }

        Self {
            slots: SpinLock::new(slots),
            free_list: SpinLock::new(free_list),
            capacity,
        }
    }

    /// Allocate a slot from the pool.
    ///
    /// Returns `None` if pool is exhausted.
    #[inline]
    pub fn alloc<F>(&self, callback: F) -> Option<CallbackSlotId>
    where
        F: FnOnce() + Send + 'static,
    {
        let index = self.free_list.lock().pop_front()?;
        self.slots.lock()[index] = Some(Box::new(callback));
        Some(CallbackSlotId(index))
    }

    /// Take a callback from a slot and return the slot to the pool.
    #[inline]
    pub fn take(&self, id: CallbackSlotId) -> Option<CallbackFn> {
        let callback = self.slots.lock()[id.0].take();
        if callback.is_some() {
            self.free_list.lock().push_back(id.0);
        }
        callback
    }

    /// Allocate with fallback to Box when pool is exhausted.
    ///
    /// This ensures allocation never fails, just potentially slower.
    #[inline]
    pub fn alloc_or_fallback<F>(&self, callback: F) -> CallbackEntry
    where
        F: FnOnce() + Send + 'static,
    {
        // Check if pool has available slots first
        let index = self.free_list.lock().pop_front();
        match index {
            Some(idx) => {
                self.slots.lock()[idx] = Some(Box::new(callback));
                CallbackEntry::Pooled(CallbackSlotId(idx))
            }
            None => CallbackEntry::Boxed(Box::new(callback)),
        }
    }

    /// Get pool capacity.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get number of available (free) slots.
    #[inline]
    pub fn available(&self) -> usize {
        self.free_list.lock().len()
    }

    /// Check if pool is exhausted.
    #[inline]
    pub fn is_exhausted(&self) -> bool {
        self.free_list.lock().is_empty()
    }
}

impl Default for CallbackPool {
    fn default() -> Self {
        Self::new(DEFAULT_POOL_CAPACITY)
    }
}
