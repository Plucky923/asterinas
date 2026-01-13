// SPDX-License-Identifier: MPL-2.0

//! RRef Registry - Lightweight tracking of RRef existence for crash recovery
//!
//! # Design
//!
//! The registry only tracks which RRef IDs exist, not their ownership.
//! Ownership is stored inline in each RRef for O(1) access.
//!
//! # Thread Safety
//!
//! Uses sharded locking with HashSet for high throughput:
//! - 64 independent shards reduce lock contention by ~64x
//! - O(1) average insert/remove operations
//!
//! # Crash Recovery
//!
//! When a domain crashes, `reclaim_domain()` must be called with a callback
//! that can check each RRef's inline owner field.

use alloc::{sync::Arc, vec::Vec};

use aster_framevisor_exchangeable::{DomainId, RRefId, RRefRegistryOps};
use hashbrown::HashSet;
use spin::{Mutex, Once};

/// Number of shards (must be power of 2)
const NUM_SHARDS: usize = 64;
const SHARD_MASK: u64 = (NUM_SHARDS - 1) as u64;

/// Initial capacity per shard
const INITIAL_CAPACITY: usize = 4096;

// ============================================================================
// Shard
// ============================================================================

struct Shard {
    ids: Mutex<HashSet<RRefId>>,
}

impl Shard {
    fn new() -> Self {
        Self {
            ids: Mutex::new(HashSet::with_capacity(INITIAL_CAPACITY)),
        }
    }
}

#[inline(always)]
fn shard_index(id: RRefId) -> usize {
    (id & SHARD_MASK) as usize
}

// ============================================================================
// RRef Registry
// ============================================================================

/// Lightweight registry that only tracks RRef existence
///
/// Ownership is stored inline in RRef, so this registry only needs to
/// track which IDs exist for crash recovery purposes.
pub struct RRefRegistry {
    shards: [Shard; NUM_SHARDS],
}

impl RRefRegistry {
    pub fn new() -> Self {
        Self {
            shards: core::array::from_fn(|_| Shard::new()),
        }
    }

    #[inline(always)]
    fn get_shard(&self, id: RRefId) -> &Shard {
        &self.shards[shard_index(id)]
    }

    /// Get total count of registered RRefs
    pub fn count(&self) -> usize {
        self.shards.iter().map(|s| s.ids.lock().len()).sum()
    }

    /// Check if an RRef ID is registered
    pub fn contains(&self, id: RRefId) -> bool {
        self.get_shard(id).ids.lock().contains(&id)
    }

    /// Get all registered RRef IDs (for debugging)
    pub fn all_ids(&self) -> Vec<RRefId> {
        let mut result = Vec::new();
        for shard in &self.shards {
            result.extend(shard.ids.lock().iter().copied());
        }
        result
    }
}

impl Default for RRefRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RRefRegistryOps for RRefRegistry {
    #[inline]
    fn register(&self, id: RRefId) {
        self.get_shard(id).ids.lock().insert(id);
    }

    #[inline]
    fn unregister(&self, id: RRefId) {
        self.get_shard(id).ids.lock().remove(&id);
    }

    fn reclaim_domain(&self, _domain: DomainId) -> Vec<RRefId> {
        // Note: Since ownership is now stored inline in RRef, we cannot
        // determine ownership from the registry alone. The caller must
        // provide a way to check each RRef's owner.
        //
        // For now, this returns an empty list. The actual reclamation
        // should be done by the domain manager which has access to the
        // RRef objects themselves.
        //
        // TODO: Implement proper crash recovery with RRef owner checking
        Vec::new()
    }
}

// ============================================================================
// Global Registry
// ============================================================================

static REGISTRY: Once<Arc<RRefRegistry>> = Once::new();

/// Get the global registry instance
pub fn get_registry() -> &'static Arc<RRefRegistry> {
    REGISTRY.call_once(|| Arc::new(RRefRegistry::new()))
}

/// Initialize the global registry and register with exchangeable crate
pub fn init() {
    let registry = get_registry().clone();
    aster_framevisor_exchangeable::init_registry(registry);
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Register a new RRef ID
#[inline]
pub fn register(id: RRefId) {
    get_registry().register(id);
}

/// Unregister an RRef ID
#[inline]
pub fn unregister(id: RRefId) {
    get_registry().unregister(id);
}

/// Get total count of registered RRefs
pub fn count() -> usize {
    get_registry().count()
}

/// Check if an RRef ID is registered
pub fn contains(id: RRefId) -> bool {
    get_registry().contains(id)
}

/// Reclaim all RRefs owned by a domain
pub fn reclaim_domain(domain: DomainId) -> Vec<RRefId> {
    get_registry().reclaim_domain(domain)
}
