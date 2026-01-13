// SPDX-License-Identifier: MPL-2.0

//! RRef Registry - Global tracking of RRef ownership across domains
//!
//! This module implements the `RRefRegistryOps` trait to provide:
//! - Ownership tracking: Which domain owns each RRef
//! - Borrow counting: How many immutable borrows exist
//! - Domain reclamation: Clean up all RRefs when a domain is destroyed
//!
//! # Thread Safety
//!
//! The registry uses fine-grained locking:
//! - `entries`: RwLock for the main entry map (read-heavy workload)
//! - `domain_refs`: RwLock for per-domain index (modified on register/unregister)
//! - Per-entry `borrow_count`: AtomicU32 for lock-free borrow counting

use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicU32, Ordering};

use aster_framevisor_exchangeable::{DomainId, RRefId, RRefRegistryOps};
use ostd::sync::RwLock;
use spin::Once;

// ============================================================================
// RRef Entry Metadata
// ============================================================================

/// Metadata for a single RRef entry
pub struct RRefEntry {
    /// Current owner domain
    owner: DomainId,
    /// Number of active immutable borrows
    borrow_count: AtomicU32,
}

impl RRefEntry {
    fn new(owner: DomainId) -> Self {
        Self {
            owner,
            borrow_count: AtomicU32::new(0),
        }
    }
}

// ============================================================================
// RRef Registry Implementation
// ============================================================================

/// Global registry for tracking RRef ownership
pub struct RRefRegistry {
    /// Map from RRef ID to entry metadata
    entries: RwLock<BTreeMap<RRefId, RRefEntry>>,
    /// Index: Domain -> Set of RRef IDs owned by that domain
    /// Used for efficient domain reclamation
    domain_refs: RwLock<BTreeMap<DomainId, BTreeSet<RRefId>>>,
}

impl RRefRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
            domain_refs: RwLock::new(BTreeMap::new()),
        }
    }

    /// Get statistics about the registry
    pub fn stats(&self) -> RegistryStats {
        let entries = self.entries.read();
        let domain_refs = self.domain_refs.read();

        let total_refs = entries.len();
        let total_domains = domain_refs.len();
        let total_borrows: u32 = entries
            .values()
            .map(|e| e.borrow_count.load(Ordering::Relaxed))
            .sum();

        RegistryStats {
            total_refs,
            total_domains,
            total_borrows,
        }
    }

    /// Get all RRef IDs owned by a domain (for debugging)
    pub fn get_domain_refs(&self, domain: DomainId) -> Vec<RRefId> {
        let domain_refs = self.domain_refs.read();
        domain_refs
            .get(&domain)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }
}

impl RRefRegistryOps for RRefRegistry {
    fn register(&self, id: RRefId, owner: DomainId) {
        // Add to main entries map
        {
            let mut entries = self.entries.write();
            entries.insert(id, RRefEntry::new(owner));
        }

        // Add to domain index
        {
            let mut domain_refs = self.domain_refs.write();
            domain_refs.entry(owner).or_default().insert(id);
        }
    }

    fn unregister(&self, id: RRefId) {
        // Remove from main entries map and get owner
        let owner = {
            let mut entries = self.entries.write();
            entries.remove(&id).map(|e| e.owner)
        };

        // Remove from domain index
        if let Some(owner) = owner {
            let mut domain_refs = self.domain_refs.write();
            if let Some(refs) = domain_refs.get_mut(&owner) {
                refs.remove(&id);
                // Clean up empty sets
                if refs.is_empty() {
                    domain_refs.remove(&owner);
                }
            }
        }
    }

    fn transfer(&self, id: RRefId, new_owner: DomainId) {
        let old_owner = {
            let mut entries = self.entries.write();
            if let Some(entry) = entries.get_mut(&id) {
                let old = entry.owner;
                entry.owner = new_owner;
                Some(old)
            } else {
                None
            }
        };

        // Update domain index
        if let Some(old_owner) = old_owner {
            if old_owner != new_owner {
                let mut domain_refs = self.domain_refs.write();

                // Remove from old owner's set
                if let Some(refs) = domain_refs.get_mut(&old_owner) {
                    refs.remove(&id);
                    if refs.is_empty() {
                        domain_refs.remove(&old_owner);
                    }
                }

                // Add to new owner's set
                domain_refs.entry(new_owner).or_default().insert(id);
            }
        }
    }

    fn get_owner(&self, id: RRefId) -> Option<DomainId> {
        let entries = self.entries.read();
        entries.get(&id).map(|e| e.owner)
    }

    fn increment_borrow(&self, id: RRefId) {
        let entries = self.entries.read();
        if let Some(entry) = entries.get(&id) {
            entry.borrow_count.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn decrement_borrow(&self, id: RRefId) {
        let entries = self.entries.read();
        if let Some(entry) = entries.get(&id) {
            // Use saturating sub to prevent underflow
            let old = entry.borrow_count.fetch_sub(1, Ordering::AcqRel);
            debug_assert!(old > 0, "Borrow count underflow for RRef {}", id);
        }
    }

    fn get_borrow_count(&self, id: RRefId) -> u32 {
        let entries = self.entries.read();
        entries
            .get(&id)
            .map(|e| e.borrow_count.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    fn reclaim_domain(&self, domain: DomainId) -> Vec<RRefId> {
        // Get all RRef IDs owned by this domain
        let refs_to_reclaim: Vec<RRefId> = {
            let mut domain_refs = self.domain_refs.write();
            domain_refs
                .remove(&domain)
                .map(|s| s.into_iter().collect())
                .unwrap_or_default()
        };

        // Remove all entries
        if !refs_to_reclaim.is_empty() {
            let mut entries = self.entries.write();
            for id in &refs_to_reclaim {
                entries.remove(id);
            }
        }

        refs_to_reclaim
    }
}

// ============================================================================
// Registry Statistics
// ============================================================================

/// Statistics about the registry state
#[derive(Debug, Clone, Copy)]
pub struct RegistryStats {
    /// Total number of registered RRefs
    pub total_refs: usize,
    /// Total number of domains with RRefs
    pub total_domains: usize,
    /// Total number of active borrows across all RRefs
    pub total_borrows: u32,
}

// ============================================================================
// Global Registry Instance
// ============================================================================

/// Global registry instance
static REGISTRY: Once<Arc<RRefRegistry>> = Once::new();

/// Get the global registry instance
pub fn get_registry() -> &'static Arc<RRefRegistry> {
    REGISTRY.call_once(|| Arc::new(RRefRegistry::new()))
}

/// Initialize the global registry and register with exchangeable crate
///
/// This must be called during FrameVisor initialization, before any RRefs are created.
pub fn init() {
    let registry = get_registry().clone();

    // Register with the exchangeable crate (no unsafe needed)
    aster_framevisor_exchangeable::init_registry(registry);
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Register a new RRef with the given owner
pub fn register(id: RRefId, owner: DomainId) {
    get_registry().register(id, owner);
}

/// Unregister an RRef
pub fn unregister(id: RRefId) {
    get_registry().unregister(id);
}

/// Transfer ownership of an RRef
pub fn transfer(id: RRefId, new_owner: DomainId) {
    get_registry().transfer(id, new_owner);
}

/// Get the owner of an RRef
pub fn get_owner(id: RRefId) -> Option<DomainId> {
    get_registry().get_owner(id)
}

/// Reclaim all RRefs owned by a domain
pub fn reclaim_domain(domain: DomainId) -> Vec<RRefId> {
    get_registry().reclaim_domain(domain)
}

/// Get registry statistics
pub fn stats() -> RegistryStats {
    get_registry().stats()
}
