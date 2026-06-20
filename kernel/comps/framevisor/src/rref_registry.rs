// SPDX-License-Identifier: MPL-2.0

//! RRef Registry - RedLeaf-style metadata tracking for RRef ownership.
//!
//! # Design
//!
//! The registry records metadata for each live RRef. Ownership is also stored
//! inline in each RRef for O(1) access, but the registry is the auditable table
//! used by FrameVisor to reason about ownership and future cleanup.
//!
//! # Thread Safety
//!
//! Uses sharded locking with HashMap for high throughput:
//! - 64 independent shards reduce lock contention by ~64x
//! - O(1) average insert/remove operations
//!
//! Fault recovery remains out of scope for the first phase. `reclaim_domain()`
//! only marks owned RRefs as reclaim candidates and returns their IDs; forced
//! typed reclamation will be added with the later recovery design.

use alloc::{sync::Arc, vec::Vec};

use aster_framevisor_exchangeable::{
    DomainId, RREF_ID_INVALID, RRefId, RRefMetadata, RRefRegistryOps, init_current_domain_provider,
};
use hashbrown::{HashMap, hash_map::Entry};

use crate::sync::{Mutex, Once};

/// Number of shards (must be power of 2)
const NUM_SHARDS: usize = 64;
const SHARD_MASK: u64 = (NUM_SHARDS - 1) as u64;

/// Initial capacity per shard
const INITIAL_CAPACITY: usize = 4096;

// ============================================================================
// Shard
// ============================================================================

struct Shard {
    entries: Mutex<HashMap<RRefId, RRefMetadata>>,
}

impl Shard {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::with_capacity(INITIAL_CAPACITY)),
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

/// Registry that tracks RRef metadata.
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
        self.shards.iter().map(|s| s.entries.lock().len()).sum()
    }

    /// Check if an RRef ID is registered
    pub fn contains(&self, id: RRefId) -> bool {
        self.get_shard(id).entries.lock().contains_key(&id)
    }

    /// Get all registered RRef IDs (for debugging)
    pub fn all_ids(&self) -> Vec<RRefId> {
        let mut result = Vec::new();
        for shard in &self.shards {
            result.extend(shard.entries.lock().keys().copied());
        }
        result
    }

    /// Returns metadata for an RRef ID.
    pub fn metadata(&self, id: RRefId) -> Option<RRefMetadata> {
        self.get_shard(id).entries.lock().get(&id).copied()
    }

    /// Returns all registered metadata snapshots.
    pub fn all_metadata(&self) -> Vec<RRefMetadata> {
        let mut result = Vec::new();
        for shard in &self.shards {
            result.extend(shard.entries.lock().values().copied());
        }
        result
    }

    /// Registers metadata if the ID is not already present.
    pub fn try_register(&self, metadata: RRefMetadata) -> bool {
        if metadata.id() == RREF_ID_INVALID {
            return false;
        }

        let mut entries = self.get_shard(metadata.id()).entries.lock();
        match entries.entry(metadata.id()) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(metadata);
                true
            }
        }
    }

    /// Removes and returns metadata if the ID is currently registered.
    pub fn try_unregister(&self, id: RRefId) -> Option<RRefMetadata> {
        self.get_shard(id).entries.lock().remove(&id)
    }
}

impl Default for RRefRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RRefRegistryOps for RRefRegistry {
    #[inline]
    fn register(&self, metadata: RRefMetadata) {
        assert!(
            self.try_register(metadata),
            "duplicate or invalid RRef registration"
        );
    }

    #[inline]
    fn unregister(&self, id: RRefId) -> RRefMetadata {
        self.try_unregister(id)
            .expect("unregistering unknown RRef ID")
    }

    fn transfer(&self, id: RRefId, current_owner: DomainId, new_owner: DomainId) -> bool {
        let mut entries = self.get_shard(id).entries.lock();
        let Some(metadata) = entries.get_mut(&id) else {
            return false;
        };
        metadata.try_transfer_to(current_owner, new_owner)
    }

    fn begin_borrow(&self, id: RRefId) -> bool {
        let mut entries = self.get_shard(id).entries.lock();
        let Some(metadata) = entries.get_mut(&id) else {
            return false;
        };
        metadata.begin_borrow()
    }

    fn end_borrow(&self, id: RRefId) -> bool {
        let mut entries = self.get_shard(id).entries.lock();
        let Some(metadata) = entries.get_mut(&id) else {
            return false;
        };
        metadata.end_borrow()
    }

    fn metadata(&self, id: RRefId) -> Option<RRefMetadata> {
        RRefRegistry::metadata(self, id)
    }

    fn reclaim_domain(&self, domain: DomainId) -> Vec<RRefId> {
        let mut reclaimed = Vec::new();
        for shard in &self.shards {
            let mut entries = shard.entries.lock();
            for metadata in entries.values_mut() {
                if metadata.owner() == domain && metadata.mark_reclaim_candidate() {
                    reclaimed.push(metadata.id());
                }
            }
        }
        reclaimed
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
    init_current_domain_provider(current_domain);
}

fn current_domain() -> DomainId {
    crate::task::current_frame_task_group_id()
        .map(|task_group_id| DomainId::Service(task_group_id.vm_id()))
        .unwrap_or(DomainId::Host)
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Get total count of registered RRefs
pub fn count() -> usize {
    get_registry().count()
}

/// Check if an RRef ID is registered
pub fn contains(id: RRefId) -> bool {
    get_registry().contains(id)
}

/// Returns metadata for an RRef ID.
pub fn metadata(id: RRefId) -> Option<RRefMetadata> {
    get_registry().metadata(id)
}

/// Returns all registered metadata snapshots.
pub fn all_metadata() -> Vec<RRefMetadata> {
    get_registry().all_metadata()
}

#[cfg(ktest)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use aster_framevisor_exchangeable::{RRef, RRefState, RegistryError, enter_domain};
    use host_ostd::prelude::ktest;

    use super::*;

    struct DropProbe;

    impl Drop for DropProbe {
        fn drop(&mut self) {
            DROP_PROBE_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl aster_framevisor_exchangeable::Exchangeable for DropProbe {}

    static DROP_PROBE_COUNT: AtomicUsize = AtomicUsize::new(0);

    #[ktest]
    fn metadata_tracks_owner_transfer_and_borrow_state() {
        let registry = RRefRegistry::new();
        let id = 42;
        registry.register(RRefMetadata::new::<u64>(id, DomainId::Host));

        let metadata = registry.metadata(id).unwrap();
        assert_eq!(metadata.owner(), DomainId::Host);
        assert_eq!(metadata.borrow_count(), 0);
        assert_eq!(metadata.state(), RRefState::Live);

        assert!(registry.transfer(id, DomainId::Host, DomainId::Service(7)));
        let metadata = registry.metadata(id).unwrap();
        assert_eq!(metadata.owner(), DomainId::Service(7));
        assert_eq!(metadata.state(), RRefState::Live);

        assert!(registry.begin_borrow(id));
        let metadata = registry.metadata(id).unwrap();
        assert_eq!(metadata.borrow_count(), 1);
        assert_eq!(metadata.state(), RRefState::Borrowed);

        assert!(registry.end_borrow(id));
        let metadata = registry.metadata(id).unwrap();
        assert_eq!(metadata.borrow_count(), 0);
        assert_eq!(metadata.state(), RRefState::Live);
    }

    #[ktest]
    fn transfer_rejects_wrong_owner_and_borrowed_rref() {
        let registry = RRefRegistry::new();
        let id = 43;
        registry.register(RRefMetadata::new::<u64>(id, DomainId::Host));

        assert!(!registry.transfer(id, DomainId::Service(1), DomainId::Service(2)));
        assert_eq!(registry.metadata(id).unwrap().owner(), DomainId::Host);

        assert!(registry.begin_borrow(id));
        assert!(!registry.transfer(id, DomainId::Host, DomainId::Service(1)));
        assert_eq!(registry.metadata(id).unwrap().owner(), DomainId::Host);
        assert_eq!(registry.metadata(id).unwrap().state(), RRefState::Borrowed);
    }

    #[ktest]
    fn duplicate_registration_is_rejected_without_overwriting_metadata() {
        let registry = RRefRegistry::new();
        let id = 45;

        assert!(registry.try_register(RRefMetadata::new::<u64>(id, DomainId::Host)));
        assert!(!registry.try_register(RRefMetadata::new::<u64>(id, DomainId::Service(1),)));

        let metadata = registry.metadata(id).unwrap();
        assert_eq!(metadata.owner(), DomainId::Host);
        assert_eq!(registry.count(), 1);
    }

    #[ktest]
    fn invalid_registration_is_rejected() {
        let registry = RRefRegistry::new();

        assert!(!registry.try_register(RRefMetadata::new::<u64>(RREF_ID_INVALID, DomainId::Host,)));
        assert_eq!(registry.count(), 0);
    }

    #[ktest]
    fn unregister_returns_removed_metadata() {
        let registry = RRefRegistry::new();
        let id = 46;

        assert!(registry.try_register(RRefMetadata::new::<u64>(id, DomainId::Host)));
        let metadata = registry.try_unregister(id).unwrap();
        assert_eq!(metadata.id(), id);
        assert_eq!(metadata.owner(), DomainId::Host);
        assert!(registry.try_unregister(id).is_none());
        assert_eq!(registry.count(), 0);
    }

    #[ktest]
    fn metadata_records_allocation_and_typed_drop_entry() {
        let registry = RRefRegistry::new();
        let id = 44;
        let allocation_addr = 0x1000;
        registry.register(RRefMetadata::new_with_allocation::<u64>(
            id,
            DomainId::Host,
            allocation_addr,
        ));

        let metadata = registry.metadata(id).unwrap();
        assert_eq!(metadata.allocation_addr(), allocation_addr);
        assert_eq!(metadata.type_id(), core::any::TypeId::of::<u64>());
        assert_eq!(metadata.type_name(), core::any::type_name::<u64>());
        (metadata.drop_fn())(metadata.id());
    }

    #[ktest]
    fn reclaim_domain_marks_only_owned_rrefs() {
        let registry = RRefRegistry::new();
        registry.register(RRefMetadata::new::<u64>(1, DomainId::Host));
        registry.register(RRefMetadata::new::<u64>(2, DomainId::Service(1)));
        registry.register(RRefMetadata::new::<u64>(3, DomainId::Service(2)));

        let reclaimed = registry.reclaim_domain(DomainId::Service(1));
        assert_eq!(reclaimed, Vec::from([2]));
        assert_eq!(registry.metadata(1).unwrap().state(), RRefState::Live);
        assert_eq!(registry.metadata(2).unwrap().state(), RRefState::Reclaimed);
        assert_eq!(registry.metadata(3).unwrap().state(), RRefState::Live);
    }

    #[ktest]
    fn reclaim_domain_waits_for_active_borrows() {
        let registry = RRefRegistry::new();
        registry.register(RRefMetadata::new::<u64>(1, DomainId::Service(1)));

        assert!(registry.begin_borrow(1));

        let reclaimed = registry.reclaim_domain(DomainId::Service(1));
        assert!(reclaimed.is_empty());
        let metadata = registry.metadata(1).unwrap();
        assert_eq!(metadata.borrow_count(), 1);
        assert_eq!(metadata.state(), RRefState::ReclaimPending);

        assert!(registry.end_borrow(1));
        let metadata = registry.metadata(1).unwrap();
        assert_eq!(metadata.borrow_count(), 0);
        assert_eq!(metadata.state(), RRefState::Reclaimed);
    }

    #[ktest]
    fn rref_token_transfer_updates_inline_and_registry_owner() {
        init();
        let host_domain_guard = enter_domain(DomainId::Host);
        let rref = RRef::new_with_owner(0x5au64, DomainId::Host);
        let id = rref.id();

        let rref = match rref.try_transfer_to(DomainId::Service(9)) {
            Ok(rref) => rref,
            Err(_) => panic!("host-owned RRef transfer should succeed"),
        };

        assert_eq!(rref.owner(), DomainId::Service(9));
        assert_eq!(metadata(id).unwrap().owner(), DomainId::Service(9));

        drop(host_domain_guard);
        let service_domain_guard = enter_domain(DomainId::Service(9));
        let rref = match rref.try_transfer_to(DomainId::Host) {
            Ok(rref) => rref,
            Err(_) => panic!("service-owned RRef transfer back should succeed"),
        };
        assert_eq!(metadata(id).unwrap().owner(), DomainId::Host);

        drop(service_domain_guard);
        let _host_domain_guard = enter_domain(DomainId::Host);
        drop(rref);
        assert!(!contains(id));
    }

    #[ktest]
    fn rref_failed_transfer_returns_original_token() {
        init();
        let host_domain_guard = enter_domain(DomainId::Host);
        let rref = RRef::new_with_owner(0x77u64, DomainId::Service(10));
        let id = rref.id();

        let rref = match rref.try_transfer_to(DomainId::Host) {
            Ok(_) => panic!("non-owner transfer should fail"),
            Err(error) => {
                assert_eq!(error.error(), RegistryError::NotOwner);
                error.into_rref()
            }
        };

        assert_eq!(rref.owner(), DomainId::Service(10));
        assert_eq!(metadata(id).unwrap().owner(), DomainId::Service(10));

        drop(host_domain_guard);
        let service_domain_guard = enter_domain(DomainId::Service(10));
        let rref = match rref.try_transfer_to(DomainId::Host) {
            Ok(rref) => rref,
            Err(_) => panic!("owner transfer should still succeed after failed transfer"),
        };

        drop(service_domain_guard);
        let _host_domain_guard = enter_domain(DomainId::Host);
        drop(rref);
        assert!(!contains(id));
    }

    #[ktest]
    fn rref_borrow_blocked_transfer_returns_original_token() {
        init();
        let host_domain_guard = enter_domain(DomainId::Host);
        let rref = RRef::new_with_owner(0x88u64, DomainId::Host);
        let id = rref.id();

        assert!(get_registry().begin_borrow(id));
        let rref = match rref.try_transfer_to(DomainId::Service(13)) {
            Ok(_) => panic!("borrowed RRef transfer should fail"),
            Err(error) => {
                assert_eq!(error.error(), RegistryError::TransferBlocked);
                error.into_rref()
            }
        };

        assert_eq!(rref.owner(), DomainId::Host);
        let rref_metadata = metadata(id).unwrap();
        assert_eq!(rref_metadata.owner(), DomainId::Host);
        assert_eq!(rref_metadata.state(), RRefState::Borrowed);

        assert!(get_registry().end_borrow(id));
        let rref_metadata = metadata(id).unwrap();
        assert_eq!(rref_metadata.owner(), DomainId::Host);
        assert_eq!(rref_metadata.state(), RRefState::Live);

        let rref = match rref.try_transfer_to(DomainId::Service(13)) {
            Ok(rref) => rref,
            Err(_) => panic!("transfer should succeed after the borrow ends"),
        };
        assert_eq!(metadata(id).unwrap().owner(), DomainId::Service(13));

        drop(host_domain_guard);
        let _service_domain_guard = enter_domain(DomainId::Service(13));
        drop(rref);
        assert!(!contains(id));
    }

    #[ktest]
    fn rref_try_into_inner_unregisters_without_dropping_value() {
        init();
        DROP_PROBE_COUNT.store(0, Ordering::Relaxed);
        let _host_domain_guard = enter_domain(DomainId::Host);
        let rref = RRef::new_with_owner(DropProbe, DomainId::Host);
        let id = rref.id();

        let value = match rref.try_into_inner() {
            Ok(value) => value,
            Err(_) => panic!("owner should be able to take the inner RRef value"),
        };

        assert!(!contains(id));
        assert_eq!(DROP_PROBE_COUNT.load(Ordering::Relaxed), 0);
        drop(value);
        assert_eq!(DROP_PROBE_COUNT.load(Ordering::Relaxed), 1);
    }

    #[ktest]
    fn rref_drop_unregisters_metadata_even_from_non_owner_domain() {
        init();
        DROP_PROBE_COUNT.store(0, Ordering::Relaxed);
        let _host_domain_guard = enter_domain(DomainId::Host);
        let rref = RRef::new_with_owner(DropProbe, DomainId::Service(12));
        let id = rref.id();

        assert_eq!(metadata(id).unwrap().owner(), DomainId::Service(12));
        drop(rref);

        assert!(!contains(id));
        assert_eq!(DROP_PROBE_COUNT.load(Ordering::Relaxed), 1);
    }

    #[ktest]
    fn rref_try_into_inner_rejects_non_owner_without_unregistering() {
        init();
        let host_domain_guard = enter_domain(DomainId::Host);
        let rref = RRef::new_with_owner(0x99u64, DomainId::Service(11));
        let id = rref.id();

        let rref = match rref.try_into_inner() {
            Ok(_) => panic!("non-owner should not take the inner RRef value"),
            Err(rref) => rref,
        };

        assert_eq!(rref.owner(), DomainId::Service(11));
        assert_eq!(metadata(id).unwrap().owner(), DomainId::Service(11));

        drop(host_domain_guard);
        let service_domain_guard = enter_domain(DomainId::Service(11));
        let rref = match rref.try_transfer_to(DomainId::Host) {
            Ok(rref) => rref,
            Err(_) => panic!("owner should be able to recover the RRef token"),
        };

        drop(service_domain_guard);
        let _host_domain_guard = enter_domain(DomainId::Host);
        drop(rref);
        assert!(!contains(id));
    }
}
