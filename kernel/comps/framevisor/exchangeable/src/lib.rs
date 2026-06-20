// SPDX-License-Identifier: MPL-2.0

//! Exchangeable trait and RRef for zero-copy data transfer between domains.
//!
//! # Design
//!
//! The `Exchangeable` trait marks types that can be safely transferred between
//! isolated domains without copying the data.
//!
//! ## Cross-Domain Ownership Tracking
//!
//! Each `RRef<T>` has an **inline owner field** (AtomicU64) for O(1) ownership
//! transfer and query. The global registry stores RedLeaf-style metadata for
//! auditing and future domain cleanup: owner, borrow count, type identity,
//! allocation identity, typed drop metadata, and lifecycle state.
//!
//! ## Performance Characteristics
//!
//! - `try_transfer_to()`: O(1) - single atomic store
//! - `owner()`: O(1) - single atomic load
//! - `try_new()`: O(1) amortized - atomic ID generation + registry insert
//! - `drop()`: O(1) amortized - registry remove
//!
//! ## Lifecycle
//!
//! 1. `RRef::try_new()` - Creates RRef with current domain as owner and registers metadata
//! 2. `RRef::try_transfer_to()` - Verifies the current domain owns the object,
//!    then updates inline owner and registry metadata or returns the original token
//! 3. `RRef::get()` / `Deref` - Verifies the current domain owns the object
//! 4. `Drop` - Unregisters ID from registry

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    any::{TypeId, type_name},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(feature = "ostd-domain")]
use ostd::{
    cpu::PinCurrentCpu,
    irq::{self, DisabledLocalIrqGuard},
};
use spin::Once;

// ============================================================================
// Domain Identification
// ============================================================================

/// Domain identifier for cross-domain exchange ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(C)]
pub enum DomainId {
    /// Host (root kernel / Asterinas)
    Host,
    /// Dynamically loaded OS service with numeric identifier.
    Service(u32),
}

impl DomainId {
    /// Special constant for Host domain
    pub const HOST: Self = DomainId::Host;

    /// Check if this is the Host domain
    #[inline]
    pub fn is_host(&self) -> bool {
        matches!(self, DomainId::Host)
    }

    /// Checks if this is a service domain.
    #[inline]
    pub fn is_service(&self) -> bool {
        matches!(self, DomainId::Service(_))
    }

    /// Returns the service ID if this is a service domain.
    #[inline]
    pub fn service_id(&self) -> Option<u32> {
        match self {
            DomainId::Service(id) => Some(*id),
            DomainId::Host => None,
        }
    }

    /// Encodes `DomainId` to `u64` for atomic storage.
    ///
    /// Host is encoded as `0`; service domain `n` is encoded as `n + 1`.
    #[inline]
    const fn to_u64(self) -> u64 {
        match self {
            DomainId::Host => 0,
            DomainId::Service(id) => (id as u64) + 1,
        }
    }

    /// Decode u64 to DomainId
    #[inline]
    const fn from_u64(value: u64) -> Self {
        if value == 0 {
            DomainId::Host
        } else {
            DomainId::Service((value - 1) as u32)
        }
    }
}

impl Default for DomainId {
    fn default() -> Self {
        DomainId::Host
    }
}

// ============================================================================
// RRef Identification
// ============================================================================

/// Unique identifier for an RRef instance
pub type RRefId = u64;

/// Invalid RRef ID (used for unregistered RRefs)
pub const RREF_ID_INVALID: RRefId = 0;

/// Global counter for generating unique RRef IDs
static NEXT_RREF_ID: AtomicU64 = AtomicU64::new(1);

/// Generate a new unique RRef ID
#[inline]
fn generate_rref_id() -> RRefId {
    NEXT_RREF_ID.fetch_add(1, Ordering::Relaxed)
}

// ============================================================================
// Registry Trait
// ============================================================================

/// Lifecycle state tracked for an RRef.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RRefState {
    /// The object is live and owned by one domain.
    Live,
    /// The object is being moved between domains.
    Moving,
    /// The object is immutably borrowed by another domain.
    Borrowed,
    /// The owner domain has faulted, but active borrows still prevent reclaim.
    ReclaimPending,
    /// The object is marked as reclaimable after owner-domain cleanup.
    Reclaimed,
}

/// Type-erased drop entry for an `RRef` allocation.
///
/// The first phase records this metadata so the registry has the same shape as
/// a RedLeaf-style exchange heap. Forced reclaim remains a later recovery
/// feature; ordinary drops are still driven by the owning `RRef<T>` token.
pub type RRefDropFn = fn(RRefId);

fn typed_drop_marker<T: Exchangeable + 'static>(_: RRefId) {
    let _ = type_name::<T>();
}

/// Metadata recorded by the exchange registry.
#[derive(Clone, Copy, Debug)]
pub struct RRefMetadata {
    id: RRefId,
    owner: DomainId,
    borrow_count: u64,
    type_id: TypeId,
    type_name: &'static str,
    allocation_addr: usize,
    drop_fn: RRefDropFn,
    state: RRefState,
}

impl PartialEq for RRefMetadata {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.owner == other.owner
            && self.borrow_count == other.borrow_count
            && self.type_id == other.type_id
            && self.type_name == other.type_name
            && self.allocation_addr == other.allocation_addr
            && self.drop_fn as usize == other.drop_fn as usize
            && self.state == other.state
    }
}

impl Eq for RRefMetadata {}

impl RRefMetadata {
    /// Creates metadata for a newly allocated `RRef<T>`.
    pub fn new<T: Exchangeable + 'static>(id: RRefId, owner: DomainId) -> Self {
        Self::new_with_allocation::<T>(id, owner, 0)
    }

    /// Creates metadata for a newly allocated `RRef<T>` with allocation identity.
    pub fn new_with_allocation<T: Exchangeable + 'static>(
        id: RRefId,
        owner: DomainId,
        allocation_addr: usize,
    ) -> Self {
        Self {
            id,
            owner,
            borrow_count: 0,
            type_id: TypeId::of::<T>(),
            type_name: type_name::<T>(),
            allocation_addr,
            drop_fn: typed_drop_marker::<T>,
            state: RRefState::Live,
        }
    }

    /// Returns the RRef ID.
    pub const fn id(&self) -> RRefId {
        self.id
    }

    /// Returns the current owner domain.
    pub const fn owner(&self) -> DomainId {
        self.owner
    }

    /// Returns the active immutable borrow count.
    pub const fn borrow_count(&self) -> u64 {
        self.borrow_count
    }

    /// Returns the Rust `TypeId`.
    pub const fn type_id(&self) -> TypeId {
        self.type_id
    }

    /// Returns the Rust type name.
    pub const fn type_name(&self) -> &'static str {
        self.type_name
    }

    /// Returns the stable address of the exchange allocation.
    pub const fn allocation_addr(&self) -> usize {
        self.allocation_addr
    }

    /// Returns the type-erased drop entry associated with this allocation.
    pub const fn drop_fn(&self) -> RRefDropFn {
        self.drop_fn
    }

    /// Returns the lifecycle state.
    pub const fn state(&self) -> RRefState {
        self.state
    }

    /// Updates owner after a completed move transfer.
    pub fn try_transfer_to(&mut self, current_owner: DomainId, owner: DomainId) -> bool {
        if self.owner != current_owner || self.borrow_count != 0 || self.state != RRefState::Live {
            return false;
        }

        self.state = RRefState::Moving;
        self.owner = owner;
        self.state = RRefState::Live;
        true
    }

    /// Records the start of an immutable borrow.
    pub fn begin_borrow(&mut self) -> bool {
        if !matches!(self.state, RRefState::Live | RRefState::Borrowed) {
            return false;
        }

        self.borrow_count = self.borrow_count.saturating_add(1);
        self.state = RRefState::Borrowed;
        true
    }

    /// Records the end of an immutable borrow.
    pub fn end_borrow(&mut self) -> bool {
        let Some(next_count) = self.borrow_count.checked_sub(1) else {
            return false;
        };
        self.borrow_count = next_count;
        if next_count == 0 {
            self.state = if self.state == RRefState::ReclaimPending {
                RRefState::Reclaimed
            } else {
                RRefState::Live
            };
        } else if self.state != RRefState::ReclaimPending {
            self.state = RRefState::Borrowed;
        }
        true
    }

    /// Marks this RRef as a reclaim candidate.
    ///
    /// Returns whether the object can be reclaimed immediately. If active
    /// immutable borrows exist, the object becomes reclaim-pending and reaches
    /// `Reclaimed` only after the final borrow ends.
    pub fn mark_reclaim_candidate(&mut self) -> bool {
        if self.borrow_count == 0 {
            self.state = RRefState::Reclaimed;
            true
        } else {
            self.state = RRefState::ReclaimPending;
            false
        }
    }
}

/// Trait for RRef registry operations.
///
/// Ownership is still stored inline in `RRef` for O(1) access. The registry
/// keeps authoritative metadata for audit, borrow tracking, and future domain
/// cleanup.
pub trait RRefRegistryOps: Send + Sync {
    /// Register a new RRef.
    fn register(&self, metadata: RRefMetadata);

    /// Unregisters an RRef ID and returns its metadata.
    fn unregister(&self, id: RRefId) -> RRefMetadata;

    /// Updates metadata after ownership transfer.
    fn transfer(&self, id: RRefId, current_owner: DomainId, new_owner: DomainId) -> bool;

    /// Starts an immutable borrow.
    fn begin_borrow(&self, id: RRefId) -> bool;

    /// Ends an immutable borrow.
    fn end_borrow(&self, id: RRefId) -> bool;

    /// Returns metadata for an RRef ID.
    fn metadata(&self, id: RRefId) -> Option<RRefMetadata>;

    /// Marks all RRefs owned by a domain as reclaim candidates.
    /// Returns the list of marked RRef IDs.
    fn reclaim_domain(&self, domain: DomainId) -> Vec<RRefId>;
}

/// Global registry instance installed by the domain runtime.
static REGISTRY: Once<Arc<dyn RRefRegistryOps>> = Once::new();

/// Initializes the global registry.
pub fn init_registry(registry: Arc<dyn RRefRegistryOps>) {
    REGISTRY.call_once(|| registry);
}

/// Get the global registry if initialized
#[inline]
fn get_registry() -> Option<&'static Arc<dyn RRefRegistryOps>> {
    REGISTRY.get()
}

// ============================================================================
// Current Domain Tracking
// ============================================================================

type CurrentDomainProvider = fn() -> DomainId;

const DOMAIN_OVERRIDE_NONE: u64 = u64::MAX;
const MAX_DOMAIN_OVERRIDE_CPUS: usize = 256;

/// Fallback executing domain used before a runtime provider is installed.
static DEFAULT_DOMAIN: AtomicU64 = AtomicU64::new(0);
static CURRENT_DOMAIN_PROVIDER: Once<CurrentDomainProvider> = Once::new();
static DOMAIN_OVERRIDES: [AtomicU64; MAX_DOMAIN_OVERRIDE_CPUS] =
    [const { AtomicU64::new(DOMAIN_OVERRIDE_NONE) }; MAX_DOMAIN_OVERRIDE_CPUS];

/// Installs a runtime provider for the current executing domain.
///
/// The runtime uses this to derive the domain from the current execution
/// context instead of relying on process-wide mutable state.
pub fn init_current_domain_provider(provider: CurrentDomainProvider) {
    CURRENT_DOMAIN_PROVIDER.call_once(|| provider);
}

/// Set the current executing domain
#[inline]
pub fn set_current_domain(domain: DomainId) {
    DEFAULT_DOMAIN.store(domain.to_u64(), Ordering::Release);
}

/// Get the current executing domain
#[inline]
pub fn get_current_domain() -> DomainId {
    current_domain_override()
        .or_else(|| CURRENT_DOMAIN_PROVIDER.get().map(|provider| provider()))
        .unwrap_or_else(|| DomainId::from_u64(DEFAULT_DOMAIN.load(Ordering::Acquire)))
}

/// Temporarily switches the current executing domain.
#[derive(Debug)]
#[must_use]
pub struct CurrentDomainGuard {
    cpu_index: usize,
    previous_override: u64,
    #[cfg(feature = "ostd-domain")]
    _irq_guard: DisabledLocalIrqGuard,
}

impl Drop for CurrentDomainGuard {
    fn drop(&mut self) {
        DOMAIN_OVERRIDES[self.cpu_index].store(self.previous_override, Ordering::Release);
    }
}

/// Enters `domain` until the returned guard is dropped.
#[inline]
pub fn enter_domain(domain: DomainId) -> CurrentDomainGuard {
    #[cfg(feature = "ostd-domain")]
    {
        let irq_guard = irq::disable_local();
        let cpu_index = domain_override_cpu_index(irq_guard.current_cpu());
        let previous_override = DOMAIN_OVERRIDES[cpu_index].swap(domain.to_u64(), Ordering::AcqRel);
        return CurrentDomainGuard {
            cpu_index,
            previous_override,
            _irq_guard: irq_guard,
        };
    }

    #[cfg(not(feature = "ostd-domain"))]
    {
        let cpu_index = 0;
        let previous_override = DOMAIN_OVERRIDES[cpu_index].swap(domain.to_u64(), Ordering::AcqRel);
        CurrentDomainGuard {
            cpu_index,
            previous_override,
        }
    }
}

#[cfg(feature = "ostd-domain")]
fn current_domain_override() -> Option<DomainId> {
    let irq_guard = irq::disable_local();
    let cpu_index = domain_override_cpu_index(irq_guard.current_cpu());
    load_domain_override(cpu_index)
}

#[cfg(not(feature = "ostd-domain"))]
fn current_domain_override() -> Option<DomainId> {
    load_domain_override(0)
}

fn load_domain_override(cpu_index: usize) -> Option<DomainId> {
    let raw_domain = DOMAIN_OVERRIDES[cpu_index].load(Ordering::Acquire);
    if raw_domain == DOMAIN_OVERRIDE_NONE {
        None
    } else {
        Some(DomainId::from_u64(raw_domain))
    }
}

#[cfg(feature = "ostd-domain")]
fn domain_override_cpu_index(cpu_id: ostd::cpu::CpuId) -> usize {
    let raw_cpu_id = u32::from(cpu_id) as usize;
    raw_cpu_id.min(MAX_DOMAIN_OVERRIDE_CPUS - 1)
}

// ============================================================================
// Exchangeable Trait
// ============================================================================

/// Marker trait for types explicitly approved for cross-domain exchange.
pub trait Exchangeable: Send {}

impl Exchangeable for () {}

macro_rules! impl_exchangeable_for_copy_values {
    ($($ty:ty),* $(,)?) => {
        $(impl Exchangeable for $ty {})*
    };
}

impl_exchangeable_for_copy_values!(bool, u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

// Heap-backed exchange values must be explicitly approved by protocol type.
// A blanket `Box<T>` implementation would allow a packet to smuggle private
// heap allocations across domains instead of moving one tracked exchange object.
impl Exchangeable for Vec<u8> {}

// ============================================================================
// RRef - Remote Reference with Inline Ownership
// ============================================================================

/// Remote Reference - A tracked reference that can be transferred between domains
///
/// # Performance
///
/// - **Ownership transfer**: O(1) atomic store (no registry lookup)
/// - **Owner query**: O(1) atomic load (no registry lookup)
/// - **Creation/Drop**: O(1) amortized (registry insert/remove)
///
/// # Design
///
/// The owner is stored inline as an `AtomicU64` for fast access.
/// The registry mirrors owner and lifecycle metadata for auditing and future
/// recovery work.
pub struct RRef<T: Exchangeable + 'static> {
    /// Unique identifier for registry (0 = consumed/invalid)
    id: RRefId,
    /// Whether this token has metadata in the global registry.
    registered: bool,
    /// Inline owner for O(1) transfer and query
    owner: AtomicU64,
    /// The exchange allocation owned by this token.
    value: Option<Box<T>>,
}

/// Error returned by a failed ownership transfer.
pub struct RRefTransferError<T: Exchangeable + 'static> {
    rref: RRef<T>,
    error: RegistryError,
}

impl<T: Exchangeable + 'static> RRefTransferError<T> {
    /// Returns the failed `RRef`.
    pub fn into_rref(self) -> RRef<T> {
        self.rref
    }

    /// Returns the transfer error reason.
    pub const fn error(&self) -> RegistryError {
        self.error
    }
}

impl<T: Exchangeable + 'static> RRef<T> {
    /// Creates a new `RRef` with the current domain as owner.
    ///
    /// # Panics
    ///
    /// Panics if the RRef registry has not been initialized.
    #[inline]
    pub fn new(value: T) -> Self {
        Self::try_new(value).expect("RRef registry must be initialized before creating RRefs")
    }

    /// Creates a new `RRef` with a specific owner.
    ///
    /// # Panics
    ///
    /// Panics if the RRef registry has not been initialized.
    #[inline]
    pub fn new_with_owner(value: T, owner: DomainId) -> Self {
        Self::try_new_with_owner(value, owner)
            .expect("RRef registry must be initialized before creating RRefs")
    }

    /// Tries to create a new `RRef` with the current domain as owner.
    #[inline]
    pub fn try_new(value: T) -> Result<Self, RegistryError> {
        Self::try_new_with_owner(value, get_current_domain())
    }

    /// Tries to create a new `RRef` with a specific owner.
    #[inline]
    pub fn try_new_with_owner(value: T, owner: DomainId) -> Result<Self, RegistryError> {
        let Some(registry) = get_registry() else {
            return Err(RegistryError::NotInitialized);
        };

        let id = generate_rref_id();
        let value = Box::new(value);
        let allocation_addr = value.as_ref() as *const T as usize;

        registry.register(RRefMetadata::new_with_allocation::<T>(
            id,
            owner,
            allocation_addr,
        ));

        Ok(Self {
            id,
            registered: true,
            owner: AtomicU64::new(owner.to_u64()),
            value: Some(value),
        })
    }

    /// Get the unique ID of this RRef
    #[inline]
    pub fn id(&self) -> RRefId {
        self.id
    }

    /// Get the current owner of this RRef
    ///
    /// **Performance**: O(1) - single atomic load
    #[inline]
    pub fn owner(&self) -> DomainId {
        DomainId::from_u64(self.owner.load(Ordering::Acquire))
    }

    /// Tries to transfer ownership to another domain.
    #[inline]
    pub fn try_transfer_to(self, new_owner: DomainId) -> Result<Self, RRefTransferError<T>> {
        let current_owner = self.owner();
        if current_owner != get_current_domain() {
            return Err(RRefTransferError {
                rref: self,
                error: RegistryError::NotOwner,
            });
        }

        if self.registered
            && let Some(registry) = get_registry()
            && !registry.transfer(self.id, current_owner, new_owner)
        {
            return Err(RRefTransferError {
                rref: self,
                error: RegistryError::TransferBlocked,
            });
        }

        self.owner.store(new_owner.to_u64(), Ordering::Release);
        Ok(self)
    }

    /// Check if the current domain owns this RRef
    #[inline]
    pub fn is_owned_by_current(&self) -> bool {
        self.owner() == get_current_domain()
    }

    /// Gets a reference to the inner value
    ///
    /// # Panics
    /// Panics if the current domain does not own this `RRef`.
    #[inline]
    pub fn get(&self) -> &T {
        assert!(
            self.is_owned_by_current(),
            "current domain does not own this RRef"
        );
        self.value.as_deref().expect("RRef value is missing")
    }

    /// Gets a mutable reference to the inner value
    ///
    /// # Panics
    /// Panics if the current domain does not own this `RRef`.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        assert!(
            self.is_owned_by_current(),
            "current domain does not own this RRef"
        );
        self.value.as_deref_mut().expect("RRef value is missing")
    }

    /// Try to get a reference to the inner value
    #[inline]
    pub fn try_get(&self) -> Option<&T> {
        if !self.is_owned_by_current() {
            return None;
        }
        self.value.as_deref()
    }

    /// Try to get a mutable reference to the inner value
    #[inline]
    pub fn try_get_mut(&mut self) -> Option<&mut T> {
        if !self.is_owned_by_current() {
            return None;
        }
        self.value.as_deref_mut()
    }

    /// Tries to consume the `RRef` and return the inner value.
    #[inline]
    pub fn try_into_inner(mut self) -> Result<T, Self> {
        if !self.is_owned_by_current() {
            return Err(self);
        }
        if self.value.is_none() {
            return Err(self);
        }

        self.take_registered_metadata_for_value_return();
        let value = self
            .value
            .take()
            .expect("RRef value was checked before metadata removal");
        self.id = RREF_ID_INVALID;
        self.registered = false;
        Ok(*value)
    }

    fn take_registered_metadata_for_value_return(&self) {
        if self.id == RREF_ID_INVALID || !self.registered {
            return;
        }

        if let Some(registry) = get_registry() {
            let _metadata = registry.unregister(self.id);
        }
    }

    fn run_registered_drop_entry(&self, registry: &Arc<dyn RRefRegistryOps>) {
        if self.id == RREF_ID_INVALID || !self.registered {
            return;
        }

        let metadata = registry.unregister(self.id);
        (metadata.drop_fn())(metadata.id());
    }
}

impl<T: Exchangeable + 'static> Drop for RRef<T> {
    fn drop(&mut self) {
        if self.id == RREF_ID_INVALID {
            return;
        }

        if self.registered
            && let Some(registry) = get_registry()
        {
            self.run_registered_drop_entry(registry);
        }
    }
}

impl<T: Exchangeable + 'static> core::ops::Deref for RRef<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<T: Exchangeable + 'static> core::ops::DerefMut for RRef<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.get_mut()
    }
}

// ============================================================================
// Utility Types
// ============================================================================

/// Errors that can occur during registry operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    /// RRef ID not found in registry
    NotFound,
    /// Domain does not own this RRef
    NotOwner,
    /// Registry not initialized
    NotInitialized,
    /// Transfer is blocked by borrow or lifecycle state.
    TransferBlocked,
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use core::sync::atomic::AtomicUsize;

    use super::*;

    struct TestRegistry {
        entries: spin::Mutex<BTreeMap<RRefId, RRefMetadata>>,
    }

    impl TestRegistry {
        fn new() -> Self {
            Self {
                entries: spin::Mutex::new(BTreeMap::new()),
            }
        }
    }

    impl RRefRegistryOps for TestRegistry {
        fn register(&self, metadata: RRefMetadata) {
            let mut entries = self.entries.lock();
            assert!(entries.insert(metadata.id(), metadata).is_none());
        }

        fn unregister(&self, id: RRefId) -> RRefMetadata {
            self.entries.lock().remove(&id).unwrap()
        }

        fn transfer(&self, id: RRefId, current_owner: DomainId, new_owner: DomainId) -> bool {
            let mut entries = self.entries.lock();
            let Some(metadata) = entries.get_mut(&id) else {
                return false;
            };
            metadata.try_transfer_to(current_owner, new_owner)
        }

        fn begin_borrow(&self, id: RRefId) -> bool {
            let mut entries = self.entries.lock();
            let Some(metadata) = entries.get_mut(&id) else {
                return false;
            };
            metadata.begin_borrow()
        }

        fn end_borrow(&self, id: RRefId) -> bool {
            let mut entries = self.entries.lock();
            let Some(metadata) = entries.get_mut(&id) else {
                return false;
            };
            metadata.end_borrow()
        }

        fn metadata(&self, id: RRefId) -> Option<RRefMetadata> {
            self.entries.lock().get(&id).copied()
        }

        fn reclaim_domain(&self, domain: DomainId) -> Vec<RRefId> {
            let mut reclaimed = Vec::new();
            for metadata in self.entries.lock().values_mut() {
                if metadata.owner() == domain && metadata.mark_reclaim_candidate() {
                    reclaimed.push(metadata.id());
                }
            }
            reclaimed
        }
    }

    fn ensure_test_registry() {
        static INIT: Once<()> = Once::new();
        INIT.call_once(|| init_registry(Arc::new(TestRegistry::new())));
    }

    struct DropCounter;

    impl Drop for DropCounter {
        fn drop(&mut self) {
            DROP_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl Exchangeable for DropCounter {}

    static DROP_COUNT: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn drop_releases_registered_value_even_from_non_owner_domain() {
        ensure_test_registry();
        DROP_COUNT.store(0, Ordering::Relaxed);
        let _host_domain_guard = enter_domain(DomainId::Host);

        drop(RRef::new_with_owner(DropCounter, DomainId::Service(1)));
        assert_eq!(DROP_COUNT.load(Ordering::Relaxed), 1);

        drop(RRef::new_with_owner(DropCounter, DomainId::Host));
        assert_eq!(DROP_COUNT.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn failed_transfer_returns_original_token() {
        ensure_test_registry();
        let host_domain_guard = enter_domain(DomainId::Host);
        let rref = RRef::new_with_owner(37u64, DomainId::Service(1));

        let rref = match rref.try_transfer_to(DomainId::Host) {
            Ok(_) => panic!("non-owner transfer should fail"),
            Err(error) => {
                assert_eq!(error.error(), RegistryError::NotOwner);
                error.into_rref()
            }
        };

        assert_eq!(rref.owner(), DomainId::Service(1));
        assert!(rref.try_get().is_none());

        drop(host_domain_guard);
        let _service_domain_guard = enter_domain(DomainId::Service(1));
        assert_eq!(*rref.get(), 37);
    }

    #[test]
    fn try_into_inner_rejects_non_owner_and_preserves_token() {
        ensure_test_registry();
        let host_domain_guard = enter_domain(DomainId::Host);
        let rref = RRef::new_with_owner(41u64, DomainId::Service(2));

        let rref = match rref.try_into_inner() {
            Ok(_) => panic!("non-owner should not take the RRef value"),
            Err(rref) => rref,
        };

        assert_eq!(rref.owner(), DomainId::Service(2));
        assert!(rref.try_get().is_none());

        drop(host_domain_guard);
        let _service_domain_guard = enter_domain(DomainId::Service(2));
        assert_eq!(
            rref.try_into_inner()
                .unwrap_or_else(|_| panic!("owner should take value")),
            41
        );
    }
}
