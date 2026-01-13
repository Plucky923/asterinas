// SPDX-License-Identifier: MPL-2.0

//! Exchangeable trait and RRef for zero-copy data transfer between domains.
//!
//! # Design
//!
//! The `Exchangeable` trait marks types that can be safely transferred between
//! Guest (FrameVM) and Host (Kernel) without copying the data.
//!
//! ## Cross-Domain Ownership Tracking
//!
//! Each `RRef<T>` has an **inline owner field** (AtomicU64) for O(1) ownership
//! transfer and query. The global registry only tracks RRef existence for
//! crash recovery.
//!
//! ## Performance Characteristics
//!
//! - `transfer_to()`: O(1) - single atomic store
//! - `owner()`: O(1) - single atomic load
//! - `new()`: O(1) amortized - atomic ID generation + registry insert
//! - `drop()`: O(1) amortized - registry remove
//!
//! ## Lifecycle
//!
//! 1. `RRef::new()` - Creates RRef with current domain as owner, registers ID
//! 2. `RRef::transfer_to()` - Updates inline owner (O(1) atomic operation)
//! 3. `Drop` - Unregisters ID from registry
//!
//! When a FrameVM is destroyed, all RRefs owned by it are reclaimed by scanning
//! the registry and checking inline owner fields.

#![no_std]
#![deny(unsafe_code)]
#![feature(auto_traits)]
#![feature(negative_impls)]

extern crate alloc;

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use spin::Once;

// ============================================================================
// Domain Identification
// ============================================================================

/// Domain identifier - represents either Host (root kernel) or a FrameVM
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(C)]
pub enum DomainId {
    /// Host (root kernel / Asterinas)
    Host,
    /// FrameVM with numeric identifier
    FrameVM(u32),
}

impl DomainId {
    /// Special constant for Host domain
    pub const HOST: Self = DomainId::Host;

    /// Check if this is the Host domain
    #[inline]
    pub fn is_host(&self) -> bool {
        matches!(self, DomainId::Host)
    }

    /// Check if this is a FrameVM domain
    #[inline]
    pub fn is_framevm(&self) -> bool {
        matches!(self, DomainId::FrameVM(_))
    }

    /// Get FrameVM ID if this is a FrameVM domain
    #[inline]
    pub fn framevm_id(&self) -> Option<u32> {
        match self {
            DomainId::FrameVM(id) => Some(*id),
            DomainId::Host => None,
        }
    }

    /// Encode DomainId to u64 for atomic storage
    /// Host = 0, FrameVM(n) = n + 1
    #[inline]
    const fn to_u64(self) -> u64 {
        match self {
            DomainId::Host => 0,
            DomainId::FrameVM(id) => (id as u64) + 1,
        }
    }

    /// Decode u64 to DomainId
    #[inline]
    const fn from_u64(value: u64) -> Self {
        if value == 0 {
            DomainId::Host
        } else {
            DomainId::FrameVM((value - 1) as u32)
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
// Registry Trait (implemented by FrameVisor)
// ============================================================================

/// Trait for RRef registry operations
///
/// The registry only tracks RRef existence (not ownership).
/// Ownership is stored inline in RRef for O(1) access.
pub trait RRefRegistryOps: Send + Sync {
    /// Register a new RRef ID
    fn register(&self, id: RRefId);

    /// Unregister an RRef ID (called on drop)
    fn unregister(&self, id: RRefId);

    /// Reclaim all RRefs owned by a domain
    /// Returns the list of reclaimed RRef IDs
    fn reclaim_domain(&self, domain: DomainId) -> Vec<RRefId>;
}

/// Global registry instance (set by FrameVisor during initialization)
static REGISTRY: Once<Arc<dyn RRefRegistryOps>> = Once::new();

/// Initialize the global registry (called by FrameVisor)
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

/// Current executing domain (encoded as u64)
static CURRENT_DOMAIN: AtomicU64 = AtomicU64::new(0); // 0 = Host

/// Set the current executing domain
#[inline]
pub fn set_current_domain(domain: DomainId) {
    CURRENT_DOMAIN.store(domain.to_u64(), Ordering::Release);
}

/// Get the current executing domain
#[inline]
pub fn get_current_domain() -> DomainId {
    DomainId::from_u64(CURRENT_DOMAIN.load(Ordering::Acquire))
}

// ============================================================================
// Exchangeable Trait
// ============================================================================

/// Marker trait for types that can be safely transferred between domains
pub auto trait Exchangeable {}

// Types that cannot be exchanged safely (contain raw pointers or references)
impl<T> !Exchangeable for *mut T {}
impl<T> !Exchangeable for *const T {}
impl<T> !Exchangeable for &T {}
impl<T> !Exchangeable for &mut T {}
impl<T> !Exchangeable for [T] {}

// Heap-allocated types are safe to exchange (ownership transfers completely)
impl Exchangeable for Vec<u8> {}
impl<T: Exchangeable + ?Sized> Exchangeable for Box<T> {}

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
/// The registry only tracks existence for crash recovery.
pub struct RRef<T: Exchangeable> {
    /// Unique identifier for registry (0 = consumed/invalid)
    id: RRefId,
    /// Inline owner for O(1) transfer and query
    owner: AtomicU64,
    /// The actual value
    value: Option<T>,
}

impl<T: Exchangeable> RRef<T> {
    /// Create a new RRef with the current domain as owner
    #[inline]
    pub fn new(value: T) -> Self {
        let id = generate_rref_id();
        let owner = get_current_domain();

        if let Some(registry) = get_registry() {
            registry.register(id);
        }

        Self {
            id,
            owner: AtomicU64::new(owner.to_u64()),
            value: Some(value),
        }
    }

    /// Create a new RRef with a specific owner
    #[inline]
    pub fn new_with_owner(value: T, owner: DomainId) -> Self {
        let id = generate_rref_id();

        if let Some(registry) = get_registry() {
            registry.register(id);
        }

        Self {
            id,
            owner: AtomicU64::new(owner.to_u64()),
            value: Some(value),
        }
    }

    /// Get the unique ID of this RRef
    #[inline]
    pub fn id(&self) -> RRefId {
        self.id
    }

    /// Check if this RRef has been consumed
    #[inline]
    pub fn is_consumed(&self) -> bool {
        self.value.is_none()
    }

    /// Get the current owner of this RRef
    ///
    /// **Performance**: O(1) - single atomic load
    #[inline]
    pub fn owner(&self) -> DomainId {
        DomainId::from_u64(self.owner.load(Ordering::Acquire))
    }

    /// Transfer ownership to another domain
    ///
    /// **Performance**: O(1) - single atomic store
    #[inline]
    pub fn transfer_to(self, new_owner: DomainId) -> Self {
        self.owner.store(new_owner.to_u64(), Ordering::Release);
        self
    }

    /// Check if the current domain owns this RRef
    #[inline]
    pub fn is_owned_by_current(&self) -> bool {
        self.owner() == get_current_domain()
    }

    /// Gets a reference to the inner value
    ///
    /// # Panics
    /// Panics if the RRef has been consumed.
    #[inline]
    pub fn get(&self) -> &T {
        self.value.as_ref().expect("RRef has been consumed")
    }

    /// Gets a mutable reference to the inner value
    ///
    /// # Panics
    /// Panics if the RRef has been consumed.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.value.as_mut().expect("RRef has been consumed")
    }

    /// Try to get a reference to the inner value
    #[inline]
    pub fn try_get(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Try to get a mutable reference to the inner value
    #[inline]
    pub fn try_get_mut(&mut self) -> Option<&mut T> {
        self.value.as_mut()
    }

    /// Consumes the RRef and returns the inner value
    ///
    /// # Panics
    /// Panics if the RRef has already been consumed.
    #[inline]
    pub fn into_inner(mut self) -> T {
        let value = self.value.take().expect("RRef has already been consumed");

        if let Some(registry) = get_registry() {
            registry.unregister(self.id);
        }

        self.id = RREF_ID_INVALID;
        value
    }

    /// Try to consume the RRef and return the inner value
    #[inline]
    pub fn try_into_inner(mut self) -> Option<T> {
        let value = self.value.take()?;

        if let Some(registry) = get_registry() {
            registry.unregister(self.id);
        }

        self.id = RREF_ID_INVALID;
        Some(value)
    }
}

impl<T: Exchangeable> Drop for RRef<T> {
    fn drop(&mut self) {
        if self.id != RREF_ID_INVALID {
            if let Some(registry) = get_registry() {
                registry.unregister(self.id);
            }
        }
    }
}

impl<T: Exchangeable> core::ops::Deref for RRef<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<T: Exchangeable> core::ops::DerefMut for RRef<T> {
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
}
