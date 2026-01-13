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
//! Each `RRef<T>` is tracked by a global registry in FrameVisor:
//! - **Owner ID**: Which domain (FrameVM or Host) owns the RRef
//! - **Borrow Count**: Number of active immutable borrows
//!
//! When an RRef is moved across domains, the owner ID is updated.
//! When an RRef is borrowed (not moved), the borrow count is incremented.
//!
//! ## Lifecycle
//!
//! 1. `RRef::new()` - Creates RRef and registers with current domain as owner
//! 2. `RRef::transfer_to()` - Moves ownership to another domain
//! 3. `RRef::borrow()` - Creates immutable borrow (increments count)
//! 4. `Drop` - Unregisters from registry when RRef is dropped
//!
//! When a FrameVM is destroyed, all RRefs owned by it are reclaimed.

#![no_std]
#![deny(unsafe_code)]
#![feature(auto_traits)]
#![feature(negative_impls)]

extern crate alloc;

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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
    pub fn is_host(&self) -> bool {
        matches!(self, DomainId::Host)
    }

    /// Check if this is a FrameVM domain
    pub fn is_framevm(&self) -> bool {
        matches!(self, DomainId::FrameVM(_))
    }

    /// Get FrameVM ID if this is a FrameVM domain
    pub fn framevm_id(&self) -> Option<u32> {
        match self {
            DomainId::FrameVM(id) => Some(*id),
            DomainId::Host => None,
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
fn generate_rref_id() -> RRefId {
    NEXT_RREF_ID.fetch_add(1, Ordering::Relaxed)
}

// ============================================================================
// Registry Trait (implemented by FrameVisor)
// ============================================================================

/// Trait for RRef registry operations
///
/// This trait is implemented by FrameVisor to track RRef ownership.
/// The actual implementation lives in `framevisor::rref_registry`.
pub trait RRefRegistryOps: Send + Sync {
    /// Register a new RRef with the given owner
    fn register(&self, id: RRefId, owner: DomainId);

    /// Unregister an RRef (called on drop)
    fn unregister(&self, id: RRefId);

    /// Transfer ownership to a new domain
    fn transfer(&self, id: RRefId, new_owner: DomainId);

    /// Get the current owner of an RRef
    fn get_owner(&self, id: RRefId) -> Option<DomainId>;

    /// Increment borrow count (for immutable borrows)
    fn increment_borrow(&self, id: RRefId);

    /// Decrement borrow count
    fn decrement_borrow(&self, id: RRefId);

    /// Get current borrow count
    fn get_borrow_count(&self, id: RRefId) -> u32;

    /// Reclaim all RRefs owned by a domain (called when domain is destroyed)
    fn reclaim_domain(&self, domain: DomainId) -> Vec<RRefId>;
}

/// Global registry instance (set by FrameVisor during initialization)
/// Uses spin::Once for safe one-time initialization without unsafe code
static REGISTRY: Once<Arc<dyn RRefRegistryOps>> = Once::new();

/// Initialize the global registry (called by FrameVisor)
///
/// This function can only be called once. Subsequent calls will be ignored.
pub fn init_registry(registry: Arc<dyn RRefRegistryOps>) {
    REGISTRY.call_once(|| registry);
}

/// Get the global registry if initialized
fn get_registry() -> Option<&'static Arc<dyn RRefRegistryOps>> {
    REGISTRY.get()
}

// ============================================================================
// Current Domain Tracking
// ============================================================================

/// Thread-local or CPU-local current domain ID
/// For simplicity, we use a global atomic. In production, this should be per-CPU.
static CURRENT_DOMAIN: AtomicU32 = AtomicU32::new(0); // 0 = Host

/// Set the current executing domain
pub fn set_current_domain(domain: DomainId) {
    let value = match domain {
        DomainId::Host => 0,
        DomainId::FrameVM(id) => id + 1, // +1 to distinguish from Host
    };
    CURRENT_DOMAIN.store(value, Ordering::Release);
}

/// Get the current executing domain
pub fn get_current_domain() -> DomainId {
    let value = CURRENT_DOMAIN.load(Ordering::Acquire);
    if value == 0 {
        DomainId::Host
    } else {
        DomainId::FrameVM(value - 1)
    }
}

// ============================================================================
// Exchangeable Trait
// ============================================================================

pub auto trait Exchangeable {}

// Types that cannot be exchanged safely
impl<T> !Exchangeable for *mut T {}
impl<T> !Exchangeable for *const T {}
impl<T> !Exchangeable for &T {}
impl<T> !Exchangeable for &mut T {}
impl<T> !Exchangeable for [T] {}

// Explicitly implement Exchangeable for heap-allocated types
// These are safe because we transfer ownership, not references
// The heap memory remains valid after transfer

/// Vec<u8> is Exchangeable - we transfer ownership of the entire Vec
/// including its heap allocation. The receiver gets full ownership.
impl Exchangeable for Vec<u8> {}

/// Box<T> is Exchangeable if T is Exchangeable
/// We transfer ownership of the boxed value.
impl<T: Exchangeable + ?Sized> Exchangeable for Box<T> {}

// ============================================================================
// RRef - Remote Reference with Ownership Tracking
// ============================================================================

/// Remote Reference - A tracked reference that can be transferred between domains
///
/// Each RRef has a unique ID that is used to track its ownership in a global registry.
/// When an RRef is moved between domains, the registry is updated to reflect the new owner.
pub struct RRef<T: Exchangeable> {
    /// Unique identifier for registry lookup (0 = consumed/invalid)
    id: RRefId,
    /// The actual value (wrapped in Option for safe extraction)
    value: Option<T>,
}

impl<T: Exchangeable> RRef<T> {
    /// Create a new RRef with the current domain as owner
    ///
    /// The RRef is automatically registered with the global registry.
    pub fn new(value: T) -> Self {
        let id = generate_rref_id();
        let owner = get_current_domain();

        // Register with the global registry if available
        if let Some(registry) = get_registry() {
            registry.register(id, owner);
        }

        Self {
            id,
            value: Some(value),
        }
    }

    /// Create a new RRef with a specific owner (for internal use)
    pub fn new_with_owner(value: T, owner: DomainId) -> Self {
        let id = generate_rref_id();

        if let Some(registry) = get_registry() {
            registry.register(id, owner);
        }

        Self {
            id,
            value: Some(value),
        }
    }

    /// Get the unique ID of this RRef
    pub fn id(&self) -> RRefId {
        self.id
    }

    /// Check if this RRef has been consumed
    pub fn is_consumed(&self) -> bool {
        self.value.is_none()
    }

    /// Get the current owner of this RRef
    pub fn owner(&self) -> DomainId {
        if let Some(registry) = get_registry() {
            registry.get_owner(self.id).unwrap_or(get_current_domain())
        } else {
            get_current_domain()
        }
    }

    /// Transfer ownership to another domain
    ///
    /// This updates the registry to reflect the new owner.
    /// The RRef itself is returned (ownership in Rust terms moves with the return value).
    pub fn transfer_to(self, new_owner: DomainId) -> Self {
        if let Some(registry) = get_registry() {
            registry.transfer(self.id, new_owner);
        }
        self
    }

    /// Create an immutable borrow of this RRef
    ///
    /// The borrow count in the registry is incremented.
    /// When the RRefBorrow is dropped, the count is decremented.
    ///
    /// # Panics
    /// Panics if the RRef has been consumed.
    pub fn borrow_tracked(&self) -> RRefBorrow<'_, T> {
        assert!(self.value.is_some(), "Cannot borrow a consumed RRef");
        if let Some(registry) = get_registry() {
            registry.increment_borrow(self.id);
        }
        RRefBorrow { rref: self }
    }

    /// Get the current borrow count
    pub fn borrow_count(&self) -> u32 {
        if let Some(registry) = get_registry() {
            registry.get_borrow_count(self.id)
        } else {
            0
        }
    }

    /// Gets a reference to the inner value
    ///
    /// # Panics
    /// Panics if the RRef has been consumed.
    pub fn get(&self) -> &T {
        self.value.as_ref().expect("RRef has been consumed")
    }

    /// Gets a mutable reference to the inner value
    ///
    /// # Panics
    /// Panics if the RRef has been consumed.
    pub fn get_mut(&mut self) -> &mut T {
        self.value.as_mut().expect("RRef has been consumed")
    }

    /// Try to get a reference to the inner value
    pub fn try_get(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Try to get a mutable reference to the inner value
    pub fn try_get_mut(&mut self) -> Option<&mut T> {
        self.value.as_mut()
    }

    /// Consumes the RRef and returns the inner value
    ///
    /// The RRef is unregistered from the registry.
    ///
    /// # Panics
    /// Panics if the RRef has already been consumed.
    pub fn into_inner(mut self) -> T {
        // Take the value out (this marks the RRef as consumed)
        let value = self.value.take().expect("RRef has already been consumed");

        // Unregister from registry
        if let Some(registry) = get_registry() {
            registry.unregister(self.id);
        }

        // Mark as invalid so Drop doesn't try to unregister again
        self.id = RREF_ID_INVALID;

        value
    }

    /// Try to consume the RRef and return the inner value
    ///
    /// Returns None if the RRef has already been consumed.
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
        // Only unregister if not already consumed (id != INVALID)
        if self.id != RREF_ID_INVALID {
            if let Some(registry) = get_registry() {
                registry.unregister(self.id);
            }
        }
    }
}

impl<T: Exchangeable> core::ops::Deref for RRef<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.value.as_ref().expect("RRef has been consumed")
    }
}

impl<T: Exchangeable> core::ops::DerefMut for RRef<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.value.as_mut().expect("RRef has been consumed")
    }
}

// ============================================================================
// RRefBorrow - Immutable Borrow Guard
// ============================================================================

/// An immutable borrow of an RRef
///
/// When this guard is dropped, the borrow count in the registry is decremented.
pub struct RRefBorrow<'a, T: Exchangeable> {
    rref: &'a RRef<T>,
}

impl<'a, T: Exchangeable> RRefBorrow<'a, T> {
    /// Get the RRef ID
    pub fn id(&self) -> RRefId {
        self.rref.id
    }

    /// Get a reference to the inner value
    pub fn get(&self) -> &T {
        self.rref.get()
    }
}

impl<T: Exchangeable> Drop for RRefBorrow<'_, T> {
    fn drop(&mut self) {
        if let Some(registry) = get_registry() {
            registry.decrement_borrow(self.rref.id);
        }
    }
}

impl<T: Exchangeable> core::ops::Deref for RRefBorrow<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.rref.get()
    }
}

// ============================================================================
// Utility Types
// ============================================================================

/// Result type for registry operations
pub type RegistryResult<T> = Result<T, RegistryError>;

/// Errors that can occur during registry operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    /// RRef ID not found in registry
    NotFound,
    /// RRef is still borrowed and cannot be transferred/dropped
    StillBorrowed,
    /// Domain does not own this RRef
    NotOwner,
    /// Registry not initialized
    NotInitialized,
}
