// SPDX-License-Identifier: MPL-2.0

//! Domain Manager - Lifecycle management for FrameVMs
//!
//! This module tracks active FrameVM domains and handles cleanup when they are destroyed.
//! When a FrameVM is destroyed, all RRefs owned by it are reclaimed via the RRef registry.

use alloc::{collections::BTreeMap, vec::Vec};

use aster_framevisor_exchangeable::DomainId;
use ostd::sync::RwLock;
use spin::Once;

use crate::rref_registry;

// ============================================================================
// Domain Info
// ============================================================================

/// Information about an active domain
#[derive(Debug, Clone)]
pub struct DomainInfo {
    /// Domain identifier
    pub id: DomainId,
    /// Whether the domain is active
    pub active: bool,
}

impl DomainInfo {
    fn new(id: DomainId) -> Self {
        Self { id, active: true }
    }
}

// ============================================================================
// Domain Manager
// ============================================================================

/// Manager for tracking active domains (FrameVMs)
pub struct DomainManager {
    /// Map of active domains
    domains: RwLock<BTreeMap<u32, DomainInfo>>,
    /// Next available FrameVM ID
    next_vm_id: RwLock<u32>,
}

impl DomainManager {
    /// Create a new domain manager
    pub fn new() -> Self {
        Self {
            domains: RwLock::new(BTreeMap::new()),
            next_vm_id: RwLock::new(0),
        }
    }

    /// Register a new FrameVM and return its ID
    pub fn register_framevm(&self) -> u32 {
        let mut next_id = self.next_vm_id.write();
        let vm_id = *next_id;
        *next_id += 1;

        let domain_id = DomainId::FrameVM(vm_id);
        let info = DomainInfo::new(domain_id);

        let mut domains = self.domains.write();
        domains.insert(vm_id, info);

        vm_id
    }

    /// Register a FrameVM with a specific ID
    pub fn register_framevm_with_id(&self, vm_id: u32) {
        let domain_id = DomainId::FrameVM(vm_id);
        let info = DomainInfo::new(domain_id);

        let mut domains = self.domains.write();
        domains.insert(vm_id, info);

        // Update next_vm_id if necessary
        let mut next_id = self.next_vm_id.write();
        if vm_id >= *next_id {
            *next_id = vm_id + 1;
        }
    }

    /// Destroy a FrameVM and reclaim all its resources
    ///
    /// This will:
    /// 1. Mark the domain as inactive
    /// 2. Reclaim all RRefs owned by this domain
    /// 3. Remove the domain from tracking
    pub fn destroy_framevm(&self, vm_id: u32) -> Vec<u64> {
        let domain_id = DomainId::FrameVM(vm_id);

        // Mark as inactive and remove
        {
            let mut domains = self.domains.write();
            if let Some(info) = domains.get_mut(&vm_id) {
                info.active = false;
            }
            domains.remove(&vm_id);
        }

        // Reclaim all RRefs owned by this domain
        rref_registry::reclaim_domain(domain_id)
    }

    /// Check if a FrameVM is active
    pub fn is_active(&self, vm_id: u32) -> bool {
        let domains = self.domains.read();
        domains.get(&vm_id).map(|d| d.active).unwrap_or(false)
    }

    /// Get the number of active FrameVMs
    pub fn active_count(&self) -> usize {
        let domains = self.domains.read();
        domains.values().filter(|d| d.active).count()
    }

    /// Get all active FrameVM IDs
    pub fn active_vm_ids(&self) -> Vec<u32> {
        let domains = self.domains.read();
        domains
            .iter()
            .filter(|(_, d)| d.active)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get domain info
    pub fn get_info(&self, vm_id: u32) -> Option<DomainInfo> {
        let domains = self.domains.read();
        domains.get(&vm_id).cloned()
    }
}

impl Default for DomainManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Instance
// ============================================================================

/// Global domain manager instance
static DOMAIN_MANAGER: Once<DomainManager> = Once::new();

/// Get the global domain manager
pub fn get_manager() -> &'static DomainManager {
    DOMAIN_MANAGER.call_once(DomainManager::new)
}

/// Initialize the domain manager
pub fn init() {
    let _ = get_manager();
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Register a new FrameVM
pub fn register_framevm() -> u32 {
    get_manager().register_framevm()
}

/// Register a FrameVM with a specific ID
pub fn register_framevm_with_id(vm_id: u32) {
    get_manager().register_framevm_with_id(vm_id)
}

/// Destroy a FrameVM
pub fn destroy_framevm(vm_id: u32) -> Vec<u64> {
    get_manager().destroy_framevm(vm_id)
}

/// Check if a FrameVM is active
pub fn is_active(vm_id: u32) -> bool {
    get_manager().is_active(vm_id)
}

/// Get the number of active FrameVMs
pub fn active_count() -> usize {
    get_manager().active_count()
}
