// SPDX-License-Identifier: MPL-2.0

//! FrameVM management registry.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use host_ostd::sync::RwLock;

use super::{
    FrameSchedGroup, FrameVcpuId, FrameVm, FrameVmConfig, MemoryDomain, VmId, VmStatus,
    instance::{control_memory_charge_bytes, validate_create_args},
};
use crate::{error::Error, prelude::Result, sync::Once};

// ============================================================================
// VM Registry
// ============================================================================

/// VM Registry for managing multiple FrameVM instances.
struct VmRegistry {
    /// Map of VM ID to FrameVM instance.
    vms: BTreeMap<VmId, Arc<FrameVm>>,
    /// Next VM ID to allocate.
    next_vm_id: VmId,
}

impl VmRegistry {
    fn new() -> Self {
        Self {
            vms: BTreeMap::new(),
            next_vm_id: VmId::new(0),
        }
    }

    fn reserve_vm_id(&mut self) -> Result<VmId> {
        while self.vms.contains_key(&self.next_vm_id) {
            self.next_vm_id = self.next_vm_id.checked_add(1).ok_or(Error::InvalidArgs)?;
        }

        let id = self.next_vm_id;
        self.next_vm_id = self.next_vm_id.checked_add(1).ok_or(Error::InvalidArgs)?;
        Ok(id)
    }
}

/// Global VM registry.
static VM_REGISTRY: Once<RwLock<VmRegistry>> = Once::new();

fn get_registry() -> &'static RwLock<VmRegistry> {
    VM_REGISTRY.call_once(|| RwLock::new(VmRegistry::new()))
}

// ============================================================================
// Public API
// ============================================================================

/// Creates a new unstarted FrameVM and returns its ID.
pub fn create_vm(config: FrameVmConfig) -> Result<VmId> {
    validate_create_args(config.vcpu_count, config.share)?;
    let startup_charge_bytes = control_memory_charge_bytes(
        config.vcpu_count,
        config.block_images.len(),
        config.network_configuration.is_some(),
        #[cfg(target_arch = "x86_64")]
        config.reserved_pci.is_some(),
        #[cfg(not(target_arch = "x86_64"))]
        false,
    )?;
    MemoryDomain::validate_limit(config.memory_limit_bytes, startup_charge_bytes)?;

    let id = {
        let mut registry = get_registry().write();
        registry.reserve_vm_id()?
    };
    let vm = Arc::new(FrameVm::new(id, config)?);
    get_registry().write().vms.insert(id, vm);
    Ok(id)
}

/// Get a FrameVM by ID.
pub fn get_vm_by_id(id: VmId) -> Option<Arc<FrameVm>> {
    get_registry().read().vms.get(&id).cloned()
}

/// Destroy a FrameVM by ID.
pub fn destroy_vm(id: VmId) -> Option<Arc<FrameVm>> {
    let vm = get_vm_by_id(id)?;
    if vm.status() != VmStatus::Stopped {
        vm.stop();
    }
    // A terminal VM can still have loader-owned frames waiting for their RCU
    // grace period. Retry the non-service release before deciding whether its
    // identity must remain quarantined.
    vm.release_stopped_memory();
    if vm.status() != VmStatus::Stopped {
        // Keep the instance and its identity quarantined until all physical
        // owner references drain.  Reusing the ID here could expose a stale
        // page or device handle to a new VM.
        return None;
    }
    if vm
        .allocator
        .get()
        .is_some_and(|allocator| allocator.has_retained_opaque_state())
    {
        ::log::warn!(
            "[framevisor] retaining VM {} while its allocator image has opaque state",
            id
        );
        return None;
    }
    if vm.memory().stats().shared_heap_committed != 0 {
        ::log::warn!(
            "[framevisor] retaining VM {} while FrameVM-owned RRefs are still live",
            id
        );
        return None;
    }
    // A VM that was created but never started still has an accepting domain.
    // Close that empty domain before removing the identity; a destroyed
    // instance must never be restartable through a stale `Arc<FrameVm>`.
    vm.memory().begin_stopping();
    vm.memory().wait_for_reservations();
    vm.release_control_memory();
    if let Err(error) = vm.memory().close() {
        ::log::warn!(
            "[framevisor] retaining VM {} because memory-domain close failed: {:?}",
            id,
            error
        );
        return None;
    }
    let vm = get_registry().write().vms.remove(&id)?;
    vm.devices().sock().release_cid();
    Some(vm)
}

/// List all VM IDs.
pub fn list_vms() -> Vec<VmId> {
    get_registry().read().vms.keys().copied().collect()
}

/// Gets the scheduler group for an ID.
pub fn get_sched_group_by_id(id: FrameVcpuId) -> Option<Arc<FrameSchedGroup>> {
    get_vm_by_id(id.vm_id()).and_then(|vm| vm.sched_group(id.vcpu_index()).cloned())
}

/// Gets all scheduler groups owned by a VM.
pub fn get_sched_groups_by_vm_id(id: VmId) -> Vec<Arc<FrameSchedGroup>> {
    get_vm_by_id(id).map_or_else(Vec::new, |vm| vm.sched_groups())
}
