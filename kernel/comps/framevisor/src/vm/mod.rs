// SPDX-License-Identifier: MPL-2.0

//! FrameVM instance management.
//!
//! This module provides the central FrameVm structure that aggregates all
//! per-VM resources including vCPUs, IHT contexts, and Vsock queues.
//!
//! # Multi-VM Support
//!
//! The module supports multiple FrameVM instances through a registry pattern.
//! Each VM is identified by a unique `VmId` and can be accessed via CID.

mod task_group;
mod vcpu;

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(feature = "host-api")]
use aster_framevsock::{cid_to_vm_id, vm_id_to_cid};
use host_ostd::sync::RwLock;
pub use task_group::{
    DEFAULT_FRAME_TASK_GROUP_SHARE, FrameTaskGroup, FrameTaskGroupId, FrameTaskGroupSnapshot,
    MAX_FRAME_TASK_GROUP_SHARE, MIN_FRAME_TASK_GROUP_SHARE, share_to_nice_hint,
    validate_frame_task_group_share,
};
pub use vcpu::Vcpu;

#[cfg(feature = "host-api")]
use crate::vsock::VcpuQueues;
use crate::{error::Error, iht, prelude::Result, sync::Once};

/// VM identifier type.
pub type VmId = u32;

/// Maximum supported vCPU count.
pub const MAX_VCPU_COUNT: usize = 4;

/// FrameVM running status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VmStatus {
    Stopped = 0,
    Starting = 1,
    Running = 2,
    Stopping = 3,
}

impl From<u8> for VmStatus {
    fn from(val: u8) -> Self {
        match val {
            1 => VmStatus::Starting,
            2 => VmStatus::Running,
            3 => VmStatus::Stopping,
            _ => VmStatus::Stopped,
        }
    }
}

/// FrameVM instance.
///
/// This structure aggregates all resources for a FrameVM instance:
/// - VM identifier for multi-VM support
/// - vCPU set with IHT contexts and Vsock queues
/// - VM status tracking
pub struct FrameVm {
    /// VM identifier
    id: VmId,
    /// Running status
    status: AtomicU8,
    /// vCPU set
    vcpus: Vec<Vcpu>,
}

impl FrameVm {
    /// Create a new FrameVM instance with the specified ID and vCPU count.
    pub fn new(id: VmId, vcpu_count: usize) -> Self {
        let vcpu_count = vcpu_count.clamp(1, MAX_VCPU_COUNT);
        let vcpus = (0..vcpu_count)
            .map(|vcpu_id| Vcpu::new(FrameTaskGroupId::new(id, vcpu_id)))
            .collect();

        Self {
            id,
            status: AtomicU8::new(VmStatus::Stopped as u8),
            vcpus,
        }
    }

    /// Get VM ID.
    pub fn id(&self) -> VmId {
        self.id
    }

    /// Get CID for this VM.
    #[cfg(feature = "host-api")]
    pub fn cid(&self) -> u64 {
        vm_id_to_cid(self.id)
    }

    /// Get vCPU count.
    pub fn vcpu_count(&self) -> usize {
        self.vcpus.len()
    }

    /// Get vCPU by ID.
    pub fn vcpu(&self, id: usize) -> Option<&Vcpu> {
        self.vcpus.get(id)
    }

    /// Get IHT context for a vCPU.
    pub fn iht_context(&self, vcpu_id: usize) -> Option<Arc<iht::IhtContext>> {
        self.vcpus.get(vcpu_id).map(|v| v.iht().clone())
    }

    /// Get Vsock queues for a vCPU.
    #[cfg(feature = "host-api")]
    pub fn vsock_queues(&self, vcpu_id: usize) -> Option<&VcpuQueues> {
        self.vcpus.get(vcpu_id).map(|v| v.vsock_queues())
    }

    /// Gets the task group for one vCPU.
    pub fn task_group(&self, vcpu_id: usize) -> Option<&Arc<FrameTaskGroup>> {
        self.vcpus.get(vcpu_id).map(|v| v.task_group())
    }

    /// Updates the task group share for one vCPU.
    pub fn set_task_group_share(&self, vcpu_id: usize, share: u32) -> Result<()> {
        let task_group = self.task_group(vcpu_id).ok_or(Error::InvalidArgs)?;
        task_group.set_share(share)
    }

    /// Returns task group snapshots for all vCPUs.
    pub fn task_group_snapshots(&self) -> Vec<FrameTaskGroupSnapshot> {
        self.vcpus
            .iter()
            .map(|vcpu| vcpu.task_group().snapshot())
            .collect()
    }

    /// Get current status.
    pub fn status(&self) -> VmStatus {
        VmStatus::from(self.status.load(Ordering::Acquire))
    }

    /// Check if VM is running.
    pub fn is_running(&self) -> bool {
        self.status() == VmStatus::Running
    }

    /// Start all vCPU IHT tasks.
    pub fn start(&self) -> Result<()> {
        self.status
            .store(VmStatus::Starting as u8, Ordering::Release);

        for vcpu in &self.vcpus {
            iht::start_iht_task(vcpu.iht().clone())?;
        }

        self.status
            .store(VmStatus::Running as u8, Ordering::Release);
        Ok(())
    }

    /// Stop all vCPUs.
    pub fn stop(&self) {
        self.status
            .store(VmStatus::Stopping as u8, Ordering::Release);

        for vcpu in &self.vcpus {
            vcpu.iht().signal_exit();
        }

        self.status
            .store(VmStatus::Stopped as u8, Ordering::Release);
    }
}

// ============================================================================
// VM Registry
// ============================================================================

/// VM Registry for managing multiple FrameVM instances.
struct VmRegistry {
    /// Map of VM ID to FrameVM instance
    vms: BTreeMap<VmId, Arc<FrameVm>>,
    /// Next available VM ID
    next_id: VmId,
}

impl VmRegistry {
    fn new() -> Self {
        Self {
            vms: BTreeMap::new(),
            next_id: 0,
        }
    }
}

/// Global VM registry.
static VM_REGISTRY: Once<RwLock<VmRegistry>> = Once::new();
static LAST_TASK_GROUP_SNAPSHOTS: RwLock<Vec<FrameTaskGroupSnapshot>> = RwLock::new(Vec::new());

fn get_registry() -> &'static RwLock<VmRegistry> {
    VM_REGISTRY.call_once(|| RwLock::new(VmRegistry::new()))
}

// ============================================================================
// Public API
// ============================================================================

/// Create a new FrameVM instance and return its ID.
pub fn create_vm(vcpu_count: usize) -> VmId {
    let id = reserve_vm_id();
    let vm = Arc::new(FrameVm::new(id, vcpu_count));
    get_registry().write().vms.insert(id, vm);
    id
}

fn reserve_vm_id() -> VmId {
    let mut registry = get_registry().write();
    let id = registry.next_id;
    registry.next_id += 1;
    id
}

/// Get a FrameVM by ID.
pub fn get_vm_by_id(id: VmId) -> Option<Arc<FrameVm>> {
    get_registry().read().vms.get(&id).cloned()
}

/// Get a FrameVM by CID.
#[cfg(feature = "host-api")]
pub fn get_vm_by_cid(cid: u64) -> Option<Arc<FrameVm>> {
    cid_to_vm_id(cid).and_then(get_vm_by_id)
}

/// Destroy a FrameVM by ID.
pub fn destroy_vm(id: VmId) -> Option<Arc<FrameVm>> {
    let vm = get_registry().write().vms.remove(&id)?;
    *LAST_TASK_GROUP_SNAPSHOTS.write() = vm.task_group_snapshots();
    Some(vm)
}

/// List all VM IDs.
pub fn list_vms() -> Vec<VmId> {
    get_registry().read().vms.keys().copied().collect()
}

/// Get total VM count.
pub fn vm_count() -> usize {
    get_registry().read().vms.len()
}

/// Gets the task group for an ID.
pub fn get_task_group_by_id(id: FrameTaskGroupId) -> Option<Arc<FrameTaskGroup>> {
    get_vm_by_id(id.vm_id()).and_then(|vm| vm.task_group(id.vcpu_id()).cloned())
}

/// Gets the default task group used by the current single-VM bring-up path.
pub fn default_task_group_id() -> Option<FrameTaskGroupId> {
    get_registry()
        .read()
        .vms
        .values()
        .next()
        .and_then(|vm| vm.task_group(0).map(|task_group| task_group.id()))
}

/// Updates the share of one FrameVM task group.
pub fn set_task_group_share(id: FrameTaskGroupId, share: u32) -> Result<()> {
    let vm = get_vm_by_id(id.vm_id()).ok_or(Error::InvalidArgs)?;
    vm.set_task_group_share(id.vcpu_id(), share)
}

/// Resets runtime accounting for one FrameVM task group.
pub fn reset_task_group_accounting(id: FrameTaskGroupId) -> Result<()> {
    let task_group = get_task_group_by_id(id).ok_or(Error::InvalidArgs)?;
    task_group.reset_accounting();
    Ok(())
}

/// Returns runtime normalized by the configured share of one FrameVM task group.
pub fn task_group_normalized_runtime_cycles(id: FrameTaskGroupId) -> Option<u64> {
    get_task_group_by_id(id).map(|task_group| task_group.normalized_runtime_cycles())
}

/// Returns active task group snapshots, or the last destroyed snapshot set.
pub fn task_group_snapshots() -> Vec<FrameTaskGroupSnapshot> {
    let active_snapshots: Vec<_> = get_registry()
        .read()
        .vms
        .values()
        .flat_map(|vm| vm.task_group_snapshots())
        .collect();
    if active_snapshots.is_empty() {
        LAST_TASK_GROUP_SNAPSHOTS.read().clone()
    } else {
        active_snapshots
    }
}

// ============================================================================
// Backward Compatibility API
// ============================================================================

/// Get the first (default) FrameVM instance.
///
/// For backward compatibility with single-VM code.
pub fn get_vm() -> Option<Arc<FrameVm>> {
    get_registry().read().vms.values().next().cloned()
}

/// Initialize a single FrameVM instance (backward compatible).
///
/// This creates VM 0 and returns a reference to it.
pub fn init(vcpu_count: usize) -> Arc<FrameVm> {
    let id = reserve_vm_id();
    let vm = Arc::new(FrameVm::new(id, vcpu_count));
    get_registry().write().vms.insert(id, vm.clone());
    vm
}

/// Get vCPU count from the first VM.
pub fn get_vcpu_count() -> usize {
    get_vm().map(|vm| vm.vcpu_count()).unwrap_or(0)
}

/// Get vCPU count for a specific VM.
pub fn get_vcpu_count_for_vm(id: VmId) -> usize {
    get_vm_by_id(id).map(|vm| vm.vcpu_count()).unwrap_or(0)
}

/// Check if any VM is running.
pub fn is_running() -> bool {
    get_registry().read().vms.values().any(|vm| vm.is_running())
}

/// Check if a specific VM is running.
pub fn is_vm_running(id: VmId) -> bool {
    get_vm_by_id(id).map(|vm| vm.is_running()).unwrap_or(false)
}
