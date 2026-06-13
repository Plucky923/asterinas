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

mod vcpu;

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU8, Ordering};

use aster_framevsock::{GUEST_CID_BASE, cid_to_vm_id, vm_id_to_cid};
use ostd::sync::RwLock;
use spin::Once;
pub use vcpu::Vcpu;

use crate::{iht, vsock::VcpuQueues};

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
        let vcpus = (0..vcpu_count).map(Vcpu::new).collect();

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
    pub fn vsock_queues(&self, vcpu_id: usize) -> Option<&VcpuQueues> {
        self.vcpus.get(vcpu_id).map(|v| v.vsock_queues())
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
    pub fn start(&self) {
        self.status
            .store(VmStatus::Starting as u8, Ordering::Release);

        for vcpu in &self.vcpus {
            iht::start_iht_task(vcpu.iht().clone());
        }

        self.status
            .store(VmStatus::Running as u8, Ordering::Release);
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

fn get_registry() -> &'static RwLock<VmRegistry> {
    VM_REGISTRY.call_once(|| RwLock::new(VmRegistry::new()))
}

// ============================================================================
// Public API
// ============================================================================

/// Create a new FrameVM instance and return its ID.
pub fn create_vm(vcpu_count: usize) -> VmId {
    let mut registry = get_registry().write();
    let id = registry.next_id;
    registry.next_id += 1;

    let vm = Arc::new(FrameVm::new(id, vcpu_count));
    registry.vms.insert(id, vm);
    id
}

/// Get a FrameVM by ID.
pub fn get_vm_by_id(id: VmId) -> Option<Arc<FrameVm>> {
    get_registry().read().vms.get(&id).cloned()
}

/// Get a FrameVM by CID.
pub fn get_vm_by_cid(cid: u64) -> Option<Arc<FrameVm>> {
    cid_to_vm_id(cid).and_then(get_vm_by_id)
}

/// Destroy a FrameVM by ID.
pub fn destroy_vm(id: VmId) -> Option<Arc<FrameVm>> {
    get_registry().write().vms.remove(&id)
}

/// List all VM IDs.
pub fn list_vms() -> Vec<VmId> {
    get_registry().read().vms.keys().copied().collect()
}

/// Get total VM count.
pub fn vm_count() -> usize {
    get_registry().read().vms.len()
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
    let mut registry = get_registry().write();
    let id = registry.next_id;
    registry.next_id += 1;

    let vm = Arc::new(FrameVm::new(id, vcpu_count));
    registry.vms.insert(id, vm.clone());
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
