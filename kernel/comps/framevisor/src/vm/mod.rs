// SPDX-License-Identifier: MPL-2.0

//! FrameVM instance management.
//!
//! This module provides the central FrameVm structure that aggregates all
//! per-VM resources including vCPUs, IHT contexts, and required devices.
//!
//! # Multi-VM Support
//!
//! The module supports multiple FrameVM instances through a registry pattern.
//! Each VM is identified by a unique `VmId` and can be accessed via CID.

mod frame_group;
mod share;
mod vcpu;

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU8, Ordering};

pub use frame_group::{FrameSchedGroup, FrameVcpuId, InnerPick, RefreshAction};
use framev_sock_common::{cid_to_vm_id, vm_id_to_cid};
use host_ostd::{cpu::CpuId as HostCpuId, sync::RwLock};
pub use share::{
    DEFAULT_FRAMEVM_SHARE, MAX_FRAMEVM_SHARE, MIN_FRAMEVM_SHARE, share_to_nice_hint,
    validate_framevm_share,
};
pub use vcpu::Vcpu;

use crate::{
    cpu::local::CpuLocalDomain,
    device::{BlockImage, Devices},
    error::Error,
    iht,
    irq_routing::VcpuIrqLoad,
    prelude::Result,
    sync::Once,
    task::{Task, scheduler::Scheduler},
    timer::VmClock,
};

/// VM identifier type.
pub type VmId = u32;

/// Maximum supported vCPU count.
pub const MAX_VCPU_COUNT: usize = 4;

const MIN_VCPU_COUNT: usize = 1;

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

/// Typed boot arguments owned by one `FrameVm`.
pub struct BootArgs {
    vcpu_count: usize,
    framev_descriptor: framev_device::FrameVDeviceDescriptor,
}

impl BootArgs {
    fn new(vcpu_count: usize, framev_descriptor: framev_device::FrameVDeviceDescriptor) -> Self {
        Self {
            vcpu_count,
            framev_descriptor,
        }
    }

    /// Returns the vCPU count visible to the service entry.
    pub const fn vcpu_count(&self) -> usize {
        self.vcpu_count
    }

    /// Returns the FrameV descriptor used by frontend binding.
    pub fn framev_descriptor(&self) -> &framev_device::FrameVDeviceDescriptor {
        &self.framev_descriptor
    }

    /// Encodes the FrameV descriptor for the current boot command-line shim.
    pub fn framev_devices_boot_arg(&self) -> alloc::string::String {
        self.framev_descriptor.encode_boot_arg()
    }
}

/// FrameVM instance.
///
/// This structure aggregates all resources for a FrameVM instance:
/// - VM identifier for multi-VM support
/// - vCPU set with IHT contexts
/// - VM status tracking
pub struct FrameVm {
    /// VM identifier
    id: VmId,
    /// Running status
    status: AtomicU8,
    /// FrameV device subsystem.
    devices: Devices,
    /// Typed service boot parameters owned by this VM.
    boot_args: BootArgs,
    /// VM-owned CPU-local state for FrameVM service code.
    cpu_local: CpuLocalDomain,
    /// VM-wide timebase for jiffies accounting.
    clock: Arc<VmClock>,
    /// Static scheduler share configured at VM creation.
    share: u32,
    /// Service-injected scheduler for this VM.
    scheduler: RwLock<Option<&'static dyn Scheduler<Task>>>,
    /// vCPU set
    vcpus: Vec<Vcpu>,
}

impl FrameVm {
    /// Create a new FrameVM instance with the specified ID and vCPU count.
    pub(crate) fn new(
        id: VmId,
        vcpu_count: usize,
        share: u32,
        block_image: Option<Arc<dyn BlockImage>>,
    ) -> Result<Self> {
        validate_create_args(vcpu_count, share)?;
        let devices = match block_image {
            Some(image) => Devices::new_with_block_image(id, vcpu_count, image)?,
            None => Devices::new(id, vcpu_count)?,
        };
        let boot_args = BootArgs::new(vcpu_count, devices.descriptor());
        let clock = Arc::new(VmClock::new());
        let vcpus = (0..vcpu_count)
            .map(|vcpu_id| Vcpu::new(FrameVcpuId::new(id, vcpu_id), share))
            .collect();

        Ok(Self {
            id,
            status: AtomicU8::new(VmStatus::Stopped as u8),
            devices,
            boot_args,
            cpu_local: CpuLocalDomain::new(),
            clock,
            share,
            scheduler: RwLock::new(None),
            vcpus,
        })
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

    /// Returns this VM's static scheduler share.
    pub const fn share(&self) -> u32 {
        self.share
    }

    /// Gets this VM's FrameV device subsystem.
    pub fn devices(&self) -> &Devices {
        &self.devices
    }

    /// Gets this VM's typed boot arguments.
    pub fn boot_args(&self) -> &BootArgs {
        &self.boot_args
    }

    /// Gets this VM's CPU-local domain.
    #[inline]
    pub fn cpu_local_domain(&self) -> &CpuLocalDomain {
        &self.cpu_local
    }

    /// Returns VM-wide elapsed jiffies.
    pub(crate) fn elapsed_jiffies(&self) -> u64 {
        self.clock.elapsed_jiffies()
    }

    pub(crate) fn record_timer_deadline(&self, deadline_tsc: u64) {
        self.clock.record_deadline(deadline_tsc);
    }

    /// Installs the service scheduler for this VM.
    pub(crate) fn install_scheduler(&self, scheduler: &'static dyn Scheduler<Task>) -> bool {
        let mut scheduler_slot = self.scheduler.write();
        if scheduler_slot.is_some() {
            return false;
        }

        *scheduler_slot = Some(scheduler);
        for group in self.sched_groups() {
            group.clear_bootstrap_service_task();
        }
        true
    }

    /// Returns the service scheduler for this VM.
    pub(crate) fn scheduler(&self) -> Option<&'static dyn Scheduler<Task>> {
        *self.scheduler.read()
    }

    /// Clears the service scheduler for this VM.
    pub(crate) fn clear_scheduler(&self) {
        *self.scheduler.write() = None;
    }

    /// Clears VM-owned timer runtime state.
    pub(crate) fn clear_timer_runtime(&self) {
        self.clock.reset();
        for vcpu in &self.vcpus {
            vcpu.iht().clear_event_sources();
        }
    }

    pub(crate) fn vcpu_irq_load(&self, vcpu_id: usize) -> Option<VcpuIrqLoad> {
        let ctx = self.iht_context(vcpu_id)?;
        let pending_work = ctx
            .pending_count()
            .saturating_add(ctx.pending_request_count())
            .saturating_add(usize::from(ctx.has_pending_timer_work()));

        Some(VcpuIrqLoad {
            online: self.status() != VmStatus::Stopped,
            runnable: true,
            virtual_interrupts_enabled: ctx.virtual_interrupts_enabled(),
            pending_work,
        })
    }

    /// Get vCPU by ID.
    pub fn vcpu(&self, id: usize) -> Option<&Vcpu> {
        self.vcpus.get(id)
    }

    /// Get IHT context for a vCPU.
    pub(crate) fn iht_context(&self, vcpu_id: usize) -> Option<Arc<iht::IhtContext>> {
        self.vcpus.get(vcpu_id).map(|v| v.iht().clone())
    }

    /// Gets the scheduler group for one vCPU.
    pub fn sched_group(&self, vcpu_id: usize) -> Option<&Arc<FrameSchedGroup>> {
        self.vcpus.get(vcpu_id).map(|v| v.sched_group())
    }

    /// Returns all scheduler groups owned by this VM.
    pub(crate) fn sched_groups(&self) -> Vec<Arc<FrameSchedGroup>> {
        self.vcpus
            .iter()
            .map(|vcpu| vcpu.sched_group().clone())
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
        if self
            .status
            .compare_exchange(
                VmStatus::Stopped as u8,
                VmStatus::Starting as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return Err(Error::InvalidArgs);
        }
        self.cpu_local.activate();
        self.devices.reset_for_start();
        for vcpu in &self.vcpus {
            vcpu.iht().reset_after_exit();
        }

        for vcpu in &self.vcpus {
            if let Err(error) = iht::start_iht_task(vcpu.iht().clone()) {
                self.devices.stop_all();
                self.status
                    .store(VmStatus::Stopped as u8, Ordering::Release);
                return Err(error);
            }
        }

        if let Err(error) = self.devices.mark_ready_all() {
            self.stop();
            return Err(error.into());
        }

        self.status
            .store(VmStatus::Running as u8, Ordering::Release);
        Ok(())
    }

    fn wait_for_iht_exit(&self) {
        for vcpu in &self.vcpus {
            let iht = vcpu.iht();
            if iht.has_task() {
                iht.wait_for_exit();
            }
        }
    }

    /// Stop all vCPUs.
    pub fn stop(&self) {
        self.request_stop();

        self.wait_for_iht_exit();
        for vcpu in &self.vcpus {
            vcpu.iht().reset_after_exit();
        }

        self.clear_timer_runtime();
        self.status
            .store(VmStatus::Stopped as u8, Ordering::Release);
    }

    /// Requests all vCPUs to stop without waiting for IHT teardown.
    pub fn request_stop(&self) {
        self.status
            .store(VmStatus::Stopping as u8, Ordering::Release);

        self.cpu_local.start_teardown();
        self.devices.stop_all();

        for vcpu in &self.vcpus {
            vcpu.iht().signal_exit();
        }
    }
}

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
            next_vm_id: 0,
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

/// Create a new FrameVM instance and return its ID.
pub fn create_vm(
    vcpu_count: usize,
    share: u32,
    block_image: Option<Arc<dyn BlockImage>>,
) -> Result<VmId> {
    validate_create_args(vcpu_count, share)?;

    let id = {
        let mut registry = get_registry().write();
        registry.reserve_vm_id()?
    };
    let vm = Arc::new(FrameVm::new(id, vcpu_count, share, block_image)?);
    get_registry().write().vms.insert(id, vm);
    Ok(id)
}

fn validate_vcpu_count(vcpu_count: usize) -> Result<()> {
    if (MIN_VCPU_COUNT..=MAX_VCPU_COUNT).contains(&vcpu_count) {
        return Ok(());
    }

    Err(Error::InvalidArgs)
}

fn validate_create_args(vcpu_count: usize, share: u32) -> Result<()> {
    validate_vcpu_count(vcpu_count)?;
    validate_framevm_share(share)
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
    let vm = get_registry().write().vms.remove(&id)?;
    vm.request_stop();
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

/// Gets the scheduler group for an ID.
pub fn get_sched_group_by_id(id: FrameVcpuId) -> Option<Arc<FrameSchedGroup>> {
    get_vm_by_id(id.vm_id()).and_then(|vm| vm.sched_group(id.vcpu_index()).cloned())
}

/// Gets all scheduler groups owned by a VM.
pub fn get_sched_groups_by_vm_id(id: VmId) -> Vec<Arc<FrameSchedGroup>> {
    get_vm_by_id(id).map_or_else(Vec::new, |vm| vm.sched_groups())
}

/// Gets running scheduler groups bound to one host CPU.
pub(crate) fn get_running_sched_groups_by_host_cpu(
    host_cpu: HostCpuId,
) -> Vec<Arc<FrameSchedGroup>> {
    get_registry()
        .read()
        .vms
        .values()
        .filter(|vm| vm.is_running())
        .flat_map(|vm| vm.sched_groups())
        .filter(|group| group.host_cpu() == host_cpu)
        .collect()
}

/// Gets the default vCPU used by the current single-VM bring-up path.
pub fn default_vcpu_id() -> Option<FrameVcpuId> {
    get_registry()
        .read()
        .vms
        .keys()
        .next()
        .copied()
        .map(|vm_id| FrameVcpuId::new(vm_id, 0))
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
pub fn init(vcpu_count: usize) -> Result<Arc<FrameVm>> {
    validate_create_args(vcpu_count, DEFAULT_FRAMEVM_SHARE)?;

    let id = get_registry().write().reserve_vm_id()?;
    let vm = Arc::new(FrameVm::new(id, vcpu_count, DEFAULT_FRAMEVM_SHARE, None)?);
    get_registry().write().vms.insert(id, vm.clone());
    Ok(vm)
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
