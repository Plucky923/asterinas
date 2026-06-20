// SPDX-License-Identifier: MPL-2.0

//! Operating system development support.

#![no_std]
#![deny(unsafe_code)]

#[cfg(all(feature = "host-api", feature = "service-payload"))]
compile_error!(
    "service payloads must build against the OSTD-compatible surface only; \
     do not enable the host control API in a payload build"
);

extern crate alloc;
extern crate host_ostd as ostd;

pub mod arch;
#[cfg(feature = "host-api")]
pub mod bench;
pub mod boot;
pub mod console;
pub mod cpu;
mod error;
#[cfg(feature = "host-api")]
pub mod iht;
#[cfg(not(feature = "host-api"))]
#[path = "service_iht.rs"]
mod iht;
pub mod irq;
pub mod log;
pub mod mm;
pub mod panic;
pub mod power;
pub mod prelude;
#[cfg(feature = "host-api")]
mod rref_registry;
#[cfg(not(feature = "host-api"))]
mod service_domain;
pub mod sync;
pub mod task;
pub mod timer;
pub mod user;
pub mod util;
#[cfg(feature = "host-api")]
pub mod vm;
#[cfg(feature = "host-api")]
pub mod vsock;

#[cfg(feature = "host-api")]
use core::sync::atomic::{AtomicBool, Ordering};

pub use aster_framevisor_macros::main;
#[cfg(feature = "host-api")]
pub use vm::{
    DEFAULT_FRAME_TASK_GROUP_SHARE, FrameTaskGroupId, FrameTaskGroupSnapshot,
    MAX_FRAME_TASK_GROUP_SHARE, MIN_FRAME_TASK_GROUP_SHARE, VmId,
};

pub use crate::{error::Error, prelude::Result};

#[doc(hidden)]
pub mod ktest {
    //! Mirrors Host OSTD's hidden ktest support module for service builds.

    pub use host_ostd::ktest::*;
}

/// Flag to track if framevisor subsystems are initialized.
#[cfg(feature = "host-api")]
static FRAMEVISOR_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "host-api")]
pub fn clear_framevm_log() {
    console::clear_output_log();
}

#[cfg(feature = "host-api")]
pub fn framevm_log_snapshot() -> alloc::string::String {
    console::output_log_snapshot()
}

#[cfg(feature = "host-api")]
pub fn inject_framevm_console_input(bytes: &[u8]) -> Result<usize> {
    console::inject_input(bytes)
}

/// Get the configured vCPU count (from first VM).
#[cfg(feature = "host-api")]
pub fn get_vcpu_count() -> usize {
    vm::get_vcpu_count()
}

/// Get vCPU count for a specific VM.
#[cfg(feature = "host-api")]
pub fn get_vcpu_count_for_vm(vm_id: VmId) -> usize {
    vm::get_vcpu_count_for_vm(vm_id)
}

// ============================================================================
// Multi-VM API
// ============================================================================

/// Initialize FrameVisor subsystems (called once at boot).
///
/// This initializes all core subsystems but does not create any VM.
/// Call `create_framevm()` to create VM instances.
#[cfg(feature = "host-api")]
pub fn init_framevisor() -> Result<()> {
    if FRAMEVISOR_INITIALIZED.swap(true, Ordering::AcqRel) {
        return Ok(()); // Already initialized
    }

    ::log::info!("[framevisor] Initializing FrameVisor subsystems...");

    let result = (|| {
        // Initialize RRef registry first (before any RRefs are created)
        rref_registry::init();
        host_ostd::symbols::add_crate_alias("ostd", "aster_framevisor");

        // Initialize core subsystems
        mm::init_mm()?;
        task::init_task();
        error::init_error();
        cpu::init_cpu();
        irq::init();
        power::init_power();
        console::install_transport_backend();

        early_println!("[framevisor] FrameVisor subsystems initialized");
        ::log::info!("[framevisor] FrameVisor subsystems initialized");
        Ok(())
    })();

    if result.is_err() {
        FRAMEVISOR_INITIALIZED.store(false, Ordering::Release);
    }

    result
}

/// Create and start a new FrameVM instance.
///
/// Returns the VM ID of the created instance.
///
/// # Arguments
/// * `vcpu_count` - Number of vCPUs for this VM (1-4)
#[cfg(feature = "host-api")]
pub fn create_framevm(vcpu_count: usize) -> Result<VmId> {
    let vm_id = create_framevm_unstarted(vcpu_count)?;
    if let Err(error) = start_framevm_by_id(vm_id) {
        return Err(error);
    }

    Ok(vm_id)
}

/// Creates a FrameVM instance without starting its IHT tasks.
#[cfg(feature = "host-api")]
pub fn create_framevm_unstarted(vcpu_count: usize) -> Result<VmId> {
    init_framevisor()?;

    let vm_id = vm::create_vm(vcpu_count);
    let vm = vm::get_vm_by_id(vm_id).ok_or(Error::NotEnoughResources)?;

    ::log::info!(
        "[framevisor] Creating FrameVM {} with {} vCPU(s)...",
        vm_id,
        vm.vcpu_count()
    );

    Ok(vm_id)
}

/// Starts a previously-created FrameVM instance.
#[cfg(feature = "host-api")]
pub fn start_framevm_by_id(vm_id: VmId) -> Result<()> {
    let vm = vm::get_vm_by_id(vm_id).ok_or(Error::InvalidArgs)?;

    if let Err(error) = vm.start() {
        vm.stop();
        vm::destroy_vm(vm_id);
        return Err(error);
    }

    // Initialize service stack for this VM's vCPUs
    let count = vm.vcpu_count();
    host_ostd::task::service_stack::init(count);
    for i in 0..count {
        host_ostd::task::service_stack::init_on_cpu(i);
    }

    ::log::info!("[framevisor] FrameVM {} started successfully", vm_id);
    Ok(())
}

/// Stop and destroy a FrameVM instance.
#[cfg(feature = "host-api")]
pub fn destroy_framevm(vm_id: VmId) {
    if let Some(vm) = vm::get_vm_by_id(vm_id) {
        vm.stop();
        vm::destroy_vm(vm_id);
        ::log::info!("[framevisor] FrameVM {} destroyed", vm_id);
    }
}

/// Get a FrameVM by ID.
#[cfg(feature = "host-api")]
pub fn get_framevm(vm_id: VmId) -> Option<alloc::sync::Arc<vm::FrameVm>> {
    vm::get_vm_by_id(vm_id)
}

/// List all VM IDs.
#[cfg(feature = "host-api")]
pub fn list_framevms() -> alloc::vec::Vec<VmId> {
    vm::list_vms()
}

/// Get total VM count.
#[cfg(feature = "host-api")]
pub fn framevm_count() -> usize {
    vm::vm_count()
}

/// Gets the default FrameVM task group for the single-VM bring-up path.
#[cfg(feature = "host-api")]
pub fn default_frame_task_group_id() -> Option<FrameTaskGroupId> {
    vm::default_task_group_id()
}

/// Validates a FrameVM task group CPU share.
#[cfg(feature = "host-api")]
pub fn validate_frame_task_group_share(share: u32) -> Result<()> {
    vm::validate_frame_task_group_share(share)
}

/// Updates the share of a FrameVM task group.
#[cfg(feature = "host-api")]
pub fn set_frame_task_group_share(task_group_id: FrameTaskGroupId, share: u32) -> Result<()> {
    vm::set_task_group_share(task_group_id, share)
}

/// Resets runtime accounting for a FrameVM task group.
#[cfg(feature = "host-api")]
pub fn reset_frame_task_group_accounting(task_group_id: FrameTaskGroupId) -> Result<()> {
    vm::reset_task_group_accounting(task_group_id)
}

/// Returns runtime normalized by the configured share for a FrameVM task group.
#[cfg(feature = "host-api")]
pub fn frame_task_group_normalized_runtime_cycles(task_group_id: FrameTaskGroupId) -> Option<u64> {
    vm::task_group_normalized_runtime_cycles(task_group_id)
}

/// Gets the nice hint for a FrameVM task group.
#[cfg(feature = "host-api")]
pub fn frame_task_group_nice_hint(task_group_id: FrameTaskGroupId) -> Option<i8> {
    vm::get_task_group_by_id(task_group_id).map(|task_group| task_group.nice_hint())
}

/// Gets the configured CPU share for a FrameVM task group.
#[cfg(feature = "host-api")]
pub fn frame_task_group_share(task_group_id: FrameTaskGroupId) -> Option<u32> {
    vm::get_task_group_by_id(task_group_id).map(|task_group| task_group.share())
}

/// Returns whether a FrameVM task group has pending scheduler work.
#[cfg(feature = "host-api")]
pub fn frame_task_group_needs_resched(task_group_id: FrameTaskGroupId) -> bool {
    task::scheduler::frame_task_group_needs_resched(task_group_id)
}

/// Returns whether virtual local interrupts are enabled for a FrameVM task group.
#[cfg(feature = "host-api")]
pub fn frame_task_group_virtual_interrupts_enabled(task_group_id: FrameTaskGroupId) -> bool {
    task::scheduler::frame_task_group_virtual_interrupts_enabled(task_group_id)
}

/// Returns the host task that the FrameVM scheduler currently selects for a task group.
#[cfg(feature = "host-api")]
pub fn frame_task_group_current_ostd_task(
    task_group_id: FrameTaskGroupId,
) -> Option<alloc::sync::Arc<ostd::task::Task>> {
    task::scheduler::frame_task_group_current_ostd_task(task_group_id)
}

/// Returns task group snapshots for active or most recently destroyed FrameVMs.
#[cfg(feature = "host-api")]
pub fn frame_task_group_snapshots() -> alloc::vec::Vec<FrameTaskGroupSnapshot> {
    vm::task_group_snapshots()
}

/// Binds the current host task to a FrameVM task group.
#[cfg(feature = "host-api")]
pub fn bind_current_task_to_frame_task_group(task_group_id: FrameTaskGroupId) -> Result<()> {
    task::bind_current_task_to_frame_task_group(task_group_id)
}

/// Clears the current host task's FrameVM task group binding.
#[cfg(feature = "host-api")]
pub fn clear_current_frame_task_group() {
    task::clear_current_frame_task_group();
}

/// Returns the FrameVM task group associated with the current task.
#[cfg(feature = "host-api")]
pub fn current_frame_task_group_id() -> Option<FrameTaskGroupId> {
    task::current_frame_task_group_id()
}

// ============================================================================
// Backward Compatibility API
// ============================================================================

/// Initialize and start FrameVM subsystems with specified vCPU count.
///
/// This is the backward-compatible API that creates a single VM (VM 0).
///
/// # Arguments
/// * `vcpu_count` - Number of vCPUs to initialize (1-4)
#[cfg(feature = "host-api")]
pub fn start_framevm(vcpu_count: usize) -> Result<()> {
    // Check if any VM is already running to avoid double initialization
    if vm::vm_count() > 0 {
        ::log::info!("[framevisor] FrameVM is already running!");
        return Ok(());
    }

    ::log::info!(
        "[framevisor] Starting FrameVM with {} vCPU(s)...",
        vcpu_count
    );

    create_framevm(vcpu_count)?;

    ::log::info!("[framevisor] FrameVM started successfully");
    Ok(())
}

/// Stop all FrameVM instances.
#[cfg(feature = "host-api")]
pub fn stop_framevm() {
    for vm_id in vm::list_vms() {
        destroy_framevm(vm_id);
    }
    boot::clear_boot_info();
    ::log::info!("[framevisor] All FrameVMs stopped");
}
