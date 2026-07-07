// SPDX-License-Identifier: MPL-2.0

//! Operating system development support.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
extern crate host_ostd as ostd;

macro_rules! __log_prefix {
    () => {
        "framevisor: "
    };
}

pub mod arch;
pub mod bench;
pub mod boot;
pub mod console;
pub mod cpu;
pub mod device;
mod error;
pub mod framev_sock;
pub mod iht;
pub mod irq;
mod irq_routing;
pub mod log;
pub mod mm;
pub mod panic;
pub mod power;
pub mod prelude;
pub mod rng;
mod rref_registry;
pub mod sync;
pub mod task;
pub mod timer;
pub mod user;
pub mod util;
pub mod vm;
pub mod vsock;

pub use aster_framevisor_macros::main;
pub use console::{
    ConsoleOutputRead, clear_input, early_print, has_input, is_active, read,
    register_input_callback, write,
};
pub use vm::{
    DEFAULT_FRAMEVM_SHARE, FrameSchedGroup, FrameVcpuId, MAX_FRAMEVM_SHARE, MIN_FRAMEVM_SHARE, VmId,
};

pub use crate::{error::Error, prelude::Result};

#[doc(hidden)]
pub mod ktest {
    //! Mirrors Host OSTD's hidden ktest support module for service builds.

    pub use host_ostd::ktest::*;
}

pub(crate) fn visible_cpu_count() -> usize {
    vm::get_vcpu_count().max(1)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FramevisorInitState {
    Uninitialized,
    Initialized,
}

/// Tracks FrameVisor subsystem initialization.
static FRAMEVISOR_INIT_STATE: sync::SpinLock<FramevisorInitState> =
    sync::SpinLock::new(FramevisorInitState::Uninitialized);

/// Get vCPU count for a specific VM.
pub fn get_vcpu_count_for_vm(vm_id: VmId) -> usize {
    vm::get_vcpu_count_for_vm(vm_id)
}

// ============================================================================
// Multi-VM API
// ============================================================================

/// Initialize FrameVisor subsystems (called once at boot).
///
/// This initializes all core subsystems but does not create any VM.
/// Creates unstarted FrameVM instances and starts them after the host scheduler is ready.
pub fn init_framevisor() -> Result<()> {
    let mut init_state = FRAMEVISOR_INIT_STATE.lock();
    if *init_state == FramevisorInitState::Initialized {
        return Ok(());
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

        early_println!("[framevisor] FrameVisor subsystems initialized");
        ::log::info!("[framevisor] FrameVisor subsystems initialized");
        Ok(())
    })();

    if result.is_ok() {
        *init_state = FramevisorInitState::Initialized;
    }

    result
}

/// Creates a FrameVM instance without starting its IHT tasks.
pub fn create_framevm_unstarted(vcpu_count: usize, share: u32) -> Result<VmId> {
    create_framevm_unstarted_with_optional_block(vcpu_count, share, None)
}

/// Creates a FrameVM instance with one block backend without starting its IHT tasks.
pub fn create_framevm_unstarted_with_block_image(
    vcpu_count: usize,
    share: u32,
    block_image: alloc::sync::Arc<dyn device::BlockImage>,
) -> Result<VmId> {
    create_framevm_unstarted_with_optional_block(vcpu_count, share, Some(block_image))
}

fn create_framevm_unstarted_with_optional_block(
    vcpu_count: usize,
    share: u32,
    block_image: Option<alloc::sync::Arc<dyn device::BlockImage>>,
) -> Result<VmId> {
    init_framevisor()?;

    let vm_id = vm::create_vm(vcpu_count, share, block_image)?;
    let vm = vm::get_vm_by_id(vm_id).ok_or(Error::NotEnoughResources)?;

    ::log::info!(
        "[framevisor] Creating FrameVM {} with {} vCPU(s)...",
        vm_id,
        vm.vcpu_count()
    );

    Ok(vm_id)
}

/// Starts a previously-created FrameVM instance.
pub fn start_framevm_by_id(vm_id: VmId) -> Result<()> {
    let vm = vm::get_vm_by_id(vm_id).ok_or(Error::InvalidArgs)?;

    if let Err(error) = vm.start() {
        vm.stop();
        vm::destroy_vm(vm_id);
        return Err(error);
    }

    // Initialize service stack for this VM's vCPUs
    let host_cpu_count = host_ostd::cpu::num_cpus();
    host_ostd::task::service_stack::init(host_cpu_count);
    for i in 0..host_cpu_count {
        host_ostd::task::service_stack::init_on_cpu(i);
    }

    ::log::info!("[framevisor] FrameVM {} started successfully", vm_id);
    Ok(())
}

/// Stop and destroy a FrameVM instance.
pub fn destroy_framevm(vm_id: VmId) {
    if vm::destroy_vm(vm_id).is_some() {
        ::log::info!("[framevisor] FrameVM {} destroyed", vm_id);
    }
}

/// Get a FrameVM by ID.
pub fn get_framevm(vm_id: VmId) -> Option<alloc::sync::Arc<vm::FrameVm>> {
    vm::get_vm_by_id(vm_id)
}

/// Encodes one FrameVM's FrameV device descriptor as boot metadata.
pub fn framev_device_descriptor_boot_arg(vm_id: VmId) -> Option<alloc::string::String> {
    vm::get_vm_by_id(vm_id).map(|vm| vm.boot_args().framev_devices_boot_arg())
}

/// List all VM IDs.
pub fn list_framevms() -> alloc::vec::Vec<VmId> {
    vm::list_vms()
}

/// Get total VM count.
pub fn framevm_count() -> usize {
    vm::vm_count()
}

/// Gets the default FrameVM vCPU for the single-VM bring-up path.
pub fn default_frame_vcpu_id() -> Option<FrameVcpuId> {
    vm::default_vcpu_id()
}

/// Validates a FrameVM vCPU CPU share.
pub fn validate_framevm_share(share: u32) -> Result<()> {
    vm::validate_framevm_share(share)
}

/// Gets the nice hint for a FrameVM vCPU.
pub fn frame_vcpu_nice_hint(frame_vcpu_id: FrameVcpuId) -> Option<i8> {
    vm::get_sched_group_by_id(FrameVcpuId::new(
        frame_vcpu_id.vm_id(),
        frame_vcpu_id.vcpu_index(),
    ))
    .map(|group| vm::share_to_nice_hint(group.share()))
}

/// Gets the configured CPU share for a FrameVM vCPU.
pub fn frame_vcpu_share(frame_vcpu_id: FrameVcpuId) -> Option<u32> {
    vm::get_sched_group_by_id(FrameVcpuId::new(
        frame_vcpu_id.vm_id(),
        frame_vcpu_id.vcpu_index(),
    ))
    .map(|group| group.share())
}

/// Returns whether a FrameVM vCPU has pending scheduler work.
pub fn frame_vcpu_needs_resched(frame_vcpu_id: FrameVcpuId) -> bool {
    task::scheduler::frame_vcpu_needs_resched(frame_vcpu_id)
}

/// Returns whether virtual local interrupts are enabled for a FrameVM vCPU.
pub fn frame_vcpu_virtual_interrupts_enabled(frame_vcpu_id: FrameVcpuId) -> bool {
    task::scheduler::frame_vcpu_virtual_interrupts_enabled(frame_vcpu_id)
}

/// Returns the host task that the FrameVM scheduler currently selects for a vCPU.
pub fn frame_vcpu_current_ostd_task(
    frame_vcpu_id: FrameVcpuId,
) -> Option<alloc::sync::Arc<ostd::task::Task>> {
    task::scheduler::frame_vcpu_current_ostd_task(frame_vcpu_id)
}

/// Binds the current host task to a FrameVM vCPU.
pub fn bind_current_task_to_frame_vcpu(frame_vcpu_id: FrameVcpuId) -> Result<()> {
    task::bind_current_task_to_frame_vcpu(frame_vcpu_id)
}

/// Clears the current host task's FrameVM vCPU binding.
pub fn clear_current_frame_vcpu() {
    task::clear_current_frame_vcpu();
}

/// Returns the FrameVM vCPU associated with the current task.
pub fn current_frame_vcpu_id() -> Option<FrameVcpuId> {
    task::current_frame_vcpu_id()
}
