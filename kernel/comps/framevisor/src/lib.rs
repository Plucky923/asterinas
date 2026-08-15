// SPDX-License-Identifier: MPL-2.0

//! Operating system development support.

#![no_std]
#![deny(unsafe_code)]
#![feature(allocator_api)]

extern crate alloc;
extern crate host_ostd as ostd;

use alloc::sync::Arc;

macro_rules! __log_prefix {
    () => {
        "framevisor: "
    };
}

pub mod arch;
#[cfg(target_arch = "x86_64")]
mod assigned_pci;
pub mod boot;
pub mod console;
pub mod cpu;
pub mod device;
mod error;
pub mod framev_net;
pub mod framev_sock;
pub mod irq;
pub mod log;
pub mod mm;
pub mod panic;
pub mod pci;
pub mod power;
pub mod prelude;
pub mod rng;
mod rref_accounting;
pub mod sync;
pub mod task;
pub mod timer;
pub mod user;
pub mod util;
pub mod vm;
pub mod vsock;

pub use aster_framevisor_macros::main;
pub use console::{
    ConsoleOutputRead, clear_input, early_print, has_input, is_active, read, take_input, write,
};
pub use task::scheduler::{
    DEFAULT_FRAMEVM_SHARE, MAX_FRAMEVM_SHARE, MIN_FRAMEVM_SHARE, validate_framevm_share,
};
pub use vm::{
    FrameSchedGroup, FrameVcpuId, FrameVmConfig, MemoryStats, TaskAdmission, TaskWorker, VmId,
};

pub use crate::{error::Error, prelude::Result};

#[doc(hidden)]
pub mod ktest {
    //! Mirrors Host OSTD's hidden ktest support module for service builds.

    pub use host_ostd::ktest::*;
}

/// Serializes one-time FrameVisor-wide setup.
static FRAMEVISOR_INITIALIZED: sync::Once<()> = sync::Once::new();

/// Returns shutdown coordination owned by the current FrameVM service.
///
/// Returns [`Error::AccessDenied`] unless the current service task carries a
/// FrameVM binding.
pub fn current_task_admission() -> Result<Arc<TaskAdmission>> {
    let frame_vm = task::current_frame_vm().ok_or(Error::AccessDenied)?;
    Ok(frame_vm.task_admission().clone())
}

// ============================================================================
// Multi-VM API
// ============================================================================

/// Initialize FrameVisor subsystems (called once at boot).
///
/// This initializes all core subsystems but does not create any VM.
/// Creates unstarted FrameVM instances and starts them after the host scheduler is ready.
pub fn init_framevisor() -> Result<()> {
    if host_ostd::cpu::num_cpus() > aster_framevisor_exchangeable::MAX_VM_OVERRIDE_CPUS {
        return Err(Error::NotEnoughResources);
    }

    FRAMEVISOR_INITIALIZED.call_once(|| {
        ::log::info!("[framevisor] Initializing FrameVisor subsystems...");
        // Install VM ownership accounting before any shared payload is created.
        rref_accounting::init();
        host_ostd::symbols::add_crate_alias("ostd", "aster_framevisor");

        early_println!("[framevisor] FrameVisor subsystems initialized");
        ::log::info!("[framevisor] FrameVisor subsystems initialized");
    });
    Ok(())
}

/// Creates an unstarted FrameVM from one complete immutable configuration.
pub fn create_framevm_unstarted(config: FrameVmConfig) -> Result<VmId> {
    init_framevisor()?;
    let vm_id = vm::create_vm(config)?;
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
        return Err(error);
    }

    ::log::info!("[framevisor] FrameVM {} started successfully", vm_id);
    Ok(())
}

/// Stop and destroy a FrameVM instance.
pub fn destroy_framevm(vm_id: VmId) -> bool {
    let destroyed = vm::destroy_vm(vm_id).is_some();
    if destroyed {
        ::log::info!("[framevisor] FrameVM {} destroyed", vm_id);
    }
    destroyed
}

/// Get a FrameVM by ID.
pub fn get_framevm(vm_id: VmId) -> Option<Arc<vm::FrameVm>> {
    vm::get_vm_by_id(vm_id)
}

/// Returns the FrameVM vCPU associated with the current task.
pub fn current_frame_vcpu_id() -> Option<FrameVcpuId> {
    task::current_frame_vcpu_id()
}
