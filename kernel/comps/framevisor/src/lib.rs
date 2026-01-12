// SPDX-License-Identifier: MPL-2.0

//! Aster FrameVisor Component
//!
//! This component provides virtualization services for FrameVM, including:
//! - Memory management (virtual memory spaces, page tables)
//! - Task scheduling and management
//! - Inter-domain communication via FrameVsock
//! - Cross-domain reference tracking (RRef)
//!
//! # Multi-VM Support
//!
//! FrameVisor supports multiple FrameVM instances. Each VM is identified by
//! a unique `VmId` and can be accessed via CID (CID = VmId + 3).

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::string::String;
pub mod bench;
pub mod cpu;
pub mod error;
pub mod iht;
pub mod irq;
pub mod mm;
pub mod power;
pub mod prelude;
pub mod rref_registry;
pub mod sync;
pub mod task;
pub mod util;
pub mod vm;
pub mod vsock;

use core::{
    fmt::{Arguments, Write},
    sync::atomic::{AtomicBool, Ordering},
};

pub use aster_framevisor_exchangeable::*;
pub use aster_framevisor_macros::main;
pub use crate::error::Error;
pub use crate::prelude::Result;
use log::info;
pub use ostd::{arch, prelude::println, user};
use spin::Once;
pub use vm::VmId;

/// Flag to track if framevisor subsystems are initialized.
static FRAMEVISOR_INITIALIZED: AtomicBool = AtomicBool::new(false);

const FRAMEVM_LOG_LIMIT: usize = 64 * 1024;
static FRAMEVM_LOG: Once<ostd::sync::SpinLock<String>> = Once::new();

fn framevm_log_slot() -> &'static ostd::sync::SpinLock<String> {
    FRAMEVM_LOG.call_once(|| ostd::sync::SpinLock::new(String::new()))
}

fn append_framevm_log(args: Arguments<'_>) {
    let mut output = framevm_log_slot().lock();
    let _ = output.write_fmt(args);
    if output.len() > FRAMEVM_LOG_LIMIT {
        let overflow = output.len() - FRAMEVM_LOG_LIMIT;
        output.drain(..overflow);
    }
}

pub fn framevm_log(args: Arguments<'_>) {
    append_framevm_log(args);
}

pub fn framevm_write_str(s: &str) {
    append_framevm_log(format_args!("{}", s));
}

pub fn clear_framevm_log() {
    framevm_log_slot().lock().clear();
}

pub fn framevm_log_snapshot() -> String {
    framevm_log_slot().lock().clone()
}

/// Get the configured vCPU count (from first VM).
pub fn get_vcpu_count() -> usize {
    vm::get_vcpu_count()
}

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
/// Call `create_framevm()` to create VM instances.
pub fn init_framevisor() -> Result<()> {
    if FRAMEVISOR_INITIALIZED.swap(true, Ordering::AcqRel) {
        return Ok(()); // Already initialized
    }

    info!("[framevisor] Initializing FrameVisor subsystems...");

    let result = (|| {
        // Initialize RRef registry first (before any RRefs are created)
        rref_registry::init();

        // Initialize core subsystems
        mm::init_mm()?;
        task::init_task();
        error::init_error();
        cpu::init_cpu();
        irq::init();

        info!("[framevisor] FrameVisor subsystems initialized");
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
pub fn create_framevm(vcpu_count: usize) -> Result<VmId> {
    // Ensure subsystems are initialized
    init_framevisor()?;

    let vm_id = vm::create_vm(vcpu_count);
    let vm = vm::get_vm_by_id(vm_id).ok_or(Error::NotEnoughResources)?;

    info!(
        "[framevisor] Creating FrameVM {} with {} vCPU(s)...",
        vm_id,
        vm.vcpu_count()
    );

    // Start all IHT tasks via the VM instance
    vm.start();

    // Initialize service stack for this VM's vCPUs
    let count = vm.vcpu_count();
    ostd::task::service_stack::init(count);
    for i in 0..count {
        ostd::task::service_stack::init_on_cpu(i);
    }

    info!("[framevisor] FrameVM {} started successfully", vm_id);
    Ok(vm_id)
}

/// Stop and destroy a FrameVM instance.
pub fn destroy_framevm(vm_id: VmId) {
    if let Some(vm) = vm::get_vm_by_id(vm_id) {
        vm.stop();
        vm::destroy_vm(vm_id);
        info!("[framevisor] FrameVM {} destroyed", vm_id);
    }
}

/// Get a FrameVM by ID.
pub fn get_framevm(vm_id: VmId) -> Option<alloc::sync::Arc<vm::FrameVm>> {
    vm::get_vm_by_id(vm_id)
}

/// List all VM IDs.
pub fn list_framevms() -> alloc::vec::Vec<VmId> {
    vm::list_vms()
}

/// Get total VM count.
pub fn framevm_count() -> usize {
    vm::vm_count()
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
pub fn start_framevm(vcpu_count: usize) -> Result<()> {
    // Check if any VM is already running to avoid double initialization
    if vm::vm_count() > 0 {
        info!("[framevisor] FrameVM is already running!");
        return Ok(());
    }

    info!(
        "[framevisor] Starting FrameVM with {} vCPU(s)...",
        vcpu_count
    );

    create_framevm(vcpu_count)?;

    info!("[framevisor] FrameVM started successfully");
    Ok(())
}

/// Stop all FrameVM instances.
pub fn stop_framevm() {
    for vm_id in vm::list_vms() {
        destroy_framevm(vm_id);
    }
    info!("[framevisor] All FrameVMs stopped");
}
