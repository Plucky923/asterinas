// SPDX-License-Identifier: MPL-2.0

//! Aster FrameVisor Component
//!
//! This component provides virtualization services for FrameVM, including:
//! - Memory management (virtual memory spaces, page tables)
//! - Task scheduling and management
//! - Inter-domain communication via FrameVsock
//! - Cross-domain reference tracking (RRef)

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

pub mod bench;
pub mod cpu;
pub mod domain;
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
pub mod vsock;

pub use aster_framevisor_exchangeable::*;
pub use aster_framevisor_macros::main;
pub use ostd::{arch, prelude::println, user, Error, Result};

/// Initialize and start FrameVM subsystems.
///
/// This function initializes all FrameVisor components in the correct order:
/// 1. RRef registry (for cross-domain reference tracking)
/// 2. Domain manager (for FrameVM lifecycle tracking)
/// 3. Memory management
/// 4. Task scheduling
/// 5. CPU management
/// 6. IRQ handling
/// 7. Vsock communication
/// 8. IHT (Interrupt Handler Tasks)
/// 9. Service stack (for ensure_stack macro support)
pub fn start_framevm() {
    println!("[framevisor] Starting FrameVM...");

    // Initialize RRef registry first (before any RRefs are created)
    rref_registry::init();

    // Initialize domain manager for FrameVM lifecycle tracking
    domain::init();

    // Initialize core subsystems
    mm::init_mm();
    task::init_task();
    error::init_error();
    cpu::init_cpu();
    irq::init();

    // Initialize vsock communication
    vsock::init();
    vsock::init_vcpu_queue(1); // Default to 1 vCPU

    // Initialize IHT manager
    // Note: start_ihts() is called from kernel/src/thread/framevm_task.rs::init()
    // but that runs early when IHT_MANAGER might not be ready.
    // So we also call it here to ensure IHTs are started.
    iht::init_iht_manager(1);
    iht::start_ihts();

    // Initialize service stack for ensure_stack macro support
    // This is needed for functions that require stack switching (e.g., bench_ensure_stack_force_switch)
    ostd::task::service_stack::init(1); // 1 CPU for now
    ostd::task::service_stack::init_on_cpu(0); // Initialize for CPU 0
}
