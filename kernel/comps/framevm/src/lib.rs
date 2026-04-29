// SPDX-License-Identifier: MPL-2.0

//! FrameVM - A lightweight virtual machine running on FrameVisor.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

extern crate alloc;

// FrameVM output is captured by FrameVisor and surfaced via `/proc/framevm`.
// Use a dedicated macro name here so call sites do not imply std-style console I/O.
macro_rules! framevm_logln {
    () => {
        aster_framevisor::framevm_log(format_args!("\n"))
    };
    ($($arg:tt)*) => {{
        aster_framevisor::framevm_log(format_args!("{}\n", format_args!($($arg)*)))
    }};
}

use alloc::{sync::Arc, vec, vec::Vec};
use core::panic::PanicInfo;

use aster_framevisor::sync::WaitQueue;

mod bench;
mod error;
mod fd_table;
mod pollee;
mod syscall;
mod task;
mod vm;
mod vsock;

use task::{
    create_user_task, post_schedule_handler, user_page_fault_handler,
    wait_for_all_user_tasks_to_exit,
};
use vm::create_vm_space;

/// Run benchmarks if enabled
const SHOULD_RUN_BENCHMARKS: bool = true;

/// The kernel's boot and initialization process is managed by OSTD.
#[aster_framevisor::main]
pub fn main() {
    framevm_logln!("[FrameVM] Starting FrameVM...");

    // Initialize vsock subsystem
    vsock::init();
    framevm_logln!("[FrameVM] Vsock subsystem initialized");

    // Run benchmarks if enabled
    if SHOULD_RUN_BENCHMARKS {
        framevm_logln!("[FrameVM] Running benchmarks...");
        bench::run_all_benchmarks();
        framevm_logln!("[FrameVM] Benchmarks completed.");
    }

    aster_framevisor::task::inject_post_schedule_handler(post_schedule_handler);
    aster_framevisor::task::inject_user_page_fault_handler(user_page_fault_handler);

    // Load and align program binary
    let program_binary = load_program_binary();

    // Create and activate VM space
    let vm_info = match create_vm_space(&program_binary) {
        Ok(info) => info,
        Err(e) => {
            framevm_logln!(
                "[FrameVM] Critical Error: Failed to create VM space: {:?}",
                e
            );
            vsock::shutdown();
            return;
        }
    };

    let vm_space = Arc::new(vm_info.vm_space);
    vm_space.activate();
    framevm_logln!("[FrameVM] VM space activated");

    // Create and run user task
    let finish_queue = Arc::new(WaitQueue::new());
    let user_task = match create_user_task(
        vm_space.clone(),
        vm_info.entry_point,
        vm_info.stack_top,
        Arc::new(vm_info.lazy_ranges),
        finish_queue.clone(),
    ) {
        Ok(task) => task,
        Err(e) => {
            framevm_logln!(
                "[FrameVM] Critical Error: Failed to create user task: {:?}",
                e
            );
            vsock::shutdown();
            return;
        }
    };

    user_task.run();
    framevm_logln!("[FrameVM] User task scheduled: {:?}", user_task);

    // Wait for task completion
    wait_for_all_user_tasks_to_exit();

    // Switch to a long-lived VM space before dropping the guest address space.
    aster_framevisor::mm::activate_safe_vm_space();
    drop(user_task);

    // Disable vsock IRQ handling and drain pending packets before exiting.
    // This prevents callbacks from touching freed guest state.
    vsock::disable_irq_and_drain();

    // Shutdown vsock subsystem before exiting
    // This prevents Host from calling Guest callbacks after Guest exits
    vsock::shutdown();

    // Stop all IHT tasks to prevent them from executing callbacks after exit.
    // This is critical: IHT tasks run in background and may reference freed resources.
    if let Some(vm) = aster_framevisor::vm::get_vm() {
        let vm_id = vm.id();
        vm.stop();
        for vcpu_id in 0..vm.vcpu_count() {
            if let Some(ctx) = vm.iht_context(vcpu_id) {
                ctx.wait_for_exit();
            }
        }
        // Drop the Arc reference before destroying the VM
        drop(vm);
        // Remove VM from registry to prevent access after exit
        aster_framevisor::vm::destroy_vm(vm_id);
        framevm_logln!("[FrameVM] IHT tasks stopped");
    }

    // Clear handlers before returning - these point to FrameVM code which will be freed
    aster_framevisor::task::clear_post_schedule_handler();
    aster_framevisor::task::clear_user_page_fault_handler();

    framevm_logln!("[FrameVM] User task finished. Exiting.");
}

fn load_program_binary() -> Vec<u8> {
    let program_data = include_bytes!("../test/bench_memory_page_rand_warm_4m");

    // Copy to heap-allocated Vec to ensure basic alignment and mutability if needed
    let mut program_binary_vec = vec![0u8; program_data.len()];
    program_binary_vec.copy_from_slice(program_data);

    framevm_logln!(
        "[FrameVM] Loaded program binary ({} bytes)",
        program_binary_vec.len()
    );
    program_binary_vec
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    framevm_logln!("[FrameVM] PANIC: {}", info);
    loop {}
}
