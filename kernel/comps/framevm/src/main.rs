// SPDX-License-Identifier: MPL-2.0

//! FrameVM - A lightweight virtual machine running on FrameVisor.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::{sync::Arc, vec, vec::Vec};
use core::{panic::PanicInfo, sync::atomic::Ordering};

use aster_framevisor::{println, task::Task};

mod bench;
mod error;
mod pollee;
mod syscall;
mod task;
mod vm;
mod vsock;

use task::{create_user_task, post_schedule_handler, UserTaskData};
use vm::create_vm_space;

/// Run benchmarks if enabled
const RUN_BENCHMARKS: bool = true;

/// The kernel's boot and initialization process is managed by OSTD.
#[aster_framevisor::main]
pub fn main() {
    println!("[FrameVM] Starting FrameVM...");

    // Initialize vsock subsystem
    vsock::init();
    println!("[FrameVM] Vsock subsystem initialized");

    // Run benchmarks if enabled
    if RUN_BENCHMARKS {
        println!("[FrameVM] Running benchmarks...");
        bench::run_all_benchmarks();
        println!("[FrameVM] Benchmarks completed.");
    }

    aster_framevisor::task::inject_post_schedule_handler(post_schedule_handler);

    // Load and align program binary
    let program_binary = load_program_binary();

    // Create and activate VM space
    let vm_info = match create_vm_space(&program_binary) {
        Ok(info) => info,
        Err(e) => {
            println!(
                "[FrameVM] Critical Error: Failed to create VM space: {:?}",
                e
            );
            vsock::shutdown();
            return;
        }
    };

    let vm_space = Arc::new(vm_info.vm_space);
    vm_space.activate();
    println!("[FrameVM] VM space activated");

    // Create and run user task
    let user_task = match create_user_task(vm_space, vm_info.entry_point, vm_info.stack_top) {
        Ok(task) => task,
        Err(e) => {
            println!(
                "[FrameVM] Critical Error: Failed to create user task: {:?}",
                e
            );
            vsock::shutdown();
            return;
        }
    };

    let finished = user_task
        .data()
        .downcast_ref::<UserTaskData>()
        .expect("Failed to get UserTaskData")
        .finished
        .clone();

    user_task.run();
    println!("[FrameVM] User task scheduled: {:?}", user_task);

    // Wait for task completion
    while !finished.load(Ordering::SeqCst) {
        Task::yield_now();
    }

    // Shutdown vsock subsystem before exiting
    // This prevents Host from calling Guest callbacks after Guest exits
    vsock::shutdown();

    println!("[FrameVM] User task finished. Exiting.");
}

fn load_program_binary() -> Vec<u8> {
    let program_data = include_bytes!("../test/bench_rtt_server");

    // Copy to heap-allocated Vec to ensure basic alignment and mutability if needed
    let mut program_binary_vec = vec![0u8; program_data.len()];
    program_binary_vec.copy_from_slice(program_data);

    println!(
        "[FrameVM] Loaded program binary ({} bytes)",
        program_binary_vec.len()
    );
    program_binary_vec
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("[FrameVM] PANIC: {}", info);
    loop {}
}
