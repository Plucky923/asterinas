// SPDX-License-Identifier: MPL-2.0

//! Aster Framevisor Component
//!
//! This component provides frame visualization and management services.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

pub mod cpu;
pub mod error;
pub mod irq;
pub mod mm;
pub mod power;
pub mod prelude;
pub mod task;
pub mod util;
pub mod vsock;

use alloc::{boxed::Box, string::String};

pub use aster_framevisor_exchangeable::*;
pub use aster_framevisor_macros::main;
pub use ostd::{arch, prelude::println, user, Error, Result};
use ostd::{mm::heap::GlobalHeapAllocator, prelude::*};

/// Hello World function to be called by framevm
pub fn hello_world() {
    println!("[framevisor] Hello World from Framevisor!");
}

pub fn print(s: String) {
    println!("[framevisor] {}", s);
}

pub fn print_num(num: Box<i32>) {
    println!("[framevisor] Boxed number: {}", *num);
}

/// Start FrameVM function
pub fn start_framevm() {
    println!("[framevisor] Starting FrameVM...");
    mm::init_mm();
    task::init_task();
    error::init_error();
    cpu::init_cpu();
    irq::init();
    vsock::init();
    // Initialize vCPU queues (default to 1 vCPU)
    vsock::init_vcpu_queue(1);
}
