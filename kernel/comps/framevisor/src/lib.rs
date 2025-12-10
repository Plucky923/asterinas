// SPDX-License-Identifier: MPL-2.0

//! Aster Framevisor Component
//!
//! This component provides frame visualization and management services.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
extern crate ostd;

pub mod cpu;
pub mod error;
pub mod mm;
pub mod prelude;
pub mod task;
pub mod util;

use alloc::{boxed::Box, string::String};

pub use aster_framevisor_macros::main;
pub use ostd::{arch, user};
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
}
