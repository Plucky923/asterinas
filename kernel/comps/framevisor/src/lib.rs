// SPDX-License-Identifier: MPL-2.0

//! Aster Framevisor Component
//!
//! This component provides frame visualization and management services.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

pub mod mm;
pub mod task;

use ostd::prelude::*;

/// Hello World function to be called by framevm
pub fn hello_world() {
    println!("[framevisor] Hello World from Framevisor!");
}

/// Start FrameVM function
pub fn start_framevm() {
    println!("[framevisor] Starting FrameVM...");
    mm::init_mm();
    task::init_task();
}
