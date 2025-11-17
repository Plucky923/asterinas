// SPDX-License-Identifier: MPL-2.0

//! FrameVM main program
//!
//! This is FrameVM executable that uses framevisor services.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;

use ostd::{hello_world, mm::VmSpace, task::Task};

#[no_mangle]
pub extern "C" fn _start() -> () {
    main();
}

fn main() {
    hello_world();
    let vmspace = create_vm_space();
    hello_world();
}

fn create_vm_space() {
    hello_world();
    VmSpace::new();
}

fn create_user_task() {
    Task::current().unwrap();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    loop {}
}
