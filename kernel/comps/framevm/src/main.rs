// SPDX-License-Identifier: MPL-2.0

//! FrameVM main program
//!
//! This is FrameVM executable that uses framevisor services.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use aster_framevisor::hello_world;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    main();
    loop {}
}

fn main() {
    hello_world();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    loop {}
}
