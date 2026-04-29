// SPDX-License-Identifier: MPL-2.0

//! FrameVM binary entry point.

#![no_std]
#![no_main]

extern crate alloc;

#[aster_framevisor::main]
fn main() {
    framevm::main();
}
