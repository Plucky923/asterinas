// SPDX-License-Identifier: MPL-2.0

#![no_std]
#![no_main]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec,
};
use core::{panic::PanicInfo, str};

use align_ext::AlignExt;
use framevisor::{
    hello_world,
    mm::{frame, vm_space, FrameAllocOptions, Vaddr, VmSpace},
    prelude::*,
    print, print_num,
    task::{disable_preempt, Task, TaskOptions},
};

/// The kernel's boot and initialization process is managed by OSTD.
/// After the process is done, the kernel's execution environment
/// (e.g., stack, heap, tasks) will be ready for use and the entry function
/// labeled as `#[ostd::main]` will be called.
#[framevisor::main]
pub fn main() {
    // hello_world();
    // let program_binary = include_bytes!("./hello");
    // let x = Box::new(42);
    // print_num(x);
    // hello_world();
    let str_data: String = String::from("Hello from FrameVM user task!\n");
    hello_world();
    print(str_data);
    hello_world();
    // let vm_space = Arc::new(create_vm_space(program_binary));
    let vm_space = Arc::new(create_vm_space());
    vm_space.activate();
    create_user_task(vm_space);
    hello_world();
}

fn create_vm_space() -> VmSpace {
    let user_pages = {
        let segment = FrameAllocOptions::new().alloc_segment(1).unwrap();
        segment
    };

    let vm_space = VmSpace::new();
    let preempt_guard = disable_preempt();
    // let mut cursor = vm_space.cursor_mut(&preempt_guard, &(0x0040_0000..0x0040_0000 + 0x1000)).unwrap();
    // drop(cursor);
    vm_space
}

fn create_user_task(vm_space: Arc<VmSpace>) {
    // Arc::new(TaskOptions::new(|| {}).data(vm_space).build().unwrap())
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    loop {}
}
