// SPDX-License-Identifier: MPL-2.0

//! Trimmed kernel image running on an OSTD-compatible object surface.

#![no_std]
#![no_main]
#![deny(unsafe_code)]
#![feature(array_try_from_fn)]
#![feature(associated_type_defaults)]
#![feature(btree_cursors)]
#![feature(debug_closure_helpers)]
#![feature(format_args_nl)]
#![feature(linked_list_cursors)]
#![feature(linked_list_retain)]
#![feature(min_specialization)]
#![feature(panic_can_unwind)]
#![feature(thin_box)]
#![feature(unique_rc_arc)]
#![feature(vec_deque_truncate_front)]

extern crate alloc;
#[macro_use]
extern crate ostd_pod;

macro_rules! __log_prefix {
    () => {
        "framevm: "
    };
}

use core::panic::PanicInfo;

#[cfg_attr(target_arch = "x86_64", path = "arch/x86/mod.rs")]
#[cfg_attr(target_arch = "riscv64", path = "arch/riscv/mod.rs")]
#[cfg_attr(target_arch = "loongarch64", path = "arch/loongarch/mod.rs")]
mod arch;
mod context;
mod cpu;
mod device;
mod error;
mod events;
mod fs;
mod init;
mod ipc;
mod net;
mod prelude;
mod process;
mod sched;
mod security;
mod syscall;
mod thread;
mod time;
mod util;
mod vm;

pub(crate) use error::{return_errno, return_errno_with_message};
pub(crate) use process::{posix_thread::futex, signal, signal as pollee};
pub(crate) use thread::task;

#[cfg(not(ktest))]
pub extern "Rust" fn __ostd_main() -> ! {
    init::main();
    ostd::power::poweroff(ostd::power::ExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    ostd::error!("[kernel] panic: {}", info);
    ostd::panic::abort()
}
