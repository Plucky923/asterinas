// SPDX-License-Identifier: MPL-2.0

//! Trimmed kernel image running on an OSTD-compatible object surface.

#![no_std]
#![no_main]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::{string::String, sync::Arc, vec::Vec};
use core::panic::PanicInfo;

use ostd::{cpu::CpuId, sync::WaitQueue};

mod console;
mod context;
mod cpu;
mod device;
mod error;
mod events;
mod fd_table;
mod fs_context;
mod futex;
mod net;
mod pollee;
mod prelude;
mod process;
mod resource;
mod robust_list;
mod rootfs;
mod scheduler;
mod share_bench;
mod signal;
mod syscall;
mod task;
mod time;
mod vm;

use ostd::task::Task;
use task::{
    create_user_task, post_schedule_handler, pre_schedule_handler, pre_user_run_handler,
    user_page_fault_handler, wait_for_user_task_to_exit,
};
use vm::{activate_kernel_vm_space, create_vm_space};

/// The kernel's boot and initialization process is managed by OSTD.
#[ostd::main]
pub fn main() {
    ostd::early_println!("[kernel] service entry");
    ostd::task::inject_pre_user_run_handler(pre_user_run_handler);
    ostd::task::inject_pre_schedule_handler(pre_schedule_handler);
    ostd::task::inject_post_schedule_handler(post_schedule_handler);
    ostd::arch::trap::inject_user_page_fault_handler(user_page_fault_handler);
    ostd::early_println!("[kernel] service hooks installed");
    scheduler::init();
    ostd::early_println!("[kernel] scheduler ready");
    time::init();
    device::init();
    futex::init();
    let rootfs = match rootfs::RootFs::install_from_boot_info() {
        Ok(rootfs) => rootfs,
        Err(e) => {
            ostd::early_println!("[kernel] critical error: failed to install rootfs: {:?}", e);
            return;
        }
    };
    ostd::early_println!("[kernel] rootfs ready");

    let boot_mode = boot_mode_from_cmdline();

    let user_tasks = match boot_mode {
        BootMode::InteractiveShell => run_init(rootfs.as_ref()),
        BootMode::BusyBoxSmoke => run_busybox_smoke(rootfs.as_ref()),
        BootMode::ShareBenchmark { duration_ms } => share_bench::run(rootfs.clone(), duration_ms),
    };
    let user_tasks = match user_tasks {
        Ok(user_tasks) => user_tasks,
        Err(e) => {
            ostd::early_println!("[kernel] critical error: kernel run failed: {:?}", e);
            Vec::new()
        }
    };

    // Switch to a long-lived VM space before dropping guest address spaces.
    activate_kernel_vm_space();
    drop(user_tasks);
}

enum BootMode {
    InteractiveShell,
    BusyBoxSmoke,
    ShareBenchmark { duration_ms: u64 },
}

fn boot_mode_from_cmdline() -> BootMode {
    let boot_info = ostd::boot::boot_info();

    if cmdline_has_value(&boot_info.kernel_cmdline, "kernel.mode", "busybox-smoke") {
        return BootMode::BusyBoxSmoke;
    }

    if !cmdline_has_value(&boot_info.kernel_cmdline, "kernel.mode", "share-benchmark") {
        return BootMode::InteractiveShell;
    }

    let duration_ms = cmdline_value(&boot_info.kernel_cmdline, "kernel.duration_ms")
        .and_then(parse_u64)
        .unwrap_or(3_000);
    BootMode::ShareBenchmark { duration_ms }
}

fn cmdline_has_value(cmdline: &str, key: &str, value: &str) -> bool {
    cmdline_value(cmdline, key).is_some_and(|found| found == value)
}

fn cmdline_value<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    cmdline.split_whitespace().find_map(|arg| {
        let (arg_key, arg_value) = arg.split_once('=')?;
        (arg_key == key).then_some(arg_value)
    })
}

fn parse_u64(value: &str) -> Option<u64> {
    let mut number = 0u64;
    for byte in value.bytes() {
        if !byte.is_ascii_digit() {
            return None;
        }
        let digit = u64::from(byte - b'0');
        number = number.checked_mul(10)?.checked_add(digit)?;
    }
    Some(number)
}

fn run_init(rootfs: &rootfs::RootFs) -> error::Result<Vec<Arc<Task>>> {
    let init_program = "/init";
    let argv = Vec::from([String::from(init_program)]);
    let envp = Vec::from([
        String::from("PATH=/bin"),
        String::from("HOME=/"),
        String::from("TERM=linux"),
    ]);

    run_user_program(rootfs, init_program, argv, envp, true)
}

fn run_busybox_smoke(rootfs: &rootfs::RootFs) -> error::Result<Vec<Arc<Task>>> {
    let shell_program = "/bin/sh";
    let command = "set -e; pwd; ls /; cat /proc/mounts; \
        test -x /bin/busybox; test -x /bin/sh; test -x /bin/vsock-probe; test -d /proc; \
        cd /tmp; pwd; printf 'framevm-cwd-ok\\n' > cwd-file; cat cwd-file; \
        rm cwd-file; test ! -e cwd-file; cd /; ls -l /linktmp; \
        /bin/vsock-probe; \
        echo kernel-busybox-rootfs ok; echo kernel-busybox-vfs ok; \
        echo kernel-busybox-smoke passed";
    let argv = Vec::from([
        String::from(shell_program),
        String::from("-c"),
        String::from(command),
    ]);
    let envp = Vec::from([
        String::from("PATH=/bin"),
        String::from("HOME=/"),
        String::from("TERM=linux"),
    ]);

    run_user_program(rootfs, shell_program, argv, envp, false)
}

fn run_user_program(
    rootfs: &rootfs::RootFs,
    program: &str,
    argv: Vec<String>,
    envp: Vec<String>,
    acquire_console_input: bool,
) -> error::Result<Vec<Arc<Task>>> {
    let program_binary = rootfs.open_file(program)?.data();

    let vm_info = create_vm_space(program_binary.as_ref(), &argv, &envp)?;
    ostd::early_println!(
        "[kernel] user ELF: program={}, entry=0x{:x}, stack=0x{:x}, heap=0x{:x}",
        program,
        vm_info.entry_point,
        vm_info.stack_top,
        vm_info.heap_base
    );
    let vm_space = Arc::new(vm_info.vm_space);

    let finish_queue = Arc::new(WaitQueue::new());
    let user_task = create_user_task(
        program,
        vm_space.clone(),
        vm_info.entry_point,
        vm_info.stack_top,
        vm_info.heap_base,
        Arc::new(vm_info.lazy_ranges),
        finish_queue,
        CpuId::bsp(),
    )?;

    if acquire_console_input {
        let _ = console::acquire_input();
    }
    user_task.run();

    // PID 1 exiting tears down the kernel image.
    wait_for_user_task_to_exit(&user_task);
    if acquire_console_input {
        let _ = console::release_input();
    }

    Ok(Vec::from([user_task]))
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    ostd::early_println!("[kernel] panic: {}", info);
    loop {}
}
