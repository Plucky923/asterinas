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
use core::{
    panic::PanicInfo,
    str,
    sync::atomic::{AtomicBool, Ordering},
};

use align_ext::AlignExt;
use aster_framevisor::{
    arch::cpu::context::UserContext,
    hello_world,
    mm::{
        frame, io::FallibleVmRead, vm_space, CachePolicy, FrameAllocOptions, PageFlags,
        PageProperty, Vaddr, VmSpace, VmWriter,
    },
    power::{poweroff, ExitCode},
    prelude::*,
    print, print_num, println,
    task::{disable_preempt, Task, TaskOptions},
    user::{ReturnReason, UserContextApi, UserMode},
};
use ostd::early_println;
use xmas_elf::{header, program, ElfFile};

struct UserTaskData {
    vm_space: Arc<VmSpace>,
    entry_point: usize,
    finished: Arc<AtomicBool>,
}

impl UserTaskData {
    fn vm_space(&self) -> Arc<VmSpace> {
        self.vm_space.clone()
    }
}

fn post_schedule_handler() {
    let task = Task::current().unwrap();
    let Some(user_task_data) = task.data().downcast_ref::<UserTaskData>() else {
        return;
    };
    let vm_space = user_task_data.vm_space();
    vm_space.activate();
}

const PAGE_SIZE: usize = 4096;

/// The kernel's boot and initialization process is managed by OSTD.
/// After the process is done, the kernel's execution environment
/// (e.g., stack, heap, tasks) will be ready for use and the entry function
/// labeled as `#[ostd::main]` will be called.
#[aster_framevisor::main]
pub fn main() {
    early_println!("[framevisor] main: Starting FrameVM main function");
    aster_framevisor::task::inject_post_schedule_handler(post_schedule_handler);
    let program_data = include_bytes!("hello");
    let mut program_binary_vec = vec![0u8; program_data.len()];
    program_binary_vec.copy_from_slice(program_data);
    let program_binary = &program_binary_vec;

    // Verify alignment just in case
    if program_binary.as_ptr() as usize % 8 != 0 {
        early_println!(
            "[framevisor] main: WARNING - program binary not 8-byte aligned! Address: {:p}",
            program_binary.as_ptr()
        );
    }

    early_println!(
        "[framevisor] main: Loaded program binary, len: {}",
        program_binary.len()
    );

    early_println!("[framevisor] main: Creating VM space...");
    let (vm_space, entry_point) = create_vm_space(program_binary);
    let vm_space = Arc::new(vm_space);
    early_println!("[framevisor] main: VM space created, activating...");
    vm_space.activate();
    early_println!("[framevisor] main: VM space activated");

    early_println!("[framevisor] main: Creating user task...");
    let user_task = create_user_task(vm_space, entry_point);

    let finished = user_task
        .data()
        .downcast_ref::<UserTaskData>()
        .unwrap()
        .finished
        .clone();

    early_println!("[framevisor] main: User task created, about to call run()...");
    user_task.run();
    early_println!("task:{:?}", user_task);

    // 防止任务退出，导致FrameVM的内存被释放
    while !finished.load(Ordering::SeqCst) {
        Task::yield_now();
    }
    early_println!("[framevisor] main: User task finished, exiting.");
}

fn create_vm_space(program: &[u8]) -> (VmSpace, usize) {
    early_println!("[framevisor] create_vm_space: Parsing ELF...");
    let elf = ElfFile::new(program).expect("Failed to parse ELF");
    header::sanity_check(&elf).expect("ELF sanity check failed");

    let vm_space = VmSpace::new();

    for ph in elf.program_iter() {
        if ph.get_type().unwrap() == program::Type::Load {
            let vaddr = ph.virtual_addr() as usize;
            let mem_size = ph.mem_size() as usize;
            let file_size = ph.file_size() as usize;
            let offset = ph.offset() as usize;
            let flags = ph.flags();

            if mem_size == 0 {
                continue;
            }

            let start_vaddr_aligned = vaddr.align_down(PAGE_SIZE);
            let end_vaddr_aligned = (vaddr + mem_size).align_up(PAGE_SIZE);
            let page_count = (end_vaddr_aligned - start_vaddr_aligned) / PAGE_SIZE;

            early_println!(
                "[framevisor] Loading segment: vaddr={:x}, mem_size={:x}, pages={}",
                vaddr,
                mem_size,
                page_count
            );

            let segment = FrameAllocOptions::new()
                .alloc_segment(page_count)
                .expect("Failed to allocate segment");

            let page_offset = vaddr % PAGE_SIZE;
            if file_size > 0 {
                segment
                    .write_bytes(page_offset, &program[offset..offset + file_size])
                    .expect("Failed to write segment data");
            }

            if mem_size > file_size {
                let bss_start = page_offset + file_size;
                let bss_size = mem_size - file_size;
                let zeros = vec![0u8; bss_size];
                segment
                    .write_bytes(bss_start, &zeros)
                    .expect("Failed to zero BSS");
            }

            let preempt_guard = disable_preempt();
            let mut cursor = vm_space
                .cursor_mut(&preempt_guard, &(start_vaddr_aligned..end_vaddr_aligned))
                .unwrap();

            let mut page_flags = PageFlags::empty();
            if flags.is_read() {
                page_flags |= PageFlags::R;
            }
            if flags.is_write() {
                page_flags |= PageFlags::W;
            }
            if flags.is_execute() {
                page_flags |= PageFlags::X;
            }

            let map_prop = PageProperty::new_user(page_flags, CachePolicy::Writeback);

            for frame in segment.into_iter() {
                cursor.map(frame.into(), map_prop);
            }
        }
    }

    let entry_point = elf.header.pt2.entry_point() as usize;
    early_println!(
        "[framevisor] create_vm_space: VM space setup complete, entry: {:x}",
        entry_point
    );
    (vm_space, entry_point)
}

fn create_user_task(vm_space: Arc<VmSpace>, entry_point: usize) -> Arc<Task> {
    fn user_task() {
        early_println!("[framevisor] user_task: Starting user task function");
        let current = Task::current();
        if current.is_none() {
            early_println!("[framevisor] user_task: ERROR - Task::current() returned None!");
            return;
        }
        let current = current.unwrap();
        early_println!("[framevisor] user_task: Got current task");

        let task_data = current.data().downcast_ref::<UserTaskData>().unwrap();

        task_data.vm_space.activate();

        let entry_point = task_data.entry_point;

        // Switching between user-kernel space is
        // performed via the UserMode abstraction.
        let mut user_mode = {
            early_println!("[framevisor] user_task: Creating user context");
            let user_ctx = create_user_context(entry_point);
            early_println!("[framevisor] user_task: Creating UserMode");
            UserMode::new(user_ctx)
        };
        early_println!("[framevisor] user_task: UserMode created, entering main loop");

        loop {
            early_println!("[framevisor] user_task: About to execute user mode");
            // The execute method returns when system
            // calls or CPU exceptions occur or some
            // events specified by the kernel occur.
            let return_reason = user_mode.execute(|| false);
            early_println!(
                "[framevisor] user_task: Returned from user mode execution, reason: {:?}",
                return_reason
            );

            // The CPU registers of the user space
            // can be accessed and manipulated via
            // the `UserContext` abstraction.
            let user_context = user_mode.context_mut();
            if ReturnReason::UserSyscall == return_reason {
                early_println!(
                    "[framevisor] user_task: Handling syscall: {}",
                    user_context.rax()
                );
                let vm_space = &task_data.vm_space;
                let should_exit = handle_syscall(user_context, vm_space);
                if should_exit {
                    break;
                }
            } else if ReturnReason::UserException == return_reason {
                let exception = user_context.take_exception();
                early_println!(
                    "[framevisor] user_task: User exception occurred: {:?}, RIP: {:x}",
                    exception,
                    user_context.rip()
                );
                break;
            } else {
                early_println!(
                    "[framevisor] user_task: Unexpected return reason: {:?}",
                    return_reason
                );
                break;
            }
        }
        println!("[framevisor] user_task: Exiting user task loop");
        task_data.finished.store(true, Ordering::SeqCst);
    }

    early_println!("[framevisor] create_user_task: Building task with vm_space");
    // Kernel tasks are managed by the Framework,
    // while scheduling algorithms for them can be
    // determined by the users of the Framework.
    let task_data = UserTaskData {
        vm_space,
        entry_point,
        finished: Arc::new(AtomicBool::new(false)),
    };
    let task = TaskOptions::new(user_task).data(task_data).build();
    if task.is_err() {
        early_println!("[framevisor] create_user_task: ERROR - Failed to build task!");
    }
    let task = Arc::new(task.unwrap());
    early_println!("[framevisor] create_user_task: Task built successfully");
    task
}

fn create_user_context(entry_point: usize) -> UserContext {
    // The user-space CPU states can be initialized
    // to arbitrary values via the `UserContext`
    // abstraction.
    let mut user_ctx = UserContext::default();
    user_ctx.set_rip(entry_point);
    user_ctx
}

fn handle_syscall(user_context: &mut UserContext, vm_space: &VmSpace) -> bool {
    const SYS_WRITE: usize = 1;
    const SYS_EXIT: usize = 60;

    match user_context.rax() {
        SYS_WRITE => {
            // Access the user-space CPU registers safely.
            let (_, buf_addr, buf_len) =
                (user_context.rdi(), user_context.rsi(), user_context.rdx());
            let buf = {
                let mut buf = vec![0u8; buf_len];
                // Copy data from the user space without
                // unsafe pointer dereferencing.
                let mut reader = vm_space.reader(buf_addr, buf_len).unwrap();
                reader
                    .read_fallible(&mut VmWriter::from(&mut buf as &mut [u8]))
                    .unwrap();
                buf
            };
            // Use the console for output safely.
            early_println!("task: {}", str::from_utf8(&buf).unwrap());
            // Manipulate the user-space CPU registers safely.
            user_context.set_rax(buf_len);
            false
        }
        SYS_EXIT => {
            early_println!("[framevisor] handle_syscall: SYS_EXIT called");
            true
        }
        _ => unimplemented!(),
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("{}", info);
    loop {}
}
