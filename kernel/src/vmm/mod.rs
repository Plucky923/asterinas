// SPDX-License-Identifier: MPL-2.0

use aster_framevisor::start_framevm;
use ostd::task::Task;

use crate::{
    fs::{
        file_handle::FileLike,
        fs_resolver::FsPath,
        utils::{AccessMode, InodeMode, OpenArgs},
    },
    net::socket::framevsock::test as framevsock_test,
    prelude::*,
    process::posix_thread::AsThreadLocal,
    thread::kernel_thread::ThreadOptions,
};

/// Load and start the FrameVM (synchronous, blocks until FrameVM exits)
pub fn load_framevm() -> Result<()> {
    let elf_data = read_framevm_elf()?;

    // Setup FrameVsock test infrastructure before starting FrameVM
    // This starts the Host echo server so Guest can connect to it
    if let Err(e) = framevsock_test::setup_pre_framevm() {
        println!(
            "[FrameVM] Warning: Failed to setup FrameVsock tests: {:?}",
            e
        );
    }

    start_framevm();
    load_framevm_file(&elf_data)?;
    Ok(())
}

/// Load and start the FrameVM with post-start tests
/// Use this for testing bidirectional communication
///
/// This spawns FrameVM in a background kernel thread, then runs
/// Host -> Guest tests in the main thread.
pub fn load_framevm_with_tests() -> Result<()> {
    // Read ELF data in the main thread (has access to filesystem)
    let elf_data = read_framevm_elf()?;

    // Setup test infrastructure first
    if let Err(e) = framevsock_test::setup_pre_framevm() {
        println!(
            "[FrameVM] Warning: Failed to setup FrameVsock tests: {:?}",
            e
        );
    }

    // Spawn FrameVM in a separate kernel thread
    println!("[FrameVM] Spawning FrameVM in background thread...");
    ThreadOptions::new(move || {
        start_framevm();
        if let Err(e) = load_framevm_file(&elf_data) {
            println!("[FrameVM] FrameVM thread error: {:?}", e);
        }
    })
    .spawn();

    println!("[FrameVM] Waiting for Guest to start...");
    for _ in 0..100000 {
        Task::yield_now();
    }
    println!("[FrameVM] Guest initialization period complete");

    // Run Host -> Guest tests
    println!("[FrameVM] Running Host -> Guest tests...");
    if let Err(e) = framevsock_test::run_post_framevm_tests() {
        println!("[FrameVM] Post-FrameVM tests failed: {:?}", e);
    }

    Ok(())
}

/// Read the FrameVM ELF file from the filesystem
fn read_framevm_elf() -> Result<Vec<u8>> {
    println!("[FrameVM] open /framevm/framevm.o");
    let task = Task::current().unwrap();
    let thread_local = task.as_thread_local().unwrap();

    let framevm_file: Arc<dyn FileLike> = {
        let fs_ref = thread_local.borrow_fs();
        let fs_resolver = fs_ref.resolver().read();

        let fs_path = FsPath::try_from("/framevm/framevm.o")?;
        let path = fs_resolver.lookup(&fs_path)?;
        let open_args =
            OpenArgs::from_modes(AccessMode::O_RDONLY, InodeMode::from_bits_truncate(0o644));
        let inode_handle = path.open(open_args)?;

        Arc::new(inode_handle)
    };
    println!("[FrameVM] /framevm/framevm.o file opened successfully");

    let file_size = framevm_file.inode().size();
    println!("[FrameVM] file size: {} bytes", file_size);

    let mut elf_data = vec![0u8; file_size];
    framevm_file.read_bytes_at(0, &mut elf_data)?;

    Ok(elf_data)
}

/// Load and run FrameVM from ELF data (blocks until FrameVM exits)
fn load_framevm_file(elf_data: &[u8]) -> Result<()> {
    let frame_vm_info = ostd::loader::FrameVmInfo::load_framevm_file(elf_data)?;

    // 直接调用入口点，不创建新 Task
    frame_vm_info.start_framevm()?;

    Ok(())
}
