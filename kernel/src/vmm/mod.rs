// SPDX-License-Identifier: MPL-2.0

use aster_framevisor::start_framevm;
use ostd::task::Task;

use crate::{
    fs::{
        file_handle::FileLike,
        path::FsPath,
        utils::{AccessMode, InodeMode, OpenArgs},
    },
    prelude::*,
    process::posix_thread::AsThreadLocal,
    thread::kernel_thread::ThreadOptions,
};

/// Load and start the FrameVM (synchronous, blocks until FrameVM exits)
pub fn load_framevm() -> Result<()> {
    let elf_data = read_framevm_elf()?;
    start_framevm();
    load_framevm_file(&elf_data)?;
    Ok(())
}

/// Load and start the FrameVM in a background thread.
///
/// This function is designed for `/proc/framevm`: it returns immediately after spawning the
/// background loader thread, so the write syscall can return without blocking the caller shell.
pub fn load_framevm_background() -> Result<()> {
    // Read the ELF data in the current task context (has filesystem access and process context).
    // We must NOT hold the file handle into the kernel thread, because:
    // - Kernel threads don't have an associated process
    // - When the file handle is dropped, InodeHandle::drop calls release_range_locks
    // - release_range_locks creates RangeLockItem::new() which calls current!().pid()
    // - current!() calls Process::current().unwrap(), which panics in a kernel thread
    let elf_data = read_framevm_elf()?;

    println!("[FrameVM] Spawning FrameVM in background thread...");
    ThreadOptions::new(move || {
        let res: Result<()> = (|| {
            start_framevm();
            load_framevm_file(&elf_data)?;
            Ok(())
        })();

        if let Err(e) = res {
            println!("[FrameVM] FrameVM thread error: {:?}", e);
        }
    })
    .spawn();

    Ok(())
}

/// Read the FrameVM ELF file from the filesystem
fn read_framevm_elf() -> Result<Vec<u8>> {
    let framevm_file = open_framevm_elf_file()?;

    let file_size = framevm_file.path().inode().size();
    println!("[FrameVM] file size: {} bytes", file_size);

    let mut elf_data = vec![0u8; file_size];
    framevm_file.read_bytes_at(0, &mut elf_data)?;

    Ok(elf_data)
}

fn open_framevm_elf_file() -> Result<Arc<dyn FileLike>> {
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
    Ok(framevm_file)
}

/// Load and run FrameVM from ELF data (blocks until FrameVM exits)
fn load_framevm_file(elf_data: &[u8]) -> Result<()> {
    let frame_vm_info = ostd::loader::FrameVmInfo::load_framevm_file(elf_data)?;

    // 直接调用入口点，不创建新 Task
    frame_vm_info.start_framevm()?;

    Ok(())
}
