// SPDX-License-Identifier: MPL-2.0

use aster_framevisor::start_framevm;
use ostd::task::Task;

use crate::{
    fs::{
        file_handle::FileLike,
        fs_resolver::FsPath,
        inode_handle::InodeHandle,
        utils::{AccessMode, InodeMode, OpenArgs},
    },
    prelude::*,
    process::posix_thread::AsThreadLocal,
};

/// Load and start the FrameVM
pub fn load_framevm() -> Result<()> {
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

    start_framevm();
    load_framevm_file(&elf_data)?;
    Ok(())
}

fn load_framevm_file(elf_data: &[u8]) -> Result<()> {
    let frame_vm_info = ostd::loader::FrameVmInfo::load_framevm_file(elf_data)?;

    // 直接调用入口点，不创建新 Task
    frame_vm_info.start_framevm()?;

    Ok(())
}
