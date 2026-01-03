use alloc::vec;

use align_ext::AlignExt;
use aster_framevisor::{
    mm::{CachePolicy, FrameAllocOptions, PageFlags, PageProperty, VmSpace},
    println,
    task::disable_preempt,
};
use xmas_elf::{
    header,
    program::{self, ProgramHeader},
    ElfFile,
};

use crate::error::{Errno, Error, Result};

const PAGE_SIZE: usize = 4096;

/// User stack configuration
const USER_STACK_BASE: usize = 0x7FFF_F000_0000; // Stack grows down from here
const USER_STACK_SIZE: usize = 16 * PAGE_SIZE; // 64KB stack

/// VM space creation result
pub struct VmSpaceInfo {
    pub vm_space: VmSpace,
    pub entry_point: usize,
    pub stack_top: usize,
}

pub fn create_vm_space(program: &[u8]) -> Result<VmSpaceInfo> {
    println!("[FrameVM] Creating VM space...");
    let elf =
        ElfFile::new(program).map_err(|_| Error::with_message(Errno::EINVAL, "ELF parse error"))?;

    header::sanity_check(&elf)
        .map_err(|_| Error::with_message(Errno::EINVAL, "ELF sanity check failed"))?;

    let vm_space = VmSpace::new();

    for ph in elf.program_iter() {
        if ph
            .get_type()
            .map_err(|_| Error::with_message(Errno::EINVAL, "Invalid program header type"))?
            == program::Type::Load
        {
            load_segment(&vm_space, &ph, program)?;
        }
    }

    // Allocate user stack
    let stack_top = allocate_user_stack(&vm_space)?;

    let entry_point = elf.header.pt2.entry_point() as usize;
    println!(
        "[FrameVM] VM space created. Entry: 0x{:x}, Stack: 0x{:x}",
        entry_point, stack_top
    );
    Ok(VmSpaceInfo {
        vm_space,
        entry_point,
        stack_top,
    })
}

/// Allocate user stack and return stack top address
fn allocate_user_stack(vm_space: &VmSpace) -> Result<usize> {
    let stack_bottom = USER_STACK_BASE - USER_STACK_SIZE;
    let page_count = USER_STACK_SIZE / PAGE_SIZE;

    println!(
        "[FrameVM] Allocating user stack: 0x{:x}-0x{:x}",
        stack_bottom, USER_STACK_BASE
    );

    let segment = FrameAllocOptions::new()
        .alloc_segment(page_count)
        .map_err(|e| Error::from(e))?;

    let preempt_guard = disable_preempt();
    let mut cursor = vm_space
        .cursor_mut(&preempt_guard, &(stack_bottom..USER_STACK_BASE))
        .map_err(|e| Error::from(e))?;

    // Stack is RW, no execute
    let page_flags = PageFlags::R | PageFlags::W;
    let map_prop = PageProperty::new_user(page_flags, CachePolicy::Writeback);

    for frame in segment.into_iter() {
        cursor.map(frame.into(), map_prop);
    }

    // Return stack top (stack grows down, so top is at higher address)
    // Align to 16 bytes as required by x86-64 ABI
    Ok(USER_STACK_BASE - 8)
}

fn load_segment(vm_space: &VmSpace, ph: &ProgramHeader, program_data: &[u8]) -> Result<()> {
    let vaddr = ph.virtual_addr() as usize;
    let mem_size = ph.mem_size() as usize;
    let file_size = ph.file_size() as usize;
    let offset = ph.offset() as usize;
    let flags = ph.flags();

    if mem_size == 0 {
        return Ok(());
    }

    let start_vaddr_aligned = vaddr.align_down(PAGE_SIZE);
    let end_vaddr_aligned = (vaddr + mem_size).align_up(PAGE_SIZE);
    let page_count = (end_vaddr_aligned - start_vaddr_aligned) / PAGE_SIZE;

    println!(
        "[FrameVM] Loading segment: vaddr=0x{:x}, pages={}",
        vaddr, page_count
    );

    let segment = FrameAllocOptions::new()
        .alloc_segment(page_count)
        .map_err(|e| Error::from(e))?;

    let page_offset = vaddr % PAGE_SIZE;
    if file_size > 0 {
        segment
            .write_bytes(page_offset, &program_data[offset..offset + file_size])
            .map_err(|e| Error::from(e))?;
    }

    if mem_size > file_size {
        let bss_start = page_offset + file_size;
        let bss_size = mem_size - file_size;
        let zeros = vec![0u8; bss_size];
        segment
            .write_bytes(bss_start, &zeros)
            .map_err(|e| Error::from(e))?;
    }

    let preempt_guard = disable_preempt();
    let mut cursor = vm_space
        .cursor_mut(&preempt_guard, &(start_vaddr_aligned..end_vaddr_aligned))
        .map_err(|e| Error::from(e))?;

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

    Ok(())
}
