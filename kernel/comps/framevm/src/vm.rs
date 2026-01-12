//! Guest VM address-space construction and user stack allocation.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use align_ext::AlignExt;
use aster_framevisor::{
    mm::{CachePolicy, FrameAllocOptions, PageFlags, PageProperty, VmSpace},
    task::disable_preempt,
};
use xmas_elf::{
    ElfFile, header,
    program::{self, ProgramHeader},
};

use crate::error::{Errno, Error, Result};

const PAGE_SIZE: usize = 4096;

/// User stack configuration
pub const USER_STACK_BASE: usize = 0x7FFF_F000_0000; // Stack grows down from here
pub const USER_STACK_SIZE: usize = 16 * PAGE_SIZE; // 64KB stack

/// Next stack base (top address). Stacks are allocated downward.
static NEXT_STACK_BASE: AtomicUsize = AtomicUsize::new(USER_STACK_BASE);

/// VM space creation result
pub struct VmSpaceInfo {
    pub vm_space: VmSpace,
    pub entry_point: usize,
    pub stack_top: usize,
    pub lazy_ranges: Vec<LazyRange>,
}

#[derive(Clone, Debug)]
pub struct LazyRange {
    start_addr: usize,
    end_addr: usize,
    page_flags: PageFlags,
}

impl LazyRange {
    pub fn new(start_addr: usize, end_addr: usize, page_flags: PageFlags) -> Self {
        Self {
            start_addr,
            end_addr,
            page_flags,
        }
    }

    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.start_addr && addr < self.end_addr
    }

    pub fn page_flags(&self) -> PageFlags {
        self.page_flags
    }
}

pub fn create_vm_space(program: &[u8]) -> Result<VmSpaceInfo> {
    framevm_logln!("[FrameVM] Creating VM space...");
    let elf =
        ElfFile::new(program).map_err(|_| Error::with_message(Errno::EINVAL, "ELF parse error"))?;

    header::sanity_check(&elf)
        .map_err(|_| Error::with_message(Errno::EINVAL, "ELF sanity check failed"))?;

    let vm_space = VmSpace::new();

    let mut lazy_ranges = Vec::new();
    for ph in elf.program_iter() {
        if ph
            .get_type()
            .map_err(|_| Error::with_message(Errno::EINVAL, "Invalid program header type"))?
            == program::Type::Load
        {
            load_segment(&vm_space, &ph, program, &mut lazy_ranges)?;
        }
    }

    // Allocate user stack
    let stack_top = allocate_user_stack(&vm_space)?;

    let entry_point = elf.header.pt2.entry_point() as usize;
    framevm_logln!(
        "[FrameVM] VM space created. Entry: 0x{:x}, Stack: 0x{:x}",
        entry_point,
        stack_top
    );
    Ok(VmSpaceInfo {
        vm_space,
        entry_point,
        stack_top,
        lazy_ranges,
    })
}

/// Allocate user stack and return stack top address
pub fn allocate_user_stack(vm_space: &VmSpace) -> Result<usize> {
    let stack_base = NEXT_STACK_BASE.fetch_sub(USER_STACK_SIZE, Ordering::SeqCst);
    let stack_bottom = stack_base - USER_STACK_SIZE;
    let page_count = USER_STACK_SIZE / PAGE_SIZE;

    framevm_logln!(
        "[FrameVM] Allocating user stack: 0x{:x}-0x{:x}",
        stack_bottom,
        stack_base
    );

    let segment = FrameAllocOptions::new()
        .alloc_segment(page_count)
        .map_err(|e| Error::from(e))?;

    let preempt_guard = disable_preempt();
    let mut cursor = vm_space
        .cursor_mut(&preempt_guard, &(stack_bottom..stack_base))
        .map_err(|e| Error::from(e))?;

    // Stack is RW, no execute
    let page_flags = PageFlags::R | PageFlags::W;
    let map_prop = PageProperty::new_user(page_flags, CachePolicy::Writeback);

    for frame in segment.into_iter() {
        cursor.map(frame.into(), map_prop);
    }

    // Return stack top (stack grows down, so top is at higher address)
    // Align to 16 bytes as required by x86-64 ABI
    Ok(stack_base - 8)
}

fn load_segment(
    vm_space: &VmSpace,
    ph: &ProgramHeader,
    program_data: &[u8],
    lazy_ranges: &mut Vec<LazyRange>,
) -> Result<()> {
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
    let file_end_vaddr = vaddr + file_size;
    let file_end_aligned = if file_size == 0 {
        start_vaddr_aligned
    } else {
        file_end_vaddr.align_up(PAGE_SIZE)
    };
    let file_map_end = core::cmp::min(file_end_aligned, end_vaddr_aligned);
    let file_page_count = (file_map_end - start_vaddr_aligned) / PAGE_SIZE;

    framevm_logln!(
        "[FrameVM] Loading segment: vaddr=0x{:x}, file_pages={}, lazy_pages={}",
        vaddr,
        file_page_count,
        (end_vaddr_aligned - file_map_end) / PAGE_SIZE
    );

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

    if file_page_count > 0 {
        let segment = FrameAllocOptions::new()
            .alloc_segment(file_page_count)
            .map_err(|e| Error::from(e))?;
        let page_offset = vaddr % PAGE_SIZE;
        if file_size > 0 {
            segment
                .write_bytes(page_offset, &program_data[offset..offset + file_size])
                .map_err(|e| Error::from(e))?;
        }

        let preempt_guard = disable_preempt();
        let mut cursor = vm_space
            .cursor_mut(&preempt_guard, &(start_vaddr_aligned..file_map_end))
            .map_err(|e| Error::from(e))?;
        for frame in segment.into_iter() {
            cursor.map(frame.into(), map_prop);
        }
    }

    if file_map_end < end_vaddr_aligned {
        let bss_start = if file_size == 0 {
            start_vaddr_aligned
        } else {
            file_end_vaddr.align_up(PAGE_SIZE)
        };
        if bss_start < end_vaddr_aligned {
            lazy_ranges.push(LazyRange::new(bss_start, end_vaddr_aligned, page_flags));
        }
    }

    Ok(())
}
