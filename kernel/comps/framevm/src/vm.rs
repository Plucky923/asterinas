//! User address-space construction and stack allocation.

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec, vec::Vec};
use core::{
    cmp,
    ops::Range,
    sync::atomic::{AtomicUsize, Ordering},
};

use align_ext::AlignExt;
use ostd::{
    mm::{
        CachePolicy, FrameAllocOptions, MAX_USERSPACE_VADDR, PageFlags, PageProperty,
        VmQueriedItem, VmSpace, frame::segment::Segment,
    },
    sync::Once,
    task::disable_preempt,
};
use xmas_elf::{
    ElfFile, header,
    program::{self},
};

use crate::{
    device,
    error::{Errno, Error, Result},
};

const PAGE_SIZE: usize = 4096;
const STATIC_PIE_BASE: usize = 0x5555_0000_0000;
const USER_MMAP_BASE: usize = 0x6000_0000_0000;

/// User stack configuration
pub const USER_STACK_BASE: usize = 0x7FFF_F000_0000; // Stack grows down from here
pub const USER_STACK_SIZE: usize = 8 * 1024 * 1024;

/// Next stack base (top address). Stacks are allocated downward.
static NEXT_STACK_BASE: AtomicUsize = AtomicUsize::new(USER_STACK_BASE);
static NEXT_MMAP_BASE: AtomicUsize = AtomicUsize::new(USER_MMAP_BASE);
static KERNEL_VM_SPACE: Once<Arc<VmSpace>> = Once::new();

#[derive(Clone, Copy)]
pub enum ExistingMapping {
    Skip,
    Replace,
    ErrorIfExists,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UserRamMapping {
    start: usize,
    end: usize,
    page_flags: PageFlags,
    cache_policy: CachePolicy,
}

impl UserRamMapping {
    const fn start(self) -> usize {
        self.start
    }

    const fn end(self) -> usize {
        self.end
    }

    const fn len(self) -> usize {
        self.end - self.start
    }

    const fn page_flags(self) -> PageFlags {
        self.page_flags
    }

    const fn cache_policy(self) -> CachePolicy {
        self.cache_policy
    }
}

/// VM space creation result
pub struct VmSpaceInfo {
    pub vm_space: VmSpace,
    pub entry_point: usize,
    pub stack_top: usize,
    pub heap_base: usize,
    pub lazy_ranges: Vec<LazyRange>,
}

pub fn activate_kernel_vm_space() {
    KERNEL_VM_SPACE
        .call_once(|| Arc::new(VmSpace::new()))
        .activate();
}

#[derive(Clone, Debug)]
pub struct LazyRange {
    start_addr: usize,
    end_addr: usize,
    page_flags: PageFlags,
}

impl LazyRange {
    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.start_addr && addr < self.end_addr
    }

    pub fn page_flags(&self) -> PageFlags {
        self.page_flags
    }
}

#[expect(dead_code)]
#[expect(non_camel_case_types)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum AuxKey {
    AT_IGNORE = 1,
    AT_EXECFD = 2,
    AT_PHDR = 3,
    AT_PHENT = 4,
    AT_PHNUM = 5,
    AT_PAGESZ = 6,
    AT_BASE = 7,
    AT_FLAGS = 8,
    AT_ENTRY = 9,
    AT_NOTELF = 10,
    AT_UID = 11,
    AT_EUID = 12,
    AT_GID = 13,
    AT_EGID = 14,
    AT_PLATFORM = 15,
    AT_HWCAP = 16,
    AT_CLKTCK = 17,
    AT_SECURE = 23,
    AT_BASE_PLATFORM = 24,
    AT_RANDOM = 25,
    AT_HWCAP2 = 26,
    AT_EXECFN = 31,
    AT_SYSINFO = 32,
    AT_SYSINFO_EHDR = 33,
}

impl AuxKey {
    const AT_NULL: u8 = 0;
}

#[derive(Clone, Debug, Default)]
struct AuxVec {
    table: BTreeMap<AuxKey, u64>,
}

impl AuxVec {
    fn new() -> Self {
        Self {
            table: BTreeMap::new(),
        }
    }

    fn set(&mut self, key: AuxKey, val: u64) {
        self.table
            .entry(key)
            .and_modify(|value| *value = val)
            .or_insert(val);
    }

    fn table(&self) -> &BTreeMap<AuxKey, u64> {
        &self.table
    }
}

pub fn create_vm_space(program: &[u8], argv: &[String], envp: &[String]) -> Result<VmSpaceInfo> {
    let elf =
        ElfFile::new(program).map_err(|_| Error::with_message(Errno::EINVAL, "ELF parse error"))?;

    header::sanity_check(&elf)
        .map_err(|_| Error::with_message(Errno::EINVAL, "ELF sanity check failed"))?;

    let vm_space = VmSpace::new();
    let load_bias = match elf.header.pt2.type_().as_type() {
        header::Type::Executable => 0,
        header::Type::SharedObject => {
            if has_interp(&elf)? {
                return Err(Error::with_message(
                    Errno::EINVAL,
                    "dynamic ELF interpreters are not supported yet",
                ));
            }
            STATIC_PIE_BASE
        }
        _ => return Err(Error::with_message(Errno::EINVAL, "unsupported ELF type")),
    };

    let heap_base = load_elf_segments(&vm_space, &elf, program, load_bias)?;
    let lazy_ranges = Vec::new();

    let entry_point = elf.header.pt2.entry_point() as usize + load_bias;
    let stack_top = allocate_initial_stack(&vm_space, &elf, load_bias, entry_point, argv, envp)?;

    Ok(VmSpaceInfo {
        vm_space,
        entry_point,
        stack_top,
        heap_base,
        lazy_ranges,
    })
}

/// Clones the mapped RAM contents of a user VM space into a new VM space.
pub fn clone_vm_space(src_vm_space: &VmSpace) -> Result<VmSpace> {
    let dst_vm_space = VmSpace::new();
    for mapped_range in collect_user_ram_mappings(src_vm_space)? {
        clone_mapped_ram_range(src_vm_space, &dst_vm_space, mapped_range)?;
    }
    Ok(dst_vm_space)
}

pub fn map_anonymous(
    vm_space: &VmSpace,
    addr: usize,
    len: usize,
    flags: PageFlags,
    existing_mapping: ExistingMapping,
) -> Result<usize> {
    let map_addr = if addr == 0 {
        NEXT_MMAP_BASE.fetch_add(len.align_up(PAGE_SIZE), Ordering::SeqCst)
    } else {
        addr.align_down(PAGE_SIZE)
    };
    let map_len = len.align_up(PAGE_SIZE);
    map_zeroed_anonymous(vm_space, map_addr, map_len, flags, existing_mapping)?;
    Ok(map_addr)
}

pub fn unmap_range(vm_space: &VmSpace, addr: usize, len: usize) -> Result<()> {
    let range = checked_user_page_range(addr, len, false, Errno::EINVAL)?;
    let preempt_guard = disable_preempt();
    let mut cursor = vm_space
        .cursor_mut(&preempt_guard, &range)
        .map_err(Error::from)?;
    cursor.unmap(range.len());
    Ok(())
}

pub fn protect_range(
    vm_space: &VmSpace,
    addr: usize,
    len: usize,
    page_flags: PageFlags,
) -> Result<()> {
    let range = checked_user_page_range(addr, len, true, Errno::ENOMEM)?;
    if range.is_empty() {
        return Ok(());
    }
    if !is_range_fully_mapped(vm_space, &range)? {
        return Err(Error::new(Errno::ENOMEM));
    }

    let preempt_guard = disable_preempt();
    let mut cursor = vm_space
        .cursor_mut(&preempt_guard, &range)
        .map_err(Error::from)?;
    if !cursor.protect(range.len(), page_flags, CachePolicy::Writeback) {
        return Err(Error::new(Errno::ENOMEM));
    }
    Ok(())
}

pub fn discard_range(vm_space: &VmSpace, addr: usize, len: usize) -> Result<()> {
    let range = checked_user_page_range(addr, len, true, Errno::ENOMEM)?;
    if range.is_empty() {
        return Ok(());
    }
    if !is_range_fully_mapped(vm_space, &range)? {
        return Err(Error::new(Errno::ENOMEM));
    }

    for mapped_range in collect_user_ram_mappings(vm_space)? {
        let start = mapped_range.start().max(range.start);
        let end = mapped_range.end().min(range.end);
        if start >= end {
            continue;
        }
        if !mapped_range.page_flags().contains(PageFlags::W) {
            return Err(Error::with_message(
                Errno::EOPNOTSUPP,
                "discarding non-writable mappings requires VMA backing metadata",
            ));
        }

        map_zeroed_anonymous_with_cache(
            vm_space,
            start,
            end - start,
            mapped_range.page_flags(),
            mapped_range.cache_policy(),
            ExistingMapping::Replace,
        )?;
    }
    Ok(())
}

fn checked_user_page_range(
    addr: usize,
    len: usize,
    allow_zero_len: bool,
    range_error: Errno,
) -> Result<Range<usize>> {
    if !addr.is_multiple_of(PAGE_SIZE) {
        return Err(Error::new(Errno::EINVAL));
    }
    if len == 0 {
        return if allow_zero_len {
            Ok(addr..addr)
        } else {
            Err(Error::new(Errno::EINVAL))
        };
    }

    let end = addr.checked_add(len).ok_or(Error::new(range_error))?;
    let end = align_up_checked(end, PAGE_SIZE, range_error)?;
    if end > max_user_page_addr() {
        return Err(Error::new(range_error));
    }
    Ok(addr..end)
}

fn max_user_page_addr() -> usize {
    MAX_USERSPACE_VADDR / PAGE_SIZE * PAGE_SIZE
}

fn align_up_checked(value: usize, align: usize, error: Errno) -> Result<usize> {
    value
        .checked_add(align - 1)
        .map(|value| value / align * align)
        .ok_or(Error::new(error))
}

pub fn is_range_fully_mapped(vm_space: &VmSpace, range: &Range<usize>) -> Result<bool> {
    let mut cursor = range.start;
    for mapped_range in collect_user_ram_mappings(vm_space)? {
        if mapped_range.end() <= cursor {
            continue;
        }
        if mapped_range.start() > cursor {
            return Ok(false);
        }
        cursor = cursor.max(mapped_range.end());
        if cursor >= range.end {
            return Ok(true);
        }
    }
    Ok(cursor >= range.end)
}

/// Returns the mapped page flags at a user virtual address.
pub fn page_flags_at(vm_space: &VmSpace, vaddr: usize) -> Result<PageFlags> {
    for mapped_range in collect_user_ram_mappings(vm_space)? {
        if mapped_range.start() <= vaddr && vaddr < mapped_range.end() {
            return Ok(mapped_range.page_flags());
        }
    }
    Err(Error::new(Errno::ENOMEM))
}

fn collect_user_ram_mappings(vm_space: &VmSpace) -> Result<Vec<UserRamMapping>> {
    let range_end = max_user_page_addr();
    let preempt_guard = disable_preempt();
    let mut cursor = vm_space
        .cursor(&preempt_guard, &(0..range_end))
        .map_err(Error::from)?;
    let mut ranges = Vec::new();

    loop {
        let cursor_addr = cursor.virt_addr();
        if cursor_addr >= range_end {
            break;
        }

        let Some(mapped_addr) = cursor.find_next(range_end - cursor_addr) else {
            break;
        };
        cursor.jump(mapped_addr).map_err(Error::from)?;

        let (mapped_range, Some(item)) = cursor.query().map_err(Error::from)? else {
            continue;
        };
        if let VmQueriedItem::MappedRam { prop, .. } = item {
            ranges.push(UserRamMapping {
                start: mapped_range.start,
                end: mapped_range.end.min(range_end),
                page_flags: prop.flags,
                cache_policy: prop.cache,
            });
        }

        let next_addr = mapped_range.end.min(range_end);
        if next_addr <= mapped_addr {
            break;
        }
        cursor.jump(next_addr).map_err(Error::from)?;
    }

    Ok(ranges)
}

fn read_user_ram_mapping(vm_space: &VmSpace, vaddr: usize, buf: &mut [u8]) -> Result<()> {
    if buf.is_empty() {
        return Ok(());
    }

    let end = vaddr
        .checked_add(buf.len())
        .ok_or(Error::new(Errno::ENOMEM))?;
    let preempt_guard = disable_preempt();
    let mut cursor = vm_space
        .cursor(&preempt_guard, &(vaddr..end))
        .map_err(Error::from)?;
    let mut copied = 0usize;

    while copied < buf.len() {
        let current = vaddr + copied;
        cursor.jump(current).map_err(Error::from)?;
        let (mapped_range, Some(item)) = cursor.query().map_err(Error::from)? else {
            return Err(Error::new(Errno::ENOMEM));
        };

        let VmQueriedItem::MappedRam { frame, .. } = item else {
            return Err(Error::new(Errno::ENOMEM));
        };

        let read_end = cmp::min(mapped_range.end, end);
        let read_len = read_end - current;
        let frame_offset = current - mapped_range.start;
        frame
            .read_bytes(frame_offset, &mut buf[copied..copied + read_len])
            .map_err(Error::from)?;
        copied += read_len;
    }

    Ok(())
}

fn map_zeroed_anonymous(
    vm_space: &VmSpace,
    start: usize,
    len: usize,
    page_flags: PageFlags,
    existing_mapping: ExistingMapping,
) -> Result<()> {
    map_zeroed_anonymous_with_cache(
        vm_space,
        start,
        len,
        page_flags,
        CachePolicy::Writeback,
        existing_mapping,
    )
}

fn map_zeroed_anonymous_with_cache(
    vm_space: &VmSpace,
    start: usize,
    len: usize,
    page_flags: PageFlags,
    cache_policy: CachePolicy,
    existing_mapping: ExistingMapping,
) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    if !start.is_multiple_of(PAGE_SIZE) || !len.is_multiple_of(PAGE_SIZE) {
        return Err(Error::new(Errno::EINVAL));
    }
    let end = start.checked_add(len).ok_or(Error::new(Errno::ENOMEM))?;
    if matches!(existing_mapping, ExistingMapping::ErrorIfExists)
        && is_user_ram_range_mapped(vm_space, start..end)?
    {
        return Err(Error::new(Errno::EEXIST));
    }

    let page_count = len / PAGE_SIZE;
    let segment = FrameAllocOptions::new()
        .alloc_segment(page_count)
        .map_err(|e| Error::from(e))?;
    zero_segment(&segment, page_count)?;
    let map_prop = PageProperty::new_user(page_flags, cache_policy);

    for (page_idx, frame) in segment.into_iter().enumerate() {
        let page_start = start + page_idx * PAGE_SIZE;
        let page_end = page_start + PAGE_SIZE;
        let preempt_guard = disable_preempt();
        let mut cursor = vm_space
            .cursor_mut(&preempt_guard, &(page_start..page_end))
            .map_err(|e| Error::from(e))?;

        if cursor.is_mapped().map_err(|e| Error::from(e))? {
            match existing_mapping {
                ExistingMapping::Skip => continue,
                ExistingMapping::Replace => {
                    cursor.unmap(PAGE_SIZE);
                    cursor.jump(page_start).map_err(|e| Error::from(e))?;
                }
                ExistingMapping::ErrorIfExists => return Err(Error::new(Errno::EEXIST)),
            }
        }

        cursor.map(frame.into(), map_prop);
    }
    Ok(())
}

fn is_user_ram_range_mapped(vm_space: &VmSpace, range: Range<usize>) -> Result<bool> {
    for mapped_range in collect_user_ram_mappings(vm_space)? {
        if mapped_range.start() < range.end && mapped_range.end() > range.start {
            return Ok(true);
        }
    }
    Ok(false)
}

fn map_segment_at(
    vm_space: &VmSpace,
    start: usize,
    len: usize,
    page_flags: PageFlags,
    segment: Segment<()>,
) -> Result<()> {
    map_segment_at_with_cache(
        vm_space,
        start,
        len,
        page_flags,
        CachePolicy::Writeback,
        segment,
    )
}

fn map_segment_at_with_cache(
    vm_space: &VmSpace,
    start: usize,
    len: usize,
    page_flags: PageFlags,
    cache_policy: CachePolicy,
    segment: Segment<()>,
) -> Result<()> {
    let preempt_guard = disable_preempt();
    let mut cursor = vm_space
        .cursor_mut(&preempt_guard, &(start..start + len))
        .map_err(|e| Error::from(e))?;

    let map_prop = PageProperty::new_user(page_flags, cache_policy);
    for frame in segment.into_iter() {
        cursor.map(frame.into(), map_prop);
    }
    Ok(())
}

fn clone_mapped_ram_range(
    src_vm_space: &VmSpace,
    dst_vm_space: &VmSpace,
    mapped_range: UserRamMapping,
) -> Result<()> {
    let start = mapped_range.start();
    let len = mapped_range.len();
    if len == 0 {
        return Ok(());
    }

    let page_count = len / PAGE_SIZE;
    let segment = FrameAllocOptions::new()
        .alloc_segment(page_count)
        .map_err(Error::from)?;

    let mut page = vec![0u8; PAGE_SIZE];
    for page_idx in 0..page_count {
        let page_vaddr = start + page_idx * PAGE_SIZE;
        read_user_ram_mapping(src_vm_space, page_vaddr, &mut page)?;
        segment
            .write_bytes(page_idx * PAGE_SIZE, &page)
            .map_err(Error::from)?;
    }

    map_segment_at_with_cache(
        dst_vm_space,
        start,
        len,
        mapped_range.page_flags(),
        mapped_range.cache_policy(),
        segment,
    )
}

struct LoadSegmentInfo {
    vaddr: usize,
    mem_size: usize,
    file_size: usize,
    offset: usize,
    page_flags: PageFlags,
}

fn load_elf_segments(
    vm_space: &VmSpace,
    elf: &ElfFile<'_>,
    program_data: &[u8],
    load_bias: usize,
) -> Result<usize> {
    let mut load_segments = Vec::new();
    let mut map_start = usize::MAX;
    let mut map_end = 0usize;
    let mut heap_base = 0usize;

    for ph in elf.program_iter() {
        if ph
            .get_type()
            .map_err(|_| Error::with_message(Errno::EINVAL, "Invalid program header type"))?
            != program::Type::Load
        {
            continue;
        }

        let vaddr = (ph.virtual_addr() as usize)
            .checked_add(load_bias)
            .ok_or(Error::new(Errno::EINVAL))?;
        let mem_size = ph.mem_size() as usize;
        let file_size = ph.file_size() as usize;
        let offset = ph.offset() as usize;
        if mem_size == 0 {
            continue;
        }

        let segment_end = vaddr
            .checked_add(mem_size)
            .ok_or(Error::new(Errno::EINVAL))?;
        let start_vaddr_aligned = vaddr.align_down(PAGE_SIZE);
        let end_vaddr_aligned = segment_end.align_up(PAGE_SIZE);
        let flags = page_flags_from_phdr(ph.flags());

        map_start = map_start.min(start_vaddr_aligned);
        map_end = map_end.max(end_vaddr_aligned);
        heap_base = heap_base.max(segment_end.align_up(PAGE_SIZE));
        load_segments.push(LoadSegmentInfo {
            vaddr,
            mem_size,
            file_size,
            offset,
            page_flags: flags,
        });
    }

    if load_segments.is_empty() {
        return Err(Error::with_message(
            Errno::EINVAL,
            "ELF has no loadable memory range",
        ));
    }

    let page_count = (map_end - map_start) / PAGE_SIZE;
    let segment = FrameAllocOptions::new()
        .alloc_segment(page_count)
        .map_err(|e| Error::from(e))?;
    zero_segment(&segment, page_count)?;

    let mut page_flags = vec![PageFlags::empty(); page_count];
    for load_segment in &load_segments {
        let segment_end = load_segment.vaddr + load_segment.mem_size;
        let start_vaddr_aligned = load_segment.vaddr.align_down(PAGE_SIZE);
        let end_vaddr_aligned = segment_end.align_up(PAGE_SIZE);
        let first_page = (start_vaddr_aligned - map_start) / PAGE_SIZE;
        let end_page = (end_vaddr_aligned - map_start) / PAGE_SIZE;
        for page_idx in first_page..end_page {
            page_flags[page_idx] |= load_segment.page_flags;
        }

        if load_segment.file_size == 0 {
            continue;
        }

        let file_end = load_segment
            .offset
            .checked_add(load_segment.file_size)
            .ok_or(Error::new(Errno::EINVAL))?;
        if file_end > program_data.len() {
            return Err(Error::new(Errno::EINVAL));
        }
        segment
            .write_bytes(
                load_segment.vaddr - map_start,
                &program_data[load_segment.offset..file_end],
            )
            .map_err(|e| Error::from(e))?;
    }

    map_pages_at(vm_space, map_start, &page_flags, segment)?;

    Ok(heap_base)
}

fn map_pages_at(
    vm_space: &VmSpace,
    start: usize,
    page_flags: &[PageFlags],
    segment: Segment<()>,
) -> Result<()> {
    let len = page_flags.len() * PAGE_SIZE;
    let preempt_guard = disable_preempt();
    let mut cursor = vm_space
        .cursor_mut(&preempt_guard, &(start..start + len))
        .map_err(|e| Error::from(e))?;

    for (frame, flags) in segment.into_iter().zip(page_flags.iter()) {
        let map_prop = PageProperty::new_user(*flags, CachePolicy::Writeback);
        cursor.map(frame.into(), map_prop);
    }
    Ok(())
}

fn page_flags_from_phdr(flags: program::Flags) -> PageFlags {
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
    page_flags
}

fn has_interp(elf: &ElfFile<'_>) -> Result<bool> {
    for ph in elf.program_iter() {
        if ph
            .get_type()
            .map_err(|_| Error::with_message(Errno::EINVAL, "Invalid program header type"))?
            == program::Type::Interp
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn zero_segment(segment: &Segment<()>, page_count: usize) -> Result<()> {
    let zeros = [0u8; PAGE_SIZE];
    for page_idx in 0..page_count {
        segment
            .write_bytes(page_idx * PAGE_SIZE, &zeros)
            .map_err(|e| Error::from(e))?;
    }
    Ok(())
}

fn allocate_initial_stack(
    vm_space: &VmSpace,
    elf: &ElfFile<'_>,
    load_bias: usize,
    entry_point: usize,
    argv: &[String],
    envp: &[String],
) -> Result<usize> {
    let stack_base = NEXT_STACK_BASE.fetch_sub(USER_STACK_SIZE, Ordering::SeqCst);
    let stack_bottom = stack_base - USER_STACK_SIZE;
    let page_count = USER_STACK_SIZE / PAGE_SIZE;
    let segment = FrameAllocOptions::new()
        .alloc_segment(page_count)
        .map_err(|e| Error::from(e))?;
    zero_segment(&segment, page_count)?;

    let stack_top = {
        let mut writer = InitialStackWriter {
            segment: &segment,
            stack_bottom,
            pos: stack_base,
        };
        writer.write(elf, load_bias, entry_point, argv, envp)?
    };

    map_segment_at(
        vm_space,
        stack_bottom,
        USER_STACK_SIZE,
        PageFlags::R | PageFlags::W,
        segment,
    )?;
    Ok(stack_top)
}

struct InitialStackWriter<'a> {
    segment: &'a Segment<()>,
    stack_bottom: usize,
    pos: usize,
}

impl InitialStackWriter<'_> {
    fn write(
        &mut self,
        elf: &ElfFile<'_>,
        load_bias: usize,
        entry_point: usize,
        argv: &[String],
        envp: &[String],
    ) -> Result<usize> {
        let envp_pointers = self.write_strings(envp.iter())?;
        let mut argv_pointers = self.write_strings(argv.iter().rev())?;
        argv_pointers.reverse();
        let random_pointer = self.write_bytes(&generate_random_for_aux_vec())?;

        let auxv = build_initial_aux_vec(elf, load_bias, entry_point, random_pointer);

        self.adjust_alignment(auxv.table().len(), argv_pointers.len(), envp_pointers.len())?;
        self.write_auxv(&auxv)?;
        self.write_pointer_array(&envp_pointers)?;
        self.write_pointer_array(&argv_pointers)?;
        self.write_u64(argv.len() as u64)?;

        Ok(self.pos)
    }

    fn write_strings<'a>(
        &mut self,
        strings: impl Iterator<Item = &'a String>,
    ) -> Result<Vec<usize>> {
        let mut pointers = Vec::new();
        for string in strings {
            let mut bytes = Vec::with_capacity(string.len() + 1);
            bytes.extend_from_slice(string.as_bytes());
            bytes.push(0);
            pointers.push(self.write_bytes(&bytes)?);
        }
        Ok(pointers)
    }

    fn adjust_alignment(
        &mut self,
        auxv_len: usize,
        argv_len: usize,
        envp_len: usize,
    ) -> Result<()> {
        self.write_u64(0)?;
        let auxv_size = (auxv_len + 1) * 2 * size_of::<u64>();
        let argv_size = (argv_len + 1) * size_of::<u64>();
        let envp_size = (envp_len + 1) * size_of::<u64>();
        let argc_size = size_of::<u64>();
        let to_write_size = auxv_size + argv_size + envp_size + argc_size;
        if !(self.pos - to_write_size).is_multiple_of(16) {
            self.write_u64(0)?;
        }
        Ok(())
    }

    fn write_auxv(&mut self, auxv: &AuxVec) -> Result<()> {
        self.write_u64(0)?;
        self.write_u64(AuxKey::AT_NULL as u64)?;
        let entries: Vec<_> = auxv
            .table()
            .iter()
            .map(|(aux_key, aux_value)| (*aux_key, *aux_value))
            .collect();
        for (aux_key, aux_value) in entries.iter() {
            self.write_u64(*aux_value)?;
            self.write_u64(*aux_key as u64)?;
        }
        Ok(())
    }

    fn write_pointer_array(&mut self, pointers: &[usize]) -> Result<()> {
        self.write_u64(0)?;
        for pointer in pointers.iter().rev() {
            self.write_u64(*pointer as u64)?;
        }
        Ok(())
    }

    fn write_u64(&mut self, value: u64) -> Result<usize> {
        self.write_bytes(&value.to_ne_bytes())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<usize> {
        self.pos = self
            .pos
            .checked_sub(bytes.len())
            .ok_or(Error::new(Errno::ENOMEM))?;
        self.pos &= !(align_of::<u8>() - 1);
        if self.pos < self.stack_bottom {
            return Err(Error::new(Errno::ENOMEM));
        }

        self.segment
            .write_bytes(self.pos - self.stack_bottom, bytes)
            .map_err(|e| Error::from(e))?;
        Ok(self.pos)
    }
}

fn generate_random_for_aux_vec() -> [u8; 16] {
    let mut random = [0u8; 16];
    device::getrandom_bytes(&mut random);
    random
}

fn build_initial_aux_vec(
    elf: &ElfFile<'_>,
    load_bias: usize,
    entry_point: usize,
    random_pointer: usize,
) -> AuxVec {
    let mut auxv = AuxVec::new();
    auxv.set(AuxKey::AT_PAGESZ, PAGE_SIZE as u64);
    auxv.set(AuxKey::AT_ENTRY, entry_point as u64);
    auxv.set(AuxKey::AT_UID, 0);
    auxv.set(AuxKey::AT_EUID, 0);
    auxv.set(AuxKey::AT_GID, 0);
    auxv.set(AuxKey::AT_EGID, 0);
    auxv.set(AuxKey::AT_SECURE, 0);
    auxv.set(AuxKey::AT_RANDOM, random_pointer as u64);

    if let Some(phdr) = find_program_header_addr(elf, load_bias) {
        auxv.set(AuxKey::AT_PHDR, phdr as u64);
        auxv.set(AuxKey::AT_PHENT, elf.header.pt2.ph_entry_size() as u64);
        auxv.set(AuxKey::AT_PHNUM, elf.header.pt2.ph_count() as u64);
    }
    auxv
}

fn find_program_header_addr(elf: &ElfFile<'_>, load_bias: usize) -> Option<usize> {
    let ph_offset = elf.header.pt2.ph_offset() as usize;
    for ph in elf.program_iter() {
        if ph.get_type().ok()? != program::Type::Load {
            continue;
        }
        let file_start = ph.offset() as usize;
        let file_end = file_start.checked_add(ph.file_size() as usize)?;
        if (file_start..file_end).contains(&ph_offset) {
            return Some(load_bias + ph.virtual_addr() as usize + ph_offset - file_start);
        }
    }
    None
}
