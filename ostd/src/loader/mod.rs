use alloc::{collections::btree_map::BTreeMap, sync::Arc};
use core::cmp;

use xmas_elf::{
    header::Type,
    program::ProgramHeader,
    sections::{
        Rel, Rela, SectionData, SectionHeader, ShType, SHF_ALLOC, SHF_EXECINSTR, SHF_TLS,
        SHF_WRITE, SHN_ABS, SHN_COMMON, SHN_UNDEF,
    },
    symbol_table::{Entry, Entry64},
    ElfFile,
};

use crate::{
    early_println,
    mm::{
        frame::allocator::FrameAllocOptions,
        io::{Infallible, VmReader, VmWriter},
        kspace::kvirt_area::KVirtArea,
        page_prop::{CachePolicy, PageFlags, PageProperty, PrivilegedPageFlags},
        PAGE_SIZE,
    },
    symbols::{self, symbol_addr_by_name},
    Result,
};

pub struct FrameVmInfo<'a> {
    elf_file: ElfFile<'a>,
    entry_point: Option<usize>,
}

impl FrameVmInfo<'_> {
    /// 获取程序的入口点地址
    pub fn entry_point(&self) -> Option<usize> {
        self.entry_point
    }

    pub fn start_framevm(&self) -> Result<()> {
        // 直接在当前 CPU 上调用，不创建新 Task
        early_println!(
            "[Loader] Entry point called directly, entry point: 0x{:x}",
            self.entry_point().unwrap_or(0)
        );
        Ok(())
    }
}

impl<'a> FrameVmInfo<'a> {
    pub fn load_framevm_file(elf_data: &'a [u8]) -> Result<FrameVmInfo<'a>> {
        early_println!("[Loader] load framevm.o");

        let elf_file = ElfFile::new(elf_data).map_err(|_| crate::Error::InvalidArgs)?;

        early_println!("[Loader] ELF file parsed successfully");
        early_println!("[Loader] ELF header: {:?}", elf_file.header);

        // 检查是否是重定位文件
        let typ = elf_file.header.pt2.type_().as_type();
        if typ != Type::Relocatable {
            return Err(crate::Error::InvalidArgs);
        }

        for (i, ph) in elf_file.program_iter().enumerate() {
            match ph {
                ProgramHeader::Ph64(ph64) => {
                    if let Ok(ph_type) = ph64.get_type() {
                        early_println!(
                            "[Loader] Program header {}: type={:?}, offset=0x{:x}, vaddr=0x{:x}, filesz=0x{:x}, memsz=0x{:x}",
                            i,
                            ph_type,
                            ph64.offset,
                            ph64.virtual_addr,
                            ph64.file_size,
                            ph64.mem_size
                        );
                    }
                }
                ProgramHeader::Ph32(_) => {
                    early_println!("[Loader] Program header {}: 32-bit (not supported)", i);
                }
            }
        }

        let (exec_bytes, ro_bytes, rw_bytes) = caculate_section_size(&elf_file);
        let section_memory = alloc_section_memory(exec_bytes, ro_bytes, rw_bytes)?;
        let sections_metadata = load_section_data(&elf_file, &section_memory)?;
        let symbol_table = get_symbol_table(&elf_file)?;
        simply_symbol(symbol_table, &elf_file, &sections_metadata)?;
        relocate_sections(
            &elf_file,
            &sections_metadata,
            default_external_symbol_resolver,
        )?;

        // 查找并记录入口点地址 (_start)
        let entry_point = find_entry_point(&elf_file, &sections_metadata)?;
        if let Some(addr) = entry_point {
            early_println!("[Loader] Entry point (_start) found at: 0x{:x}", addr);
        } else {
            early_println!("[Loader] Warning: Entry point (_start) not found");
        }

        Ok(FrameVmInfo {
            elf_file,
            entry_point,
        })
    }
}

fn get_symbol_table<'a>(elf_file: &'a ElfFile) -> Result<&'a [Entry64]> {
    early_println!("[Loader] Parsing symbol table...");
    let symtab_data = elf_file
        .section_iter()
        .find(|sec| sec.get_type() == Ok(ShType::SymTab))
        .ok_or(crate::Error::InvalidArgs)
        .and_then(|sec| {
            sec.get_data(&elf_file)
                .map_err(|_| crate::Error::InvalidArgs)
        });

    match symtab_data {
        Ok(SectionData::SymbolTable64(symtab)) => Ok(symtab),
        _ => Err(crate::Error::InvalidArgs),
    }
}

// 这个决定后续分配为section分配的内存应该是什么类型
#[derive(Debug)]
enum SectionMemoryType {
    Text,
    RoData,
    RwData,
}

fn select_section_bucket(sh_type: u64) -> SectionMemoryType {
    let is_text = sh_type & SHF_EXECINSTR != 0;
    let is_rodata = sh_type & SHF_WRITE == 0;
    let is_rwdata = sh_type & SHF_WRITE != 0;

    if is_text {
        SectionMemoryType::Text
    } else if is_rwdata {
        SectionMemoryType::RwData
    } else if is_rodata {
        SectionMemoryType::RoData
    } else {
        early_println!("Invalid section type: {:?}", sh_type);
        SectionMemoryType::RoData
    }
}

fn caculate_section_size(elf_file: &ElfFile) -> (usize, usize, usize) {
    early_println!("[Loader] Analyzing sections...");

    let mut exec_bytes = 0;
    let mut ro_bytes = 0;
    let mut rw_bytes = 0;

    for (i, sh) in elf_file.section_iter().enumerate() {
        let Ok(name) = sh.get_name(elf_file) else {
            continue;
        };
        let Ok(sh_type) = sh.get_type() else { continue };

        let flags = sh.flags();
        let should_alloc = (SHF_ALLOC & flags) != 0;
        let size = sh.size() as usize;

        early_println!(
            "---->[Loader] Section {}: name={}, type={:?}, addr=0x{:x}, size=0x{:x}, should_alloc={}",
            i,
            name,
            sh_type,
            sh.address(),
            size,
            should_alloc
        );

        if !should_alloc {
            continue;
        }

        if name.contains("debug") {
            continue;
        }

        // 计算对齐后的大小
        let align = cmp::max(sh.align() as usize, 1);
        let aligned_size = if align > 0 {
            (size + align - 1) / align * align
        } else {
            size
        };

        // 判断需要分配什么样的内存
        let bucket = select_section_bucket(flags);
        match bucket {
            SectionMemoryType::Text => {
                exec_bytes += aligned_size;
            }
            SectionMemoryType::RoData => {
                ro_bytes += aligned_size;
            }
            SectionMemoryType::RwData => {
                rw_bytes += aligned_size;
            }
        }
        early_println!(
            "section memory type: {:?} aligned size: 0x{:x}",
            bucket,
            aligned_size
        );
    }

    early_println!("[Loader] Executable bytes: 0x{:x}", exec_bytes);
    early_println!("[Loader] Read-only bytes: 0x{:x}", ro_bytes);
    early_println!("[Loader] Read-write bytes: 0x{:x}", rw_bytes);

    (exec_bytes, ro_bytes, rw_bytes)
}

/// 存储已分配的内存区域
struct SectionMemory {
    exec_kvirt: Option<KVirtArea>,
    ro_kvirt: Option<KVirtArea>,
    rw_kvirt: Option<KVirtArea>,
}

fn alloc_section_memory(
    exec_bytes: usize,
    ro_bytes: usize,
    rw_bytes: usize,
) -> Result<SectionMemory> {
    early_println!("[Loader] Allocating memory for sections...");

    // 分配Frame并映射到内核的页表上
    let alloc_section_memory = |pages: usize| -> Result<Option<KVirtArea>> {
        if pages == 0 {
            return Ok(None);
        }
        let segment = FrameAllocOptions::new()
            .zeroed(true)
            .alloc_segment(pages)
            .map_err(|_| crate::Error::NoMemory)?;
        let prop = PageProperty {
            flags: PageFlags::RWX,
            cache: CachePolicy::Writeback,
            priv_flags: PrivilegedPageFlags::empty(),
        };
        // area_size 需要是字节数，map_offset 应该从 0 开始
        let kvirt_area = KVirtArea::map_frames(pages * PAGE_SIZE, 0, segment.into_iter(), prop);
        Ok(Some(kvirt_area))
    };

    // 将size对其到页面大小倍数
    let align_to_page = |size: usize| -> usize {
        if size == 0 {
            0
        } else {
            (size + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE
        }
    };

    let exec_pages = align_to_page(exec_bytes) / PAGE_SIZE;
    let ro_pages = align_to_page(ro_bytes) / PAGE_SIZE;
    let rw_pages = align_to_page(rw_bytes) / PAGE_SIZE;

    let exec_kvirt = alloc_section_memory(exec_pages)?;
    let ro_kvirt = alloc_section_memory(ro_pages)?;
    let rw_kvirt = alloc_section_memory(rw_pages)?;

    if let Some(ref kvirt) = exec_kvirt {
        early_println!(
            "[Loader] Allocated executable memory: {} pages at 0x{:x}",
            exec_pages,
            kvirt.start()
        );
    }
    if let Some(ref kvirt) = ro_kvirt {
        early_println!(
            "[Loader] Allocated read-only memory: {} pages at 0x{:x}",
            ro_pages,
            kvirt.start()
        );
    }
    if let Some(ref kvirt) = rw_kvirt {
        early_println!(
            "[Loader] Allocated read-write memory: {} pages at 0x{:x}",
            rw_pages,
            kvirt.start()
        );
    }

    early_println!("[Loader] Memory allocation completed");
    Ok(SectionMemory {
        exec_kvirt,
        ro_kvirt,
        rw_kvirt,
    })
}

struct SectionsMetadata<'a> {
    loaded_sections: BTreeMap<usize, Arc<LoadSection<'a>>>,
}

/// 记录加载到映射页里的section的基地址，偏移量等信息
struct LoadSection<'a> {
    base_addr: usize,
    offset: usize,
    size: usize,
    align: usize,
    sh_type: ShType,
    section_data: Option<&'a [u8]>,
    verified: bool,
}

fn load_section_data<'a>(
    elf_file: &'a ElfFile,
    section_memory: &SectionMemory,
) -> Result<SectionsMetadata<'a>> {
    early_println!("[Loader] Start Loading section data...");

    let mut sections_metadata = SectionsMetadata {
        loaded_sections: BTreeMap::new(),
    };

    let mut exec_cursor = 0usize;
    let mut ro_cursor = 0usize;
    let mut rw_cursor = 0usize;

    for (i, sh) in elf_file.section_iter().enumerate() {
        let Ok(name) = sh.get_name(elf_file) else {
            continue;
        };
        let Ok(sh_type) = sh.get_type() else {
            continue;
        };

        let flags = sh.flags();
        if (flags & SHF_ALLOC) == 0 {
            continue;
        }

        if name.contains("debug") {
            continue;
        }

        let size = sh.size() as usize;
        if size == 0 {
            continue;
        }

        let align = cmp::max(sh.align() as usize, 1);

        let bucket = select_section_bucket(flags);
        let (cursor, kvirt) = match bucket {
            SectionMemoryType::Text => (
                &mut exec_cursor,
                section_memory
                    .exec_kvirt
                    .as_ref()
                    .ok_or(crate::Error::InvalidArgs)?,
            ),
            SectionMemoryType::RwData => (
                &mut rw_cursor,
                section_memory
                    .rw_kvirt
                    .as_ref()
                    .ok_or(crate::Error::InvalidArgs)?,
            ),
            SectionMemoryType::RoData => (
                &mut ro_cursor,
                section_memory
                    .ro_kvirt
                    .as_ref()
                    .ok_or(crate::Error::InvalidArgs)?,
            ),
        };

        // 对齐到页面大小倍数
        let offset = align_up(*cursor, align);
        let end = offset.checked_add(size).ok_or(crate::Error::InvalidArgs)?;

        // 检查是否超出内存区域
        let area_len = kvirt.end() - kvirt.start();
        if end > area_len {
            return Err(crate::Error::InvalidArgs);
        }

        let section_data = if sh_type == ShType::NoBits {
            None
        } else {
            Some(sh.raw_data(elf_file))
        };

        unsafe {
            let mut writer = VmWriter::from_kernel_space((kvirt.start() + offset) as *mut u8, size);
            if section_data.is_none() {
                let filled = writer.fill_zeros(size);
                if filled != size {
                    return Err(crate::Error::InvalidArgs);
                }
            } else {
                let data = section_data.unwrap();
                if data.len() != size {
                    return Err(crate::Error::InvalidArgs);
                }
                let written = writer.write(&mut VmReader::from(data));
                if written != data.len() {
                    return Err(crate::Error::InvalidArgs);
                }
            }
        }

        let verified = verify_section_memory(kvirt, offset, size, sh_type, section_data)?;
        if !verified {
            early_println!(
                "[Loader] Section {} ({}) verification failed at bucket {:?}",
                i,
                name,
                bucket
            );
            return Err(crate::Error::InvalidArgs);
        }
        *cursor = end;
        early_println!(
            "[Loader] Section {} ({}) loaded to bucket {:?}: size=0x{:x}, align=0x{:x}, offset=0x{:x}, verified={}",
            i,
            name,
            bucket,
            size,
            align,
            offset,
            verified
        );

        sections_metadata.loaded_sections.insert(
            i,
            Arc::new(LoadSection {
                base_addr: kvirt.start() + offset,
                offset,
                size,
                align,
                sh_type,
                section_data,
                verified,
            }),
        );
    }
    Ok(sections_metadata)
}

fn align_up(value: usize, align: usize) -> usize {
    if align <= 1 {
        return value;
    }
    let rem = value % align;
    if rem == 0 {
        value
    } else {
        value + (align - rem)
    }
}

const VERIFY_CHUNK_SIZE: usize = 256;

fn verify_section_memory(
    kvirt: &KVirtArea,
    offset: usize,
    size: usize,
    sh_type: ShType,
    section_data: Option<&[u8]>,
) -> Result<bool> {
    if size == 0 {
        return Ok(true);
    }

    unsafe {
        let mut dst_reader =
            VmReader::from_kernel_space((kvirt.start() + offset) as *const u8, size);
        let verified = if sh_type == ShType::NoBits {
            reader_is_zeroed(&mut dst_reader, size)
        } else if let Some(data) = section_data {
            reader_equals_slice(&mut dst_reader, data)
        } else {
            true
        };
        Ok(verified)
    }
}

fn reader_is_zeroed(reader: &mut VmReader<'_, Infallible>, mut remaining: usize) -> bool {
    let mut scratch = [0u8; VERIFY_CHUNK_SIZE];
    while remaining > 0 {
        let chunk_len = remaining.min(VERIFY_CHUNK_SIZE);
        let mut writer = VmWriter::from(&mut scratch[..chunk_len]);
        let read_len = reader.read(&mut writer);
        if read_len != chunk_len {
            return false;
        }
        if scratch[..read_len].iter().any(|&byte| byte != 0) {
            return false;
        }
        remaining -= read_len;
    }
    true
}

fn reader_equals_slice(reader: &mut VmReader<'_, Infallible>, data: &[u8]) -> bool {
    let mut processed = 0usize;
    let mut scratch = [0u8; VERIFY_CHUNK_SIZE];
    while processed < data.len() {
        let chunk_len = (data.len() - processed).min(VERIFY_CHUNK_SIZE);
        let mut writer = VmWriter::from(&mut scratch[..chunk_len]);
        let read_len = reader.read(&mut writer);
        if read_len != chunk_len {
            return false;
        }
        if scratch[..read_len] != data[processed..processed + read_len] {
            return false;
        }
        processed += read_len;
    }
    reader.remain() == 0
}

/// 完善好
fn simply_symbol(
    symbol_table: &[Entry64],
    elf_file: &ElfFile,
    loaded_sections: &SectionsMetadata,
) -> Result<()> {
    early_println!("[Loader] Simplying symbol...");
    for entry in symbol_table {
        let name = entry.get_name(elf_file).unwrap_or("");
        let shndx = entry.shndx();
        if shndx == SHN_UNDEF {
            let find_symbol = symbol_addr_by_name(name);
            early_println!(
                "[Loader] Symbol '{}' not found, find_symbol: 0x{:x}",
                name,
                find_symbol.unwrap_or(0)
            );
            continue;
        }
        if let Some(section) = loaded_sections.loaded_sections.get(&(shndx as usize)) {
            let value = section.base_addr + entry.value() as usize;
            early_println!(
                "[Loader] Symbol '{}' found in loaded sections, value: 0x{:x}",
                name,
                value
            );
        } else {
            early_println!("[Loader] Symbol '{}' not found in loaded sections", name);
            continue;
        }
    }
    Ok(())
}

/// 查找入口点地址 (_start 符号)
fn find_entry_point(
    elf_file: &ElfFile,
    sections_metadata: &SectionsMetadata,
) -> Result<Option<usize>> {
    let symbol_table = get_symbol_table(elf_file)?;

    // 查找 _start 符号
    for symbol in symbol_table.iter() {
        let name = symbol.get_name(elf_file).unwrap_or("");
        if name == "_start" {
            // 解析符号地址
            let section_index = symbol.shndx();
            if section_index == 0 {
                // 未定义符号
                continue;
            }

            if let Some(loaded_section) = sections_metadata
                .loaded_sections
                .get(&(section_index as usize))
            {
                let entry_addr = loaded_section.base_addr + symbol.value() as usize;
                return Ok(Some(entry_addr));
            }
        }
    }

    Ok(None)
}

/// 外部符号解析器类型
/// 参数：符号名称
/// 返回：符号地址，如果找不到返回 None
pub type ExternalSymbolResolver = fn(&str) -> Option<usize>;

/// 默认的外部符号解析器
/// 尝试从内核符号表中查找符号
/// 先 demangle 符号名称，然后在符号表中查找
fn default_external_symbol_resolver(name: &str) -> Option<usize> {
    // 使用 symbols 模块的按名称查找函数
    // 该函数会自动处理 demangle 和匹配
    let result = symbols::symbol_addr_by_name(name);

    if result.is_some() {
        // 成功找到符号，打印调试信息
        early_println!(
            "[Loader] Symbol '{}' resolved to 0x{:x}",
            name,
            result.unwrap()
        );
    } else {
        // 添加调试信息
        use rustc_demangle::demangle;
        let demangled = demangle(name);
        early_println!(
            "[Loader] Symbol lookup failed: mangled='{}', demangled='{}', table_size={}",
            name,
            demangled,
            symbols::symbols_len()
        );
    }

    result
}

/// 解析符号地址
/// 如果符号在当前文件中定义，返回其加载后的地址
/// 如果符号是外部符号，尝试通过 resolver 解析
fn resolve_symbol_address(
    symbol: &Entry64,
    _symbol_index: usize,
    symbol_name: &str,
    _elf_file: &ElfFile,
    sections_metadata: &SectionsMetadata,
    external_resolver: ExternalSymbolResolver,
) -> Option<usize> {
    let section_index = symbol.shndx();

    // SHN_UNDEF (0) 表示未定义的外部符号
    if section_index == 0 {
        // 尝试通过外部解析器解析
        return external_resolver(symbol_name);
    }

    // SHN_ABS (65521) 表示绝对地址，不需要重定位
    if section_index == 65521 {
        return Some(symbol.value() as usize);
    }

    // 从已加载的section中查找符号地址
    if let Some(loaded_section) = sections_metadata
        .loaded_sections
        .get(&(section_index as usize))
    {
        // 符号地址 = section基地址 + 符号在section中的偏移
        let symbol_addr = loaded_section.base_addr + symbol.value() as usize;
        return Some(symbol_addr);
    }

    None
}

/// 执行单个重定位
/// 返回 Ok(true) 表示指令已被转换（如 call 转换为间接调用），应该跳过验证
/// 返回 Ok(false) 表示正常处理，需要验证
fn apply_relocation(
    reloc_offset: u64,
    reloc_type: u32,
    symbol_addr: usize,
    addend: i64,
    target_section_base: usize,
    elf_file: &ElfFile,
) -> Result<bool> {
    // 计算重定位目标地址（在内存中的实际地址）
    let reloc_addr = target_section_base + reloc_offset as usize;

    // 根据重定位类型计算新值
    let new_value = match reloc_type {
        // R_X86_64_64: 64位绝对地址
        1 => (symbol_addr as i64 + addend) as u64,
        // R_X86_64_PC32 或 R_X86_64_PLT32: 32位PC相对地址
        4 => {
            // PC相对地址 = 符号地址 + addend - (当前指令地址 + 4)
            // 当前指令地址是 reloc_addr，+4 是因为指令长度
            let pc = reloc_addr + 4;
            let diff = (symbol_addr as i64 + addend) - (pc as i64);
            // 检查是否超出32位有符号范围
            if diff < i32::MIN as i64 || diff > i32::MAX as i64 {
                // 超出范围，尝试转换为间接调用
                early_println!(
                    "[Loader] Warning: R_X86_64_PC32 relocation out of range (diff={}), converting to indirect call",
                    diff
                );
                early_println!(
                    "[Loader]   symbol_addr=0x{:x}, pc=0x{:x}, reloc_addr=0x{:x}",
                    symbol_addr,
                    pc,
                    reloc_addr
                );

                // 读取当前指令，检查指令类型
                // R_X86_64_PC32 重定位可以用于多种指令：
                // - call rel32 (E8) - 重定位偏移指向操作码后的32位偏移
                // - jmp rel32 (E9) - 重定位偏移指向操作码后的32位偏移
                // - lea reg, [rip+rel32] (48 8D ...) - 重定位偏移指向指令内部的disp32字段
                // - mov reg, [rip+rel32] (48 8B ...) - 重定位偏移指向指令内部的disp32字段
                // 注意：重定位偏移可能指向指令的操作数字段，而不是操作码！
                unsafe {
                    // 读取重定位地址周围32字节以便分析
                    let mut context_bytes = [0u8; 32];
                    let context_start = if reloc_addr >= 16 { reloc_addr - 16 } else { 0 };
                    for i in 0..32 {
                        if let Some(addr) = context_start.checked_add(i) {
                            if addr < reloc_addr + 16 {
                                context_bytes[i] = core::ptr::read_volatile(addr as *const u8);
                            }
                        }
                    }

                    // 打印上下文字节（简化版本）
                    early_println!(
                        "[Loader]   Bytes around reloc_addr 0x{:x} (offset 0x{:x}):",
                        reloc_addr,
                        reloc_offset
                    );
                    let start_idx = if reloc_addr >= context_start + 16 {
                        16
                    } else {
                        (reloc_addr - context_start) as usize
                    };
                    let end_idx = (start_idx + 16).min(32);
                    for i in start_idx..end_idx {
                        let addr = context_start + i;
                        if addr == reloc_addr {
                            early_println!(
                                "[Loader]     0x{:x}: [{:02x}] <-- reloc_addr",
                                addr,
                                context_bytes[i]
                            );
                        } else {
                            early_println!("[Loader]     0x{:x}: [{:02x}]", addr, context_bytes[i]);
                        }
                    }

                    // 尝试向前查找指令开始（最多向前16字节）
                    let mut found_instr_start = None;
                    for back_offset in 1..=16 {
                        let check_addr = reloc_addr.checked_sub(back_offset);
                        if let Some(addr) = check_addr {
                            let byte = core::ptr::read_volatile(addr as *const u8);
                            // 检查是否是 call (E8) 或 jmp (E9)
                            if byte == 0xE8 || byte == 0xE9 {
                                found_instr_start = Some((addr, byte));
                                early_println!(
                                    "[Loader]   Found instruction start at 0x{:x}: 0x{:02x} (offset -{})",
                                    addr,
                                    byte,
                                    back_offset
                                );
                                break;
                            }
                            // 检查是否是 lea/mov [rip+rel32] 的前缀
                            if byte == 0x48 {
                                let next_byte = core::ptr::read_volatile((addr + 1) as *const u8);
                                if (next_byte & 0xF8) == 0x8D || (next_byte & 0xF8) == 0x8B {
                                    found_instr_start = Some((addr, byte));
                                    early_println!(
                                        "[Loader]   Found instruction start at 0x{:x}: 0x{:02x} 0x{:02x} (offset -{})",
                                        addr,
                                        byte,
                                        next_byte,
                                        back_offset
                                    );
                                    break;
                                }
                            }
                        }
                    }

                    // 尝试从重定位地址向前查找指令开始
                    // 对于 call/jmp，重定位偏移应该指向操作码后的32位偏移（即偏移+1）
                    // 对于 lea/mov，重定位偏移指向指令内部的disp32字段
                    let instr_ptr = reloc_addr as *const u8;
                    let mut instr_bytes = [0u8; 16];
                    for i in 0..16 {
                        instr_bytes[i] = core::ptr::read_volatile(instr_ptr.add(i));
                    }

                    // 对于 call/jmp 指令，转换为间接调用/跳转时，应该直接使用符号地址
                    // addend 是用于 PC 相对地址计算的，不适用于绝对地址
                    let target_addr = symbol_addr as u64;

                    // 根据找到的指令开始位置处理
                    if let Some((instr_start, instr_byte)) = found_instr_start {
                        // 检查是否是 call rel32 (E8)
                        if instr_byte == 0xE8 {
                            // call rel32 指令，转换为间接调用
                            // 原指令：E8 [32位相对偏移] (5字节)
                            // 新指令：48 B8 [64位绝对地址] FF D0 (mov rax, addr64; call rax) (12字节)
                            // 注意：使用符号地址，不使用 addend（addend 只用于 PC 相对地址计算）
                            let mov_rax_bytes = [0x48u8, 0xB8];
                            let call_rax_bytes = [0xFFu8, 0xD0];
                            unsafe {
                                let mut writer =
                                    VmWriter::from_kernel_space(instr_start as *mut u8, 12);
                                let written1 =
                                    writer.write(&mut VmReader::from(&mov_rax_bytes[..])); // mov rax, imm64 (2字节)
                                if written1 != 2 {
                                    return Err(crate::Error::InvalidArgs);
                                }
                                writer.write_val(&target_addr)?; // 64位地址 (8字节)
                                let written2 =
                                    writer.write(&mut VmReader::from(&call_rax_bytes[..])); // call rax (2字节)
                                if written2 != 2 {
                                    return Err(crate::Error::InvalidArgs);
                                }
                            }
                            early_println!(
                                "[Loader]   Converted call to indirect call: mov rax, 0x{:x}; call rax (symbol_addr=0x{:x}, addend={})",
                                target_addr,
                                symbol_addr,
                                addend
                            );
                            early_println!(
                                "[Loader]   Warning: Patched 12 bytes (original 5-byte call), may affect following 7 bytes"
                            );
                            return Ok(true); // 已转换，跳过验证
                        }
                        // 检查是否是 jmp rel32 (E9)
                        else if instr_byte == 0xE9 {
                            // jmp rel32 指令，转换为间接跳转
                            // 原指令：E9 [32位相对偏移] (5字节)
                            // 新指令：48 B8 [64位绝对地址] FF E0 (mov rax, addr64; jmp rax) (12字节)
                            // 注意：使用符号地址，不使用 addend
                            let mov_rax_bytes = [0x48u8, 0xB8];
                            let jmp_rax_bytes = [0xFFu8, 0xE0];
                            unsafe {
                                let mut writer =
                                    VmWriter::from_kernel_space(instr_start as *mut u8, 12);
                                let written1 =
                                    writer.write(&mut VmReader::from(&mov_rax_bytes[..])); // mov rax, imm64 (2字节)
                                if written1 != 2 {
                                    return Err(crate::Error::InvalidArgs);
                                }
                                writer.write_val(&target_addr)?; // 64位地址 (8字节)
                                let written2 =
                                    writer.write(&mut VmReader::from(&jmp_rax_bytes[..])); // jmp rax (2字节)
                                if written2 != 2 {
                                    return Err(crate::Error::InvalidArgs);
                                }
                            }
                            early_println!(
                                "[Loader]   Converted jmp to indirect jmp: mov rax, 0x{:x}; jmp rax (symbol_addr=0x{:x}, addend={})",
                                target_addr,
                                symbol_addr,
                                addend
                            );
                            early_println!(
                                "[Loader]   Warning: Patched 12 bytes (original 5-byte jmp), may affect following 7 bytes"
                            );
                            return Ok(true); // 已转换，跳过验证
                        }
                    }

                    // 如果没有找到指令开始，尝试直接检查重定位地址处的指令
                    let instr_byte = instr_bytes[0];
                    // 检查是否是 lea reg, [rip+rel32] (48 8D ...) 或 mov reg, [rip+rel32] (48 8B ...)
                    // 这些指令的重定位偏移指向指令内部的32位偏移字段，不是指令开始
                    if instr_bytes[0] == 0x48 && (instr_bytes[1] & 0xF8) == 0x8D {
                        // lea reg, [rip+rel32] - 指令格式：48 8D [modrm] [sib] [disp32]
                        // 重定位偏移指向 disp32 字段（通常是第3-6字节）
                        // 对于这种情况，我们需要将 lea 转换为 mov reg, imm64
                        // 但这需要知道目标寄存器，比较复杂
                        early_println!(
                            "[Loader]   Detected lea instruction, but conversion is complex (needs register info)"
                        );
                        early_println!(
                            "[Loader]   Error: R_X86_64_PC32 relocation out of range for lea instruction"
                        );
                        return Err(crate::Error::InvalidArgs);
                    } else if instr_bytes[0] == 0x48 && (instr_bytes[1] & 0xF8) == 0x8B {
                        // mov reg, [rip+rel32] - 类似处理
                        early_println!(
                            "[Loader]   Detected mov [rip+rel32] instruction, but conversion is complex"
                        );
                        early_println!(
                            "[Loader]   Error: R_X86_64_PC32 relocation out of range for mov instruction"
                        );
                        return Err(crate::Error::InvalidArgs);
                    } else {
                        // 未知指令类型
                        early_println!(
                            "[Loader] Error: R_X86_64_PC32 relocation out of range and unsupported instruction type (0x{:02x} {:02x} {:02x} {:02x})",
                            instr_bytes[0],
                            instr_bytes[1],
                            instr_bytes[2],
                            instr_bytes[3]
                        );
                        early_println!(
                            "[Loader]   Note: R_X86_64_PC32 is typically used for call/jmp/lea/mov instructions"
                        );
                        return Err(crate::Error::InvalidArgs);
                    }
                }
            }
            // 先转换为有符号i32，再转换为u32，这样可以保留符号位
            (diff as i32 as u32) as u64
        }
        // R_X86_64_32: 32位绝对地址
        // 注意：如果符号地址超出 32 位范围，这会导致地址截断
        // 对于 VMALLOC 范围内的地址，应该使用 R_X86_64_64 或 R_X86_64_PC32
        10 => {
            let value = symbol_addr as i64 + addend;
            // 检查是否超出32位无符号范围
            if value < 0 || value > u32::MAX as i64 {
                early_println!(
                    "[Loader] Error: R_X86_64_32 relocation out of range: value={}, symbol_addr=0x{:x}, addend=0x{:x}",
                    value,
                    symbol_addr,
                    addend
                );
                return Err(crate::Error::InvalidArgs);
            }
            value as u32 as u64
        }
        // R_X86_64_RELATIVE: 相对重定位（用于共享库）
        8 => {
            // 对于可重定位文件，这通常不应该出现
            // 但如果有，就是 addend + 基地址
            (target_section_base as i64 + addend) as u64
        }
        // R_X86_64_GOTPCREL: GOT PC 相对重定位
        // 用于访问全局偏移表（GOT）中的条目
        // 由于我们没有实现 GOT，将其转换为直接 PC 相对访问（类似于 R_X86_64_PC32）
        9 => {
            // GOTPCREL 的计算公式是：GOT[符号] - PC + addend
            // 由于没有 GOT，我们直接使用符号地址：符号地址 - PC + addend
            let pc = reloc_addr + 4;
            let diff = (symbol_addr as i64 + addend) - (pc as i64);
            // 检查是否超出32位有符号范围
            if diff < i32::MIN as i64 || diff > i32::MAX as i64 {
                early_println!(
                    "[Loader] Warning: R_X86_64_GOTPCREL relocation out of range (diff={}), converting to indirect access",
                    diff
                );
                early_println!(
                    "[Loader]   symbol_addr=0x{:x}, pc=0x{:x}, reloc_addr=0x{:x}",
                    symbol_addr,
                    pc,
                    reloc_addr
                );

                // 读取指令，检查是否是 mov reg, [rip+got_offset]
                unsafe {
                    let instr_ptr = reloc_addr as *const u8;
                    let mut instr_bytes = [0u8; 16];
                    for i in 0..16 {
                        instr_bytes[i] = core::ptr::read_volatile(instr_ptr.add(i));
                    }

                    // 检查是否是 mov reg, [rip+rel32] (48 8B ...)
                    if instr_bytes[0] == 0x48 && (instr_bytes[1] & 0xF8) == 0x8B {
                        // mov reg, [rip+rel32] - 转换为 mov reg, [符号地址]
                        // 但这需要知道目标寄存器，比较复杂
                        // 更简单的方法：转换为 mov reg, imm64; mov reg, [reg]
                        // 或者：lea reg, [rip+0]; mov [reg], symbol_addr; mov reg, [reg]
                        // 实际上，最简单的方法是：将 mov reg, [rip+rel32] 转换为 mov reg, imm64（直接加载符号地址）
                        // 但这改变了指令语义（从加载值变为加载地址）

                        // 更实用的方法：转换为 movabs reg, symbol_addr; mov reg, [reg]
                        // 但这需要知道目标寄存器

                        early_println!("[Loader]   Detected mov [rip+got_offset] instruction");
                        early_println!(
                            "[Loader]   Error: R_X86_64_GOTPCREL relocation out of range, conversion requires register info"
                        );
                        return Err(crate::Error::InvalidArgs);
                    } else {
                        early_println!(
                            "[Loader]   Error: R_X86_64_GOTPCREL relocation out of range, unsupported instruction (0x{:02x} {:02x} {:02x} {:02x})",
                            instr_bytes[0],
                            instr_bytes[1],
                            instr_bytes[2],
                            instr_bytes[3]
                        );
                        return Err(crate::Error::InvalidArgs);
                    }
                }
            }
            // 先转换为有符号i32，再转换为u32，这样可以保留符号位
            (diff as i32 as u32) as u64
        }
        _ => {
            early_println!(
                "[Loader] Warning: Unsupported relocation type {} at offset 0x{:x}",
                reloc_type,
                reloc_offset
            );
            return Err(crate::Error::InvalidArgs);
        }
    };

    // 写入新值到内存
    unsafe {
        match reloc_type {
            1 | 8 => {
                // 64位值
                let val: u64 = new_value;
                let mut writer = VmWriter::from_kernel_space(reloc_addr as *mut u8, 8);
                writer.write_val(&val)?;
            }
            4 | 9 | 10 => {
                // 32位值（PC32, GOTPCREL, 32位绝对地址）
                let val: u32 = new_value as u32;
                let mut writer = VmWriter::from_kernel_space(reloc_addr as *mut u8, 4);
                writer.write_val(&val)?;
            }
            _ => {
                return Err(crate::Error::InvalidArgs);
            }
        }
    }

    Ok(false) // 正常处理，需要验证
}

fn relocate_sections(
    elf_file: &ElfFile,
    sections_metadata: &SectionsMetadata,
    external_resolver: ExternalSymbolResolver,
) -> Result<()> {
    let symbol_table = get_symbol_table(elf_file)?;
    early_println!("[Loader] Starting relocation...");

    // 遍历所有重定位section
    for reloc_section in elf_file.section_iter() {
        let Ok(reloc_section_name) = reloc_section.get_name(elf_file) else {
            continue;
        };

        let info = reloc_section.info();
        early_println!("info: {:?}", info);
        if info == 0 {
            continue;
        }

        // 查找section号为info的section
        let target_section = elf_file.section_header(info as u16);

        let Ok(target_section) = target_section else {
            continue;
        };

        if target_section.flags() & SHF_ALLOC == 0 {
            continue;
        }

        let name = target_section.get_name(elf_file).map_err(|_| crate::Error::InvalidArgs)?;
        match reloc_section.get_data(elf_file) {
            Ok(SectionData::Rela64(rela)) => {
                early_println!(
                    "[Loader] Processing {} relocations for section '{}'",
                    rela.len(),
                    name
                );
                apply_relocate_add(rela, &target_section, elf_file)?;
            }
            Ok(SectionData::Rel64(rel)) => {
                early_println!(
                    "[Loader] Processing {} relocations for section '{}'",
                    rel.len(),
                    name
                );
                apply_relocate(rel, &target_section, elf_file)?;
            }
            _ => {
                continue;
            }
        }
    }
    early_println!("[Loader] Relocation completed");
    Ok(())
}

fn apply_relocate_add(
    rel: &[Rela<u64>],
    target_section: &SectionHeader,
    elf_file: &ElfFile,
) -> Result<()> {
    for reloc in rel {
        let symbol_idx = reloc.get_symbol_table_index() as usize;
        let offset = reloc.get_offset();
        let typ = reloc.get_type();
        let addend = reloc.get_addend() as i64;
        early_println!("reloc: symbol_idx={}, offset={}, typ={}, addend={}", symbol_idx, offset, typ, addend);
    }

    Ok(())
}

fn apply_relocate(
    rel: &[Rel<u64>],
    target_section: &SectionHeader,
    elf_file: &ElfFile,
) -> Result<()> {
    Ok(())
}
