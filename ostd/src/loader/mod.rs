use alloc::{collections::btree_map::BTreeMap, sync::Arc, vec::Vec};
use core::cmp;

use rustc_demangle::demangle;
use xmas_elf::{
    ElfFile,
    header::Type,
    program::ProgramHeader,
    sections::{
        Rel, Rela, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHN_UNDEF, SectionData, SectionHeader,
        ShType,
    },
    symbol_table::{Entry, Entry64},
};

use crate::{
    Result,
    alloc::string::ToString,
    early_println,
    mm::{
        PAGE_SIZE,
        frame::allocator::FrameAllocOptions,
        io::{Infallible, VmReader, VmWriter},
        kspace::kvirt_area::KVirtArea,
        page_prop::{CachePolicy, PageFlags, PageProperty, PrivilegedPageFlags},
    },
    symbols::symbol_addr_by_name,
    task::{Task, TaskOptions},
};

pub struct FrameVmInfo<'a> {
    elf_file: ElfFile<'a>,
    entry_point: Option<usize>,
    section_memory: Option<SectionMemory>,
}

impl<'a> FrameVmInfo<'a> {
    fn entry_point(&self) -> Option<usize> {
        self.entry_point
    }

    pub fn start_framevm(&self) -> Result<()> {
        // 直接在当前 CPU 上调用，不创建新 Task
        let start = self.entry_point().unwrap_or(0);
        early_println!(
            "[Loader] Entry point called directly, entry point: 0x{:x}",
            start
        );

        if start == 0 {
            early_println!("[Loader] ERROR: Entry point is 0, cannot proceed");
            return Err(crate::Error::InvalidArgs);
        }

        // 打印入口点附近的代码内容（前 128 字节）
        unsafe {
            early_println!("[Loader] Dumping code at entry point (first 128 bytes):");
            let code_ptr = start as *const u8;
            let mut line_buffer = alloc::string::String::new();
            for i in 0..128 {
                if i % 16 == 0 {
                    if !line_buffer.is_empty() {
                        early_println!("{}", line_buffer);
                        line_buffer.clear();
                    }
                    line_buffer = alloc::format!("[Loader] 0x{:x}: ", start + i);
                }
                let mut byte = [0u8; 1];
                let mut reader = VmReader::from_kernel_space(code_ptr.add(i), 1);
                if reader.read(&mut VmWriter::from(&mut byte[..])) == 1 {
                    line_buffer.push_str(&alloc::format!("{:02x} ", byte[0]));
                } else {
                    line_buffer.push_str("?? ");
                }
            }
            if !line_buffer.is_empty() {
                early_println!("{}", line_buffer);
            }

            // 尝试解析前几条指令
            early_println!("[Loader] Attempting to disassemble first few instructions:");
            let mut hex_buffer = alloc::string::String::new();
            for i in 0..32.min(128) {
                let mut byte = [0u8; 1];
                let mut reader = VmReader::from_kernel_space(code_ptr.add(i), 1);
                if reader.read(&mut VmWriter::from(&mut byte[..])) == 1 {
                    hex_buffer.push_str(&alloc::format!("{:02x}", byte[0]));
                } else {
                    hex_buffer.push_str("??");
                }
            }
            early_println!("{}", hex_buffer);
        }

        // 打印入口点函数的反汇编信息（前几条指令）
        early_println!("[Loader] Entry point function starts at 0x{:x}", start);
        early_println!("[Loader] About to call entry point...");

        let entry: extern "Rust" fn() = unsafe { core::mem::transmute(start) };
        unsafe { entry() };

        early_println!("framevm end");
        Ok(())
    }

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
        relocate_sections(&elf_file, &sections_metadata)?;

        // 打印代码段边界信息
        if let Some(ref exec_kvirt) = section_memory.exec_kvirt {
            early_println!(
                "[Loader] Executable code segment: start=0x{:x}, end=0x{:x}, size=0x{:x} bytes",
                exec_kvirt.start(),
                exec_kvirt.end(),
                exec_kvirt.end() - exec_kvirt.start()
            );
        }

        // 查找并记录入口点地址 (_start)
        let entry_point = find_entry_point(&elf_file, &sections_metadata)?;
        if let Some(addr) = entry_point {
            early_println!("[Loader] Entry point (_start) found at: 0x{:x}", addr);
            // 检查入口点是否在代码段内
            if let Some(ref exec_kvirt) = section_memory.exec_kvirt {
                if addr < exec_kvirt.start() || addr >= exec_kvirt.end() {
                    early_println!(
                        "[Loader] ERROR: Entry point 0x{:x} is outside executable segment [0x{:x}, 0x{:x})",
                        addr,
                        exec_kvirt.start(),
                        exec_kvirt.end()
                    );
                    return Err(crate::Error::InvalidArgs);
                }
            }
        } else {
            early_println!("[Loader] Warning: Entry point (_start) not found");
        }

        Ok(FrameVmInfo {
            elf_file,
            entry_point,
            section_memory: Some(section_memory),
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

    let mut exec_cursor = 0;
    let mut ro_cursor = 0;
    let mut rw_cursor = 0;

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

        // 只跳过真正的 debug section（以 .debug 开头），而不是名称中包含 "debug" 的所有 section
        // 因为代码 section 的名称可能包含 "debug" 字符串（如函数名）
        if name.starts_with(".debug") {
            continue;
        }

        let align = cmp::max(sh.align() as usize, 1);

        // 判断需要分配什么样的内存
        let bucket = select_section_bucket(flags);
        match bucket {
            SectionMemoryType::Text => {
                exec_cursor = align_up(exec_cursor, align);
                exec_cursor += size;
            }
            SectionMemoryType::RoData => {
                ro_cursor = align_up(ro_cursor, align);
                ro_cursor += size;
            }
            SectionMemoryType::RwData => {
                rw_cursor = align_up(rw_cursor, align);
                rw_cursor += size;
            }
        }
        early_println!(
            "section memory type: {:?} size: 0x{:x} align: 0x{:x}",
            bucket,
            size,
            align
        );
    }

    early_println!("[Loader] Executable bytes: 0x{:x}", exec_cursor);
    early_println!("[Loader] Read-only bytes: 0x{:x}", ro_cursor);
    early_println!("[Loader] Read-write bytes: 0x{:x}", rw_cursor);

    (exec_cursor, ro_cursor, rw_cursor)
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
        let kvirt_area =
            KVirtArea::map_module_frames(pages * PAGE_SIZE, 0, segment.into_iter(), prop);
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

        // 只跳过真正的 debug section（以 .debug 开头），而不是名称中包含 "debug" 的所有 section
        // 因为代码 section 的名称可能包含 "debug" 字符串（如函数名）
        if name.starts_with(".debug") {
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

/// 查找入口点地址 (__ostd_main 符号)
fn find_entry_point(
    elf_file: &ElfFile,
    sections_metadata: &SectionsMetadata,
) -> Result<Option<usize>> {
    let symbol_table = get_symbol_table(elf_file)?;

    // 查找 __framevm_main 符号
    for symbol in symbol_table.iter() {
        let name = symbol.get_name(elf_file).unwrap_or("");
        if name == "__framevm_main" {
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

fn relocate_sections(elf_file: &ElfFile, sections_metadata: &SectionsMetadata) -> Result<()> {
    let symbol_table = get_symbol_table(elf_file)?;
    early_println!("[Loader] Starting relocation...");

    // 遍历所有重定位section
    for reloc_section in elf_file.section_iter() {
        let Ok(_reloc_section_name) = reloc_section.get_name(elf_file) else {
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

        let name = target_section
            .get_name(elf_file)
            .map_err(|_| crate::Error::InvalidArgs)?;
        match reloc_section.get_data(elf_file) {
            Ok(SectionData::Rela64(rela)) => {
                early_println!(
                    "[Loader] Processing {} RELA relocations for section '{}'",
                    rela.len(),
                    name
                );
                apply_relocate_add(
                    rela,
                    info as usize,
                    elf_file,
                    &sections_metadata,
                    symbol_table,
                )?;
            }
            Ok(SectionData::Rel64(rel)) => {
                early_println!(
                    "[Loader] Processing {} REL relocations for section '{}'",
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

/// 应用 RELA 重定位
/// 参考 Linux 内核的x86的__write_relocate_add 函数实现
fn apply_relocate_add(
    rel: &[Rela<u64>],
    target_section_index: usize,
    elf_file: &ElfFile,
    sections_metadata: &SectionsMetadata,
    symbol_table: &[Entry64],
) -> Result<()> {
    // 获取目标 section 的基地址
    early_println!(
        "[Loader] Looking up target section index {} in loaded_sections (total: {} sections)",
        target_section_index,
        sections_metadata.loaded_sections.len()
    );

    // 打印所有已加载的 section 索引，用于调试
    let loaded_indices: Vec<usize> = sections_metadata.loaded_sections.keys().copied().collect();
    early_println!("[Loader] Available section indices: {:?}", loaded_indices);

    let target_section_base = sections_metadata
        .loaded_sections
        .get(&target_section_index)
        .map(|section| {
            early_println!(
                "[Loader] Found target section {}: base_addr=0x{:x}, offset=0x{:x}, size=0x{:x}, align=0x{:x}",
                target_section_index,
                section.base_addr,
                section.offset,
                section.size,
                section.align
            );
            section.base_addr
        })
        .ok_or_else(|| {
            early_println!(
                "[Loader] Error: Target section index {} not found in loaded_sections!",
                target_section_index
            );
            early_println!(
                "[Loader] Available section indices: {:?}",
                sections_metadata.loaded_sections.keys().collect::<Vec<_>>()
            );
            // 尝试获取 section 名称以便调试
            if let Ok(target_section) = elf_file.section_header(target_section_index as u16) {
                if let Ok(name) = target_section.get_name(elf_file) {
                    early_println!(
                        "[Loader] Target section name: '{}', type: {:?}, flags: 0x{:x}",
                        name,
                        target_section.get_type().unwrap_or(ShType::Null),
                        target_section.flags()
                    );
                }
            }
            crate::Error::InvalidArgs
        })?;

    early_println!(
        "[Loader] Applying {} relocations to section {} (base: 0x{:x})",
        rel.len(),
        target_section_index,
        target_section_base
    );

    // 遍历每个重定位条目
    for (i, reloc) in rel.iter().enumerate() {
        let symbol_idx = reloc.get_symbol_table_index() as usize;
        let offset = reloc.get_offset();
        let reloc_type = reloc.get_type();
        let addend = reloc.get_addend() as i64;

        // 计算要修改的目标地址
        let loc = target_section_base + offset as usize;

        // 获取符号
        let symbol = symbol_table
            .get(symbol_idx)
            .ok_or(crate::Error::InvalidArgs)?;

        let symbol_name = symbol.get_name(elf_file).unwrap_or("");

        // 计算符号的实际地址：根据符号所在的段和偏移量
        let symbol_addr = {
            let shndx = symbol.shndx();
            if shndx == SHN_UNDEF {
                // 未定义的符号，尝试从外部符号表查找
                match symbol_addr_by_name(symbol_name) {
                    Some(addr) => addr as u64,
                    None => {
                        // 打印 demangle 后的符号名，方便调试像
                        // core::ptr::drop_in_place<ostd::mm::vm_space::VmSpace> 这样的符号。
                        let demangled = demangle(symbol_name).to_string();
                        early_println!(
                            "[Loader] Error: Cannot resolve undefined symbol '{}' (demangled: '{}') for relocation type {}",
                            symbol_name,
                            demangled,
                            reloc_type
                        );
                        return Err(crate::Error::InvalidArgs);
                    }
                }
            } else if let Some(section) = sections_metadata.loaded_sections.get(&(shndx as usize)) {
                // 符号在已加载的段中：段基地址 + 符号偏移
                (section.base_addr + symbol.value() as usize) as u64
            } else {
                // 符号不在已加载的段中，使用原始值
                symbol.value() as u64
            }
        };

        // 基础值 = 符号地址 + addend
        // addend 是有符号的，需要正确处理
        // 使用有符号算术：将 u64 转换为 i64，进行有符号加法，再转换回 u64
        let mut val = ((symbol_addr as i64).wrapping_add(addend)) as u64;

        early_println!(
            "[Loader] Reloc[{}]: type={}, symbol='{}' (0x{:x}), addend=0x{:x}, loc=0x{:x}, val=0x{:x}",
            i,
            reloc_type,
            symbol_name,
            symbol_addr,
            addend,
            loc,
            val
        );

        // 根据重定位类型处理
        let size = match reloc_type {
            // R_X86_64_NONE (0): 无需任何操作
            0 => {
                continue;
            }
            // R_X86_64_64 (1): 64 位绝对地址（如 movabs $imm64, %rax）
            1 => 8,
            // R_X86_64_32 (10): 32 位绝对地址（无符号）
            10 => {
                // 检查截断后是否丢失高位
                let val_u32 = val as u32;
                if val != val_u32 as u64 {
                    early_println!(
                        "[Loader] Error: overflow in relocation type {} val 0x{:x}",
                        reloc_type,
                        val
                    );
                    early_println!("[Loader] Module likely not compiled with -mcmodel=kernel");
                    return Err(crate::Error::InvalidArgs);
                }
                4
            }
            // R_X86_64_32S (11): 32 位绝对地址（有符号）
            11 => {
                // 有符号截断检查
                let val_i32 = val as i32;
                if val as i64 != val_i32 as i64 {
                    early_println!(
                        "[Loader] Error: overflow in relocation type {} val 0x{:x}",
                        reloc_type,
                        val
                    );
                    early_println!("[Loader] Module likely not compiled with -mcmodel=kernel");
                    return Err(crate::Error::InvalidArgs);
                }
                4
            }
            // R_X86_64_PC32 (2): 32 位 PC 相对（如 callq、jmp）
            // R_X86_64_PLT32 (4): PLT 入口也是 32 位 PC 相对
            2 | 4 => {
                // PC 相对地址 = 符号地址 + addend - (当前指令地址)
                // S + A - P
                // 注意：对于 call 指令，P 是操作数字节的地址，执行时 PC 指向下一条指令（P + 指令长度）
                // 所以实际跳转地址 = PC + offset = (loc + 指令长度) + offset
                let val_before = val;
                val = val.wrapping_sub(loc as u64);
                // 验证 32 位有符号范围：必须在 ±2GB 范围内
                let val_i32 = val as i32;
                let val_i64 = val as i64;

                // 计算实际跳转目标地址（用于调试）
                // 对于 call 指令（e8 XX XX XX XX），指令长度是 5 字节
                // 执行时 PC = loc + 5，跳转目标 = PC + offset = loc + 5 + offset
                let instruction_length = 5; // call 指令通常是 5 字节
                let execution_pc = loc + instruction_length;
                let jump_target = (execution_pc as i64).wrapping_add(val_i32 as i64) as u64;

                early_println!(
                    "[Loader] PC32/PLT32 relocation calculation: symbol=0x{:x}, addend={}, loc=0x{:x}, val_before=0x{:x}, val_after=0x{:x} ({}), execution_pc=0x{:x}, jump_target=0x{:x}",
                    symbol_addr,
                    addend,
                    loc,
                    val_before,
                    val,
                    val_i32,
                    execution_pc,
                    jump_target
                );

                // 检查是否有符号扩展问题（值超出 32 位有符号范围）
                if val_i64 != val_i32 as i64 {
                    early_println!(
                        "[Loader] Error: PC relative offset out of range for type {}: val=0x{:x} ({}), loc=0x{:x}, symbol=0x{:x}",
                        reloc_type,
                        val,
                        val_i64,
                        loc,
                        symbol_addr
                    );
                    early_println!(
                        "[Loader] Offset exceeds ±2GB range for 32-bit PC relative relocation"
                    );
                    return Err(crate::Error::InvalidArgs);
                }
                4
            }
            // R_X86_64_PC64 (5): 64 位 PC 相对（极少使用）
            24 => {
                val = val.wrapping_sub(loc as u64);
                8
            }

            _ => {
                early_println!(
                    "[Loader] Error: Unsupported relocation type: {}, symbol '{}'",
                    reloc_type,
                    symbol_name
                );
                return Err(crate::Error::InvalidArgs);
            }
        };

        // 安全检查：目标位置必须原本是 0
        unsafe {
            let mut existing_bytes = [0u8; 8];
            let mut reader = VmReader::from_kernel_space(loc as *const u8, size);
            let read_len = reader.read(&mut VmWriter::from(&mut existing_bytes[..size]));
            if read_len != size {
                early_println!(
                    "[Loader] Error: Failed to read existing value at 0x{:x}",
                    loc
                );
                return Err(crate::Error::InvalidArgs);
            }

            // 检查是否为零
            let is_zero = match size {
                4 => {
                    let existing_val = u32::from_le_bytes([
                        existing_bytes[0],
                        existing_bytes[1],
                        existing_bytes[2],
                        existing_bytes[3],
                    ]);
                    existing_val == 0
                }
                8 => {
                    let existing_val = u64::from_le_bytes([
                        existing_bytes[0],
                        existing_bytes[1],
                        existing_bytes[2],
                        existing_bytes[3],
                        existing_bytes[4],
                        existing_bytes[5],
                        existing_bytes[6],
                        existing_bytes[7],
                    ]);
                    existing_val == 0
                }
                _ => false,
            };

            if !is_zero {
                early_println!(
                    "[Loader] Error: Invalid relocation target, existing value is nonzero for type {}, loc 0x{:x}, val 0x{:x}",
                    reloc_type,
                    loc,
                    val
                );
                return Err(crate::Error::InvalidArgs);
            }

            // 写入新值
            early_println!(
                "[Loader] About to write {} bytes to 0x{:x} (val=0x{:x})",
                size,
                loc,
                val
            );
            let mut writer = VmWriter::from_kernel_space(loc as *mut u8, size);
            match size {
                4 => {
                    // 对于 32 位值，根据重定位类型决定是有符号还是无符号
                    match reloc_type {
                        // R_X86_64_32: 无符号 32 位
                        10 => {
                            let val_u32 = val as u32;
                            writer.write_val(&val_u32).map_err(|e| {
                                early_println!(
                                    "[Loader] Error: Failed to write 32-bit value 0x{:x} to 0x{:x}: {:?}",
                                    val_u32,
                                    loc,
                                    e
                                );
                                e
                            })?;
                        }
                        // R_X86_64_32S, R_X86_64_PC32, R_X86_64_PLT32: 有符号 32 位
                        _ => {
                            // 将 u64 转换为有符号 i32，然后写入（会自动进行符号扩展）
                            let val_i32 = val as i32;
                            early_println!(
                                "[Loader] Writing PC relative value: val=0x{:x}, val_i32=0x{:x} ({})",
                                val,
                                val_i32 as u32,
                                val_i32
                            );
                            writer.write_val(&val_i32).map_err(|e| {
                                early_println!(
                                    "[Loader] Error: Failed to write 32-bit PC relative value 0x{:x} to 0x{:x}: {:?}",
                                    val_i32 as u32,
                                    loc,
                                    e
                                );
                                e
                            })?;
                        }
                    }
                }
                8 => {
                    // 64 位值直接写入
                    writer.write_val(&val).map_err(|e| {
                        early_println!(
                            "[Loader] Error: Failed to write 64-bit value 0x{:x} to 0x{:x}: {:?}",
                            val,
                            loc,
                            e
                        );
                        e
                    })?;
                }
                _ => {
                    early_println!(
                        "[Loader] Error: Invalid size {} for relocation type {}",
                        size,
                        reloc_type
                    );
                    return Err(crate::Error::InvalidArgs);
                }
            }

            // 验证写入的值
            let mut verify_bytes = [0u8; 8];
            let mut reader = VmReader::from_kernel_space(loc as *const u8, size);
            let read_len = reader.read(&mut VmWriter::from(&mut verify_bytes[..size]));
            if read_len == size {
                early_println!(
                    "[Loader] Reloc[{}] verified: wrote bytes at 0x{:x}: {:02x?}",
                    i,
                    loc,
                    &verify_bytes[..size]
                );
            }

            early_println!(
                "[Loader] Reloc[{}] applied: type={}, wrote {} bytes (0x{:x}) to 0x{:x}",
                i,
                reloc_type,
                size,
                val,
                loc
            );
        }
    }

    Ok(())
}

fn apply_relocate(
    _rel: &[Rel<u64>],
    _target_section: &SectionHeader,
    _elf_file: &ElfFile,
) -> Result<()> {
    Ok(())
}
