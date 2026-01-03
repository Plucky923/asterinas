use alloc::{string::ToString, vec::Vec};

use rustc_demangle::demangle;
use xmas_elf::{
    ElfFile,
    sections::{Rela, SHF_ALLOC, SHN_UNDEF, SectionData, ShType},
    symbol_table::{Entry, Entry64},
};

use super::{parser::SectionsMetadata, symbol::get_symbol_table};
use crate::{Result, early_println, mm::io::VmWriter, symbols::symbol_addr_by_name};

pub fn relocate_sections(elf_file: &ElfFile, sections_metadata: &SectionsMetadata) -> Result<()> {
    let symbol_table = get_symbol_table(elf_file)?;
    early_println!("[Loader] Starting relocation...");

    let mut total_relocations = 0;

    // 遍历所有重定位section
    for reloc_section in elf_file.section_iter() {
        let Ok(_reloc_section_name) = reloc_section.get_name(elf_file) else {
            continue;
        };

        let info = reloc_section.info();
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
                apply_relocate_add(
                    rela,
                    info as usize,
                    elf_file,
                    &sections_metadata,
                    symbol_table,
                )?;
                early_println!(
                    "[Loader] Applied {} RELA relocations to section '{}'",
                    rela.len(),
                    name
                );
                total_relocations += rela.len();
            }
            Ok(SectionData::Rel64(rel)) => {
                // FrameVM usually uses RELA on x86_64
                early_println!(
                    "[Loader] Ignored {} REL relocations for section '{}' (not implemented)",
                    rel.len(),
                    name
                );
            }
            _ => {
                continue;
            }
        }
    }
    early_println!(
        "[Loader] Relocation completed. Total applied: {}",
        total_relocations
    );
    Ok(())
}

/// 应用 RELA 重定位
fn apply_relocate_add(
    rel: &[Rela<u64>],
    target_section_index: usize,
    elf_file: &ElfFile,
    sections_metadata: &SectionsMetadata,
    symbol_table: &[Entry64],
) -> Result<()> {
    let target_section_base =
        get_target_section_base(target_section_index, sections_metadata, elf_file)?;

    // 移除详细的每段重定位开始日志
    /*
    early_println!(
        "[Loader] Applying {} relocations to section {} (base: 0x{:x})",
        rel.len(),
        target_section_index,
        target_section_base
    );
    */

    for (i, reloc) in rel.iter().enumerate() {
        process_relocation_entry(
            i,
            reloc,
            target_section_base,
            elf_file,
            sections_metadata,
            symbol_table,
        )?;
    }

    Ok(())
}

fn get_target_section_base(
    target_section_index: usize,
    sections_metadata: &SectionsMetadata,
    elf_file: &ElfFile,
) -> Result<usize> {
    sections_metadata
        .loaded_sections
        .get(&target_section_index)
        .map(|section| section.base_addr)
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
        })
}

fn process_relocation_entry(
    _index: usize,
    reloc: &Rela<u64>,
    target_section_base: usize,
    elf_file: &ElfFile,
    sections_metadata: &SectionsMetadata,
    symbol_table: &[Entry64],
) -> Result<()> {
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

    // 计算符号的实际地址
    let symbol_addr = resolve_symbol_address(symbol, symbol_name, reloc_type, sections_metadata)?;

    // 基础值 = 符号地址 + addend
    let val = ((symbol_addr as i64).wrapping_add(addend)) as u64;

    match reloc_type {
        // R_X86_64_NONE
        0 => Ok(()),
        // R_X86_64_64
        1 => write_val(loc, val, 8),
        // R_X86_64_32
        10 => {
            let val_u32 = val as u32;
            if val != val_u32 as u64 {
                log_overflow(reloc_type, val);
                return Err(crate::Error::InvalidArgs);
            }
            write_val(loc, val, 4)
        }
        // R_X86_64_32S
        11 => {
            let val_i32 = val as i32;
            if val as i64 != val_i32 as i64 {
                log_overflow(reloc_type, val);
                return Err(crate::Error::InvalidArgs);
            }
            write_val(loc, val, 4)
        }
        // R_X86_64_PC32 (2) | R_X86_64_PLT32 (4)
        2 | 4 => handle_pc_relative(loc, val, reloc_type, symbol_addr, 4),
        // R_X86_64_PC64
        24 => handle_pc_relative(loc, val, reloc_type, symbol_addr, 8),
        _ => {
            early_println!(
                "[Loader] Error: Unsupported relocation type: {}, symbol '{}'",
                reloc_type,
                symbol_name
            );
            Err(crate::Error::InvalidArgs)
        }
    }
}

fn resolve_symbol_address(
    symbol: &Entry64,
    symbol_name: &str,
    reloc_type: u32,
    sections_metadata: &SectionsMetadata,
) -> Result<u64> {
    let shndx = symbol.shndx();
    if shndx == SHN_UNDEF {
        match symbol_addr_by_name(symbol_name) {
            Some(addr) => Ok(addr as u64),
            None => {
                let demangled = demangle(symbol_name).to_string();
                early_println!(
                    "[Loader] Error: Cannot resolve undefined symbol '{}' (demangled: '{}') for relocation type {}",
                    symbol_name,
                    demangled,
                    reloc_type
                );
                Err(crate::Error::InvalidArgs)
            }
        }
    } else if let Some(section) = sections_metadata.loaded_sections.get(&(shndx as usize)) {
        Ok((section.base_addr + symbol.value() as usize) as u64)
    } else {
        Ok(symbol.value() as u64)
    }
}

fn handle_pc_relative(
    loc: usize,
    val: u64,
    reloc_type: u32,
    symbol_addr: u64,
    size: usize,
) -> Result<()> {
    let rel_val = val.wrapping_sub(loc as u64);

    if size == 4 {
        let val_i32 = rel_val as i32;
        let val_i64 = rel_val as i64;

        if val_i64 != val_i32 as i64 {
            early_println!(
                "[Loader] Error: PC relative offset out of range for type {}: val=0x{:x} ({}), loc=0x{:x}, symbol=0x{:x}",
                reloc_type,
                rel_val,
                val_i64,
                loc,
                symbol_addr
            );
            return Err(crate::Error::InvalidArgs);
        }
    }

    write_val(loc, rel_val, size)
}

fn write_val(loc: usize, val: u64, size: usize) -> Result<()> {
    unsafe {
        let mut writer = VmWriter::from_kernel_space(loc as *mut u8, size);
        match size {
            4 => {
                let val_u32 = val as u32;
                writer
                    .write_val(&val_u32)
                    .map_err(|_| crate::Error::InvalidArgs)?;
            }
            8 => {
                writer
                    .write_val(&val)
                    .map_err(|_| crate::Error::InvalidArgs)?;
            }
            _ => return Err(crate::Error::InvalidArgs),
        }
    }
    Ok(())
}

fn log_overflow(reloc_type: u32, val: u64) {
    early_println!(
        "[Loader] Error: overflow in relocation type {} val 0x{:x}",
        reloc_type,
        val
    );
    early_println!("[Loader] Module likely not compiled with -mcmodel=kernel");
}
