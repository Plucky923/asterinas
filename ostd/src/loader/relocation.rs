use alloc::{format, string::ToString, vec, vec::Vec};

use rustc_demangle::demangle;
use xmas_elf::{
    ElfFile,
    sections::{Rela, SHF_ALLOC, SHN_UNDEF, SectionData, ShType},
    symbol_table::{Entry, Entry64},
};

use super::{invalid_args, parser::SectionsMetadata, symbol::get_symbol_table};
use crate::{Result, early_println, mm::io::VmWriter, symbols::symbol_addr_by_name};

pub fn relocate_sections(elf_file: &ElfFile, sections_metadata: &SectionsMetadata) -> Result<()> {
    let symbol_table = get_symbol_table(elf_file)?;
    let mut symbol_addr_cache = vec![None; symbol_table.len()];
    let loaded_section_bases = loaded_section_bases(elf_file, sections_metadata);
    log::info!("[Loader] Starting relocation...");
    early_println!(
        "[Loader] Starting relocation: symbols={}",
        symbol_table.len()
    );

    let mut total_relocations = 0;
    let mut processed_relocations = 0usize;

    // Iterate only relocation sections. Large Rust service objects contain many
    // per-function sections with long symbol names, so name lookup on unrelated
    // sections dominates boot time.
    for reloc_section in elf_file.section_iter() {
        let Ok(section_type) = reloc_section.get_type() else {
            continue;
        };
        if !matches!(section_type, ShType::Rela | ShType::Rel) {
            continue;
        }

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

        match reloc_section.get_data(elf_file) {
            Ok(SectionData::Rela64(rela)) => {
                apply_relocate_add(
                    rela,
                    info as usize,
                    elf_file,
                    &loaded_section_bases,
                    symbol_table,
                    &mut symbol_addr_cache,
                    &mut processed_relocations,
                )?;
                total_relocations += rela.len();
            }
            Ok(SectionData::Rel64(rel)) => {
                early_println!(
                    "[Loader] Ignored {} REL relocations (not implemented)",
                    rel.len()
                );
            }
            _ => {
                continue;
            }
        }
    }
    log::info!(
        "[Loader] Relocation completed. Total applied: {}",
        total_relocations
    );
    early_println!("[Loader] Relocation completed: total={}", total_relocations);
    Ok(())
}

fn loaded_section_bases(
    elf_file: &ElfFile,
    sections_metadata: &SectionsMetadata,
) -> Vec<Option<usize>> {
    let mut section_bases = vec![None; elf_file.section_iter().count()];
    for (&index, section) in sections_metadata.loaded_sections.iter() {
        if let Some(slot) = section_bases.get_mut(index) {
            *slot = Some(section.base_addr);
        }
    }
    section_bases
}

/// 应用 RELA 重定位
fn apply_relocate_add(
    rel: &[Rela<u64>],
    target_section_index: usize,
    elf_file: &ElfFile,
    loaded_section_bases: &[Option<usize>],
    symbol_table: &[Entry64],
    symbol_addr_cache: &mut [Option<u64>],
    processed_relocations: &mut usize,
) -> Result<()> {
    let target_section_base =
        get_target_section_base(target_section_index, loaded_section_bases, elf_file)?;

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
            loaded_section_bases,
            symbol_table,
            symbol_addr_cache,
            processed_relocations,
        )?;
    }

    Ok(())
}

fn get_target_section_base(
    target_section_index: usize,
    loaded_section_bases: &[Option<usize>],
    elf_file: &ElfFile,
) -> Result<usize> {
    loaded_section_bases
        .get(target_section_index)
        .and_then(|base| *base)
        .ok_or_else(|| {
            early_println!(
                "[Loader] Error: Target section index {} not found in loaded_sections!",
                target_section_index
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
            invalid_args(format!(
                "target section index {} not found in loaded section map",
                target_section_index
            ))
        })
}

fn process_relocation_entry(
    _index: usize,
    reloc: &Rela<u64>,
    target_section_base: usize,
    elf_file: &ElfFile,
    loaded_section_bases: &[Option<usize>],
    symbol_table: &[Entry64],
    symbol_addr_cache: &mut [Option<u64>],
    processed_relocations: &mut usize,
) -> Result<()> {
    *processed_relocations += 1;
    if *processed_relocations % 50_000 == 0 {
        early_println!("[Loader] Relocated {} entries", *processed_relocations);
    }

    let symbol_idx = reloc.get_symbol_table_index() as usize;
    let offset = reloc.get_offset();
    let reloc_type = reloc.get_type();
    let addend = reloc.get_addend() as i64;

    if reloc_type == 0 {
        return Ok(());
    }

    // 计算要修改的目标地址
    let loc = target_section_base + offset as usize;

    // 获取符号
    let symbol = symbol_table.get(symbol_idx).ok_or_else(|| {
        invalid_args(format!(
            "invalid symbol table index {} in relocation",
            symbol_idx
        ))
    })?;

    // 计算符号的实际地址
    let symbol_addr = resolve_symbol_address(
        symbol_idx,
        symbol,
        reloc_type,
        elf_file,
        loaded_section_bases,
        symbol_addr_cache,
    )?;

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
                return Err(invalid_args(format!(
                    "32-bit signed relocation overflow for type {} with value 0x{:x}",
                    reloc_type, val
                )));
            }
            write_val(loc, val, 4)
        }
        // R_X86_64_32S
        11 => {
            let val_i32 = val as i32;
            if val as i64 != val_i32 as i64 {
                log_overflow(reloc_type, val);
                return Err(invalid_args(format!(
                    "32-bit relocation overflow for type {} with value 0x{:x}",
                    reloc_type, val
                )));
            }
            write_val(loc, val, 4)
        }
        // R_X86_64_PC32 (2) | R_X86_64_PLT32 (4)
        2 | 4 => handle_pc_relative(loc, val, reloc_type, symbol_addr, 4),
        // R_X86_64_PC64
        24 => handle_pc_relative(loc, val, reloc_type, symbol_addr, 8),
        _ => {
            let symbol_name = symbol.get_name(elf_file).unwrap_or("");
            early_println!(
                "[Loader] Error: Unsupported relocation type: {}, symbol '{}'",
                reloc_type,
                symbol_name
            );
            Err(invalid_args(format!(
                "unsupported relocation type {} for symbol `{}`",
                reloc_type, symbol_name
            )))
        }
    }
}

fn resolve_symbol_address(
    symbol_idx: usize,
    symbol: &Entry64,
    reloc_type: u32,
    elf_file: &ElfFile,
    loaded_section_bases: &[Option<usize>],
    symbol_addr_cache: &mut [Option<u64>],
) -> Result<u64> {
    if let Some(addr) = symbol_addr_cache[symbol_idx] {
        return Ok(addr);
    }

    let shndx = symbol.shndx();
    let resolved_addr = if shndx == SHN_UNDEF {
        let symbol_name = symbol.get_name(elf_file).unwrap_or("");
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
                Err(invalid_args(format!(
                    "cannot resolve undefined symbol `{}` (demangled: `{}`) for relocation type {}",
                    symbol_name, demangled, reloc_type
                )))
            }
        }
    } else if let Some(Some(section_base)) = loaded_section_bases.get(shndx as usize) {
        Ok((*section_base + symbol.value() as usize) as u64)
    } else {
        Ok(symbol.value() as u64)
    }?;

    symbol_addr_cache[symbol_idx] = Some(resolved_addr);
    Ok(resolved_addr)
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
            return Err(invalid_args(format!(
                "PC-relative relocation type {} out of range: rel=0x{:x}, loc=0x{:x}, symbol=0x{:x}",
                reloc_type, rel_val, loc, symbol_addr
            )));
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
                writer.write_val(&val_u32).map_err(|_| {
                    invalid_args(format!(
                        "failed to write {}-byte relocation at 0x{:x}",
                        size, loc
                    ))
                })?;
            }
            8 => {
                writer.write_val(&val).map_err(|_| {
                    invalid_args(format!(
                        "failed to write {}-byte relocation at 0x{:x}",
                        size, loc
                    ))
                })?;
            }
            _ => {
                return Err(invalid_args(format!(
                    "unsupported relocation write size {} at 0x{:x}",
                    size, loc
                )));
            }
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
