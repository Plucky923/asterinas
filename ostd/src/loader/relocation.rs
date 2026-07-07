use alloc::{
    collections::btree_set::BTreeSet,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use rustc_demangle::demangle;
use xmas_elf::{
    ElfFile,
    sections::{Rela, SHN_UNDEF, SectionData, ShType},
    symbol_table::{Entry, Entry64},
};

use super::{
    invalid_args,
    parser::SectionsMetadata,
    service_object::{ServiceObject, ServiceRelocationSection},
    symbol::get_symbol_table,
};
use crate::{Result, early_println, mm::io::VmWriter, symbols::framevm_symbol_addr_by_name};

const SHN_ABS: u16 = 0xfff1;
const SHN_COMMON: u16 = 0xfff2;
const SHN_LORESERVE: u16 = 0xff00;

struct RelocationPlan {
    work_items: Vec<RelocationWorkItem>,
    total_relocations: usize,
}

struct RelocationWorkItem {
    loc: usize,
    reloc_type: u32,
    addend: i64,
    symbol_addr: u64,
}

struct MissingImport {
    raw_symbol: String,
    demangled_symbol: String,
    relocation_type: u32,
}

pub fn relocate_sections(
    service_object: &ServiceObject,
    sections_metadata: &SectionsMetadata,
) -> Result<()> {
    let elf_file = service_object.elf_file();
    let symbol_table = get_symbol_table(elf_file)?;
    let loaded_section_bases = loaded_section_bases(elf_file, sections_metadata);
    log::info!("[Loader] Starting relocation...");

    let relocation_plan =
        build_relocation_plan(service_object, &loaded_section_bases, symbol_table)?;
    apply_relocation_plan(&relocation_plan)?;

    log::info!(
        "[Loader] Relocation completed. Total applied: {}",
        relocation_plan.total_relocations
    );
    Ok(())
}

fn build_relocation_plan(
    service_object: &ServiceObject,
    loaded_section_bases: &[Option<usize>],
    symbol_table: &[Entry64],
) -> Result<RelocationPlan> {
    let elf_file = service_object.elf_file();
    let mut resolved_symbols = vec![None; symbol_table.len()];
    let mut missing_imports = Vec::new();
    let mut missing_import_keys = BTreeSet::new();
    let mut work_items = Vec::new();
    let mut total_relocations = 0usize;

    for relocation_info in service_object.relocation_sections() {
        let reloc_section = elf_file
            .section_header(relocation_info.section_index() as u16)
            .map_err(|_| {
                invalid_args(format!(
                    "relocation section {} is no longer available in service object",
                    relocation_info.section_index()
                ))
            })?;

        match reloc_section.get_data(elf_file) {
            Ok(SectionData::Rela64(rela)) => {
                total_relocations += rela.len();
                plan_relocate_add(
                    rela,
                    *relocation_info,
                    elf_file,
                    &loaded_section_bases,
                    symbol_table,
                    &mut resolved_symbols,
                    &mut missing_imports,
                    &mut missing_import_keys,
                    &mut work_items,
                )?;
            }
            Ok(SectionData::Rel64(rel)) => {
                if !rel.is_empty() {
                    return Err(invalid_args(format!(
                        "REL relocation section for target section {} is unsupported",
                        relocation_info.target_section_index()
                    )));
                }
            }
            _ => {
                continue;
            }
        }
    }

    if !missing_imports.is_empty() {
        return Err(invalid_args(missing_imports_error(&missing_imports)));
    }

    Ok(RelocationPlan {
        work_items,
        total_relocations,
    })
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

fn plan_relocate_add(
    rel: &[Rela<u64>],
    relocation_info: ServiceRelocationSection,
    elf_file: &ElfFile,
    loaded_section_bases: &[Option<usize>],
    symbol_table: &[Entry64],
    resolved_symbols: &mut [Option<u64>],
    missing_imports: &mut Vec<MissingImport>,
    missing_import_keys: &mut BTreeSet<Vec<u8>>,
    work_items: &mut Vec<RelocationWorkItem>,
) -> Result<()> {
    let target_section_index = relocation_info.target_section_index();
    let target_section_base =
        get_target_section_base(target_section_index, loaded_section_bases, elf_file)?;

    for reloc in rel {
        plan_relocation_entry(
            reloc,
            target_section_base,
            relocation_info.target_section_size(),
            elf_file,
            loaded_section_bases,
            symbol_table,
            resolved_symbols,
            missing_imports,
            missing_import_keys,
            work_items,
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

fn plan_relocation_entry(
    reloc: &Rela<u64>,
    target_section_base: usize,
    target_section_size: u64,
    elf_file: &ElfFile,
    loaded_section_bases: &[Option<usize>],
    symbol_table: &[Entry64],
    resolved_symbols: &mut [Option<u64>],
    missing_imports: &mut Vec<MissingImport>,
    missing_import_keys: &mut BTreeSet<Vec<u8>>,
    work_items: &mut Vec<RelocationWorkItem>,
) -> Result<()> {
    let symbol_idx = reloc.get_symbol_table_index() as usize;
    let offset = reloc.get_offset();
    let reloc_type = reloc.get_type();
    let addend = reloc.get_addend() as i64;

    if reloc_type == 0 {
        return Ok(());
    }

    let write_size = relocation_write_size(reloc_type, symbol_idx, elf_file, symbol_table)?;
    let relocation_end = offset.checked_add(write_size as u64).ok_or_else(|| {
        invalid_args(format!(
            "relocation offset 0x{:x} overflows for write size {}",
            offset, write_size
        ))
    })?;
    if relocation_end > target_section_size {
        return Err(invalid_args(format!(
            "relocation write exceeds target section: offset=0x{:x}, size={}, section_size=0x{:x}",
            offset, write_size, target_section_size
        )));
    }
    let loc = target_section_base
        .checked_add(offset as usize)
        .ok_or_else(|| invalid_args("relocation target address overflows"))?;
    let symbol = symbol_table.get(symbol_idx).ok_or_else(|| {
        invalid_args(format!(
            "invalid symbol table index {} in relocation",
            symbol_idx
        ))
    })?;

    let Some(symbol_addr) = resolve_symbol_address_for_plan(
        symbol_idx,
        symbol,
        reloc_type,
        elf_file,
        loaded_section_bases,
        resolved_symbols,
        missing_imports,
        missing_import_keys,
    )?
    else {
        return Ok(());
    };

    work_items.push(RelocationWorkItem {
        loc,
        reloc_type,
        addend,
        symbol_addr,
    });
    Ok(())
}

fn apply_relocation_plan(plan: &RelocationPlan) -> Result<()> {
    let mut processed_relocations = 0usize;
    for work_item in &plan.work_items {
        processed_relocations += 1;
        if let Err(error) = apply_relocation_work_item(work_item) {
            early_println!(
                "[Loader] ERROR: relocation item {} failed: type={}, loc=0x{:x}, symbol=0x{:x}, addend={}",
                processed_relocations,
                work_item.reloc_type,
                work_item.loc,
                work_item.symbol_addr,
                work_item.addend
            );
            return Err(error);
        }
    }
    Ok(())
}

fn apply_relocation_work_item(work_item: &RelocationWorkItem) -> Result<()> {
    let val = ((work_item.symbol_addr as i64).wrapping_add(work_item.addend)) as u64;

    match work_item.reloc_type {
        // R_X86_64_64
        1 => write_val(work_item.loc, val, 8),
        // R_X86_64_32
        10 => {
            let val_u32 = val as u32;
            if val != val_u32 as u64 {
                log_overflow(work_item.reloc_type, val);
                return Err(invalid_args(format!(
                    "32-bit signed relocation overflow for type {} with value 0x{:x}",
                    work_item.reloc_type, val
                )));
            }
            write_val(work_item.loc, val, 4)
        }
        // R_X86_64_32S
        11 => {
            let val_i32 = val as i32;
            if val as i64 != val_i32 as i64 {
                log_overflow(work_item.reloc_type, val);
                return Err(invalid_args(format!(
                    "32-bit relocation overflow for type {} with value 0x{:x}",
                    work_item.reloc_type, val
                )));
            }
            write_val(work_item.loc, val, 4)
        }
        // R_X86_64_PC32 (2) | R_X86_64_PLT32 (4)
        2 | 4 => handle_pc_relative(
            work_item.loc,
            val,
            work_item.reloc_type,
            work_item.symbol_addr,
            4,
        ),
        // R_X86_64_PC64
        24 => handle_pc_relative(
            work_item.loc,
            val,
            work_item.reloc_type,
            work_item.symbol_addr,
            8,
        ),
        _ => Err(invalid_args(format!(
            "unsupported relocation type {} reached relocation application",
            work_item.reloc_type
        ))),
    }
}

fn resolve_symbol_address_for_plan(
    symbol_idx: usize,
    symbol: &Entry64,
    reloc_type: u32,
    elf_file: &ElfFile,
    loaded_section_bases: &[Option<usize>],
    resolved_symbols: &mut [Option<u64>],
    missing_imports: &mut Vec<MissingImport>,
    missing_import_keys: &mut BTreeSet<Vec<u8>>,
) -> Result<Option<u64>> {
    if symbol_idx == 0 {
        return Ok(Some(0));
    }

    if let Some(addr) = resolved_symbols[symbol_idx] {
        return Ok(Some(addr));
    }

    let shndx = symbol.shndx();
    let resolved_addr = if shndx == SHN_UNDEF {
        let symbol_name = symbol_name_bytes(elf_file, symbol.name())?;
        match framevm_symbol_addr_by_name(symbol_name) {
            Some(addr) => Ok(addr as u64),
            None => {
                if missing_import_keys.insert(symbol_name.to_vec()) {
                    missing_imports.push(MissingImport {
                        raw_symbol: raw_symbol_display(symbol_name),
                        demangled_symbol: demangled_symbol_display(symbol_name),
                        relocation_type: reloc_type,
                    });
                }
                return Ok(None);
            }
        }
    } else if let Some(Some(section_base)) = loaded_section_bases.get(shndx as usize) {
        let addr = section_base
            .checked_add(symbol.value() as usize)
            .ok_or_else(|| invalid_args("loaded service-section symbol address overflows"))?;
        Ok(addr as u64)
    } else if shndx == SHN_ABS {
        Ok(symbol.value())
    } else if shndx == SHN_COMMON || shndx >= SHN_LORESERVE {
        Err(invalid_args(format!(
            "unsupported relocation symbol section class 0x{:x} for `{}`",
            shndx,
            symbol_display(elf_file, symbol)
        )))
    } else {
        Err(invalid_args(format!(
            "relocation references unloaded service section {} for `{}`",
            shndx,
            symbol_display(elf_file, symbol)
        )))
    }?;

    resolved_symbols[symbol_idx] = Some(resolved_addr);
    Ok(Some(resolved_addr))
}

fn relocation_write_size(
    reloc_type: u32,
    symbol_idx: usize,
    elf_file: &ElfFile,
    symbol_table: &[Entry64],
) -> Result<usize> {
    match reloc_type {
        1 | 24 => Ok(8),
        2 | 4 | 10 | 11 => Ok(4),
        _ => {
            let symbol = symbol_table.get(symbol_idx);
            let symbol_name = symbol
                .map(|symbol| symbol_display(elf_file, symbol))
                .unwrap_or_else(|| "<invalid symbol index>".to_string());
            Err(invalid_args(format!(
                "unsupported relocation type {} for symbol `{}`",
                reloc_type, symbol_name
            )))
        }
    }
}

fn missing_imports_error(missing_imports: &[MissingImport]) -> String {
    let mut message = format!(
        "cannot resolve {} undefined FrameVM import(s) before relocation",
        missing_imports.len()
    );
    for missing in missing_imports.iter().take(16) {
        message.push_str("; ");
        message.push_str(&missing.raw_symbol);
        message.push_str(" (demangled: ");
        message.push_str(&missing.demangled_symbol);
        message.push_str(", relocation_type: ");
        message.push_str(&missing.relocation_type.to_string());
        message.push(')');
    }
    message
}

fn symbol_display(elf_file: &ElfFile, symbol: &Entry64) -> String {
    symbol_name_bytes(elf_file, symbol.name())
        .map(raw_symbol_display)
        .unwrap_or_else(|_| "<invalid symbol name>".to_string())
}

fn symbol_name_bytes<'a>(elf_file: &'a ElfFile, offset: u32) -> Result<&'a [u8]> {
    let string_table = symbol_string_table(elf_file)?;
    let start = offset as usize;
    if start >= string_table.len() {
        return Err(invalid_args(format!(
            "symbol-name offset {} exceeds service string table size {}",
            start,
            string_table.len()
        )));
    }
    let end = string_table[start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|position| start + position)
        .ok_or_else(|| {
            invalid_args(format!(
                "symbol-name offset {} is not nul-terminated in service string table",
                start
            ))
        })?;
    Ok(&string_table[start..end])
}

fn symbol_string_table<'a>(elf_file: &'a ElfFile) -> Result<&'a [u8]> {
    let section = elf_file
        .find_section_by_name(".strtab")
        .ok_or_else(|| invalid_args("missing `.strtab` in service module object"))?;
    if section.get_type() != Ok(ShType::StrTab) {
        return Err(invalid_args(
            "service module `.strtab` section has an unexpected type",
        ));
    }
    Ok(section.raw_data(elf_file))
}

fn raw_symbol_display(raw_name: &[u8]) -> String {
    match core::str::from_utf8(raw_name) {
        Ok(name) => name.to_string(),
        Err(_) => format!("0x{}", bytes_to_hex(raw_name)),
    }
}

fn demangled_symbol_display(raw_name: &[u8]) -> String {
    match core::str::from_utf8(raw_name) {
        Ok(name) => demangle(name).to_string(),
        Err(_) => "<non-utf8>".to_string(),
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
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
