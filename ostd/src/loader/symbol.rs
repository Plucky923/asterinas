use alloc::{format, string::ToString};

use rustc_demangle::demangle;
use xmas_elf::{
    sections::{SectionData, ShType, SHN_UNDEF},
    symbol_table::{Entry, Entry64},
    ElfFile,
};

use super::{invalid_args, parser::SectionsMetadata};
use crate::{symbols::symbol_addr_by_name, Result};

pub fn get_symbol_table<'a>(elf_file: &'a ElfFile) -> Result<&'a [Entry64]> {
    let symtab_data = elf_file
        .section_iter()
        .find(|sec| sec.get_type() == Ok(ShType::SymTab))
        .ok_or_else(|| invalid_args("missing `.symtab` in FrameVM object"))
        .and_then(|sec| {
            sec.get_data(&elf_file)
                .map_err(|_| invalid_args("failed to read `.symtab` from FrameVM object"))
        });

    match symtab_data {
        Ok(SectionData::SymbolTable64(symtab)) => Ok(symtab),
        _ => Err(invalid_args(
            "unsupported symbol table format in FrameVM object",
        )),
    }
}

/// 查找入口点地址 (__framevm_main 符号)
pub fn find_entry_point(
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
            if section_index == SHN_UNDEF {
                // 如果符号在当前ELF未定义，尝试从内核符号表查找
                if let Some(addr) = symbol_addr_by_name(name) {
                    return Ok(Some(addr));
                }
                return Err(invalid_args(format!(
                    "entry symbol `__framevm_main` is undefined and cannot be resolved"
                )));
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
