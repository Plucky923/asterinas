use alloc::string::ToString;

use rustc_demangle::demangle;
use xmas_elf::{
    ElfFile,
    sections::{SHN_UNDEF, SectionData, ShType},
    symbol_table::{Entry, Entry64},
};

use super::parser::SectionsMetadata;
use crate::{Result, symbols::symbol_addr_by_name};

pub fn get_symbol_table<'a>(elf_file: &'a ElfFile) -> Result<&'a [Entry64]> {
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
