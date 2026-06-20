use alloc::{
    format,
    string::{String, ToString},
};
use core::str;

use rustc_demangle::demangle;
use xmas_elf::{
    ElfFile,
    sections::{SHN_UNDEF, SectionData, ShType},
    symbol_table::{Entry, Entry64},
};

use super::{invalid_args, parser::SectionsMetadata};
use crate::{Result, symbols::symbol_addr_by_name};

pub fn get_symbol_table<'a>(elf_file: &'a ElfFile) -> Result<&'a [Entry64]> {
    let symtab_data = elf_file
        .section_iter()
        .find(|sec| sec.get_type() == Ok(ShType::SymTab))
        .ok_or_else(|| invalid_args("missing `.symtab` in service module object"))
        .and_then(|sec| {
            sec.get_data(&elf_file)
                .map_err(|_| invalid_args("failed to read `.symtab` from service module object"))
        });

    match symtab_data {
        Ok(SectionData::SymbolTable64(symtab)) => Ok(symtab),
        _ => Err(invalid_args(
            "unsupported symbol table format in service module object",
        )),
    }
}

const DYNAMIC_ENTRY_SYMBOL: &str = "__ostd_dynamic_main";
const ENTRY_SYMBOL: &str = "__ostd_main";

/// A service module entry point.
#[derive(Clone, Copy, Debug)]
pub struct EntryPoint {
    addr: usize,
    kind: EntryPointKind,
}

impl EntryPoint {
    /// Creates a dynamic-module entry point.
    fn dynamic(addr: usize) -> Self {
        Self {
            addr,
            kind: EntryPointKind::Dynamic,
        }
    }

    /// Creates an OSTD main entry point.
    fn ostd_main(addr: usize) -> Self {
        Self {
            addr,
            kind: EntryPointKind::OstdMain,
        }
    }

    /// Returns the relocated entry address.
    pub fn addr(self) -> usize {
        self.addr
    }

    /// Returns whether this entry point returns to the loader.
    pub fn returns_to_loader(self) -> bool {
        self.kind == EntryPointKind::Dynamic
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryPointKind {
    Dynamic,
    OstdMain,
}

/// Finds the service module entry point.
pub fn find_entry_point(
    elf_file: &ElfFile,
    sections_metadata: &SectionsMetadata,
) -> Result<Option<EntryPoint>> {
    let symbol_table = get_symbol_table(elf_file)?;

    if let Some(entry) = find_entry_symbol(
        elf_file,
        sections_metadata,
        symbol_table,
        DYNAMIC_ENTRY_SYMBOL,
    )? {
        return Ok(Some(EntryPoint::dynamic(entry)));
    }

    Ok(
        find_entry_symbol(elf_file, sections_metadata, symbol_table, ENTRY_SYMBOL)?
            .map(EntryPoint::ostd_main),
    )
}

fn find_entry_symbol(
    elf_file: &ElfFile,
    sections_metadata: &SectionsMetadata,
    symbol_table: &[Entry64],
    entry_symbol: &str,
) -> Result<Option<usize>> {
    let symbol_string_table = symbol_string_table(elf_file)?;
    let entry_symbol_path_suffix = entry_symbol_path_suffix(entry_symbol);
    for symbol in symbol_table.iter() {
        let name = symbol_name(symbol_string_table, symbol.name()).unwrap_or("");
        if !is_entry_symbol(name, entry_symbol, &entry_symbol_path_suffix) {
            continue;
        }

        let section_index = symbol.shndx();
        if section_index == SHN_UNDEF {
            if let Some(addr) = symbol_addr_by_name(name) {
                return Ok(Some(addr));
            }
            return Err(invalid_args(format!(
                "entry symbol `{entry_symbol}` is undefined and cannot be resolved"
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

    Ok(None)
}

fn is_entry_symbol(symbol_name: &str, entry_symbol: &str, entry_symbol_path_suffix: &str) -> bool {
    if symbol_name == entry_symbol {
        return true;
    }

    let demangled = demangle(symbol_name).to_string();
    demangled == entry_symbol || demangled.ends_with(entry_symbol_path_suffix)
}

fn entry_symbol_path_suffix(entry_symbol: &str) -> String {
    let mut suffix = String::with_capacity(entry_symbol.len() + 2);
    suffix.push_str("::");
    suffix.push_str(entry_symbol);
    suffix
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

fn symbol_name(string_table: &[u8], offset: u32) -> Option<&str> {
    let start = offset as usize;
    if start >= string_table.len() {
        return None;
    }

    let end = string_table[start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|position| start + position)
        .unwrap_or(string_table.len());
    str::from_utf8(&string_table[start..end]).ok()
}
