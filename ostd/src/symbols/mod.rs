//! Runtime symbol table support for resolving function and object names.

use alloc::{collections::btree_map::BTreeMap, format, string::String, vec::Vec};

use rustc_demangle::demangle;
use spin::Once;
use xmas_elf::{
    sections::{SectionData, ShType},
    symbol_table::{Binding, Entry},
    ElfFile,
};

use crate::{alloc::string::ToString, early_print, early_println, sync::SpinLock};

/// Initializes the global symbol table if the bootloader provided symbol data.
pub fn symbols_table_init() {
    if let Some(symbols) = crate::boot::boot_info().symbols {
        parse_symbols_file_from_binary(symbols);
    } else {
        early_print!("[ostd] No symbols were provided by the bootloader.");
    }

    traverse_symbols();
}

/// A single entry within the kernel symbol table.
#[derive(Clone, Debug)]
pub struct SymbolEntry {
    /// Demangled symbol name.
    pub name: String,
    /// Starting address of the symbol in the kernel image.
    pub addr: usize,
    /// Length of the symbol in bytes.
    pub size: usize,
}

type SymbolTable = SpinLock<BTreeMap<usize, SymbolEntry>>;

static SYMBOLS_TABLE: Once<SymbolTable> = Once::new();

fn symbol_table() -> &'static SymbolTable {
    SYMBOLS_TABLE.call_once(|| SpinLock::new(BTreeMap::new()))
}

fn parse_symbols_file_from_binary(symbols: &[u8]) {
    const ELF_MAGIC: &[u8; 4] = b"\x7FELF";

    if symbols.len() < ELF_MAGIC.len() || &symbols[..4] != ELF_MAGIC {
        early_print!(
            "[ostd] Symbols payload is not an ELF binary (len={}, magic={:02x?}).",
            symbols.len(),
            &symbols[..symbols.len().min(4)]
        );
        return;
    }

    let elf_file = match ElfFile::new(symbols) {
        Ok(file) => file,
        Err(err) => {
            early_print!("[ostd] Failed to parse ELF symbols: {:?}", err);
            return;
        }
    };

    let Some(ssec) = elf_file
        .section_iter()
        .find(|s| s.get_type() == Ok(ShType::SymTab))
    else {
        early_print!("[ostd] No symbol table section found in ELF symbols.");
        return;
    };

    let symtab = match ssec.get_data(&elf_file) {
        Ok(SectionData::SymbolTable64(symtab)) => symtab,
        _ => {
            early_print!("[ostd] Unsupported symbol table format in ELF symbols.");
            return;
        }
    };

    {
        let mut table = symbol_table().lock();
        table.clear();

        let mut total_symbols = 0;
        let mut processed_symbols = 0;
        let mut framevisor_count = 0;

        for entry in symtab.iter() {
            total_symbols += 1;
            if let (Ok(bind), Ok(typ)) = (entry.get_binding(), entry.get_type()) {
                let global = bind == Binding::Global || bind == Binding::Weak;
                if (typ == xmas_elf::symbol_table::Type::Func
                    || typ == xmas_elf::symbol_table::Type::Object)
                    || global
                {
                    processed_symbols += 1;
                    let address = entry.value() as usize;
                    let size = entry.size() as usize;
                    let name = entry.get_name(&elf_file).unwrap_or("<invalid utf8>");
                    let demangled = demangle(name).to_string();

                    // Match framevisor symbols case-insensitively
                    // Check both raw name and demangled name
                    let name_lower = name.to_lowercase();
                    let demangled_lower = demangled.to_lowercase();
                    if name_lower.contains("framevisor")
                        || name_lower.contains("aster_framevisor")
                        || demangled_lower.contains("framevisor")
                        || demangled_lower.contains("aster_framevisor")
                    {
                        framevisor_count += 1;
                        // Debug: print first few framevisor symbols
                        if framevisor_count <= 5 {
                            early_println!(
                                "[ostd] Found framevisor symbol: {} (raw: {})",
                                demangled,
                                name
                            );
                        }
                        table.insert(
                            address,
                            SymbolEntry {
                                name: demangled,
                                addr: address,
                                size,
                            },
                        );
                    }
                }
            }
        }

        early_println!(
            "[ostd] Symbol parsing: total={}, processed={}, framevisor={}",
            total_symbols,
            processed_symbols,
            framevisor_count
        );
    }

    early_println!(
        "[ostd] Loaded {} symbol entries.",
        symbol_table().lock().len()
    );
}

/// Inserts or replaces a symbol entry at the given address.
pub fn add_symbol_entry(addr: usize, entry: SymbolEntry) {
    symbol_table().lock().insert(addr, entry);
}

/// Retrieves the symbol information for a specific address, if present.
pub fn symbol_by_addr(addr: usize) -> Option<SymbolEntry> {
    symbol_table().lock().get(&addr).cloned()
}

/// Strips the hash suffix from a demangled symbol name.
/// For example: "aster_framevisor::hello_world::h22af09a1146ed360" -> "aster_framevisor::hello_world"
fn strip_hash_suffix(name: &str) -> &str {
    // Rust mangled names have format: path::to::function::h<hex_hash>
    // We want to remove the ::h<hex_hash> part
    if let Some(pos) = name.rfind("::h") {
        // Check if what follows looks like a hex hash (at least 8 hex digits)
        let after_hash = &name[pos + 3..];
        if after_hash.len() >= 8 && after_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return &name[..pos];
        }
    }
    name
}

/// Retrieves the symbol address by name.
///
/// This function searches for a symbol by its name. It will:
/// 1. Try to match the exact name (mangled or demangled)
/// 2. Try to demangle the input name and match against demangled names (ignoring hash suffixes)
/// 3. For names starting with `ostd::`, also try mapping to `aster_framevisor::` and resolving again.
///
/// Returns the symbol address if found, None otherwise.
pub fn symbol_addr_by_name(name: &str) -> Option<usize> {
    let table = symbol_table().lock();

    // 1. First, try exact match (usually demangled names stored in the table).
    for (_addr, entry) in table.iter() {
        if entry.name == name {
            return Some(entry.addr);
        }
    }

    // 2. Demangle the input name and strip hash suffix.
    let demangled = demangle(name).to_string();
    let demangled_no_hash = strip_hash_suffix(&demangled);

    // 2.1 Build candidate names:
    //   - the original demangled_no_hash
    //   - if it starts with "ostd::", also try replacing the prefix with "aster_framevisor::"
    //   - if it contains "ostd::" inside（例如 core::ptr::drop_in_place<ostd::...>），
    //     也尝试把内部的 "ostd::" 替换为 "aster_framevisor::"
    //
    // This allows resolving symbols that were compiled against a dependency
    // aliased as `ostd` but actually come from the `aster_framevisor` crate.
    let mut candidates: Vec<String> = Vec::new();
    candidates.push(demangled_no_hash.to_string());

    if let Some(rest) = demangled_no_hash.strip_prefix("ostd::") {
        candidates.push(format!("aster_framevisor::{}", rest));
    }

    // 例如：core::ptr::drop_in_place<ostd::mm::vm_space::VmSpace>
    // 我们希望把内部的 `ostd::` 替换成 `aster_framevisor::`，
    // 映射到 core::ptr::drop_in_place<aster_framevisor::mm::vm_space::VmSpace>
    if demangled_no_hash.contains("ostd::") {
        let replaced = demangled_no_hash.replacen("ostd::", "aster_framevisor::", 1);
        if replaced != demangled_no_hash {
            candidates.push(replaced);
        }
    }

    // 2.2 Try to match each candidate against the demangled symbol names in the table.
    for cand in &candidates {
        for (_addr, entry) in table.iter() {
            let entry_no_hash = strip_hash_suffix(&entry.name);
            if entry_no_hash == cand {
                return Some(entry.addr);
            }
        }
    }

    // 3. Fallback: also try matching the raw input name against stored names (including mangled).
    for (_addr, entry) in table.iter() {
        if entry.name == name {
            return Some(entry.addr);
        }
    }

    None
}

/// Returns the number of tracked symbols.
pub fn symbols_len() -> usize {
    symbol_table().lock().len()
}

/// Logs every loaded symbol to the early console for diagnostics.
pub fn traverse_symbols() {
    let table = symbol_table().lock();
    for (addr, entry) in table.iter() {
        early_print!(
            "[ostd] Symbol: addr=0x{:x}, size={}, name={}",
            addr,
            entry.size,
            entry.name
        );
    }
}
