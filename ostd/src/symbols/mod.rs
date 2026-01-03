use alloc::{collections::btree_map::BTreeMap, format, string::String, sync::Arc, vec::Vec};

use rustc_demangle::demangle;
use spin::Once;
use xmas_elf::{
    ElfFile,
    sections::{SectionData, ShType},
    symbol_table::{Binding, Entry},
};

use crate::{alloc::string::ToString, early_print, early_println, sync::SpinLock};

/// Initializes the global symbol table if the bootloader provided symbol data.
pub fn symbols_table_init() {
    if let Some(symbols) = crate::boot::boot_info().symbols {
        parse_symbols_file_from_binary(symbols);
    } else {
        early_print!("[ostd] No symbols were provided by the bootloader.");
    }
}

/// A single entry within the kernel symbol table.
#[derive(Clone, Debug)]
pub struct SymbolEntry {
    /// Demangled symbol name.
    pub name: Arc<str>,
    /// Starting address of the symbol in the kernel image.
    pub addr: usize,
    /// Length of the symbol in bytes.
    pub size: usize,
}

struct SymbolTableInner {
    by_addr: BTreeMap<usize, SymbolEntry>,
    by_name: BTreeMap<Arc<str>, usize>,
}

impl SymbolTableInner {
    fn new() -> Self {
        Self {
            by_addr: BTreeMap::new(),
            by_name: BTreeMap::new(),
        }
    }

    fn insert(&mut self, addr: usize, entry: SymbolEntry) {
        // If there's an existing entry with the same name, we keep the one with the smaller address
        // or just overwrite. The requirement says "lowest starting address".
        // Let's check if the name is already in by_name.
        if let Some(&existing_addr) = self.by_name.get(&entry.name) {
            if addr < existing_addr {
                self.by_name.insert(entry.name.clone(), addr);
            }
        } else {
            self.by_name.insert(entry.name.clone(), addr);
        }
        self.by_addr.insert(addr, entry);
    }

    fn clear(&mut self) {
        self.by_addr.clear();
        self.by_name.clear();
    }

    fn len(&self) -> usize {
        self.by_addr.len()
    }
}

type SymbolTable = SpinLock<SymbolTableInner>;

static SYMBOLS_TABLE: Once<SymbolTable> = Once::new();

fn symbol_table() -> &'static SymbolTable {
    SYMBOLS_TABLE.call_once(|| SpinLock::new(SymbolTableInner::new()))
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
                    let demangled_arc: Arc<str> = demangled.into();

                    table.insert(
                        address,
                        SymbolEntry {
                            name: demangled_arc,
                            addr: address,
                            size,
                        },
                    );
                }
            }
        }

        early_println!(
            "[ostd] Symbol parsing: total={}, processed={}",
            total_symbols,
            processed_symbols,
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
    symbol_table().lock().by_addr.get(&addr).cloned()
}

/// Retrieves the symbol address by name.
pub fn symbol_addr_by_name(name: &str) -> Option<usize> {
    let table = symbol_table().lock();
    let search_key = demangle(name).to_string();
    table.by_name.get(search_key.as_str()).copied()
}

/// Returns the number of tracked symbols.
pub fn symbols_len() -> usize {
    symbol_table().lock().len()
}
