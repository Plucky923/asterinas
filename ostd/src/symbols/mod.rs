use alloc::{collections::btree_map::BTreeMap, string::String, sync::Arc, vec::Vec};

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
    by_raw_name: BTreeMap<Arc<str>, usize>,
    by_normalized_raw_name: BTreeMap<Arc<str>, usize>,
    by_name: BTreeMap<Arc<str>, usize>,
    by_normalized_name: BTreeMap<Arc<str>, usize>,
    by_crate_path: BTreeMap<Arc<str>, usize>,
    by_normalized_crate_path: BTreeMap<Arc<str>, usize>,
}

impl SymbolTableInner {
    fn new() -> Self {
        Self {
            by_addr: BTreeMap::new(),
            by_raw_name: BTreeMap::new(),
            by_normalized_raw_name: BTreeMap::new(),
            by_name: BTreeMap::new(),
            by_normalized_name: BTreeMap::new(),
            by_crate_path: BTreeMap::new(),
            by_normalized_crate_path: BTreeMap::new(),
        }
    }

    fn insert(&mut self, raw_name: Arc<str>, addr: usize, entry: SymbolEntry) {
        if let Some(normalized_raw_name) = normalize_rust_v0_mangled_crate_disambiguators(&raw_name)
        {
            Self::insert_name(
                &mut self.by_normalized_raw_name,
                Arc::from(normalized_raw_name),
                addr,
            );
        }

        Self::insert_name(&mut self.by_raw_name, raw_name, addr);
        Self::insert_name(&mut self.by_name, entry.name.clone(), addr);

        if let Some(crate_path) = rust_symbol_crate_path_key(&entry.name) {
            Self::insert_name(&mut self.by_crate_path, Arc::from(crate_path), addr);
        }

        if let Some(normalized_name) = normalize_rust_crate_disambiguators(&entry.name) {
            Self::insert_name(
                &mut self.by_normalized_name,
                Arc::from(normalized_name.as_str()),
                addr,
            );
            if let Some(crate_path) = rust_symbol_crate_path_key(&normalized_name) {
                Self::insert_name(
                    &mut self.by_normalized_crate_path,
                    Arc::from(crate_path),
                    addr,
                );
            }
        }

        self.by_addr.insert(addr, entry);
    }

    fn insert_name(map: &mut BTreeMap<Arc<str>, usize>, name: Arc<str>, addr: usize) {
        if let Some(&existing_addr) = map.get(&name) {
            if addr < existing_addr {
                map.insert(name, addr);
            }
            return;
        }

        map.insert(name, addr);
    }

    fn clear(&mut self) {
        self.by_addr.clear();
        self.by_raw_name.clear();
        self.by_normalized_raw_name.clear();
        self.by_name.clear();
        self.by_normalized_name.clear();
        self.by_crate_path.clear();
        self.by_normalized_crate_path.clear();
    }

    fn len(&self) -> usize {
        self.by_addr.len()
    }
}

type SymbolTable = SpinLock<SymbolTableInner>;
type CrateAliases = SpinLock<BTreeMap<Arc<str>, Vec<Arc<str>>>>;

static SYMBOLS_TABLE: Once<SymbolTable> = Once::new();
static CRATE_ALIASES: Once<CrateAliases> = Once::new();

fn symbol_table() -> &'static SymbolTable {
    SYMBOLS_TABLE.call_once(|| SpinLock::new(SymbolTableInner::new()))
}

fn crate_aliases() -> &'static CrateAliases {
    CRATE_ALIASES.call_once(|| SpinLock::new(BTreeMap::new()))
}

/// Registers a crate-name alias for resolving dynamically loaded Rust modules.
pub fn add_crate_alias(import_crate: &'static str, target_crate: &'static str) {
    let mut aliases = crate_aliases().lock();
    let targets = aliases.entry(Arc::from(import_crate)).or_default();
    if targets.iter().any(|target| target.as_ref() == target_crate) {
        return;
    }

    targets.push(Arc::from(target_crate));
}

fn crate_alias_snapshot() -> Vec<(Arc<str>, Vec<Arc<str>>)> {
    crate_aliases()
        .lock()
        .iter()
        .map(|(import_crate, target_crates)| (Arc::clone(import_crate), target_crates.clone()))
        .collect()
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
                    let raw_name: Arc<str> = name.into();
                    let demangled_arc: Arc<str> = demangled.into();

                    table.insert(
                        raw_name,
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
    let raw_name = entry.name.clone();
    symbol_table().lock().insert(raw_name, addr, entry);
}

/// Retrieves the symbol information for a specific address, if present.
pub fn symbol_by_addr(addr: usize) -> Option<SymbolEntry> {
    symbol_table().lock().by_addr.get(&addr).cloned()
}

/// Retrieves the symbol address by name.
pub fn symbol_addr_by_name(name: &str) -> Option<usize> {
    let search_key = demangle(name).to_string();
    let crate_aliases = crate_alias_snapshot();
    let table = symbol_table().lock();
    if let Some(addr) = table.by_raw_name.get(name).copied() {
        return Some(addr);
    }

    for (import_crate, target_crates) in crate_aliases {
        for target_crate in target_crates {
            if let Some(addr) = lookup_symbol_by_crate_alias_path(
                &table,
                &search_key,
                import_crate.as_ref(),
                target_crate.as_ref(),
            ) {
                return Some(addr);
            }
        }
    }

    if let Some(addr) = table.by_name.get(search_key.as_str()).copied() {
        return Some(addr);
    }

    if let Some(normalized_raw_name) = normalize_rust_v0_mangled_crate_disambiguators(name)
        && let Some(addr) = table
            .by_normalized_raw_name
            .get(normalized_raw_name.as_str())
            .copied()
    {
        return Some(addr);
    }

    let normalized_name = normalize_rust_crate_disambiguators(&search_key);
    if let Some(normalized_name) = &normalized_name {
        if let Some(addr) = table.by_name.get(normalized_name.as_str()).copied() {
            return Some(addr);
        }

        if let Some(addr) = table
            .by_normalized_name
            .get(normalized_name.as_str())
            .copied()
        {
            return Some(addr);
        }
    }

    let lookup_name = normalized_name.as_deref().unwrap_or(search_key.as_str());
    lookup_symbol_by_crate_and_path(&table, lookup_name)
}

fn lookup_symbol_by_crate_alias_path(
    table: &SymbolTableInner,
    requested_name: &str,
    alias_crate: &str,
    target_crate: &str,
) -> Option<usize> {
    let mut search_start = 0;
    while let Some((instance_start, requested_crate_instance)) =
        find_rust_crate_instance(requested_name, alias_crate, search_start)
    {
        let target_name = rewrite_rust_crate_instance_path(
            requested_name,
            requested_crate_instance,
            target_crate,
        );
        if let Some(addr) = lookup_symbol_by_name_or_path(table, &target_name) {
            return Some(addr);
        }

        search_start = instance_start + requested_crate_instance.len();
    }

    None
}

fn lookup_symbol_by_name_or_path(table: &SymbolTableInner, requested_name: &str) -> Option<usize> {
    if let Some(addr) = table.by_name.get(requested_name).copied() {
        return Some(addr);
    }

    let normalized_name = normalize_rust_crate_disambiguators(requested_name);
    if let Some(normalized_name) = &normalized_name {
        if let Some(addr) = table.by_name.get(normalized_name.as_str()).copied() {
            return Some(addr);
        }

        if let Some(addr) = table
            .by_normalized_name
            .get(normalized_name.as_str())
            .copied()
        {
            return Some(addr);
        }
    }

    let lookup_name = normalized_name.as_deref().unwrap_or(requested_name);
    lookup_symbol_by_crate_and_path(table, lookup_name)
}

fn rewrite_rust_crate_instance_path(
    name: &str,
    alias_crate_instance: &str,
    target_crate: &str,
) -> String {
    let mut alias_path = String::with_capacity(alias_crate_instance.len() + 2);
    alias_path.push_str(alias_crate_instance);
    alias_path.push_str("::");

    let mut target_path = String::with_capacity(target_crate.len() + 2);
    target_path.push_str(target_crate);
    target_path.push_str("::");

    name.replace(alias_path.as_str(), target_path.as_str())
}

/// Returns the number of tracked symbols.
pub fn symbols_len() -> usize {
    symbol_table().lock().len()
}

fn lookup_symbol_by_crate_and_path(
    table: &SymbolTableInner,
    requested_name: &str,
) -> Option<usize> {
    let requested_key = rust_symbol_crate_path_key(requested_name)?;
    table
        .by_crate_path
        .get(requested_key.as_str())
        .copied()
        .or_else(|| {
            table
                .by_normalized_crate_path
                .get(requested_key.as_str())
                .copied()
        })
}

fn rust_symbol_crate_name(name: &str) -> Option<&str> {
    let bracket_index = name.find('[').unwrap_or(name.len());
    let path_index = name.find("::").unwrap_or(name.len());
    let end_index = bracket_index.min(path_index);
    (end_index != 0).then_some(&name[..end_index])
}

fn find_rust_crate_instance<'a>(
    name: &'a str,
    crate_name: &str,
    search_start: usize,
) -> Option<(usize, &'a str)> {
    let mut offset = search_start;
    while let Some(relative_start) = name[offset..].find(crate_name) {
        let start = offset + relative_start;
        let after_crate_name = start + crate_name.len();

        if !is_rust_path_boundary(name, start) {
            offset = after_crate_name;
            continue;
        }

        let after = &name[after_crate_name..];
        if after.starts_with("::") {
            return Some((start, &name[start..after_crate_name]));
        }

        if let Some(after_disambiguator) = after.strip_prefix('[')
            && let Some(end) = after_disambiguator.find(']')
        {
            let hash = &after_disambiguator[..end];
            let instance_end = after_crate_name + end + 2;
            if is_rust_crate_disambiguator(hash) && name[instance_end..].starts_with("::") {
                return Some((start, &name[start..instance_end]));
            }
        }

        offset = after_crate_name;
    }

    None
}

fn is_rust_path_boundary(name: &str, start: usize) -> bool {
    if start == 0 {
        return true;
    }

    let previous_byte = name.as_bytes()[start - 1];
    !previous_byte.is_ascii_alphanumeric() && previous_byte != b'_'
}

fn rust_symbol_path(name: &str) -> Option<&str> {
    name.find("::").map(|index| &name[index..])
}

fn rust_symbol_crate_path_key(name: &str) -> Option<String> {
    let crate_name = rust_symbol_crate_name(name)?;
    let path = rust_symbol_path(name)?;
    let mut key = String::with_capacity(crate_name.len() + path.len());
    key.push_str(crate_name);
    key.push_str(path);
    Some(key)
}

fn normalize_rust_v0_mangled_crate_disambiguators(name: &str) -> Option<String> {
    if !name.starts_with("_R") {
        return None;
    }

    let mut normalized_name = String::with_capacity(name.len());
    let mut remaining = name;
    let mut changed = false;

    while let Some(start) = remaining.find("Cs") {
        normalized_name.push_str(&remaining[..start]);
        let disambiguator = &remaining[start + 2..];

        let Some(end) = disambiguator.find('_') else {
            normalized_name.push_str(&remaining[start..]);
            return changed.then_some(normalized_name);
        };

        if end == 0 {
            normalized_name.push_str(&remaining[start..=start + 1]);
            remaining = &remaining[start + 2..];
            continue;
        }

        let after_disambiguator = &disambiguator[end + 1..];
        if !after_disambiguator
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_digit)
        {
            normalized_name.push_str(&remaining[..start + 2 + end + 1]);
            remaining = after_disambiguator;
            continue;
        }

        changed = true;
        normalized_name.push_str("C_");
        remaining = after_disambiguator;
    }

    normalized_name.push_str(remaining);
    changed.then_some(normalized_name)
}

fn normalize_rust_crate_disambiguators(name: &str) -> Option<String> {
    let mut normalized_name = String::with_capacity(name.len());
    let mut remaining = name;
    let mut changed = false;

    while let Some(start) = remaining.find('[') {
        normalized_name.push_str(&remaining[..start]);
        remaining = &remaining[start..];

        let Some(end) = remaining.find(']') else {
            normalized_name.push_str(remaining);
            return changed.then_some(normalized_name);
        };

        let hash = &remaining[1..end];
        let after_disambiguator = &remaining[end + 1..];
        if is_rust_crate_disambiguator(hash) && after_disambiguator.starts_with("::") {
            changed = true;
            remaining = after_disambiguator;
            continue;
        }

        normalized_name.push_str(&remaining[..=end]);
        remaining = after_disambiguator;
    }

    normalized_name.push_str(remaining);
    changed.then_some(normalized_name)
}

fn is_rust_crate_disambiguator(hash: &str) -> bool {
    (1..=16).contains(&hash.len()) && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}
