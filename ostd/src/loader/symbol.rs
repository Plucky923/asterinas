use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
};

use rustc_demangle::demangle;
use xmas_elf::{
    sections::{SHN_ABS, SHN_COMMON, SHN_LORESERVE, SHN_UNDEF},
    symbol_table::{Binding, Entry, Entry64, Type},
};

use super::{
    invalid_args,
    memory::{LoadedSection, SectionMemory, SectionMemoryType},
    service_object::ServiceObject,
};
use crate::{
    Result,
    loader::{DefinedSymbol, DefinedSymbolObserver},
};

/// Reports symbols whose values point into mapped service sections.
pub(super) fn observe_defined_symbols(
    service_object: &ServiceObject,
    loaded_sections: &[Option<LoadedSection>],
    section_memory: &Arc<SectionMemory>,
    observe_symbol_fn: &DefinedSymbolObserver<'_>,
) -> Result<()> {
    let symbol_table = service_object.symbol_table()?;
    for symbol in symbol_table {
        let name = service_object.symbol_name(symbol.name())?;
        let is_provider_symbol =
            name == b"__GLOBAL_FRAME_ALLOCATOR_REF" || name == b"__GLOBAL_HEAP_ALLOCATOR_REF";
        let section_index = symbol.shndx();
        if matches!(section_index, SHN_UNDEF | SHN_ABS | SHN_COMMON)
            || section_index >= SHN_LORESERVE
        {
            if is_provider_symbol {
                return Err(invalid_args(format!(
                    "provider symbol `{}` has an unsupported section class 0x{:x}",
                    String::from_utf8_lossy(name),
                    section_index
                )));
            }
            continue;
        }
        let section = match loaded_sections.get(usize::from(section_index)) {
            Some(Some(section)) => *section,
            Some(None) => {
                if name == b"__GLOBAL_FRAME_ALLOCATOR_REF" || name == b"__GLOBAL_HEAP_ALLOCATOR_REF"
                {
                    return Err(invalid_args(format!(
                        "provider symbol `{}` is not in a loaded section",
                        String::from_utf8_lossy(name)
                    )));
                }
                continue;
            }
            None => {
                return Err(invalid_args(format!(
                    "defined symbol references invalid section {}",
                    section_index
                )));
            }
        };
        if is_provider_symbol {
            let binding = symbol
                .get_binding()
                .map_err(|_| invalid_args("provider symbol has an invalid binding"))?;
            let symbol_type = symbol
                .get_type()
                .map_err(|_| invalid_args("provider symbol has an invalid type"))?;
            if binding != Binding::Global
                || symbol_type != Type::Object
                || section.memory_type() == SectionMemoryType::Text
            {
                return Err(invalid_args(format!(
                    "provider symbol `{}` is not a global non-executable object",
                    String::from_utf8_lossy(name)
                )));
            }
        }
        let symbol_value = usize::try_from(symbol.value())
            .map_err(|_| invalid_args("defined service symbol value exceeds usize"))?;
        let size = usize::try_from(symbol.size())
            .map_err(|_| invalid_args("defined service symbol size overflows"))?;
        if !section.contains_range(symbol_value, size) {
            return Err(invalid_args(format!(
                "defined symbol `{}` exceeds section {}",
                String::from_utf8_lossy(name),
                section_index
            )));
        }
        let address = section
            .base()
            .checked_add(symbol_value)
            .ok_or_else(|| invalid_args("defined service symbol address overflows"))?;
        observe_symbol_fn(&DefinedSymbol {
            name,
            address,
            size,
            section_memory: Arc::clone(section_memory),
        })?;
    }
    Ok(())
}

const DYNAMIC_ENTRY_SYMBOL: &str = "__ostd_dynamic_main";
const ENTRY_SYMBOL: &str = "__ostd_main";

/// A service module entry point.
#[derive(Clone, Copy, Debug)]
pub(super) struct EntryPoint {
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
    pub(super) fn addr(self) -> usize {
        self.addr
    }

    /// Returns whether this entry point returns to the loader.
    pub(super) fn returns_to_loader(self) -> bool {
        self.kind == EntryPointKind::Dynamic
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryPointKind {
    Dynamic,
    OstdMain,
}

/// Finds the service module entry point.
pub(super) fn find_entry_point(
    service_object: &ServiceObject,
    loaded_sections: &[Option<LoadedSection>],
) -> Result<Option<EntryPoint>> {
    let symbol_table = service_object.symbol_table()?;

    if let Some(entry) = find_entry_symbol(
        service_object,
        loaded_sections,
        symbol_table,
        DYNAMIC_ENTRY_SYMBOL,
    )? {
        return Ok(Some(EntryPoint::dynamic(entry)));
    }

    Ok(
        find_entry_symbol(service_object, loaded_sections, symbol_table, ENTRY_SYMBOL)?
            .map(EntryPoint::ostd_main),
    )
}

fn find_entry_symbol(
    service_object: &ServiceObject,
    loaded_sections: &[Option<LoadedSection>],
    symbol_table: &[Entry64],
    entry_symbol: &str,
) -> Result<Option<usize>> {
    let entry_symbol_path_suffix = format!("::{entry_symbol}");
    for symbol in symbol_table.iter() {
        let name = match core::str::from_utf8(service_object.symbol_name(symbol.name())?) {
            Ok(name) => name,
            Err(_) => continue,
        };
        if !is_entry_symbol(name, entry_symbol, &entry_symbol_path_suffix) {
            continue;
        }

        let section_index = symbol.shndx();
        if section_index == SHN_UNDEF {
            continue;
        }

        let Some(section) = loaded_sections
            .get(usize::from(section_index))
            .copied()
            .flatten()
        else {
            continue;
        };
        if symbol
            .get_type()
            .map_err(|_| invalid_args(format!("entry symbol `{name}` has an invalid type")))?
            != Type::Func
        {
            return Err(invalid_args(format!(
                "entry symbol `{name}` is not a function"
            )));
        }
        if section.memory_type() != SectionMemoryType::Text {
            return Err(invalid_args(format!(
                "entry symbol `{name}` is not in an executable section"
            )));
        }
        let symbol_value = usize::try_from(symbol.value())
            .map_err(|_| invalid_args("service entry-point value exceeds usize"))?;
        let symbol_size = usize::try_from(symbol.size())
            .map_err(|_| invalid_args("service entry-point size exceeds usize"))?;
        if !section.contains_range(symbol_value, symbol_size)
            || !section.contains_address(symbol_value)
        {
            return Err(invalid_args(format!(
                "entry symbol `{name}` exceeds its executable section"
            )));
        }
        let entry_addr = section
            .base()
            .checked_add(symbol_value)
            .ok_or_else(|| invalid_args("service entry-point address overflows"))?;
        return Ok(Some(entry_addr));
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
