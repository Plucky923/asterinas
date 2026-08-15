use alloc::{
    collections::btree_set::BTreeSet,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use rustc_demangle::demangle;
use xmas_elf::{
    sections::{Rela, SHN_UNDEF, SectionData, ShType},
    symbol_table::{Entry, Entry64, Type as SymbolType},
};

use super::{
    invalid_args,
    memory::LoadedSection,
    service_object::{ServiceObject, ServiceRelocationSection},
};
use crate::{Result, mm::io::VmWriter};

const SHN_ABS: u16 = 0xfff1;
const SHN_COMMON: u16 = 0xfff2;
const SHN_LORESERVE: u16 = 0xff00;

struct RelocationPlan {
    work_items: Vec<RelocationWorkItem>,
    deferred_work_items: Vec<DeferredRelocation>,
    total_relocations: usize,
}

struct RelocationWorkItem {
    loc: usize,
    reloc_type: u32,
    addend: i64,
    symbol_addr: u64,
}

struct DeferredRelocation {
    loc: usize,
    reloc_type: u32,
    addend: i64,
    symbol_name: Vec<u8>,
}

enum PlannedSymbolAddress {
    Resolved(u64),
    Deferred,
}

struct MissingImport {
    raw_symbol: String,
    demangled_symbol: String,
    relocation_type: u32,
}

/// Relocates a service module with an explicit undefined-symbol resolver.
pub(super) fn relocate_sections_with(
    service_object: &ServiceObject,
    loaded_sections: &[Option<LoadedSection>],
    resolve_symbol_fn: &dyn Fn(&[u8]) -> Option<u64>,
    defer_symbol_fn: &dyn Fn(&[u8]) -> bool,
) -> Result<DeferredRelocations> {
    let symbol_table = service_object.symbol_table()?;
    log::info!("[Loader] Starting relocation...");

    let relocation_plan = build_relocation_plan(
        service_object,
        loaded_sections,
        symbol_table,
        resolve_symbol_fn,
        defer_symbol_fn,
    )?;
    apply_relocation_plan(&relocation_plan)?;

    log::info!(
        "[Loader] Relocation completed. Total applied: {}",
        relocation_plan.total_relocations
    );
    Ok(DeferredRelocations {
        work_items: relocation_plan.deferred_work_items,
    })
}

pub(super) struct DeferredRelocations {
    work_items: Vec<DeferredRelocation>,
}

impl DeferredRelocations {
    pub(super) fn resolve_and_apply(
        self,
        resolve_symbol_fn: &dyn Fn(&[u8]) -> Option<u64>,
    ) -> Result<()> {
        if self.work_items.is_empty() {
            return Ok(());
        }

        let mut work_items = Vec::with_capacity(self.work_items.len());
        let mut missing_imports = Vec::new();
        let mut missing_import_keys = BTreeSet::new();

        for deferred in self.work_items {
            let Some(symbol_addr) = resolve_symbol_fn(&deferred.symbol_name) else {
                if missing_import_keys.insert(deferred.symbol_name.clone()) {
                    missing_imports.push(MissingImport {
                        raw_symbol: raw_symbol_display(&deferred.symbol_name),
                        demangled_symbol: demangled_symbol_display(&deferred.symbol_name),
                        relocation_type: deferred.reloc_type,
                    });
                }
                continue;
            };

            let work_item = RelocationWorkItem {
                loc: deferred.loc,
                reloc_type: deferred.reloc_type,
                addend: deferred.addend,
                symbol_addr,
            };
            validate_relocation_value(&work_item)?;
            work_items.push(work_item);
        }

        if !missing_imports.is_empty() {
            return Err(invalid_args(missing_imports_error(&missing_imports)));
        }

        apply_relocation_plan(&RelocationPlan {
            work_items,
            deferred_work_items: Vec::new(),
            total_relocations: 0,
        })
    }
}

fn build_relocation_plan(
    service_object: &ServiceObject,
    loaded_sections: &[Option<LoadedSection>],
    symbol_table: &[Entry64],
    resolve_symbol_fn: &dyn Fn(&[u8]) -> Option<u64>,
    defer_symbol_fn: &dyn Fn(&[u8]) -> bool,
) -> Result<RelocationPlan> {
    let elf_file = service_object.elf_file();
    let mut resolved_symbols = vec![None; symbol_table.len()];
    let mut missing_imports = Vec::new();
    let mut missing_import_keys = BTreeSet::new();
    let mut work_items = Vec::new();
    let mut deferred_work_items = Vec::new();
    let mut total_relocations = 0usize;

    for relocation_info in service_object.relocation_sections() {
        let reloc_section = elf_file
            .section_header(relocation_info.section_index)
            .map_err(|_| {
                invalid_args(format!(
                    "relocation section {} is no longer available in service object",
                    relocation_info.section_index
                ))
            })?;

        let relocation_type = reloc_section
            .get_type()
            .map_err(|_| invalid_args("relocation section has an invalid type"))?;
        match (relocation_type, reloc_section.get_data(elf_file)) {
            (ShType::Rela, Ok(SectionData::Rela64(rela))) => {
                total_relocations = total_relocations
                    .checked_add(rela.len())
                    .ok_or_else(|| invalid_args("relocation count overflows usize"))?;
                plan_relocate_add(
                    rela,
                    *relocation_info,
                    service_object,
                    loaded_sections,
                    symbol_table,
                    &mut resolved_symbols,
                    &mut missing_imports,
                    &mut missing_import_keys,
                    &mut work_items,
                    &mut deferred_work_items,
                    resolve_symbol_fn,
                    defer_symbol_fn,
                )?;
            }
            (ShType::Rel, Ok(SectionData::Rel64(_))) => {
                return Err(invalid_args(format!(
                    "REL relocation section for target section {} is unsupported",
                    relocation_info.target_section_index
                )));
            }
            (_, Err(_)) => {
                return Err(invalid_args(format!(
                    "failed to read relocation section for target section {}",
                    relocation_info.target_section_index
                )));
            }
            (ShType::Rela, Ok(_)) => {
                return Err(invalid_args(format!(
                    "RELA relocation section for target section {} has an unsupported layout",
                    relocation_info.target_section_index
                )));
            }
            (ShType::Rel, Ok(_)) => {
                return Err(invalid_args(format!(
                    "REL relocation section for target section {} has an unsupported layout",
                    relocation_info.target_section_index
                )));
            }
            (_, Ok(_)) => {
                return Err(invalid_args(
                    "service relocation section has an unsupported type",
                ));
            }
        }
    }

    if !missing_imports.is_empty() {
        return Err(invalid_args(missing_imports_error(&missing_imports)));
    }

    Ok(RelocationPlan {
        work_items,
        deferred_work_items,
        total_relocations,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "relocation planning keeps independent validation state explicit"
)]
fn plan_relocate_add(
    rel: &[Rela<u64>],
    relocation_info: ServiceRelocationSection,
    service_object: &ServiceObject,
    loaded_sections: &[Option<LoadedSection>],
    symbol_table: &[Entry64],
    resolved_symbols: &mut [Option<u64>],
    missing_imports: &mut Vec<MissingImport>,
    missing_import_keys: &mut BTreeSet<Vec<u8>>,
    work_items: &mut Vec<RelocationWorkItem>,
    deferred_work_items: &mut Vec<DeferredRelocation>,
    resolve_symbol_fn: &dyn Fn(&[u8]) -> Option<u64>,
    defer_symbol_fn: &dyn Fn(&[u8]) -> bool,
) -> Result<()> {
    let target_section = get_target_section(relocation_info.target_section_index, loaded_sections)?;

    for reloc in rel {
        plan_relocation_entry(
            reloc,
            target_section,
            service_object,
            loaded_sections,
            symbol_table,
            resolved_symbols,
            missing_imports,
            missing_import_keys,
            work_items,
            deferred_work_items,
            resolve_symbol_fn,
            defer_symbol_fn,
        )?;
    }

    Ok(())
}

fn get_target_section(
    target_section_index: u16,
    loaded_sections: &[Option<LoadedSection>],
) -> Result<LoadedSection> {
    loaded_sections
        .get(usize::from(target_section_index))
        .and_then(|base| *base)
        .ok_or_else(|| {
            invalid_args(format!(
                "target section index {} not found in loaded section map",
                target_section_index
            ))
        })
}

#[expect(
    clippy::too_many_arguments,
    reason = "relocation validation inputs remain explicit"
)]
fn plan_relocation_entry(
    reloc: &Rela<u64>,
    target_section: LoadedSection,
    service_object: &ServiceObject,
    loaded_sections: &[Option<LoadedSection>],
    symbol_table: &[Entry64],
    resolved_symbols: &mut [Option<u64>],
    missing_imports: &mut Vec<MissingImport>,
    missing_import_keys: &mut BTreeSet<Vec<u8>>,
    work_items: &mut Vec<RelocationWorkItem>,
    deferred_work_items: &mut Vec<DeferredRelocation>,
    resolve_symbol_fn: &dyn Fn(&[u8]) -> Option<u64>,
    defer_symbol_fn: &dyn Fn(&[u8]) -> bool,
) -> Result<()> {
    let symbol_idx = usize::try_from(reloc.get_symbol_table_index())
        .map_err(|_| invalid_args("relocation symbol index exceeds usize"))?;
    let offset = reloc.get_offset();
    let reloc_type = reloc.get_type();
    // `Rela<u64>` exposes the ELF addend bits as `u64`; preserve their signed
    // two's-complement interpretation for the x86-64 relocation formulas.
    let addend = i64::from_ne_bytes(reloc.get_addend().to_ne_bytes());

    if reloc_type == 0 {
        return Ok(());
    }

    let write_size = relocation_write_size(reloc_type, symbol_idx, service_object, symbol_table)?;
    let write_size_u64 =
        u64::try_from(write_size).map_err(|_| invalid_args("relocation write size exceeds u64"))?;
    let relocation_end = offset.checked_add(write_size_u64).ok_or_else(|| {
        invalid_args(format!(
            "relocation offset 0x{:x} overflows for write size {}",
            offset, write_size
        ))
    })?;
    let target_section_size = u64::try_from(target_section.size())
        .map_err(|_| invalid_args("target section size exceeds u64"))?;
    if relocation_end > target_section_size {
        return Err(invalid_args(format!(
            "relocation write exceeds target section: offset=0x{:x}, size={}, section_size=0x{:x}",
            offset, write_size, target_section_size
        )));
    }
    let offset =
        usize::try_from(offset).map_err(|_| invalid_args("relocation offset exceeds usize"))?;
    let loc = target_section
        .base()
        .checked_add(offset)
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
        service_object,
        loaded_sections,
        resolved_symbols,
        missing_imports,
        missing_import_keys,
        resolve_symbol_fn,
        defer_symbol_fn,
    )?
    else {
        return Ok(());
    };

    match symbol_addr {
        PlannedSymbolAddress::Resolved(symbol_addr) => {
            let work_item = RelocationWorkItem {
                loc,
                reloc_type,
                addend,
                symbol_addr,
            };
            validate_relocation_value(&work_item)?;
            work_items.push(work_item);
        }
        PlannedSymbolAddress::Deferred => {
            let symbol_name = service_object.symbol_name(symbol.name())?.to_vec();
            deferred_work_items.push(DeferredRelocation {
                loc,
                reloc_type,
                addend,
                symbol_name,
            });
        }
    }
    Ok(())
}

fn apply_relocation_plan(plan: &RelocationPlan) -> Result<()> {
    for work_item in &plan.work_items {
        apply_relocation_work_item(work_item)?;
    }
    Ok(())
}

fn apply_relocation_work_item(work_item: &RelocationWorkItem) -> Result<()> {
    let val = ((work_item.symbol_addr as i64).wrapping_add(work_item.addend)) as u64;

    match work_item.reloc_type {
        // R_X86_64_64
        1 => write_val(work_item.loc, val, 8),
        // R_X86_64_32
        10 => write_val(work_item.loc, val, 4),
        // R_X86_64_32S
        11 => write_val(work_item.loc, val, 4),
        // R_X86_64_PC32 (2) | R_X86_64_PLT32 (4)
        2 | 4 => write_val(work_item.loc, val.wrapping_sub(work_item.loc as u64), 4),
        // R_X86_64_PC64
        24 => write_val(work_item.loc, val.wrapping_sub(work_item.loc as u64), 8),
        _ => Err(invalid_args(format!(
            "unsupported relocation type {} reached relocation application",
            work_item.reloc_type
        ))),
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "symbol resolution tracks independent diagnostic collections"
)]
fn resolve_symbol_address_for_plan(
    symbol_idx: usize,
    symbol: &Entry64,
    reloc_type: u32,
    service_object: &ServiceObject,
    loaded_sections: &[Option<LoadedSection>],
    resolved_symbols: &mut [Option<u64>],
    missing_imports: &mut Vec<MissingImport>,
    missing_import_keys: &mut BTreeSet<Vec<u8>>,
    resolve_symbol_fn: &dyn Fn(&[u8]) -> Option<u64>,
    defer_symbol_fn: &dyn Fn(&[u8]) -> bool,
) -> Result<Option<PlannedSymbolAddress>> {
    if symbol_idx == 0 {
        return Ok(Some(PlannedSymbolAddress::Resolved(0)));
    }

    if let Some(addr) = resolved_symbols
        .get(symbol_idx)
        .copied()
        .ok_or_else(|| invalid_args("relocation symbol index is out of range"))?
    {
        return Ok(Some(PlannedSymbolAddress::Resolved(addr)));
    }

    let shndx = symbol.shndx();
    let resolved_addr = if shndx == SHN_UNDEF {
        let symbol_name = service_object.symbol_name(symbol.name())?;
        validate_provider_import(symbol_name, symbol, reloc_type)?;
        if defer_symbol_fn(symbol_name) {
            return Ok(Some(PlannedSymbolAddress::Deferred));
        }
        match resolve_symbol_fn(symbol_name) {
            Some(addr) => Ok(addr),
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
    } else if shndx == SHN_ABS {
        Ok(symbol.value())
    } else if shndx == SHN_COMMON || shndx >= SHN_LORESERVE {
        Err(invalid_args(format!(
            "unsupported relocation symbol section class 0x{:x} for `{}`",
            shndx,
            symbol_display(service_object, symbol)
        )))
    } else if let Some(Some(section)) = loaded_sections.get(usize::from(shndx)) {
        let symbol_value = usize::try_from(symbol.value())
            .map_err(|_| invalid_args("relocation symbol value exceeds usize"))?;
        let symbol_size = usize::try_from(symbol.size())
            .map_err(|_| invalid_args("relocation symbol size exceeds usize"))?;
        if !section.contains_range(symbol_value, symbol_size) {
            return Err(invalid_args(format!(
                "relocation symbol `{}` exceeds section {}",
                symbol_display(service_object, symbol),
                shndx
            )));
        }
        let addr = section
            .base()
            .checked_add(symbol_value)
            .ok_or_else(|| invalid_args("loaded service-section symbol address overflows"))?;
        Ok(u64::try_from(addr)
            .map_err(|_| invalid_args("loaded service-section symbol address exceeds u64"))?)
    } else {
        Err(invalid_args(format!(
            "relocation references unloaded service section {} for `{}`",
            shndx,
            symbol_display(service_object, symbol)
        )))
    }?;

    let resolved_symbol = resolved_symbols
        .get_mut(symbol_idx)
        .ok_or_else(|| invalid_args("relocation symbol index is out of range"))?;
    *resolved_symbol = Some(resolved_addr);
    Ok(Some(PlannedSymbolAddress::Resolved(resolved_addr)))
}

fn validate_provider_import(symbol_name: &[u8], symbol: &Entry64, reloc_type: u32) -> Result<()> {
    if !matches!(
        symbol_name,
        b"__GLOBAL_FRAME_ALLOCATOR_REF" | b"__GLOBAL_HEAP_ALLOCATOR_REF"
    ) {
        return Ok(());
    }

    let symbol_type = symbol
        .get_type()
        .map_err(|_| invalid_args("provider import has an invalid type"))?;
    if !matches!(symbol_type, SymbolType::NoType | SymbolType::Object)
        || !matches!(reloc_type, 1 | 24)
    {
        return Err(invalid_args(
            "provider import must be an object reference with a 64-bit relocation",
        ));
    }
    Ok(())
}

fn relocation_write_size(
    reloc_type: u32,
    symbol_idx: usize,
    service_object: &ServiceObject,
    symbol_table: &[Entry64],
) -> Result<usize> {
    match reloc_type {
        1 | 24 => Ok(8),
        2 | 4 | 10 | 11 => Ok(4),
        _ => {
            let symbol = symbol_table.get(symbol_idx);
            let symbol_name = symbol
                .map(|symbol| symbol_display(service_object, symbol))
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
        "cannot resolve {} undefined FrameVM import(s) during relocation",
        missing_imports.len()
    );
    for missing in missing_imports {
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

fn symbol_display(service_object: &ServiceObject, symbol: &Entry64) -> String {
    service_object
        .symbol_name(symbol.name())
        .map(raw_symbol_display)
        .unwrap_or_else(|_| "<invalid symbol name>".to_string())
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

fn validate_relocation_value(work_item: &RelocationWorkItem) -> Result<()> {
    let value = ((work_item.symbol_addr as i64).wrapping_add(work_item.addend)) as u64;
    match work_item.reloc_type {
        10 if value != u64::from(value as u32) => Err(invalid_args(format!(
            "32-bit unsigned relocation overflow for type {} with value 0x{:x}",
            work_item.reloc_type, value
        ))),
        11 if value as i64 != (value as i32) as i64 => Err(invalid_args(format!(
            "32-bit signed relocation overflow for type {} with value 0x{:x}",
            work_item.reloc_type, value
        ))),
        10 | 11 => Ok(()),
        2 | 4 => {
            let relative = value.wrapping_sub(work_item.loc as u64);
            if relative as i64 != (relative as i32) as i64 {
                return Err(invalid_args(format!(
                    "PC-relative relocation type {} out of range: rel=0x{:x}, loc=0x{:x}, symbol=0x{:x}",
                    work_item.reloc_type, relative, work_item.loc, work_item.symbol_addr
                )));
            }
            Ok(())
        }
        1 | 24 => Ok(()),
        _ => Err(invalid_args(format!(
            "unsupported relocation type {} reached relocation validation",
            work_item.reloc_type
        ))),
    }
}

fn write_val(loc: usize, val: u64, size: usize) -> Result<()> {
    // SAFETY: The relocation plan checked `loc + size` against the target
    // section, and all loaded sections remain writable until relocation ends.
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

#[cfg(ktest)]
mod tests {
    use ostd_macros::ktest;

    use super::*;

    #[ktest]
    fn validates_narrow_relocation_ranges_before_writes() {
        let unsigned = RelocationWorkItem {
            loc: 0x1000,
            reloc_type: 10,
            addend: 0,
            symbol_addr: 0x1_0000_0000,
        };
        assert!(validate_relocation_value(&unsigned).is_err());

        let signed = RelocationWorkItem {
            loc: 0x1000,
            reloc_type: 11,
            addend: 0,
            symbol_addr: 0x8000_0000,
        };
        assert!(validate_relocation_value(&signed).is_err());

        let pc_relative = RelocationWorkItem {
            loc: 0x1000,
            reloc_type: 2,
            addend: 0,
            symbol_addr: 0x1_0000_1000,
        };
        assert!(validate_relocation_value(&pc_relative).is_err());

        let valid = RelocationWorkItem {
            loc: 0x1000,
            reloc_type: 2,
            addend: 1,
            symbol_addr: 0x1000,
        };
        assert!(validate_relocation_value(&valid).is_ok());
    }
}
