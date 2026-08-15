use alloc::{format, vec::Vec};

use xmas_elf::{
    ElfFile,
    header::{Class, Data, Machine, Type as ElfType, Version},
    sections::{Rel, Rela, SHF_ALLOC, SectionData, SectionHeader, ShType},
    symbol_table::{Entry, Entry64, Type as SymbolType},
};

use super::invalid_args;
use crate::Result;

pub(super) struct ServiceObject<'a> {
    elf_file: ElfFile<'a>,
    relocation_sections: Vec<ServiceRelocationSection>,
    symbol_table_index: u16,
    string_table_index: u16,
}

impl<'a> ServiceObject<'a> {
    pub(super) fn parse(elf_data: &'a [u8]) -> Result<Self> {
        if !(elf_data.as_ptr() as usize).is_multiple_of(align_of::<u64>()) {
            return Err(invalid_args("service module ELF payload is not aligned"));
        }
        let elf_file = ElfFile::new(elf_data)
            .map_err(|_| invalid_args("failed to parse service module object as ELF"))?;
        validate_elf_structure(&elf_file)?;

        let typ = elf_file.header.pt2.type_().as_type();
        if typ != ElfType::Relocatable {
            return Err(invalid_args(format!(
                "service module object is not relocatable: {:?}",
                typ
            )));
        }

        let symbol_table_index = find_symbol_table_index(&elf_file)?;
        let string_table_index = find_string_table_index(&elf_file)?;
        let symbol_table = elf_file
            .section_header(symbol_table_index)
            .map_err(|_| invalid_args("service module `.symtab` section is unavailable"))?;
        if symbol_table.link() != u32::from(string_table_index) {
            return Err(invalid_args(
                "service module `.symtab` does not link to `.strtab`",
            ));
        }
        let relocation_sections = collect_relocation_sections(&elf_file, symbol_table_index)?;
        let service_object = Self {
            elf_file,
            relocation_sections,
            symbol_table_index,
            string_table_index,
        };
        let _ = service_object.symbol_table()?;
        let _ = service_object.string_table()?;
        service_object.validate_symbol_names()?;
        Ok(service_object)
    }

    pub(super) fn elf_file(&self) -> &ElfFile<'a> {
        &self.elf_file
    }

    pub(super) fn relocation_sections(&self) -> &[ServiceRelocationSection] {
        &self.relocation_sections
    }

    pub(super) fn symbol_table(&self) -> Result<&[Entry64]> {
        let section = self
            .elf_file
            .section_header(self.symbol_table_index)
            .map_err(|_| invalid_args("service module `.symtab` section is unavailable"))?;

        match section.get_data(&self.elf_file) {
            Ok(SectionData::SymbolTable64(symbol_table)) => {
                let first_global = usize::try_from(section.info())
                    .map_err(|_| invalid_args("service module `.symtab` info exceeds usize"))?;
                if first_global > symbol_table.len() {
                    return Err(invalid_args(
                        "service module `.symtab` info exceeds symbol count",
                    ));
                }
                Ok(symbol_table)
            }
            Ok(_) => Err(invalid_args(
                "unsupported symbol table format in service module object",
            )),
            Err(_) => Err(invalid_args(
                "failed to read `.symtab` from service module object",
            )),
        }
    }

    pub(super) fn symbol_name(&self, offset: u32) -> Result<&[u8]> {
        let string_table = self.string_table()?;
        let string_table = string_table.raw_data(&self.elf_file);
        let start = usize::try_from(offset)
            .map_err(|_| invalid_args("service symbol-name offset exceeds usize"))?;
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
            .and_then(|position| start.checked_add(position))
            .ok_or_else(|| {
                invalid_args(format!(
                    "symbol-name offset {} is not nul-terminated in service string table",
                    start
                ))
            })?;
        Ok(&string_table[start..end])
    }

    fn validate_symbol_names(&self) -> Result<()> {
        for (symbol_index, symbol) in self.symbol_table()?.iter().enumerate() {
            if symbol_index == 0 && symbol.name() != 0 {
                return Err(invalid_args(
                    "service module `.symtab` null symbol has a nonzero name offset",
                ));
            }
            let symbol_type = symbol
                .get_type()
                .map_err(|_| invalid_args("service symbol has an invalid type"))?;
            if matches!(symbol_type, SymbolType::Tls | SymbolType::Common) {
                return Err(invalid_args(
                    "service module contains an unsupported TLS or common symbol",
                ));
            }
            self.symbol_name(symbol.name())?;
        }
        Ok(())
    }

    fn string_table(&self) -> Result<SectionHeader<'a>> {
        let string_table = self
            .elf_file
            .section_header(self.string_table_index)
            .map_err(|_| invalid_args("service module `.strtab` section is unavailable"))?;
        if string_table.get_type() != Ok(ShType::StrTab) {
            return Err(invalid_args(
                "service module `.strtab` section has an unexpected type",
            ));
        }
        let bytes = string_table.raw_data(&self.elf_file);
        if bytes.first() != Some(&0) || bytes.last() != Some(&0) {
            return Err(invalid_args(
                "service module `.strtab` must start and end with NUL",
            ));
        }
        Ok(string_table)
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ServiceRelocationSection {
    pub(super) section_index: u16,
    pub(super) target_section_index: u16,
}

fn collect_relocation_sections(
    elf_file: &ElfFile,
    symbol_table_index: u16,
) -> Result<Vec<ServiceRelocationSection>> {
    let mut relocation_sections = Vec::new();
    for (section_index, section) in elf_file.section_iter().enumerate() {
        let Ok(section_type) = section.get_type() else {
            continue;
        };
        if !matches!(section_type, ShType::Rela | ShType::Rel) {
            continue;
        }
        if section.link() != u32::from(symbol_table_index) {
            return Err(invalid_args(format!(
                "relocation section {} does not link to `.symtab`",
                section_index
            )));
        }

        let target_section_index = usize::try_from(section.info()).map_err(|_| {
            invalid_args(format!(
                "relocation section {} has an invalid target section index",
                section_index
            ))
        })?;
        if target_section_index == 0 {
            continue;
        }
        if target_section_index >= usize::from(0xff00_u16) {
            return Err(invalid_args(format!(
                "relocation section {} references reserved target section {}",
                section_index, target_section_index
            )));
        }
        let section_index = u16::try_from(section_index).map_err(|_| {
            invalid_args(format!(
                "relocation section index {} exceeds ELF section-index range",
                section_index
            ))
        })?;
        let target_section_index = u16::try_from(target_section_index).map_err(|_| {
            invalid_args(format!(
                "relocation section {} references target section {} outside ELF section-index range",
                section_index, target_section_index
            ))
        })?;
        let target_section = elf_file.section_header(target_section_index).map_err(|_| {
            invalid_args(format!(
                "relocation section {} references invalid target section {}",
                section_index, target_section_index
            ))
        })?;
        if (target_section.flags() & SHF_ALLOC) == 0 {
            continue;
        }

        relocation_sections.push(ServiceRelocationSection {
            section_index,
            target_section_index,
        });
    }
    Ok(relocation_sections)
}

fn find_symbol_table_index(elf_file: &ElfFile) -> Result<u16> {
    let mut symbol_table_index = None;
    for (section_index, section) in elf_file.section_iter().enumerate() {
        if section.get_type() != Ok(ShType::SymTab) {
            continue;
        }
        let section_index = u16::try_from(section_index).map_err(|_| {
            invalid_args("service module `.symtab` section index exceeds ELF range")
        })?;
        if symbol_table_index.replace(section_index).is_some() {
            return Err(invalid_args(
                "service module contains multiple `.symtab` sections",
            ));
        }
    }
    symbol_table_index.ok_or_else(|| invalid_args("missing `.symtab` in service module object"))
}

fn find_string_table_index(elf_file: &ElfFile) -> Result<u16> {
    let mut string_table_index = None;
    for (section_index, section) in elf_file.section_iter().enumerate() {
        if section.get_name(elf_file).ok() != Some(".strtab") {
            continue;
        }
        let section_index = u16::try_from(section_index).map_err(|_| {
            invalid_args("service module `.strtab` section index exceeds ELF range")
        })?;
        if string_table_index.replace(section_index).is_some() {
            return Err(invalid_args(
                "service module contains multiple `.strtab` sections",
            ));
        }
    }
    string_table_index.ok_or_else(|| invalid_args("missing `.strtab` in service module object"))
}

fn validate_elf_structure(elf_file: &ElfFile) -> Result<()> {
    let header = &elf_file.header;
    if header.pt1.class() != Class::SixtyFour {
        return Err(invalid_args("service module ELF is not 64-bit"));
    }
    if header.pt1.data() != Data::LittleEndian {
        return Err(invalid_args("service module ELF is not little-endian"));
    }
    if header.pt1.version() != Version::Current || header.pt2.version() != 1 {
        return Err(invalid_args("service module ELF has an invalid version"));
    }
    if header.pt2.machine().as_machine() != Machine::X86_64 {
        return Err(invalid_args("service module ELF is not x86-64"));
    }
    if header.pt2.header_size() != 64 {
        return Err(invalid_args(
            "service module ELF header has an invalid size",
        ));
    }

    let section_count = header.pt2.sh_count();
    if section_count == 0 || section_count > 0xff00 {
        return Err(invalid_args(
            "service module ELF has an invalid section count",
        ));
    }
    if header.pt2.sh_entry_size() != 64 {
        return Err(invalid_args(
            "service module ELF section-header size is unsupported",
        ));
    }
    if header.pt2.sh_str_index() >= section_count {
        return Err(invalid_args(
            "service module ELF section-name table index is out of range",
        ));
    }
    if header.pt2.ph_count() != 0 {
        return Err(invalid_args(
            "service module ELF must not contain program headers",
        ));
    }
    if header.pt2.sh_offset() < u64::from(header.pt2.header_size()) {
        return Err(invalid_args(
            "service module ELF section-header table overlaps the ELF header",
        ));
    }
    validate_section_header_table_alignment(header.pt2.sh_offset())?;
    validate_table_range(
        header.pt2.ph_offset(),
        header.pt2.ph_entry_size(),
        header.pt2.ph_count(),
        elf_file.input.len(),
        "program-header table",
    )?;
    validate_table_range(
        header.pt2.sh_offset(),
        header.pt2.sh_entry_size(),
        section_count,
        elf_file.input.len(),
        "section-header table",
    )?;

    let sections = (0..section_count)
        .map(|index| {
            elf_file.section_header(index).map_err(|_| {
                invalid_args(format!(
                    "service module section header {} is invalid",
                    index
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let null_section = sections[0];
    if null_section.get_type() != Ok(ShType::Null)
        || null_section.name() != 0
        || null_section.flags() != 0
        || null_section.address() != 0
        || null_section.offset() != 0
        || null_section.size() != 0
        || null_section.link() != 0
        || null_section.info() != 0
        || null_section.align() != 0
        || null_section.entry_size() != 0
    {
        return Err(invalid_args(
            "service module ELF null section header is malformed",
        ));
    }
    let string_table_section = sections[usize::from(header.pt2.sh_str_index())];
    if string_table_section.get_type() != Ok(ShType::StrTab) {
        return Err(invalid_args(
            "service module ELF section-name table is not a string table",
        ));
    }
    let section_names = section_bytes(
        elf_file,
        &string_table_section,
        usize::from(header.pt2.sh_str_index()),
    )?;
    if section_names.first() != Some(&0) || section_names.last() != Some(&0) {
        return Err(invalid_args(
            "service module ELF section-name table must start and end with NUL",
        ));
    }

    for (index, section) in sections.iter().enumerate() {
        validate_section_name(section_names, section, index)?;
        let section_type = section.get_type().map_err(|_| {
            invalid_args(format!(
                "service module section {} has an invalid type",
                index
            ))
        })?;
        if section_type == ShType::NoBits {
            let offset = usize::try_from(section.offset())
                .map_err(|_| invalid_args(format!("section {} offset exceeds usize", index)))?;
            if offset > elf_file.input.len() {
                return Err(invalid_args(format!(
                    "section {} offset exceeds ELF payload",
                    index
                )));
            }
            continue;
        }

        let data = section_bytes(elf_file, section, index)?;
        match section_type {
            ShType::SymTab => validate_array_section::<Entry64>(section, data, index, ".symtab")?,
            ShType::Rela => validate_array_section::<Rela<u64>>(section, data, index, "RELA")?,
            ShType::Rel => validate_array_section::<Rel<u64>>(section, data, index, "REL")?,
            _ => {}
        }
    }
    Ok(())
}

fn validate_section_header_table_alignment(offset: u64) -> Result<()> {
    let required_alignment = u64::try_from(align_of::<u64>())
        .map_err(|_| invalid_args("section-header alignment exceeds u64"))?;
    if !offset.is_multiple_of(required_alignment) {
        return Err(invalid_args(
            "service module ELF section-header table is not aligned",
        ));
    }
    Ok(())
}

fn validate_table_range(
    offset: u64,
    entry_size: u16,
    count: u16,
    payload_size: usize,
    table_name: &str,
) -> Result<()> {
    let table_size = u64::from(entry_size)
        .checked_mul(u64::from(count))
        .ok_or_else(|| invalid_args(format!("{table_name} size overflows")))?;
    let end = offset
        .checked_add(table_size)
        .ok_or_else(|| invalid_args(format!("{table_name} range overflows")))?;
    let payload_size =
        u64::try_from(payload_size).map_err(|_| invalid_args("ELF payload size exceeds u64"))?;
    if end > payload_size {
        return Err(invalid_args(format!("{table_name} exceeds ELF payload")));
    }
    if count != 0 && entry_size == 0 {
        return Err(invalid_args(format!("{table_name} has zero-sized entries")));
    }
    Ok(())
}

fn section_bytes<'a>(
    elf_file: &'a ElfFile<'a>,
    section: &SectionHeader<'a>,
    section_index: usize,
) -> Result<&'a [u8]> {
    let offset = usize::try_from(section.offset())
        .map_err(|_| invalid_args(format!("section {section_index} offset exceeds usize")))?;
    let size = usize::try_from(section.size())
        .map_err(|_| invalid_args(format!("section {section_index} size exceeds usize")))?;
    let end = offset
        .checked_add(size)
        .ok_or_else(|| invalid_args(format!("section {section_index} range overflows")))?;
    elf_file
        .input
        .get(offset..end)
        .ok_or_else(|| invalid_args(format!("section {section_index} exceeds ELF payload")))
}

fn validate_section_name(
    section_names: &[u8],
    section: &SectionHeader<'_>,
    section_index: usize,
) -> Result<()> {
    let name_offset = usize::try_from(section.name())
        .map_err(|_| invalid_args(format!("section {section_index} name exceeds usize")))?;
    let name_bytes = section_names
        .get(name_offset..)
        .ok_or_else(|| invalid_args(format!("section {section_index} name is out of range")))?;
    let name_end = name_bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| invalid_args(format!("section {section_index} name is not terminated")))?;
    let name = &name_bytes[..name_end];
    core::str::from_utf8(name)
        .map_err(|_| invalid_args(format!("section {section_index} name is not UTF-8")))?;
    Ok(())
}

fn validate_array_section<T>(
    section: &SectionHeader<'_>,
    data: &[u8],
    section_index: usize,
    section_kind: &str,
) -> Result<()> {
    let element_size = size_of::<T>();
    if element_size == 0 || !data.len().is_multiple_of(element_size) {
        return Err(invalid_args(format!(
            "{section_kind} section {section_index} has a partial entry"
        )));
    }
    if usize::try_from(section.entry_size()).ok() != Some(element_size) {
        return Err(invalid_args(format!(
            "{section_kind} section {section_index} has an invalid entry size"
        )));
    }
    if !(data.as_ptr() as usize).is_multiple_of(align_of::<T>()) {
        return Err(invalid_args(format!(
            "{section_kind} section {section_index} is not aligned"
        )));
    }
    Ok(())
}

#[cfg(ktest)]
mod tests {
    use ostd_macros::ktest;

    use super::validate_section_header_table_alignment;

    #[ktest]
    fn rejects_unaligned_section_header_tables() {
        assert!(validate_section_header_table_alignment(1).is_err());
        assert!(validate_section_header_table_alignment(8).is_ok());
    }
}
