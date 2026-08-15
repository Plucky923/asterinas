// SPDX-License-Identifier: MPL-2.0

//! Actual FrameVM host-import extraction from the final loadable service object.
//!
//! This module owns the OSDK-side ELF relocation scan. It intentionally exposes
//! only a sorted raw-byte import set and bounded diagnostic evidence, leaving the
//! parser choice and relocation-section details private to OSDK.

use std::{
    collections::BTreeMap,
    fmt, fs,
    path::{Path, PathBuf},
};

use xmas_elf::{
    ElfFile,
    sections::{Rela, SHF_ALLOC, SHN_UNDEF, SectionData, ShType},
    symbol_table::{Entry, Entry64},
};

use super::types::FrameVmStageError;

const MAX_RELOCATION_LOCATIONS: usize = 16;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct RustCrateIdentity {
    crate_name: String,
    disambiguator: String,
}

impl RustCrateIdentity {
    fn new(crate_name: String, disambiguator: String) -> Self {
        Self {
            crate_name,
            disambiguator,
        }
    }

    pub(super) fn crate_name(&self) -> &str {
        &self.crate_name
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct RawSymbolName(Vec<u8>);

impl RawSymbolName {
    pub(super) fn new(bytes: &[u8]) -> Result<Self, FrameVmStageError> {
        if bytes.is_empty() {
            return Err(FrameVmStageError::ImportValidation(
                "relocation references an empty undefined symbol name".to_string(),
            ));
        }
        Ok(Self(bytes.to_vec()))
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(super) fn display_lossy(&self) -> String {
        String::from_utf8_lossy(&self.0).into_owned()
    }

    pub(super) fn hex(&self) -> String {
        bytes_to_hex(&self.0)
    }
}

impl fmt::Display for RawSymbolName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.display_lossy())
    }
}

#[derive(Clone, Debug)]
pub(super) struct ActualHostImports {
    object: PathBuf,
    imports: BTreeMap<RawSymbolName, ImportEvidence>,
}

impl ActualHostImports {
    fn new(object: PathBuf, imports: BTreeMap<RawSymbolName, ImportEvidence>) -> Self {
        Self { object, imports }
    }

    pub(super) fn object(&self) -> &Path {
        &self.object
    }

    pub(super) fn len(&self) -> usize {
        self.imports.len()
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (&RawSymbolName, &ImportEvidence)> {
        self.imports.iter()
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct ImportEvidence {
    relocation_count: usize,
    relocation_locations: Vec<RelocationLocation>,
}

impl ImportEvidence {
    fn record(&mut self, location: RelocationLocation) {
        self.relocation_count += 1;
        if self.relocation_locations.len() < MAX_RELOCATION_LOCATIONS {
            self.relocation_locations.push(location);
        }
    }

    pub(super) fn relocation_count(&self) -> usize {
        self.relocation_count
    }

    pub(super) fn relocation_locations(&self) -> &[RelocationLocation] {
        &self.relocation_locations
    }
}

#[derive(Clone, Debug)]
pub(super) struct RelocationLocation {
    relocation_section_index: usize,
    relocation_entry_index: usize,
    target_section_index: usize,
    target_offset: u64,
    relocation_type: u32,
}

impl RelocationLocation {
    fn new(
        relocation_section_index: usize,
        relocation_entry_index: usize,
        target_section_index: usize,
        target_offset: u64,
        relocation_type: u32,
    ) -> Self {
        Self {
            relocation_section_index,
            relocation_entry_index,
            target_section_index,
            target_offset,
            relocation_type,
        }
    }

    pub(super) fn relocation_section_index(&self) -> usize {
        self.relocation_section_index
    }

    pub(super) fn relocation_entry_index(&self) -> usize {
        self.relocation_entry_index
    }

    pub(super) fn target_section_index(&self) -> usize {
        self.target_section_index
    }

    pub(super) fn target_offset(&self) -> u64 {
        self.target_offset
    }

    pub(super) fn relocation_type(&self) -> u32 {
        self.relocation_type
    }
}

pub(super) fn collect_actual_host_imports(
    object_path: &Path,
) -> Result<ActualHostImports, FrameVmStageError> {
    let bytes = fs::read(object_path).map_err(|error| {
        FrameVmStageError::ImportValidation(format!(
            "failed to read final FrameVM object {}: {error}",
            object_path.display()
        ))
    })?;
    let elf = ElfFile::new(&bytes).map_err(|error| {
        FrameVmStageError::ImportValidation(format!(
            "failed to parse final FrameVM object {}: {error:?}",
            object_path.display()
        ))
    })?;
    let (symbol_table, symbol_names) = symbol_table_and_names(&elf)?;
    let mut imports = BTreeMap::<RawSymbolName, ImportEvidence>::new();

    for (relocation_section_index, relocation_section) in elf.section_iter().enumerate() {
        let Ok(section_type) = relocation_section.get_type() else {
            continue;
        };
        if !matches!(section_type, ShType::Rela | ShType::Rel) {
            continue;
        }

        let target_section_index = relocation_section.info() as usize;
        if target_section_index == 0 {
            continue;
        }
        let Ok(target_section) = elf.section_header(target_section_index as u16) else {
            continue;
        };
        if target_section.flags() & SHF_ALLOC == 0 {
            continue;
        }

        match relocation_section.get_data(&elf) {
            Ok(SectionData::Rela64(relocations)) => collect_rela_imports(
                relocations,
                relocation_section_index,
                target_section_index,
                symbol_table,
                symbol_names,
                &mut imports,
            )?,
            Ok(SectionData::Rel64(relocations)) => {
                for (relocation_entry_index, relocation) in relocations.iter().enumerate() {
                    collect_relocation_import(
                        relocation.get_symbol_table_index() as usize,
                        relocation.get_offset(),
                        relocation.get_type(),
                        relocation_section_index,
                        relocation_entry_index,
                        target_section_index,
                        symbol_table,
                        symbol_names,
                        &mut imports,
                    )?;
                }
            }
            _ => {}
        }
    }

    Ok(ActualHostImports::new(object_path.to_path_buf(), imports))
}

fn collect_rela_imports(
    relocations: &[Rela<u64>],
    relocation_section_index: usize,
    target_section_index: usize,
    symbol_table: &[Entry64],
    symbol_names: &[u8],
    imports: &mut BTreeMap<RawSymbolName, ImportEvidence>,
) -> Result<(), FrameVmStageError> {
    for (relocation_entry_index, relocation) in relocations.iter().enumerate() {
        collect_relocation_import(
            relocation.get_symbol_table_index() as usize,
            relocation.get_offset(),
            relocation.get_type(),
            relocation_section_index,
            relocation_entry_index,
            target_section_index,
            symbol_table,
            symbol_names,
            imports,
        )?;
    }
    Ok(())
}

#[expect(clippy::too_many_arguments)]
fn collect_relocation_import(
    symbol_index: usize,
    target_offset: u64,
    relocation_type: u32,
    relocation_section_index: usize,
    relocation_entry_index: usize,
    target_section_index: usize,
    symbol_table: &[Entry64],
    symbol_names: &[u8],
    imports: &mut BTreeMap<RawSymbolName, ImportEvidence>,
) -> Result<(), FrameVmStageError> {
    if relocation_type == 0 {
        return Ok(());
    }
    if symbol_index == 0 {
        return Ok(());
    }

    let symbol = symbol_table.get(symbol_index).ok_or_else(|| {
        FrameVmStageError::ImportValidation(format!(
            "relocation references invalid symbol-table index {symbol_index}"
        ))
    })?;
    if symbol.shndx() != SHN_UNDEF {
        return Ok(());
    }

    let raw_name = RawSymbolName::new(symbol_name_bytes(symbol_names, symbol.name())?)?;
    let location = RelocationLocation::new(
        relocation_section_index,
        relocation_entry_index,
        target_section_index,
        target_offset,
        relocation_type,
    );
    imports.entry(raw_name).or_default().record(location);
    Ok(())
}

fn symbol_table_and_names<'a>(
    elf: &'a ElfFile<'a>,
) -> Result<(&'a [Entry64], &'a [u8]), FrameVmStageError> {
    let symbol_table_section = elf
        .section_iter()
        .find(|section| section.get_type() == Ok(ShType::SymTab))
        .ok_or_else(|| {
            FrameVmStageError::ImportValidation(
                "final FrameVM object is missing `.symtab`".to_string(),
            )
        })?;
    let symbol_table = match symbol_table_section.get_data(elf) {
        Ok(SectionData::SymbolTable64(symbol_table)) => symbol_table,
        _ => {
            return Err(FrameVmStageError::ImportValidation(
                "final FrameVM object has unsupported symbol table format".to_string(),
            ));
        }
    };

    let names_section = elf
        .section_header(symbol_table_section.link() as u16)
        .map_err(|_| {
            FrameVmStageError::ImportValidation(
                "final FrameVM object has invalid symbol-name string table link".to_string(),
            )
        })?;
    if names_section.get_type() != Ok(ShType::StrTab) {
        return Err(FrameVmStageError::ImportValidation(
            "final FrameVM object symbol-name table is not a string table".to_string(),
        ));
    }

    Ok((symbol_table, names_section.raw_data(elf)))
}

pub(super) fn symbol_name_bytes(
    symbol_names: &[u8],
    offset: u32,
) -> Result<&[u8], FrameVmStageError> {
    let start = offset as usize;
    if start >= symbol_names.len() {
        return Err(FrameVmStageError::ImportValidation(format!(
            "symbol-name offset {start} exceeds string table size {}",
            symbol_names.len()
        )));
    }
    let end = symbol_names[start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|position| start + position)
        .ok_or_else(|| {
            FrameVmStageError::ImportValidation(format!(
                "symbol-name offset {start} is not nul-terminated"
            ))
        })?;
    Ok(&symbol_names[start..end])
}

pub(super) fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(super) fn normalize_raw_symbol_name(name: &RawSymbolName) -> Option<String> {
    let name = std::str::from_utf8(name.as_bytes()).ok()?;
    normalize_rust_v0_mangled_crate_disambiguators(name)
}

pub(super) fn normalize_raw_symbol_str(name: &str) -> Option<String> {
    normalize_rust_v0_mangled_crate_disambiguators(name)
}

pub(super) fn first_rust_crate_identity_str(name: &str) -> Option<RustCrateIdentity> {
    rust_crate_identities_str(name).next()
}

pub(super) fn rust_crate_identities_str(
    name: &str,
) -> impl Iterator<Item = RustCrateIdentity> + '_ {
    RustCrateIdentityIter {
        remaining: name,
        offset: 0,
    }
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

struct RustCrateIdentityIter<'a> {
    remaining: &'a str,
    offset: usize,
}

impl Iterator for RustCrateIdentityIter<'_> {
    type Item = RustCrateIdentity;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(relative_start) = self.remaining.find("Cs") {
            let absolute_start = self.offset + relative_start;
            let candidate = &self.remaining[relative_start..];
            self.offset = absolute_start + 2;
            self.remaining = &candidate[2..];

            if let Some(identity) = parse_rust_crate_identity(candidate) {
                return Some(identity);
            }
        }
        None
    }
}

fn parse_rust_crate_identity(candidate: &str) -> Option<RustCrateIdentity> {
    let disambiguator = candidate.strip_prefix("Cs")?;
    let separator = disambiguator.find('_')?;
    if separator == 0 {
        return None;
    }

    let crate_name_with_len = &disambiguator[separator + 1..];
    let crate_name_length_end = crate_name_with_len
        .as_bytes()
        .iter()
        .position(|byte| !byte.is_ascii_digit())?;
    if crate_name_length_end == 0 {
        return None;
    }

    let crate_name_length = crate_name_with_len[..crate_name_length_end]
        .parse::<usize>()
        .ok()?;
    let crate_name_start = crate_name_length_end;
    let crate_name_end = crate_name_start.checked_add(crate_name_length)?;
    let crate_name = crate_name_with_len.get(crate_name_start..crate_name_end)?;

    Some(RustCrateIdentity::new(
        crate_name.to_string(),
        disambiguator[..separator].to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use std::{fs, process::Command};

    use tempfile::TempDir;

    use super::*;

    struct AssembledObject {
        _temp_dir: TempDir,
        path: PathBuf,
    }

    fn assemble(source: &str) -> AssembledObject {
        let temp_dir = TempDir::new().expect("failed to create temporary directory");
        let source_path = temp_dir.path().join("input.S");
        let object_path = temp_dir.path().join("input.o");
        fs::write(&source_path, source).expect("failed to write assembly source");

        let output = Command::new("as")
            .arg("-o")
            .arg(&object_path)
            .arg(&source_path)
            .output()
            .expect("failed to run assembler");
        assert!(
            output.status.success(),
            "assembler failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        AssembledObject {
            _temp_dir: temp_dir,
            path: object_path,
        }
    }

    #[test]
    fn collects_sorted_relocation_referenced_undefined_symbols() {
        let object = assemble(
            r#"
.text
.global framevm_probe
framevm_probe:
    call z_import
    call a_import
    ret
.globl nm_only_import
"#,
        );

        let imports = collect_actual_host_imports(&object.path).unwrap();
        let names = imports
            .iter()
            .map(|(name, _)| name.display_lossy())
            .collect::<Vec<_>>();

        assert_eq!(names, ["a_import", "z_import"]);
        for (_, evidence) in imports.iter() {
            assert_eq!(evidence.relocation_count(), 1);
            assert_eq!(evidence.relocation_locations().len(), 1);
        }
    }
}
