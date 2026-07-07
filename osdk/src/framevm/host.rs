// SPDX-License-Identifier: MPL-2.0

//! Final host ELF symbol matching for FrameVM imports.
//!
//! This module validates OSDK's typed actual-import set against the selected
//! final host artifact. Runtime code never consumes this module's diagnostic
//! layout; later symbol-table generation consumes only the typed matches.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    os::unix::ffi::OsStringExt,
    path::{Path, PathBuf},
};

use xmas_elf::{
    ElfFile,
    sections::{SHN_UNDEF, SectionData, ShType},
    symbol_table::Entry,
};

use super::{
    imports::{self, ActualHostImports, RawSymbolName},
    process,
    types::FrameVmStageError,
};

#[derive(Clone, Debug)]
pub(super) struct HostElfArtifact {
    path: PathBuf,
}

impl HostElfArtifact {
    pub(super) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone, Debug)]
pub(super) struct HostImportValidation {
    host_elf: HostElfArtifact,
    matches: Vec<HostSymbolMatch>,
    missing_imports: Vec<RawSymbolName>,
    ambiguous_imports: Vec<AmbiguousHostSymbol>,
}

impl HostImportValidation {
    fn new(
        host_elf: HostElfArtifact,
        matches: Vec<HostSymbolMatch>,
        missing_imports: Vec<RawSymbolName>,
        ambiguous_imports: Vec<AmbiguousHostSymbol>,
    ) -> Self {
        Self {
            host_elf,
            matches,
            missing_imports,
            ambiguous_imports,
        }
    }

    pub(super) fn host_elf(&self) -> &HostElfArtifact {
        &self.host_elf
    }

    pub(super) fn matches(&self) -> &[HostSymbolMatch] {
        &self.matches
    }

    pub(super) fn missing_imports(&self) -> &[RawSymbolName] {
        &self.missing_imports
    }

    pub(super) fn ambiguous_imports(&self) -> &[AmbiguousHostSymbol] {
        &self.ambiguous_imports
    }

    pub(super) fn is_exact_match(&self) -> bool {
        self.missing_imports.is_empty() && self.ambiguous_imports.is_empty()
    }
}

#[derive(Clone, Debug)]
pub(super) struct HostSymbolMatch {
    import_name: RawSymbolName,
    exported_name: RawSymbolName,
    value: u64,
    size: u64,
    kind: String,
    binding: String,
}

impl HostSymbolMatch {
    fn new(import_name: RawSymbolName, definition: HostSymbolDefinition) -> Self {
        Self {
            import_name,
            exported_name: definition.name,
            value: definition.value,
            size: definition.size,
            kind: definition.kind,
            binding: definition.binding,
        }
    }

    pub(super) fn import_name(&self) -> &RawSymbolName {
        &self.import_name
    }

    pub(super) fn exported_name(&self) -> &RawSymbolName {
        &self.exported_name
    }

    pub(super) fn value(&self) -> u64 {
        self.value
    }

    pub(super) fn size(&self) -> u64 {
        self.size
    }

    pub(super) fn kind(&self) -> &str {
        &self.kind
    }

    pub(super) fn binding(&self) -> &str {
        &self.binding
    }
}

#[derive(Clone, Debug)]
pub(super) struct AmbiguousHostSymbol {
    import_name: RawSymbolName,
    definitions: Vec<HostSymbolDefinition>,
}

impl AmbiguousHostSymbol {
    fn new(import_name: RawSymbolName, definitions: Vec<HostSymbolDefinition>) -> Self {
        Self {
            import_name,
            definitions,
        }
    }

    pub(super) fn import_name(&self) -> &RawSymbolName {
        &self.import_name
    }

    pub(super) fn definitions(&self) -> &[HostSymbolDefinition] {
        &self.definitions
    }
}

#[derive(Clone, Debug)]
pub(super) struct HostSymbolDefinition {
    name: RawSymbolName,
    value: u64,
    size: u64,
    kind: String,
    binding: String,
    section_name: Option<String>,
    section_offset: Option<u64>,
}

impl HostSymbolDefinition {
    fn new(
        name: RawSymbolName,
        value: u64,
        size: u64,
        kind: String,
        binding: String,
        section_name: Option<String>,
        section_offset: Option<u64>,
    ) -> Self {
        Self {
            name,
            value,
            size,
            kind,
            binding,
            section_name,
            section_offset,
        }
    }

    pub(super) fn name(&self) -> &RawSymbolName {
        &self.name
    }

    pub(super) fn value(&self) -> u64 {
        self.value
    }

    pub(super) fn size(&self) -> u64 {
        self.size
    }

    pub(super) fn kind(&self) -> &str {
        &self.kind
    }

    pub(super) fn binding(&self) -> &str {
        &self.binding
    }

    fn section_name(&self) -> Option<&str> {
        self.section_name.as_deref()
    }

    fn section_offset(&self) -> Option<u64> {
        self.section_offset
    }
}

pub(super) fn validate_actual_imports(
    host_elf: HostElfArtifact,
    imports: &ActualHostImports,
) -> Result<HostImportValidation, FrameVmStageError> {
    let symbols = read_defined_symbols(host_elf.path())?;
    let mut matches = Vec::new();
    let mut missing_imports = Vec::new();
    let mut ambiguous_imports = Vec::new();

    for (import_name, _) in imports.iter() {
        match symbols.exact.get(import_name) {
            Some(definitions) if definitions.len() == 1 => {
                matches.push(HostSymbolMatch::new(
                    import_name.clone(),
                    definitions[0].clone(),
                ));
            }
            Some(definitions) => {
                ambiguous_imports.push(AmbiguousHostSymbol::new(
                    import_name.clone(),
                    definitions.clone(),
                ));
            }
            None => {
                missing_imports.push(import_name.clone());
            }
        }
    }

    Ok(HostImportValidation::new(
        host_elf,
        matches,
        missing_imports,
        ambiguous_imports,
    ))
}

pub(super) fn publish_exact_import_aliases(
    validation: &HostImportValidation,
) -> Result<bool, FrameVmStageError> {
    if validation.missing_imports().is_empty() || !validation.ambiguous_imports().is_empty() {
        return Ok(false);
    }

    let symbols = read_defined_symbols(validation.host_elf().path())?;
    let mut aliases = Vec::new();
    for import_name in validation.missing_imports() {
        let Some(definition) = symbols.find_normalized_alias(import_name) else {
            continue;
        };
        aliases.push(HostSymbolAlias::new(
            import_name.clone(),
            definition.clone(),
        ));
    }
    if aliases.is_empty() {
        return Ok(false);
    }

    let mut command = process::command("objcopy");
    for alias in &aliases {
        command.arg("--add-symbol").arg(alias_objcopy_arg(alias)?);
    }
    command.arg(validation.host_elf().path());
    process::run_status(
        command,
        "publishing exact FrameVM host import aliases",
        FrameVmStageError::ImportValidation,
    )?;
    Ok(true)
}

#[derive(Default)]
struct HostDefinedSymbols {
    exact: BTreeMap<RawSymbolName, Vec<HostSymbolDefinition>>,
    normalized: BTreeMap<String, Vec<HostSymbolDefinition>>,
}

impl HostDefinedSymbols {
    fn insert(&mut self, definition: HostSymbolDefinition) {
        if let Some(normalized_name) = imports::normalize_raw_symbol_name(definition.name()) {
            self.normalized
                .entry(normalized_name)
                .or_default()
                .push(definition.clone());
        }
        self.exact
            .entry(definition.name().clone())
            .or_default()
            .push(definition);
    }

    fn find_normalized_alias(&self, import_name: &RawSymbolName) -> Option<&HostSymbolDefinition> {
        let normalized_name = imports::normalize_raw_symbol_name(import_name)?;
        let definitions = self.normalized.get(&normalized_name)?;
        let mut linkable_definitions = definitions
            .iter()
            .filter(|definition| {
                definition.section_name().is_some() && definition.section_offset().is_some()
            })
            .collect::<Vec<_>>();
        linkable_definitions.sort_by_key(|definition| definition.value());
        match linkable_definitions.as_slice() {
            [definition] => Some(*definition),
            _ => None,
        }
    }
}

fn read_defined_symbols(host_elf: &Path) -> Result<HostDefinedSymbols, FrameVmStageError> {
    let bytes = fs::read(host_elf).map_err(|error| {
        FrameVmStageError::ImportValidation(format!(
            "failed to read final host ELF {}: {error}",
            host_elf.display()
        ))
    })?;
    let elf = ElfFile::new(&bytes).map_err(|error| {
        FrameVmStageError::ImportValidation(format!(
            "failed to parse final host ELF {}: {error:?}",
            host_elf.display()
        ))
    })?;
    let (symbol_table, symbol_names) = symbol_table_and_names(&elf)?;
    let mut definitions = HostDefinedSymbols::default();

    for symbol in symbol_table {
        if symbol.shndx() == SHN_UNDEF {
            continue;
        }
        let raw_name = imports::symbol_name_bytes(symbol_names, symbol.name())?;
        if raw_name.is_empty() {
            continue;
        }
        let name = RawSymbolName::new(raw_name)?;
        let kind = symbol
            .get_type()
            .map(|kind| format!("{kind:?}"))
            .unwrap_or_else(|_| "unknown".to_string());
        let binding = symbol
            .get_binding()
            .map(|binding| format!("{binding:?}"))
            .unwrap_or_else(|_| "unknown".to_string());
        let (section_name, section_offset) = symbol_section_location(&elf, symbol)?;
        let definition = HostSymbolDefinition::new(
            name,
            symbol.value(),
            symbol.size(),
            kind,
            binding,
            section_name,
            section_offset,
        );
        definitions.insert(definition);
    }

    Ok(definitions)
}

#[derive(Clone, Debug)]
struct HostSymbolAlias {
    import_name: RawSymbolName,
    target: HostSymbolDefinition,
}

impl HostSymbolAlias {
    fn new(import_name: RawSymbolName, target: HostSymbolDefinition) -> Self {
        Self {
            import_name,
            target,
        }
    }

    fn import_name(&self) -> &RawSymbolName {
        &self.import_name
    }

    fn target(&self) -> &HostSymbolDefinition {
        &self.target
    }
}

fn alias_objcopy_arg(alias: &HostSymbolAlias) -> Result<OsString, FrameVmStageError> {
    let Some(section_name) = alias.target().section_name() else {
        return Err(FrameVmStageError::ImportValidation(format!(
            "cannot publish exact alias for {} because matched host symbol has no section",
            alias.import_name()
        )));
    };
    let Some(section_offset) = alias.target().section_offset() else {
        return Err(FrameVmStageError::ImportValidation(format!(
            "cannot publish exact alias for {} because matched host symbol has no section offset",
            alias.import_name()
        )));
    };

    let mut argument = Vec::new();
    argument.extend(alias.import_name().as_bytes());
    argument.push(b'=');
    argument.extend(section_name.as_bytes());
    argument.push(b':');
    argument.extend(format!("0x{section_offset:x},global").as_bytes());
    if let Some(kind) = objcopy_symbol_kind(alias.target()) {
        argument.push(b',');
        argument.extend(kind.as_bytes());
    }
    Ok(OsString::from_vec(argument))
}

fn objcopy_symbol_kind(definition: &HostSymbolDefinition) -> Option<&'static str> {
    match definition.kind() {
        "Func" => Some("function"),
        "Object" => Some("object"),
        _ => None,
    }
}

fn symbol_section_location(
    elf: &ElfFile<'_>,
    symbol: &xmas_elf::symbol_table::Entry64,
) -> Result<(Option<String>, Option<u64>), FrameVmStageError> {
    let section_index = symbol.shndx() as usize;
    if section_index >= elf.section_iter().count() {
        return Ok((None, None));
    }

    let Ok(section) = elf.section_header(symbol.shndx()) else {
        return Ok((None, None));
    };
    let section_name = section.get_name(elf).map_err(|_| {
        FrameVmStageError::ImportValidation(format!(
            "failed to read host section name for symbol section {}",
            symbol.shndx()
        ))
    })?;
    let section_address = section.address();
    let Some(section_offset) = symbol.value().checked_sub(section_address) else {
        return Ok((Some(section_name.to_string()), None));
    };
    Ok((Some(section_name.to_string()), Some(section_offset)))
}

fn symbol_table_and_names<'a>(
    elf: &'a ElfFile<'a>,
) -> Result<(&'a [xmas_elf::symbol_table::Entry64], &'a [u8]), FrameVmStageError> {
    let symbol_table_section = elf
        .section_iter()
        .find(|section| section.get_type() == Ok(ShType::SymTab))
        .ok_or_else(|| {
            FrameVmStageError::ImportValidation("final host ELF is missing `.symtab`".to_string())
        })?;
    let symbol_table = match symbol_table_section.get_data(elf) {
        Ok(SectionData::SymbolTable64(symbol_table)) => symbol_table,
        _ => {
            return Err(FrameVmStageError::ImportValidation(
                "final host ELF has unsupported symbol table format".to_string(),
            ));
        }
    };

    let names_section = elf
        .section_header(symbol_table_section.link() as u16)
        .map_err(|_| {
            FrameVmStageError::ImportValidation(
                "final host ELF has invalid symbol-name string table link".to_string(),
            )
        })?;
    if names_section.get_type() != Ok(ShType::StrTab) {
        return Err(FrameVmStageError::ImportValidation(
            "final host ELF symbol-name table is not a string table".to_string(),
        ));
    }

    Ok((symbol_table, names_section.raw_data(elf)))
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

    fn imports_for_symbol(raw_symbol: &str) -> ActualHostImports {
        let service = assemble(&format!(
            r#"
.text
.global framevm_probe
framevm_probe:
    call {raw_symbol}
    ret
"#
        ));
        imports::collect_actual_host_imports(&service.path).unwrap()
    }

    #[test]
    fn validates_exact_imports_after_build_time_alias_publication() {
        let import_name = "_RNvCsFRAMEVM_3foo";
        let host_name = "_RNvCsHOSTAAA_3foo";
        let imports = imports_for_symbol(import_name);
        let host = assemble(&format!(
            r#"
.text
.global {host_name}
.type {host_name}, @function
{host_name}:
    ret
.size {host_name}, . - {host_name}
"#
        ));
        let host_elf = HostElfArtifact::new(host.path.clone());

        let validation = validate_actual_imports(host_elf.clone(), &imports).unwrap();
        assert!(!validation.is_exact_match());
        assert_eq!(validation.missing_imports().len(), 1);

        assert!(publish_exact_import_aliases(&validation).unwrap());
        let validation = validate_actual_imports(host_elf, &imports).unwrap();
        assert!(validation.is_exact_match());
        let symbol_match = validation.matches().first().unwrap();
        assert_eq!(symbol_match.import_name().display_lossy(), import_name);
        assert_eq!(symbol_match.exported_name().display_lossy(), import_name);
    }

    #[test]
    fn rejects_missing_imports_without_guessing_unrelated_symbols() {
        let imports = imports_for_symbol("_RNvCsFRAMEVM_3foo");
        let host = assemble(
            r#"
.text
.global unrelated_host_symbol
.type unrelated_host_symbol, @function
unrelated_host_symbol:
    ret
.size unrelated_host_symbol, . - unrelated_host_symbol
"#,
        );
        let host_elf = HostElfArtifact::new(host.path.clone());

        let validation = validate_actual_imports(host_elf, &imports).unwrap();
        assert!(!validation.is_exact_match());
        assert_eq!(validation.missing_imports().len(), 1);
        assert!(!publish_exact_import_aliases(&validation).unwrap());
    }
}
