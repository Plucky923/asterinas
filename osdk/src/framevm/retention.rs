// SPDX-License-Identifier: MPL-2.0

//! Linker-level ordinary dependency retention for FrameVM objects.
//!
//! This module owns the build-only rlib selection, extraction, and relocatable
//! linker inputs used before OSDK discovers the final actual host import set.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use super::{imports, policy::FrameVmPolicy, process, types::FrameVmStageError};

const FRAMEVM_RELOCATABLE_LINKER_SCRIPT: &str = r#"
SECTIONS
{
  PROVIDE(__executable_start = 0);
  PROVIDE(__cpu_local_start = 0);
  .text 0 : { *(.text .text.*) }
  PROVIDE(__etext = .);
  .rodata 0 : { *(.rodata .rodata.*) }
  .data 0 : { *(.data .data.*) }
  .bss 0 : { *(.bss .bss.* COMMON) }
  .cpu_local 0 : { *(.cpu_local .cpu_local.*) }
  PROVIDE(__cpu_local_end = .);
  .tdata 0 : { *(.tdata .tdata.*) }
  .tbss 0 : { *(.tbss .tbss.*) }
  .init_array 0 : { *(.init_array .init_array.*) }
  .fini_array 0 : { *(.fini_array .fini_array.*) }
  .ctors 0 : { *(.ctors .ctors.*) }
  .dtors 0 : { *(.dtors .dtors.*) }
  .eh_frame 0 : {
    PROVIDE(__eh_frame = .);
    PROVIDE(__GNU_EH_FRAME_HDR = .);
    *(.eh_frame .eh_frame.*)
  }
  .gcc_except_table 0 : { *(.gcc_except_table .gcc_except_table.*) }
  .framevm.exports 0 : { *(.framevm.exports .framevm.exports.*) }
  .framevm.imports 0 : { *(.framevm.imports .framevm.imports.*) }
  .framevm.meta 0 : { *(.framevm.meta .framevm.meta.*) }
}
"#;

#[derive(Clone, Debug)]
pub(super) struct RetainedRlib {
    pub(super) crate_name: String,
    pub(super) rlib: PathBuf,
    pub(super) matched_input_symbols: Vec<String>,
    pub(super) object_count: usize,
}

#[derive(Clone, Debug)]
struct RlibSelection {
    crate_name: String,
    rlibs: Vec<PathBuf>,
    selected_rlib: PathBuf,
    matched_input_symbols: Vec<String>,
    selected_by_input: bool,
}

pub(super) fn retain_ordinary_rlibs(
    policy: &FrameVmPolicy,
    target_dir: &Path,
    target: &str,
    profile: &str,
    build_dir: &Path,
    input_raw_symbols: &BTreeSet<&str>,
) -> Result<Vec<RetainedRlib>, FrameVmStageError> {
    let mut selections = Vec::new();
    for crate_name in &policy.bundling.ordinary_rlibs {
        let rlibs = find_crate_rlibs(target_dir, target, profile, crate_name)?;
        let fallback_rlib = rlibs.last().cloned().ok_or_else(|| {
            FrameVmStageError::ObjectLink(format!(
                "FrameVM dependency rlib not found for {crate_name}"
            ))
        })?;
        let (selected_rlib, matched_input_symbols) =
            select_rlib_by_symbols(&rlibs, input_raw_symbols)?
                .unwrap_or((fallback_rlib, Vec::new()));
        selections.push(RlibSelection {
            crate_name: crate_name.clone(),
            rlibs,
            selected_rlib,
            selected_by_input: !matched_input_symbols.is_empty(),
            matched_input_symbols,
        });
    }

    resolve_transitive_rlib_versions(&mut selections, input_raw_symbols)?;

    let mut retained = Vec::new();
    for selection in selections {
        let extract_dir = build_dir.join(
            selection
                .selected_rlib
                .file_stem()
                .and_then(|name| name.to_str())
                .ok_or_else(|| {
                    FrameVmStageError::ObjectLink(format!(
                        "rlib path has no valid file stem: {}",
                        selection.selected_rlib.display()
                    ))
                })?,
        );
        fs::create_dir_all(&extract_dir).map_err(|error| {
            FrameVmStageError::ObjectLink(format!(
                "failed to create rlib extraction directory {}: {error}",
                extract_dir.display()
            ))
        })?;
        let mut command = process::command("ar");
        command
            .arg("x")
            .arg(&selection.selected_rlib)
            .current_dir(&extract_dir);
        process::run_status(
            command,
            "extracting FrameVM ordinary dependency rlib",
            FrameVmStageError::ObjectLink,
        )?;
        remove_file_if_exists(&extract_dir.join("lib.rmeta"))?;

        retained.push(RetainedRlib {
            crate_name: selection.crate_name,
            rlib: selection.selected_rlib,
            matched_input_symbols: selection.matched_input_symbols,
            object_count: collect_object_files(&extract_dir)?.len(),
        });
    }

    Ok(retained)
}

pub(super) fn find_policy_rlibs(
    target_dir: &Path,
    target: &str,
    profile: &str,
    crate_names: &[String],
) -> Result<Vec<PathBuf>, FrameVmStageError> {
    let mut files = Vec::new();
    for crate_name in crate_names {
        let rlibs = find_crate_rlibs(target_dir, target, profile, crate_name)?;
        let rlib = rlibs.last().cloned().ok_or_else(|| {
            FrameVmStageError::ImportValidation(format!(
                "host symbol rlib not found for {crate_name}"
            ))
        })?;
        files.push(rlib);
    }
    Ok(files)
}

pub(super) fn find_policy_rlib_candidates(
    target_dir: &Path,
    target: &str,
    profile: &str,
    crate_names: &[String],
) -> Result<Vec<PathBuf>, FrameVmStageError> {
    let mut files = Vec::new();
    for crate_name in crate_names {
        let rlibs = find_crate_rlibs(target_dir, target, profile, crate_name)?;
        if rlibs.is_empty() {
            return Err(FrameVmStageError::ImportValidation(format!(
                "host symbol rlib not found for {crate_name}"
            )));
        }
        files.extend(rlibs);
    }
    Ok(files)
}

pub(super) fn collect_object_files(root: &Path) -> Result<Vec<PathBuf>, FrameVmStageError> {
    let mut objects = Vec::new();
    collect_object_files_inner(root, &mut objects)?;
    objects.sort();
    Ok(objects)
}

pub(super) fn run_ld_relocatable(
    output: &Path,
    objects: &[PathBuf],
) -> Result<(), FrameVmStageError> {
    let linker_script = output.with_extension("ld");
    fs::write(&linker_script, FRAMEVM_RELOCATABLE_LINKER_SCRIPT).map_err(|error| {
        FrameVmStageError::ObjectLink(format!(
            "failed to write FrameVM relocatable linker script {}: {error}",
            linker_script.display()
        ))
    })?;

    let mut command = process::command("ld");
    command
        .arg("-r")
        .arg("-T")
        .arg(&linker_script)
        .arg("-o")
        .arg(output)
        .args(objects);
    let result = process::run_status(
        command,
        "linking FrameVM relocatable object",
        FrameVmStageError::ObjectLink,
    );
    remove_file_if_exists(&linker_script)?;
    result
}

pub(super) fn undefined_raw_symbols(path: &Path) -> Result<Vec<String>, FrameVmStageError> {
    nm_symbols(path, NmMode::UndefinedRaw)
}

pub(super) fn undefined_demangled_symbols(path: &Path) -> Result<Vec<String>, FrameVmStageError> {
    nm_symbols(path, NmMode::UndefinedDemangled)
}

pub(super) fn defined_raw_symbols(path: &Path) -> Result<Vec<String>, FrameVmStageError> {
    nm_symbols(path, NmMode::DefinedRaw)
}

pub(super) fn defined_demangled_symbols(path: &Path) -> Result<Vec<String>, FrameVmStageError> {
    nm_symbols(path, NmMode::DefinedDemangled)
}

pub(super) fn pre_host_final_retention_rustflags<'a>(
    shared_rustflags: &'a [&'a str],
    imports: &'a super::imports::ActualHostImports,
    host_symbol_files: &[PathBuf],
) -> Result<Vec<String>, FrameVmStageError> {
    let host_side_symbols =
        host_side_retention_symbols_from_candidates(imports, host_symbol_files)?;
    retention_rustflags(shared_rustflags, imports, &host_side_symbols)
}

pub(super) fn final_host_retention_rustflags<'a>(
    shared_rustflags: &'a [&'a str],
    imports: &'a super::imports::ActualHostImports,
    host_symbol_files: &[PathBuf],
    final_host_elf: &Path,
) -> Result<Vec<String>, FrameVmStageError> {
    let host_side_symbols =
        host_side_retention_symbols_for_final_host(imports, host_symbol_files, final_host_elf)?;
    retention_rustflags(shared_rustflags, imports, &host_side_symbols)
}

fn host_side_retention_symbols_from_candidates(
    actual_imports: &super::imports::ActualHostImports,
    host_symbol_files: &[PathBuf],
) -> Result<BTreeSet<String>, FrameVmStageError> {
    let actual_import_normalized_names = actual_imports
        .iter()
        .filter_map(|(raw_import, _)| imports::normalize_raw_symbol_name(raw_import))
        .collect::<BTreeSet<_>>();
    let mut host_side_symbols = BTreeSet::new();
    for file in host_symbol_files {
        for raw_symbol in defined_raw_symbols(file)? {
            let Some(normalized_name) = imports::normalize_raw_symbol_str(&raw_symbol) else {
                continue;
            };
            if actual_import_normalized_names.contains(&normalized_name) {
                host_side_symbols.insert(raw_symbol);
            }
        }
    }
    Ok(host_side_symbols)
}

fn retention_rustflags<'a>(
    shared_rustflags: &'a [&'a str],
    imports: &'a super::imports::ActualHostImports,
    host_side_symbols: &BTreeSet<String>,
) -> Result<Vec<String>, FrameVmStageError> {
    let mut rustflags = shared_rustflags
        .iter()
        .map(|flag| (*flag).to_string())
        .collect::<Vec<_>>();
    let mut requested_symbols = host_side_symbols.clone();
    for (raw_name, _) in imports.iter() {
        let raw_name = std::str::from_utf8(raw_name.as_bytes()).map_err(|_| {
            FrameVmStageError::ImportValidation(format!(
                "FrameVM host retention currently requires UTF-8 linker symbol names, got 0x{}",
                raw_name.hex()
            ))
        })?;
        requested_symbols.insert(raw_name.to_string());
    }

    for raw_name in requested_symbols {
        rustflags.push("-C link-arg=-u".to_string());
        rustflags.push(format!("-C link-arg={}", raw_name));
    }
    Ok(rustflags)
}

fn host_side_retention_symbols_for_final_host(
    actual_imports: &super::imports::ActualHostImports,
    host_symbol_files: &[PathBuf],
    final_host_elf: &Path,
) -> Result<BTreeSet<String>, FrameVmStageError> {
    let mut host_identities = observed_rust_crate_identities(final_host_elf)?;
    prefer_non_import_identities(&mut host_identities, actual_imports)?;
    let mut host_symbols_by_normalized_name = BTreeMap::<String, BTreeSet<String>>::new();
    for file in host_symbol_files {
        for raw_symbol in defined_raw_symbols(file)? {
            let Some(identity) = imports::first_rust_crate_identity_str(&raw_symbol) else {
                continue;
            };
            let Some(crate_identities) = host_identities.get(identity.crate_name()) else {
                continue;
            };
            if !crate_identities.contains(&identity) {
                continue;
            }
            if let Some(normalized_name) = imports::normalize_raw_symbol_str(&raw_symbol) {
                host_symbols_by_normalized_name
                    .entry(normalized_name)
                    .or_default()
                    .insert(raw_symbol);
            }
        }
    }

    unique_normalized_host_symbols(actual_imports, &host_symbols_by_normalized_name)
}

fn prefer_non_import_identities(
    host_identities: &mut BTreeMap<String, BTreeSet<imports::RustCrateIdentity>>,
    actual_imports: &super::imports::ActualHostImports,
) -> Result<(), FrameVmStageError> {
    let import_identities = actual_import_crate_identities(actual_imports)?;
    for (crate_name, imported_identities) in import_identities {
        let Some(observed_identities) = host_identities.get_mut(&crate_name) else {
            continue;
        };
        let non_import_identities = observed_identities
            .difference(&imported_identities)
            .cloned()
            .collect::<BTreeSet<_>>();
        if !non_import_identities.is_empty() {
            *observed_identities = non_import_identities;
        }
    }
    Ok(())
}

fn actual_import_crate_identities(
    actual_imports: &super::imports::ActualHostImports,
) -> Result<BTreeMap<String, BTreeSet<imports::RustCrateIdentity>>, FrameVmStageError> {
    let mut identities = BTreeMap::<String, BTreeSet<imports::RustCrateIdentity>>::new();
    for (raw_import, _) in actual_imports.iter() {
        let raw_import = std::str::from_utf8(raw_import.as_bytes()).map_err(|_| {
            FrameVmStageError::ImportValidation(format!(
                "FrameVM host retention currently requires UTF-8 linker symbol names, got 0x{}",
                raw_import.hex()
            ))
        })?;
        for identity in imports::rust_crate_identities_str(raw_import) {
            identities
                .entry(identity.crate_name().to_string())
                .or_default()
                .insert(identity);
        }
    }
    Ok(identities)
}

fn unique_normalized_host_symbols(
    actual_imports: &super::imports::ActualHostImports,
    host_symbols_by_normalized_name: &BTreeMap<String, BTreeSet<String>>,
) -> Result<BTreeSet<String>, FrameVmStageError> {
    let mut retention_symbols = BTreeSet::new();
    for (raw_import, _) in actual_imports.iter() {
        let Some(normalized_name) = imports::normalize_raw_symbol_name(raw_import) else {
            continue;
        };
        let Some(host_symbols) = host_symbols_by_normalized_name.get(&normalized_name) else {
            continue;
        };
        if host_symbols.len() == 1
            && let Some(host_symbol) = host_symbols.first()
        {
            retention_symbols.insert(host_symbol.clone());
        }
    }
    Ok(retention_symbols)
}

fn observed_rust_crate_identities(
    final_host_elf: &Path,
) -> Result<BTreeMap<String, BTreeSet<imports::RustCrateIdentity>>, FrameVmStageError> {
    let mut identities = BTreeMap::<String, BTreeSet<imports::RustCrateIdentity>>::new();
    for raw_symbol in defined_raw_symbols(final_host_elf)? {
        let Some(identity) = imports::first_rust_crate_identity_str(&raw_symbol) else {
            continue;
        };
        identities
            .entry(identity.crate_name().to_string())
            .or_default()
            .insert(identity);
    }
    Ok(identities)
}

fn resolve_transitive_rlib_versions(
    selections: &mut [RlibSelection],
    input_raw_symbols: &BTreeSet<&str>,
) -> Result<(), FrameVmStageError> {
    for _ in 0..=selections.len() {
        let mut unresolved_symbols = input_raw_symbols
            .iter()
            .map(|symbol| (*symbol).to_string())
            .collect::<BTreeSet<_>>();
        let mut selected_defined_symbols = BTreeSet::new();

        for selection in selections.iter() {
            unresolved_symbols.extend(undefined_raw_symbols(&selection.selected_rlib)?);
            selected_defined_symbols.extend(defined_raw_symbols(&selection.selected_rlib)?);
        }
        for symbol in selected_defined_symbols {
            unresolved_symbols.remove(&symbol);
        }

        let unresolved_refs = unresolved_symbols
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let mut changed = false;
        for selection in selections.iter_mut() {
            // Direct service-object imports carry Cargo's chosen crate metadata.
            // Replacing them with transitive matches can oscillate between
            // incompatible rlib variants from the same target directory.
            if selection.selected_by_input {
                continue;
            }
            let Some((selected_rlib, _)) =
                select_rlib_by_symbols(&selection.rlibs, &unresolved_refs)?
            else {
                continue;
            };
            if selected_rlib != selection.selected_rlib {
                selection.selected_rlib = selected_rlib;
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
    }

    Err(FrameVmStageError::ObjectLink(
        "ordinary dependency rlib selection did not converge".to_string(),
    ))
}

fn select_rlib_by_symbols(
    rlibs: &[PathBuf],
    raw_symbols: &BTreeSet<&str>,
) -> Result<Option<(PathBuf, Vec<String>)>, FrameVmStageError> {
    for rlib in rlibs.iter().rev() {
        let matched_symbols = defined_raw_symbols(rlib)?
            .into_iter()
            .filter(|symbol| raw_symbols.contains(symbol.as_str()))
            .collect::<Vec<_>>();
        if !matched_symbols.is_empty() {
            return Ok(Some((rlib.clone(), matched_symbols)));
        }
    }
    Ok(None)
}

fn find_crate_rlibs(
    target_dir: &Path,
    target: &str,
    profile: &str,
    crate_name: &str,
) -> Result<Vec<PathBuf>, FrameVmStageError> {
    let deps_dir = target_dir
        .join(target)
        .join(profile_directory(profile))
        .join("deps");
    let prefix = format!("lib{crate_name}-");
    let mut rlibs = Vec::new();
    let entries = fs::read_dir(&deps_dir).map_err(|error| {
        FrameVmStageError::ObjectLink(format!(
            "failed to read target deps directory {}: {error}",
            deps_dir.display()
        ))
    })?;

    for entry in entries {
        let path = entry
            .map_err(|error| {
                FrameVmStageError::ObjectLink(format!(
                    "failed to read target deps entry in {}: {error}",
                    deps_dir.display()
                ))
            })?
            .path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if file_name.starts_with(&prefix) && file_name.ends_with(".rlib") {
            rlibs.push(path);
        }
    }
    rlibs.sort_by(|left, right| {
        path_modified_time(left)
            .cmp(&path_modified_time(right))
            .then_with(|| left.cmp(right))
    });
    Ok(rlibs)
}

fn profile_directory(profile: &str) -> &str {
    if profile == "dev" { "debug" } else { profile }
}

fn collect_object_files_inner(
    root: &Path,
    objects: &mut Vec<PathBuf>,
) -> Result<(), FrameVmStageError> {
    for entry in fs::read_dir(root).map_err(|error| {
        FrameVmStageError::ObjectLink(format!("failed to read {}: {error}", root.display()))
    })? {
        let path = entry
            .map_err(|error| {
                FrameVmStageError::ObjectLink(format!(
                    "failed to read entry under {}: {error}",
                    root.display()
                ))
            })?
            .path();
        if path.is_dir() {
            collect_object_files_inner(&path, objects)?;
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("o") {
            objects.push(path);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum NmMode {
    UndefinedRaw,
    UndefinedDemangled,
    DefinedRaw,
    DefinedDemangled,
}

fn nm_symbols(path: &Path, mode: NmMode) -> Result<Vec<String>, FrameVmStageError> {
    let mut args = Vec::<OsString>::new();
    match mode {
        NmMode::UndefinedRaw => args.push("-u".into()),
        NmMode::UndefinedDemangled => {
            args.push("-u".into());
            args.push("-C".into());
        }
        NmMode::DefinedRaw => args.push("--defined-only".into()),
        NmMode::DefinedDemangled => {
            args.push("--defined-only".into());
            args.push("-C".into());
        }
    }
    args.push(path.as_os_str().to_owned());
    let output = process::capture_stdout(
        "nm",
        args,
        "reading ELF symbols with nm",
        FrameVmStageError::ObjectBuild,
    )?;
    Ok(output.lines().filter_map(parse_nm_symbol_line).collect())
}

fn parse_nm_symbol_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.ends_with(':') {
        return None;
    }

    let tokens = token_ranges(trimmed);
    if tokens.is_empty() {
        return None;
    }

    let symbol_start = if is_symbol_type(token_text(trimmed, tokens[0])) {
        tokens.get(1)?.0
    } else if tokens
        .get(1)
        .is_some_and(|range| is_symbol_type(token_text(trimmed, *range)))
    {
        tokens.get(2)?.0
    } else {
        tokens.last()?.0
    };
    let symbol = trimmed[symbol_start..].trim();
    (!symbol.is_empty()).then(|| symbol.to_string())
}

fn token_ranges(text: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = None;
    for (index, character) in text.char_indices() {
        if character.is_whitespace() {
            if let Some(start_index) = start.take() {
                ranges.push((start_index, index));
            }
        } else if start.is_none() {
            start = Some(index);
        }
    }
    if let Some(start_index) = start {
        ranges.push((start_index, text.len()));
    }
    ranges
}

fn token_text(text: &str, range: (usize, usize)) -> &str {
    &text[range.0..range.1]
}

fn is_symbol_type(token: &str) -> bool {
    token.len() == 1
        && matches!(
            token.as_bytes()[0] as char,
            'A' | 'B'
                | 'C'
                | 'D'
                | 'G'
                | 'I'
                | 'N'
                | 'R'
                | 'S'
                | 'T'
                | 'U'
                | 'V'
                | 'W'
                | 'a'
                | 'b'
                | 'c'
                | 'd'
                | 'g'
                | 'i'
                | 'n'
                | 'r'
                | 's'
                | 't'
                | 'u'
                | 'v'
                | 'w'
        )
}

fn remove_file_if_exists(path: &Path) -> Result<(), FrameVmStageError> {
    if path.exists() {
        fs::remove_file(path).map_err(|error| {
            FrameVmStageError::ObjectLink(format!("failed to remove {}: {error}", path.display()))
        })?;
    }
    Ok(())
}

fn path_modified_time(path: &Path) -> SystemTime {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}
