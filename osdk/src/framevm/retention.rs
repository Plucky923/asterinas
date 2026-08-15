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
  /* CPU-local objects are Host imports, so their section base must be too. */
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

/// A service rlib supplied to the linker as an on-demand archive.
///
/// The linker extracts only members that satisfy unresolved service imports.
/// This keeps allocation-aware standard-library code in the service image
/// without pulling in unrelated Host generic instantiations.
#[derive(Clone, Debug, serde::Serialize)]
pub(super) struct OnDemandRlib {
    pub(super) crate_name: String,
    pub(super) rlib: PathBuf,
}

#[derive(Clone, Debug)]
struct RlibSelection {
    crate_name: String,
    rlibs: Vec<PathBuf>,
    selected_rlib: PathBuf,
    matched_input_symbols: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct HostRetentionRequest {
    rustflags: Vec<String>,
    requested_symbols: BTreeSet<String>,
}

impl HostRetentionRequest {
    pub(super) fn rustflags(&self) -> &[String] {
        &self.rustflags
    }
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

/// Finds service rlibs whose members are selected by the relocatable linker.
pub(super) fn find_on_demand_rlibs(
    policy: &FrameVmPolicy,
    target_dir: &Path,
    target: &str,
    profile: &str,
    input_raw_symbols: &BTreeSet<&str>,
) -> Result<Vec<OnDemandRlib>, FrameVmStageError> {
    let mut retained = Vec::new();
    for crate_name in &policy.bundling.on_demand_rlibs {
        let rlibs = find_crate_rlibs(target_dir, target, profile, crate_name)?;
        let fallback_rlib = rlibs.last().cloned().ok_or_else(|| {
            FrameVmStageError::ObjectLink(format!(
                "FrameVM on-demand dependency rlib not found for {crate_name}"
            ))
        })?;
        let rlib = select_rlib_by_symbols(&rlibs, input_raw_symbols)?
            .map(|(rlib, _)| rlib)
            .unwrap_or(fallback_rlib);
        retained.push(OnDemandRlib {
            crate_name: crate_name.clone(),
            rlib,
        });
    }
    Ok(retained)
}

pub(super) fn find_policy_rlib_candidates(
    target_dir: &Path,
    target: &str,
    profile: &str,
    crate_names: &[String],
) -> Result<Vec<PathBuf>, FrameVmStageError> {
    match find_policy_rlib_candidates_in(target_dir, target, profile, crate_names) {
        Ok(files) => Ok(files),
        Err(primary_error) => {
            let dedicated_target_dir = target_dir.join("framevm-host-symbols");
            find_policy_rlib_candidates_in(
                &dedicated_target_dir,
                target,
                profile,
                crate_names,
            )
            .map_err(|fallback_error| {
                FrameVmStageError::ImportValidation(format!(
                    "host symbol rlib lookup failed in {} ({primary_error}) and {} ({fallback_error})",
                    target_dir.display(),
                    dedicated_target_dir.display()
                ))
            })
        }
    }
}

fn find_policy_rlib_candidates_in(
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

/// Links objects followed by archives whose members are extracted on demand.
pub(super) fn run_ld_relocatable_with_archives(
    output: &Path,
    objects: &[PathBuf],
    archives: &[PathBuf],
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
        .args(objects)
        .args(archives);
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

pub(super) fn pre_host_final_retention_request(
    shared_rustflags: &[&str],
    imports: &super::imports::ActualHostImports,
    host_symbol_files: &[PathBuf],
    supplemental_archives: &[PathBuf],
    response_file: &Path,
) -> Result<HostRetentionRequest, FrameVmStageError> {
    let host_side_symbols =
        host_side_retention_symbols_from_candidates(imports, host_symbol_files)?;
    retention_request(
        shared_rustflags,
        imports,
        &host_side_symbols,
        supplemental_archives,
        response_file,
    )
}

pub(super) fn final_host_retention_request(
    shared_rustflags: &[&str],
    imports: &super::imports::ActualHostImports,
    host_symbol_files: &[PathBuf],
    supplemental_archives: &[PathBuf],
    final_host_elf: &Path,
    response_file: &Path,
) -> Result<HostRetentionRequest, FrameVmStageError> {
    let host_side_symbols =
        host_side_retention_symbols_for_final_host(imports, host_symbol_files, final_host_elf)?;
    retention_request(
        shared_rustflags,
        imports,
        &host_side_symbols,
        supplemental_archives,
        response_file,
    )
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

fn retention_request(
    shared_rustflags: &[&str],
    imports: &super::imports::ActualHostImports,
    host_side_symbols: &BTreeSet<String>,
    supplemental_archives: &[PathBuf],
    response_file: &Path,
) -> Result<HostRetentionRequest, FrameVmStageError> {
    let requested_symbols = requested_retention_symbols(imports, host_side_symbols)?;
    let retention_archives =
        matching_retention_archives(imports, host_side_symbols, supplemental_archives)?;
    let retention_archives = materialize_stable_archives(&retention_archives, response_file)?;
    write_linker_response_file(response_file, &requested_symbols)?;

    let mut rustflags = shared_rustflags
        .iter()
        .map(|flag| (*flag).to_string())
        .collect::<Vec<_>>();
    if !requested_symbols.is_empty() {
        rustflags.push(format!("-C link-arg=@{}", response_file.display()));
    }
    for archive in retention_archives {
        rustflags.push(format!("-C link-arg={}", archive.display()));
    }

    Ok(HostRetentionRequest {
        rustflags,
        requested_symbols,
    })
}

fn materialize_stable_archives(
    archives: &BTreeSet<PathBuf>,
    response_file: &Path,
) -> Result<Vec<PathBuf>, FrameVmStageError> {
    let staging_dir = response_file.parent().ok_or_else(|| {
        FrameVmStageError::ObjectBuild(format!(
            "host retention response file has no parent: {}",
            response_file.display()
        ))
    })?;
    let stable_dir = staging_dir.join("host-retention-archives");
    fs::create_dir_all(&stable_dir).map_err(|error| {
        FrameVmStageError::ObjectBuild(format!(
            "failed to create stable host archive directory {}: {error}",
            stable_dir.display()
        ))
    })?;

    let mut stable_archives = Vec::with_capacity(archives.len());
    for archive in archives {
        let crate_name = rlib_crate_name(archive).ok_or_else(|| {
            FrameVmStageError::ImportValidation(format!(
                "host symbol archive has no Cargo rlib name: {}",
                archive.display()
            ))
        })?;
        let stable_archive = stable_dir.join(format!("lib{crate_name}.rlib"));
        let staged_archive = staging_dir.join(format!("host-retention-lib{crate_name}.rlib"));
        remove_file_if_exists(&staged_archive)?;
        fs::hard_link(archive, &staged_archive)
            .or_else(|_| fs::copy(archive, &staged_archive).map(|_| ()))
            .map_err(|error| {
                FrameVmStageError::ObjectBuild(format!(
                    "failed to stage host archive {} as {}: {error}",
                    archive.display(),
                    staged_archive.display()
                ))
            })?;
        fs::rename(&staged_archive, &stable_archive).map_err(|error| {
            FrameVmStageError::ObjectBuild(format!(
                "failed to publish stable host archive {}: {error}",
                stable_archive.display()
            ))
        })?;
        stable_archives.push(stable_archive);
    }
    Ok(stable_archives)
}

fn matching_retention_archives(
    imports: &super::imports::ActualHostImports,
    host_side_symbols: &BTreeSet<String>,
    host_symbol_files: &[PathBuf],
) -> Result<BTreeSet<PathBuf>, FrameVmStageError> {
    let imported_symbols = imports
        .iter()
        .map(|(raw_import, _)| raw_import.as_bytes())
        .collect::<BTreeSet<_>>();
    let host_side_symbols = host_side_symbols
        .iter()
        .map(String::as_bytes)
        .collect::<BTreeSet<_>>();
    let mut archives_by_crate = BTreeMap::<String, (usize, usize, SystemTime, PathBuf)>::new();
    for file in host_symbol_files {
        let defined_symbols = defined_raw_symbols(file)?;
        let import_match_count = defined_symbols
            .iter()
            .filter(|symbol| imported_symbols.contains(symbol.as_bytes()))
            .count();
        let host_match_count = defined_symbols
            .iter()
            .filter(|symbol| host_side_symbols.contains(symbol.as_bytes()))
            .count();
        if import_match_count == 0 && host_match_count == 0 {
            continue;
        }

        let crate_name = rlib_crate_name(file).ok_or_else(|| {
            FrameVmStageError::ImportValidation(format!(
                "host symbol archive has no Cargo rlib name: {}",
                file.display()
            ))
        })?;
        // Rustc already links the target's `alloc` crate. The `-u` entries in
        // the response file retain its requested symbols; appending another
        // `liballoc.rlib` also defines the allocator error handler.
        if crate_name == "alloc" {
            continue;
        }
        let candidate = (
            import_match_count,
            host_match_count,
            path_modified_time(file),
            file.clone(),
        );
        let selected = archives_by_crate
            .entry(crate_name.to_string())
            .or_insert_with(|| candidate.clone());
        if candidate > *selected {
            *selected = candidate;
        }
    }
    Ok(archives_by_crate
        .into_values()
        .map(|(_, _, _, path)| path)
        .collect())
}

fn rlib_crate_name(path: &Path) -> Option<&str> {
    path.file_name()?
        .to_str()?
        .strip_prefix("lib")?
        .strip_suffix(".rlib")?
        .rsplit_once('-')
        .map(|(crate_name, _)| crate_name)
}

fn requested_retention_symbols(
    imports: &super::imports::ActualHostImports,
    host_side_symbols: &BTreeSet<String>,
) -> Result<BTreeSet<String>, FrameVmStageError> {
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
    Ok(requested_symbols)
}

fn write_linker_response_file(
    response_file: &Path,
    requested_symbols: &BTreeSet<String>,
) -> Result<(), FrameVmStageError> {
    let mut response = String::new();
    for raw_name in requested_symbols {
        if raw_name.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(FrameVmStageError::ImportValidation(format!(
                "FrameVM host retention linker symbol contains whitespace: {raw_name}"
            )));
        }

        response.push_str("-u\n");
        response.push_str(raw_name);
        response.push('\n');
    }

    fs::write(response_file, response).map_err(|error| {
        FrameVmStageError::ObjectBuild(format!(
            "failed to write FrameVM host retention linker response file {}: {error}",
            response_file.display()
        ))
    })
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
            let mut candidate_symbols = unresolved_refs.clone();
            candidate_symbols.extend(selection.matched_input_symbols.iter().map(String::as_str));
            let Some((selected_rlib, _)) = select_rlib_by_symbols_preserving(
                &selection.rlibs,
                &candidate_symbols,
                &selection.matched_input_symbols,
            )?
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
    select_rlib_by_symbols_preserving(rlibs, raw_symbols, &[])
}

fn select_rlib_by_symbols_preserving(
    rlibs: &[PathBuf],
    raw_symbols: &BTreeSet<&str>,
    required_symbols: &[String],
) -> Result<Option<(PathBuf, Vec<String>)>, FrameVmStageError> {
    let mut best_match: Option<(PathBuf, Vec<String>)> = None;
    for rlib in rlibs.iter().rev() {
        let defined_symbols = defined_raw_symbols(rlib)?;
        if !required_symbols
            .iter()
            .all(|symbol| defined_symbols.contains(symbol))
        {
            continue;
        }
        let matched_symbols = defined_symbols
            .into_iter()
            .filter(|symbol| raw_symbols.contains(symbol.as_str()))
            .collect::<Vec<_>>();
        if matched_symbols.is_empty() {
            continue;
        }
        if best_match
            .as_ref()
            .is_none_or(|(_, best_symbols)| matched_symbols.len() > best_symbols.len())
        {
            best_match = Some((rlib.clone(), matched_symbols));
        }
    }
    Ok(best_match)
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

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use super::{find_policy_rlib_candidates, rlib_crate_name};

    #[test]
    fn parses_cargo_rlib_crate_name() {
        assert_eq!(
            rlib_crate_name(Path::new("target/deps/libcompiler_builtins-deadbeef.rlib")),
            Some("compiler_builtins")
        );
        assert_eq!(rlib_crate_name(Path::new("target/deps/libcore.rlib")), None);
    }

    #[test]
    fn policy_rlibs_fall_back_to_the_dedicated_host_symbol_target() {
        let temp_dir = tempfile::tempdir().unwrap();
        let target_dir = temp_dir.path().join("target");
        let dedicated_target_dir = target_dir.join("framevm-host-symbols");
        let dedicated_deps = dedicated_target_dir.join("x86_64-unknown-none/debug/deps");
        fs::create_dir_all(&dedicated_deps).unwrap();
        let dedicated_rlib = dedicated_deps.join("libcore-dedicated.rlib");
        fs::write(&dedicated_rlib, []).unwrap();
        assert_eq!(
            find_policy_rlib_candidates(
                &target_dir,
                "x86_64-unknown-none",
                "dev",
                &["core".to_string()]
            )
            .unwrap(),
            vec![dedicated_rlib]
        );

        let regular_deps = target_dir.join("x86_64-unknown-none/debug/deps");
        fs::create_dir_all(&regular_deps).unwrap();
        let regular_rlib = regular_deps.join("libcore-regular.rlib");
        fs::write(&regular_rlib, []).unwrap();
        assert_eq!(
            find_policy_rlib_candidates(
                &target_dir,
                "x86_64-unknown-none",
                "dev",
                &["core".to_string()]
            )
            .unwrap(),
            vec![regular_rlib]
        );
    }
}
