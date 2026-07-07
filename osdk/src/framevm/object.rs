// SPDX-License-Identifier: MPL-2.0

//! FrameVM service-object compilation, dependency bundling, and validation.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::Serialize;
use xmas_elf::{ElfFile, sections::SHF_ALLOC};

use crate::{
    commands::COMMON_CARGO_ARGS,
    config::scheme::Build,
    util::{DirGuard, get_kernel_crate, get_target_directory},
};

use super::{
    imports::{self, ActualHostImports},
    policy::FrameVmPolicy,
    process, report, retention, rustflags,
    types::{FrameVmBuildConfig, FrameVmStageError},
};

const FRAMEVM_PACKAGE: &str = "aster-framevm";
const DEFAULT_OBJECT_RELPATH: &str = "build/framevm/framevm.o";
const FRAMEVM_CFLAGS: &str = "-fno-PIE -fno-pic -fno-plt";
const FRAMEVM_RUSTFLAGS: &[&str] = &[
    "-C panic=abort",
    "-C relocation-model=static",
    "-C code-model=kernel",
    "-Z direct-access-external-data=yes",
    "-Z relax-elf-relocations=no",
    "-C link-arg=-no-pie",
    "-C relro-level=off",
    "-C force-unwind-tables=yes",
    "--check-cfg cfg(ktest)",
    "-C no-redzone=y",
    "-C target-feature=+ermsb",
    "-Zshare-generics=no",
];

#[derive(Clone, Debug)]
pub(super) struct FrameVmObjectArtifact {
    pub(super) path: PathBuf,
    pub(super) report_dir: PathBuf,
    pub(super) actual_imports: ActualHostImports,
    pub(super) dependency_summary: FrameVmDependencySummary,
}

impl FrameVmObjectArtifact {
    pub(super) fn with_published_paths(&self, path: PathBuf, report_dir: PathBuf) -> Self {
        Self {
            path,
            report_dir,
            actual_imports: self.actual_imports.clone(),
            dependency_summary: self.dependency_summary,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct FrameVmDependencySummary {
    retained_rlib_count: usize,
    bundled_object_count: usize,
}

impl FrameVmDependencySummary {
    fn new(retained_rlib_count: usize, bundled_object_count: usize) -> Self {
        Self {
            retained_rlib_count,
            bundled_object_count,
        }
    }

    pub(super) fn retained_rlib_count(self) -> usize {
        self.retained_rlib_count
    }

    pub(super) fn bundled_object_count(self) -> usize {
        self.bundled_object_count
    }
}

#[derive(Clone, Debug)]
pub(super) struct ObjectBuildContext<'a> {
    pub(super) workspace_root: &'a Path,
    pub(super) cargo_target_dir: &'a Path,
    pub(super) build: &'a Build,
    pub(super) config: &'a FrameVmBuildConfig,
}

#[derive(Clone, Debug)]
struct ImportSymbol {
    raw: String,
    demangled: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum ImportClass {
    AllowedHostDynamic,
    NonHostException,
    OrdinaryDependency,
    RawException,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
struct ClassifiedImport {
    raw: String,
    demangled: String,
    class: ImportClass,
    host_match_count: usize,
    host_matches: Vec<String>,
}

#[derive(Clone, Debug, Default)]
struct HostSymbolIndex {
    raw: BTreeMap<String, BTreeSet<String>>,
    demangled: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Serialize)]
struct BuildReport<'a> {
    input_object: String,
    output_object: String,
    retained_rlibs: Vec<RetainedRlibReport<'a>>,
    bundled_objects: Vec<String>,
    host_symbol_files: Vec<String>,
}

#[derive(Serialize)]
struct RetainedRlibReport<'a> {
    crate_name: &'a str,
    rlib: String,
    matched_input_symbols: &'a [String],
    object_count: usize,
}

#[derive(Serialize)]
struct ScanReport<'a> {
    object: String,
    import_count: usize,
    ordinary_dependency_markers: &'a [String],
    imports: &'a [ImportSymbolReport<'a>],
}

#[derive(Serialize)]
struct ImportSymbolReport<'a> {
    raw: &'a str,
    demangled: &'a str,
}

#[derive(Serialize)]
struct ValidateReport<'a> {
    object: String,
    valid: bool,
    error_count: usize,
    host_symbol_files: Vec<String>,
    class_counts: BTreeMap<ImportClass, usize>,
    errors: &'a [String],
    imports: &'a [ClassifiedImport],
}

#[derive(Serialize)]
struct RetentionReport<'a> {
    retention_hook_ran: bool,
    object: String,
    retained_import_count: usize,
    retained_ordinary_rlibs: &'a [String],
}

impl Serialize for ImportSymbol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ImportSymbolReport {
            raw: &self.raw,
            demangled: &self.demangled,
        }
        .serialize(serializer)
    }
}

pub(super) fn default_object_output(workspace_root: &Path) -> PathBuf {
    workspace_root.join(DEFAULT_OBJECT_RELPATH)
}

pub(super) fn build_framevm_object(
    context: &ObjectBuildContext<'_>,
) -> Result<FrameVmObjectArtifact, FrameVmStageError> {
    if context.config.target != "x86_64-unknown-none" {
        return Err(FrameVmStageError::ObjectBuild(format!(
            "unsupported framevm target {}; only x86_64-unknown-none is supported",
            context.config.target
        )));
    }

    let object_output = context
        .config
        .object_output
        .clone()
        .unwrap_or_else(|| default_object_output(context.workspace_root));
    let object_output = absolute_path(context.workspace_root, object_output);
    let report_dir = object_output
        .parent()
        .ok_or_else(|| {
            FrameVmStageError::ObjectBuild(format!(
                "object output has no parent: {}",
                object_output.display()
            ))
        })?
        .to_path_buf();
    fs::create_dir_all(&report_dir).map_err(|error| {
        FrameVmStageError::ObjectBuild(format!(
            "failed to create object output directory {}: {error}",
            report_dir.display()
        ))
    })?;

    let service_target_dir = persistent_service_target_dir(context.workspace_root)?;
    fs::create_dir_all(&service_target_dir).map_err(|error| {
        FrameVmStageError::ObjectBuild(format!(
            "failed to create framevm service target directory {}: {error}",
            service_target_dir.display()
        ))
    })?;

    let initial_object = compile_initial_object(context, &report_dir, &service_target_dir)?;
    let policy = FrameVmPolicy::load_default()?;
    let linked_object = link_final_object(
        &policy,
        &initial_object,
        &object_output,
        &report_dir,
        &service_target_dir,
        context.cargo_target_dir,
        &context.config.target,
        context.build,
        context.workspace_root,
    )?;

    let artifact = FrameVmObjectArtifact {
        path: object_output,
        report_dir,
        actual_imports: linked_object.actual_imports,
        dependency_summary: linked_object.dependency_summary,
    };
    report::write_actual_import_report(&artifact)?;
    Ok(artifact)
}

fn compile_initial_object(
    context: &ObjectBuildContext<'_>,
    report_dir: &Path,
    service_target_dir: &Path,
) -> Result<PathBuf, FrameVmStageError> {
    let _dir_guard = DirGuard::change_dir(context.workspace_root);

    remove_matching_objects(report_dir)?;
    let explicit_output = report_dir.join("framevm-initial.o");
    remove_file_if_exists(&explicit_output)?;

    let mut framevm_rustflags = rustflags::SHARED_RUSTFLAGS.to_vec();
    framevm_rustflags.extend(FRAMEVM_RUSTFLAGS);

    let mut command = process::command("cargo");
    command.env("RUSTFLAGS", framevm_rustflags.join(" "));
    command.env("CFLAGS_x86_64-unknown-none", FRAMEVM_CFLAGS);
    command.env("CARGO_INCREMENTAL", "0");
    command
        .arg("rustc")
        .arg("--quiet")
        .arg("-p")
        .arg(FRAMEVM_PACKAGE)
        .arg("--lib")
        .arg("--target")
        .arg(&context.config.target)
        .arg("--target-dir")
        .arg(service_target_dir)
        .args(COMMON_CARGO_ARGS)
        .arg(format!("--profile={}", context.build.profile));

    if !context.config.features.is_empty() {
        command
            .arg("--features")
            .arg(context.config.features.join(" "));
    }
    if context.config.no_default_features {
        command.arg("--no-default-features");
    }

    command
        .arg("--")
        .arg("--emit=obj")
        .arg("-o")
        .arg(&explicit_output);

    process::run_status(
        command,
        "compiling aster-framevm service object",
        FrameVmStageError::ObjectBuild,
    )?;

    newest_generated_object(report_dir)
        .or_else(|| explicit_output.exists().then_some(explicit_output.clone()))
        .ok_or_else(|| {
            FrameVmStageError::ObjectBuild(format!(
                "framevm object not found in {} after cargo rustc",
                report_dir.display()
            ))
        })
}

fn persistent_service_target_dir(workspace_root: &Path) -> Result<PathBuf, FrameVmStageError> {
    let default_object_output = default_object_output(workspace_root);
    let report_dir = default_object_output.parent().ok_or_else(|| {
        FrameVmStageError::ObjectBuild(format!(
            "default framevm object output has no parent: {}",
            default_object_output.display()
        ))
    })?;

    Ok(report_dir.join("service-target"))
}

fn link_final_object(
    policy: &FrameVmPolicy,
    input_object: &Path,
    output_object: &Path,
    report_dir: &Path,
    service_target_dir: &Path,
    host_target_dir: &Path,
    target: &str,
    build: &Build,
    workspace_root: &Path,
) -> Result<LinkedFrameVmObject, FrameVmStageError> {
    let dependency_dir = report_dir.join("bundled-deps");
    let dependency_object = report_dir.join("framevm-bundled-deps.o");
    remove_path_if_exists(&dependency_dir)?;
    remove_file_if_exists(&dependency_object)?;
    fs::create_dir_all(&dependency_dir).map_err(|error| {
        FrameVmStageError::ObjectLink(format!(
            "failed to create dependency staging directory {}: {error}",
            dependency_dir.display()
        ))
    })?;

    let input_imports = scan_imports(input_object)?;
    let input_raw_symbols = input_imports
        .iter()
        .map(|symbol| symbol.raw.as_str())
        .collect::<BTreeSet<_>>();
    let retained_rlibs = retention::retain_ordinary_rlibs(
        policy,
        service_target_dir,
        target,
        &build.profile,
        &dependency_dir,
        &input_raw_symbols,
    )?;
    let bundled_objects = retention::collect_object_files(&dependency_dir)?;
    if bundled_objects.is_empty() {
        return Err(FrameVmStageError::ObjectLink(
            "ordinary dependency retention produced no objects".to_string(),
        ));
    }

    retention::run_ld_relocatable(&dependency_object, &bundled_objects)?;
    retention::run_ld_relocatable(
        output_object,
        &[input_object.to_path_buf(), dependency_object.clone()],
    )?;
    validate_no_allocated_cpu_local_section(output_object)?;

    let final_imports = scan_imports(output_object)?;
    let actual_imports = imports::collect_actual_host_imports(output_object)?;
    let mut host_symbol_files =
        find_or_build_host_symbol_rlibs(policy, host_target_dir, target, build, workspace_root)?;
    host_symbol_files.sort();
    host_symbol_files.dedup();
    let host_index = read_host_symbol_index(&host_symbol_files)?;
    let classified_imports = classify_imports(policy, &final_imports, &host_index);
    let validation_errors = validation_errors(&classified_imports);

    write_reports(
        policy,
        report_dir,
        input_object,
        output_object,
        &retained_rlibs,
        &bundled_objects,
        &host_symbol_files,
        &final_imports,
        &classified_imports,
        &validation_errors,
    )?;

    remove_path_if_exists(&dependency_dir)?;
    remove_file_if_exists(&dependency_object)?;

    if validation_errors.is_empty() {
        Ok(LinkedFrameVmObject {
            actual_imports,
            dependency_summary: FrameVmDependencySummary::new(
                retained_rlibs.len(),
                bundled_objects.len(),
            ),
        })
    } else {
        Err(FrameVmStageError::ImportValidation(
            validation_errors.join("; "),
        ))
    }
}

fn validate_no_allocated_cpu_local_section(object: &Path) -> Result<(), FrameVmStageError> {
    let bytes = fs::read(object).map_err(|error| {
        FrameVmStageError::ObjectLink(format!(
            "failed to read final FrameVM object {} while checking CPU-local sections: {error}",
            object.display()
        ))
    })?;
    let elf = ElfFile::new(&bytes).map_err(|error| {
        FrameVmStageError::ObjectLink(format!(
            "failed to parse final FrameVM object {} while checking CPU-local sections: {error:?}",
            object.display()
        ))
    })?;

    for section in elf.section_iter() {
        let Ok(name) = section.get_name(&elf) else {
            continue;
        };
        if name == ".cpu_local" && section.flags() & SHF_ALLOC != 0 {
            return Err(FrameVmStageError::ObjectLink(format!(
                "final FrameVM object {} contains allocated `.cpu_local` section of {} bytes; remove Host OSTD CPU-local providers or allocator CPU-local caches from FrameVM-loaded dependencies",
                object.display(),
                section.size(),
            )));
        }
    }

    Ok(())
}

fn find_or_build_host_symbol_rlibs(
    policy: &FrameVmPolicy,
    host_target_dir: &Path,
    target: &str,
    build: &Build,
    workspace_root: &Path,
) -> Result<Vec<PathBuf>, FrameVmStageError> {
    match retention::find_policy_rlibs(
        host_target_dir,
        target,
        &build.profile,
        &policy.host_symbols.rlibs,
    ) {
        Ok(files) => Ok(files),
        Err(first_error) => {
            build_host_symbol_rlibs(workspace_root, host_target_dir, target, build)?;
            retention::find_policy_rlibs(
                host_target_dir,
                target,
                &build.profile,
                &policy.host_symbols.rlibs,
            )
            .map_err(|second_error| {
                FrameVmStageError::ObjectBuild(format!(
                    "failed to build host symbol rlibs after initial lookup failed ({first_error}): {second_error}"
                ))
            })
        }
    }
}

fn build_host_symbol_rlibs(
    workspace_root: &Path,
    host_target_dir: &Path,
    target: &str,
    build: &Build,
) -> Result<(), FrameVmStageError> {
    let _dir_guard = DirGuard::change_dir(workspace_root);
    let kernel_crate = get_kernel_crate();

    let mut host_rustflags = rustflags::SHARED_RUSTFLAGS.to_vec();
    host_rustflags.extend([
        "-C no-redzone=y",
        "-C code-model=kernel",
        "-Z direct-access-external-data=yes",
        "-C target-feature=+ermsb",
    ]);
    if !build.rustflags.is_empty() {
        host_rustflags.push(build.rustflags.as_str());
    }

    let mut command = process::command("cargo");
    command.env("RUSTFLAGS", host_rustflags.join(" "));
    command.env("CFLAGS_x86_64-unknown-none", FRAMEVM_CFLAGS);
    command.env("CARGO_INCREMENTAL", "0");
    command
        .arg("build")
        .arg("--quiet")
        .arg("-p")
        .arg(kernel_crate.name)
        .arg("--target")
        .arg(target)
        .arg("--target-dir")
        .arg(host_target_dir)
        .args(COMMON_CARGO_ARGS)
        .arg(format!("--profile={}", build.profile));

    if !build.features.is_empty() {
        command.arg("--features").arg(build.features.join(" "));
    }
    if build.no_default_features {
        command.arg("--no-default-features");
    }
    for override_config in &build.override_configs {
        command.arg("--config").arg(override_config);
    }

    process::run_status(
        command,
        "building framevm host symbol rlibs",
        FrameVmStageError::ObjectBuild,
    )
}

struct LinkedFrameVmObject {
    actual_imports: ActualHostImports,
    dependency_summary: FrameVmDependencySummary,
}

fn scan_imports(object: &Path) -> Result<Vec<ImportSymbol>, FrameVmStageError> {
    let raw_symbols = retention::undefined_raw_symbols(object)?;
    let demangled_symbols = retention::undefined_demangled_symbols(object)?;
    let mut imports = raw_symbols
        .iter()
        .enumerate()
        .map(|(index, raw)| ImportSymbol {
            raw: raw.clone(),
            demangled: demangled_symbols
                .get(index)
                .cloned()
                .unwrap_or_else(|| raw.clone()),
        })
        .collect::<Vec<_>>();
    imports.sort_by(|left, right| {
        left.demangled
            .cmp(&right.demangled)
            .then_with(|| left.raw.cmp(&right.raw))
    });
    imports.dedup_by(|left, right| left.raw == right.raw && left.demangled == right.demangled);
    Ok(imports)
}

fn read_host_symbol_index(files: &[PathBuf]) -> Result<HostSymbolIndex, FrameVmStageError> {
    let mut index = HostSymbolIndex::default();
    for file in files {
        let file_label = report::stable_path_string(file);
        for symbol in retention::defined_raw_symbols(file)? {
            index
                .raw
                .entry(symbol.clone())
                .or_default()
                .insert(format!("{file_label}:{symbol}"));
        }
        for symbol in retention::defined_demangled_symbols(file)? {
            index
                .demangled
                .entry(symbol.clone())
                .or_default()
                .insert(format!("{file_label}:{symbol}"));
        }
    }
    Ok(index)
}

fn classify_imports(
    policy: &FrameVmPolicy,
    imports: &[ImportSymbol],
    host_index: &HostSymbolIndex,
) -> Vec<ClassifiedImport> {
    imports
        .iter()
        .map(|symbol| {
            let class = classify_import(policy, symbol);
            let mut host_matches = BTreeSet::new();
            if class == ImportClass::AllowedHostDynamic {
                if let Some(matches) = host_index.raw.get(&symbol.raw) {
                    host_matches.extend(matches.iter().cloned());
                }
                if host_matches.is_empty()
                    && let Some(matches) = host_index.demangled.get(&symbol.demangled)
                {
                    host_matches.extend(matches.iter().cloned());
                }
            }

            ClassifiedImport {
                raw: symbol.raw.clone(),
                demangled: symbol.demangled.clone(),
                class,
                host_match_count: host_matches.len(),
                host_matches: host_matches.into_iter().collect(),
            }
        })
        .collect()
}

fn classify_import(policy: &FrameVmPolicy, symbol: &ImportSymbol) -> ImportClass {
    if policy
        .validation
        .raw_exception_symbols
        .iter()
        .any(|allowed| {
            allowed == &symbol.raw
                || allowed == &symbol.demangled
                || symbol.demangled.contains(allowed)
        })
    {
        return ImportClass::RawException;
    }

    if policy
        .bundling
        .ordinary_dependency_markers
        .iter()
        .any(|marker| ordinary_dependency_marker_matches(&symbol.demangled, marker))
    {
        return ImportClass::OrdinaryDependency;
    }

    if policy
        .validation
        .non_host_exception_prefixes
        .iter()
        .any(|prefix| symbol.demangled.starts_with(prefix) || symbol.demangled.contains(prefix))
        || policy
            .validation
            .non_host_exception_contains
            .iter()
            .any(|needle| symbol.demangled.contains(needle))
    {
        return ImportClass::NonHostException;
    }

    if policy
        .validation
        .allowed_host_dynamic_prefixes
        .iter()
        .any(|prefix| symbol.demangled.starts_with(prefix) || symbol.demangled.contains(prefix))
        || policy
            .validation
            .allowed_host_dynamic_contains
            .iter()
            .any(|needle| symbol.demangled.contains(needle))
    {
        return ImportClass::AllowedHostDynamic;
    }

    ImportClass::Unknown
}

fn ordinary_dependency_marker_matches(demangled: &str, marker: &str) -> bool {
    if marker.is_empty() {
        return false;
    }

    if demangled.starts_with(marker) {
        return true;
    }

    if demangled
        .strip_prefix('<')
        .is_some_and(|trimmed| trimmed.starts_with(marker))
    {
        return true;
    }

    demangled.contains(&format!(" as {marker}"))
}

fn validation_errors(imports: &[ClassifiedImport]) -> Vec<String> {
    let mut errors = Vec::new();
    for import in imports {
        match import.class {
            ImportClass::AllowedHostDynamic if import.host_match_count == 0 => {
                errors.push(format!(
                    "missing host symbol for {} ({})",
                    import.demangled, import.raw
                ))
            }
            ImportClass::AllowedHostDynamic if import.host_match_count > 1 => errors.push(format!(
                "ambiguous host symbol for {} ({} matches)",
                import.demangled, import.host_match_count
            )),
            ImportClass::OrdinaryDependency => errors.push(format!(
                "ordinary dependency import was not retained: {} ({})",
                import.demangled, import.raw
            )),
            ImportClass::Unknown => errors.push(format!(
                "unknown framevm import: {} ({})",
                import.demangled, import.raw
            )),
            _ => {}
        }
    }
    errors
}

#[expect(clippy::too_many_arguments)]
fn write_reports(
    policy: &FrameVmPolicy,
    report_dir: &Path,
    input_object: &Path,
    output_object: &Path,
    retained_rlibs: &[retention::RetainedRlib],
    bundled_objects: &[PathBuf],
    host_symbol_files: &[PathBuf],
    final_imports: &[ImportSymbol],
    classified_imports: &[ClassifiedImport],
    validation_errors: &[String],
) -> Result<(), FrameVmStageError> {
    let retained_rlibs_report = retained_rlibs
        .iter()
        .map(|retained| RetainedRlibReport {
            crate_name: &retained.crate_name,
            rlib: report::stable_path_string(&retained.rlib),
            matched_input_symbols: &retained.matched_input_symbols,
            object_count: retained.object_count,
        })
        .collect::<Vec<_>>();
    write_json(
        &report_dir.join("build-object-report.json"),
        &BuildReport {
            input_object: report::stable_path_string(input_object),
            output_object: report::stable_path_string(output_object),
            retained_rlibs: retained_rlibs_report,
            bundled_objects: bundled_objects
                .iter()
                .map(|path| report::stable_path_string(path))
                .collect(),
            host_symbol_files: host_symbol_files
                .iter()
                .map(|path| report::stable_path_string(path))
                .collect(),
        },
    )?;

    let import_reports = final_imports
        .iter()
        .map(|import| ImportSymbolReport {
            raw: &import.raw,
            demangled: &import.demangled,
        })
        .collect::<Vec<_>>();
    write_json(
        &report_dir.join("scan-imports-report.json"),
        &ScanReport {
            object: report::stable_path_string(output_object),
            import_count: final_imports.len(),
            ordinary_dependency_markers: &policy.bundling.ordinary_dependency_markers,
            imports: &import_reports,
        },
    )?;

    let mut class_counts = BTreeMap::<ImportClass, usize>::new();
    for import in classified_imports {
        *class_counts.entry(import.class).or_default() += 1;
    }
    write_json(
        &report_dir.join("validate-imports-report.json"),
        &ValidateReport {
            object: report::stable_path_string(output_object),
            valid: validation_errors.is_empty(),
            error_count: validation_errors.len(),
            host_symbol_files: host_symbol_files
                .iter()
                .map(|path| report::stable_path_string(path))
                .collect(),
            class_counts,
            errors: validation_errors,
            imports: classified_imports,
        },
    )?;

    write_json(
        &report_dir.join("retain-report.json"),
        &RetentionReport {
            retention_hook_ran: true,
            object: report::stable_path_string(output_object),
            retained_import_count: final_imports.len(),
            retained_ordinary_rlibs: &policy.bundling.ordinary_rlibs,
        },
    )
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), FrameVmStageError> {
    let content = serde_json::to_string_pretty(value).map_err(|error| {
        FrameVmStageError::ObjectBuild(format!("failed to serialize {}: {error}", path.display()))
    })?;
    fs::write(path, content).map_err(|error| {
        FrameVmStageError::ObjectBuild(format!("failed to write {}: {error}", path.display()))
    })
}

fn newest_generated_object(report_dir: &Path) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    let entries = fs::read_dir(report_dir).ok()?;
    for entry in entries {
        let path = entry.ok()?.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if file_name.starts_with("framevm-") && file_name.ends_with(".o") {
            candidates.push(path);
        }
    }
    candidates
        .into_iter()
        .max_by(|left, right| path_modified_time(left).cmp(&path_modified_time(right)))
}

fn remove_matching_objects(report_dir: &Path) -> Result<(), FrameVmStageError> {
    let entries = fs::read_dir(report_dir).map_err(|error| {
        FrameVmStageError::ObjectBuild(format!("failed to read {}: {error}", report_dir.display()))
    })?;
    for entry in entries {
        let path = entry
            .map_err(|error| {
                FrameVmStageError::ObjectBuild(format!(
                    "failed to read entry under {}: {error}",
                    report_dir.display()
                ))
            })?
            .path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if file_name.starts_with("framevm-") && file_name.ends_with(".o") {
            remove_file_if_exists(&path)?;
        }
    }
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> Result<(), FrameVmStageError> {
    if path.is_dir() {
        fs::remove_dir_all(path).map_err(|error| {
            FrameVmStageError::ObjectLink(format!("failed to remove {}: {error}", path.display()))
        })
    } else {
        remove_file_if_exists(path)
    }
}

fn remove_file_if_exists(path: &Path) -> Result<(), FrameVmStageError> {
    if path.exists() {
        fs::remove_file(path).map_err(|error| {
            FrameVmStageError::ObjectLink(format!("failed to remove {}: {error}", path.display()))
        })?;
    }
    Ok(())
}

fn absolute_path(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn path_modified_time(path: &Path) -> SystemTime {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

pub(super) fn cargo_target_directory() -> PathBuf {
    get_target_directory()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_dependency_markers_match_crate_paths_without_module_false_positives() {
        assert!(ordinary_dependency_marker_matches(
            "log::__private_api::loc",
            "log::"
        ));
        assert!(ordinary_dependency_marker_matches(
            "<log::__private_api::GlobalLogger as log::Log>::log",
            "log::"
        ));
        assert!(ordinary_dependency_marker_matches(
            "<u8 as funty::Integral>::count_ones",
            "funty::"
        ));
        assert!(!ordinary_dependency_marker_matches(
            "aster_framevisor::log::DYNAMIC_MAX_LEVEL",
            "log::"
        ));
    }
}
