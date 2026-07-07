// SPDX-License-Identifier: MPL-2.0

//! Human-readable FrameVM transaction reports.

use std::{
    fs,
    path::{Component, Path, PathBuf},
    time::Instant,
};

use serde::Serialize;

use crate::bundle::FrameVmArtifactSet;

use super::{
    host::{AmbiguousHostSymbol, HostImportValidation, HostSymbolMatch},
    identity::{
        FrameVmArtifactSetMetadata, FrameVmExportManifestArtifact, FrameVmExportRequestArtifact,
        FrameVmStageInputIdentities, FrameVmTransactionIdentity, RawSymbolCompatibilityContext,
        TransactionHashInput,
    },
    imports::{ActualHostImports, RawSymbolName, RelocationLocation},
    metadata::FrameVmMetadataArtifact,
    object::FrameVmObjectArtifact,
    package::InitramfsArtifact,
    symbols::FrameVmSymbolsArtifact,
    types::FrameVmStageError,
};

#[derive(Serialize)]
struct BuildIndex<'a> {
    contract: &'static str,
    object: String,
    object_size_bytes: u64,
    framevm_symbols: String,
    framevm_symbols_hash: String,
    framevm_symbols_count: usize,
    framevm_symbols_size_bytes: usize,
    framevm_metadata: String,
    framevm_metadata_hash: String,
    framevm_metadata_size_bytes: usize,
    framevm_export_manifest: String,
    framevm_export_manifest_hash: String,
    framevm_export_manifest_size_bytes: usize,
    framevm_export_request: String,
    framevm_export_request_hash: String,
    framevm_export_request_size_bytes: usize,
    transaction_id: String,
    transaction_hash_algorithm: &'static str,
    transaction_hash_inputs: &'a [TransactionHashInput],
    raw_symbol_compatibility: &'a RawSymbolCompatibilityContext,
    host_elf_hash: String,
    actual_imports_hash: String,
    framevm_artifact_set: FrameVmArtifactSet,
    stage_input_identities: &'a FrameVmStageInputIdentities,
    initramfs: String,
    bundle: String,
    validation_status: &'static str,
}

#[derive(Serialize)]
struct ActualImportsReport {
    object: String,
    import_count: usize,
    imports: Vec<ActualImportEntryReport>,
}

#[derive(Serialize)]
struct ActualImportEntryReport {
    raw_symbol_name: String,
    raw_symbol_name_hex: String,
    relocation_count: usize,
    relocation_locations: Vec<RelocationLocationReport>,
}

#[derive(Serialize)]
struct RelocationLocationReport {
    relocation_section_index: usize,
    relocation_entry_index: usize,
    target_section_index: usize,
    target_offset: u64,
    relocation_type: u32,
}

#[derive(Serialize)]
struct FinalHostValidationReport {
    object: String,
    host_elf: String,
    exact_match: bool,
    import_count: usize,
    matched_count: usize,
    missing_count: usize,
    ambiguous_count: usize,
    matches: Vec<HostSymbolMatchReport>,
    missing_imports: Vec<RawSymbolReport>,
    ambiguous_imports: Vec<AmbiguousHostSymbolReport>,
}

#[derive(Serialize)]
struct HostSymbolMatchReport {
    import_name: RawSymbolReport,
    exported_name: RawSymbolReport,
    value: u64,
    value_hex: String,
    size: u64,
    kind: String,
    binding: String,
}

#[derive(Serialize)]
struct AmbiguousHostSymbolReport {
    import_name: RawSymbolReport,
    definitions: Vec<HostSymbolDefinitionReport>,
}

#[derive(Serialize)]
struct HostSymbolDefinitionReport {
    name: RawSymbolReport,
    value: u64,
    value_hex: String,
    size: u64,
    kind: String,
    binding: String,
}

#[derive(Serialize)]
struct RawSymbolReport {
    raw_symbol_name: String,
    raw_symbol_name_hex: String,
}

#[derive(Clone, Debug, Default)]
pub(super) struct StageTimings {
    stages: Vec<StageTiming>,
}

#[derive(Clone, Debug, Serialize)]
struct StageTiming {
    stage: &'static str,
    elapsed_ms: u128,
}

#[derive(Serialize)]
struct StageTimingReport<'a> {
    contract: &'static str,
    workflow: &'static str,
    stages: &'a [StageTiming],
    total_elapsed_ms: u128,
}

impl StageTimings {
    pub(super) fn new() -> Self {
        Self { stages: Vec::new() }
    }

    pub(super) fn measure<T>(
        &mut self,
        stage: &'static str,
        operation: impl FnOnce() -> Result<T, FrameVmStageError>,
    ) -> Result<T, FrameVmStageError> {
        let started_at = Instant::now();
        let result = operation();
        self.stages.push(StageTiming {
            stage,
            elapsed_ms: started_at.elapsed().as_millis(),
        });
        result
    }

    pub(super) fn measure_value<T>(
        &mut self,
        stage: &'static str,
        operation: impl FnOnce() -> T,
    ) -> T {
        let started_at = Instant::now();
        let value = operation();
        self.stages.push(StageTiming {
            stage,
            elapsed_ms: started_at.elapsed().as_millis(),
        });
        value
    }

    pub(super) fn record(&mut self, stage: &'static str, elapsed_ms: u128) {
        self.stages.push(StageTiming { stage, elapsed_ms });
    }

    fn total_elapsed_ms(&self) -> u128 {
        self.stages.iter().map(|stage| stage.elapsed_ms).sum()
    }
}

pub(super) fn write_build_index(
    object: &FrameVmObjectArtifact,
    symbols: &FrameVmSymbolsArtifact,
    metadata: &FrameVmMetadataArtifact,
    export_manifest: &FrameVmExportManifestArtifact,
    export_request: &FrameVmExportRequestArtifact,
    transaction_identity: &FrameVmTransactionIdentity,
    artifact_set: &FrameVmArtifactSetMetadata,
    stage_input_identities: &FrameVmStageInputIdentities,
    initramfs: &InitramfsArtifact,
    bundle: &Path,
) -> Result<(), FrameVmStageError> {
    let object_size_bytes = fs::metadata(&object.path)
        .map_err(|error| {
            FrameVmStageError::ObjectBuild(format!(
                "failed to inspect {}: {error}",
                object.path.display()
            ))
        })?
        .len();
    let index = BuildIndex {
        contract: "framevm-service-build-loading",
        object: stable_path_string(&object.path),
        object_size_bytes,
        framevm_symbols: stable_path_string(symbols.path()),
        framevm_symbols_hash: symbols.payload_hash().hex(),
        framevm_symbols_count: symbols.symbol_count(),
        framevm_symbols_size_bytes: symbols.payload_size(),
        framevm_metadata: stable_path_string(metadata.path()),
        framevm_metadata_hash: metadata.payload_hash().hex(),
        framevm_metadata_size_bytes: metadata.payload_size(),
        framevm_export_manifest: stable_path_string(export_manifest.path()),
        framevm_export_manifest_hash: transaction_identity.export_manifest_hash().hex(),
        framevm_export_manifest_size_bytes: export_manifest.payload_size(),
        framevm_export_request: stable_path_string(export_request.path()),
        framevm_export_request_hash: export_request.payload_hash().hex(),
        framevm_export_request_size_bytes: export_request.payload_size(),
        transaction_id: transaction_identity.transaction_id().hex(),
        transaction_hash_algorithm: "sha256",
        transaction_hash_inputs: transaction_identity.hash_inputs(),
        raw_symbol_compatibility: transaction_identity.raw_symbol_compatibility(),
        host_elf_hash: transaction_identity.host_elf_hash().hex(),
        actual_imports_hash: transaction_identity.actual_imports_hash().hex(),
        framevm_artifact_set: artifact_set.bundle_manifest_entry(),
        stage_input_identities,
        initramfs: stable_path_string(&initramfs.path),
        bundle: stable_path_string(bundle),
        validation_status: "passed",
    };
    let content = serde_json::to_string_pretty(&index).map_err(|error| {
        FrameVmStageError::ObjectBuild(format!("failed to serialize build index: {error}"))
    })?;
    fs::write(build_index_path(object), content).map_err(|error| {
        FrameVmStageError::ObjectBuild(format!("failed to write build index: {error}"))
    })
}

pub(super) fn write_stage_timing_report(
    report_dir: &Path,
    workflow: &'static str,
    timings: &StageTimings,
) -> Result<(), FrameVmStageError> {
    write_json(
        &report_dir.join(format!("{workflow}-timings-report.json")),
        &StageTimingReport {
            contract: "framevm-service-build-loading",
            workflow,
            stages: &timings.stages,
            total_elapsed_ms: timings.total_elapsed_ms(),
        },
    )
}

pub(super) fn write_actual_import_report(
    object: &FrameVmObjectArtifact,
) -> Result<(), FrameVmStageError> {
    write_json(
        &object.report_dir.join("actual-imports-report.json"),
        &ActualImportsReport {
            object: stable_path_string(object.actual_imports.object()),
            import_count: object.actual_imports.len(),
            imports: actual_import_entries(&object.actual_imports),
        },
    )
}

pub(super) fn write_final_host_validation_report(
    object: &FrameVmObjectArtifact,
    validation: &HostImportValidation,
) -> Result<(), FrameVmStageError> {
    write_json(
        &object.report_dir.join("final-host-validation-report.json"),
        &FinalHostValidationReport {
            object: stable_path_string(&object.path),
            host_elf: stable_path_string(validation.host_elf().path()),
            exact_match: validation.is_exact_match(),
            import_count: object.actual_imports.len(),
            matched_count: validation.matches().len(),
            missing_count: validation.missing_imports().len(),
            ambiguous_count: validation.ambiguous_imports().len(),
            matches: host_symbol_matches(validation.matches()),
            missing_imports: raw_symbols(validation.missing_imports()),
            ambiguous_imports: ambiguous_host_symbols(validation.ambiguous_imports()),
        },
    )
}

fn build_index_path(object: &FrameVmObjectArtifact) -> PathBuf {
    object.report_dir.join("build-index.json")
}

fn actual_import_entries(imports: &ActualHostImports) -> Vec<ActualImportEntryReport> {
    imports
        .iter()
        .map(|(name, evidence)| ActualImportEntryReport {
            raw_symbol_name: name.display_lossy(),
            raw_symbol_name_hex: name.hex(),
            relocation_count: evidence.relocation_count(),
            relocation_locations: relocation_locations(evidence.relocation_locations()),
        })
        .collect()
}

fn relocation_locations(locations: &[RelocationLocation]) -> Vec<RelocationLocationReport> {
    locations
        .iter()
        .map(|location| RelocationLocationReport {
            relocation_section_index: location.relocation_section_index(),
            relocation_entry_index: location.relocation_entry_index(),
            target_section_index: location.target_section_index(),
            target_offset: location.target_offset(),
            relocation_type: location.relocation_type(),
        })
        .collect()
}

fn host_symbol_matches(matches: &[HostSymbolMatch]) -> Vec<HostSymbolMatchReport> {
    matches
        .iter()
        .map(|symbol_match| HostSymbolMatchReport {
            import_name: raw_symbol(symbol_match.import_name()),
            exported_name: raw_symbol(symbol_match.exported_name()),
            value: symbol_match.value(),
            value_hex: format!("0x{:x}", symbol_match.value()),
            size: symbol_match.size(),
            kind: symbol_match.kind().to_string(),
            binding: symbol_match.binding().to_string(),
        })
        .collect()
}

fn raw_symbols(symbols: &[RawSymbolName]) -> Vec<RawSymbolReport> {
    symbols.iter().map(raw_symbol).collect()
}

fn ambiguous_host_symbols(symbols: &[AmbiguousHostSymbol]) -> Vec<AmbiguousHostSymbolReport> {
    symbols
        .iter()
        .map(|symbol| AmbiguousHostSymbolReport {
            import_name: raw_symbol(symbol.import_name()),
            definitions: symbol
                .definitions()
                .iter()
                .map(|definition| HostSymbolDefinitionReport {
                    name: raw_symbol(definition.name()),
                    value: definition.value(),
                    value_hex: format!("0x{:x}", definition.value()),
                    size: definition.size(),
                    kind: definition.kind().to_string(),
                    binding: definition.binding().to_string(),
                })
                .collect(),
        })
        .collect()
}

fn raw_symbol(symbol: &RawSymbolName) -> RawSymbolReport {
    RawSymbolReport {
        raw_symbol_name: symbol.display_lossy(),
        raw_symbol_name_hex: symbol.hex(),
    }
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), FrameVmStageError> {
    let content = serde_json::to_string_pretty(value).map_err(|error| {
        FrameVmStageError::ObjectBuild(format!("failed to serialize {}: {error}", path.display()))
    })?;
    fs::write(path, content).map_err(|error| {
        FrameVmStageError::ObjectBuild(format!("failed to write {}: {error}", path.display()))
    })
}

pub(super) fn stable_path_string(path: &Path) -> String {
    let components = path
        .components()
        .filter_map(path_component_text)
        .collect::<Vec<_>>();
    if components.is_empty() {
        return ".".to_string();
    }

    if let Some(index) = components
        .iter()
        .position(|component| component.starts_with(".framevm-staging-"))
    {
        return join_components(&components[index + 1..]);
    }

    for anchor in ["build", "target", "test", "kernel", "services", "osdk"] {
        if let Some(index) = components.iter().position(|component| component == anchor) {
            return join_components(&components[index..]);
        }
    }

    let tail_start = components.len().saturating_sub(2);
    join_components(&components[tail_start..])
}

fn path_component_text(component: Component<'_>) -> Option<String> {
    match component {
        Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
        Component::CurDir => Some(".".to_string()),
        _ => None,
    }
}

fn join_components(components: &[String]) -> String {
    if components.is_empty() {
        return ".".to_string();
    }
    components.join("/")
}
