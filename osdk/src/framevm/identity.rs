// SPDX-License-Identifier: MPL-2.0

//! FrameVM artifact-set identity and export manifest generation.
//!
//! This module owns the OSDK-side compatibility facts used to pair a host
//! artifact, a FrameVM service object, its export manifest, and its runtime
//! symbol table. Runtime lookup data remains in `framevm.symbols`.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    bundle::FrameVmArtifactSet as BundleFrameVmArtifactSet, commands::COMMON_CARGO_ARGS,
    config::Config,
};

use super::{
    host::{HostImportValidation, HostSymbolMatch},
    imports::{ActualHostImports, RawSymbolName},
    metadata::{self, FrameVmMetadataArtifact},
    object::FrameVmObjectArtifact,
    process, rustflags,
    symbols::FrameVmSymbolsArtifact,
    types::{FrameVmBuildConfig, FrameVmStageError},
};

const EXPORT_MANIFEST_FILE_NAME: &str = "framevm-export-manifest.json";
const EXPORT_REQUEST_FILE_NAME: &str = "framevm.export-request";
const TRANSACTION_ID_ALGORITHM: &str = "sha256";
const CONTRACT_NAME: &str = "framevm-service-build-loading";
const FRAMEVM_SOURCE_HASH_ROOTS: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    "kernel/Cargo.toml",
    "kernel/src",
    "kernel/comps/framev-blk",
    "kernel/comps/framev-console",
    "kernel/comps/framev-device",
    "kernel/comps/framev-rng",
    "kernel/comps/framev-sock",
    "kernel/comps/framevisor",
    "ostd/Cargo.toml",
    "ostd/libs",
    "ostd/src",
    "osdk/src/bundle",
    "osdk/src/commands/build",
    "osdk/src/cli.rs",
    "osdk/src/commands/framevm.rs",
    "osdk/src/commands/mod.rs",
    "osdk/src/commands/util.rs",
    "osdk/src/framevm",
    "services/aster-framevm",
    "test/initramfs/nix/framevm-rootfs-image.nix",
    "test/initramfs/nix/framevmctl.nix",
    "test/initramfs/src/init",
    "test/initramfs/src/framevm",
    "test/initramfs/src/framevmctl",
    "test/initramfs/src/regression/network/vsock/framev_vsock_echo.c",
    "tools/framevm-service-check",
];
const SERVICE_OBJECT_INPUT_ROOTS: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    "kernel/Cargo.toml",
    "kernel/comps/block",
    "kernel/comps/framev-blk",
    "kernel/comps/framev-console",
    "kernel/comps/framev-device",
    "kernel/comps/framev-rng",
    "kernel/comps/framev-sock",
    "kernel/comps/framevisor-ostd",
    "kernel/libs",
    "ostd/Cargo.toml",
    "ostd/libs",
    "ostd/src",
    "services/aster-framevm",
    "osdk/src/framevm",
];
const HOST_SYMBOL_INPUT_ROOTS: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    "kernel/Cargo.toml",
    "kernel/src",
    "kernel/comps",
    "kernel/libs",
    "ostd/Cargo.toml",
    "ostd/libs",
    "ostd/src",
    "osdk/src/commands/build",
    "osdk/src/framevm",
];
const SERVICE_CHECK_INPUT_ROOTS: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "tools/framevm-service-check",
    "services/aster-framevm",
    "kernel/src",
    "kernel/comps",
    "kernel/libs",
];
const SERVICE_CHECK_CONFIG_PATH: &str = "tools/framevm-service-check/config.toml";
const SERVICE_CHECK_TRIM_MANIFEST_PATH: &str = "tools/framevm-service-check/trim-manifest.toml";

#[derive(Clone, Debug)]
pub(super) struct ArtifactHash([u8; 32]);

impl ArtifactHash {
    pub(super) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(super) fn hex(&self) -> String {
        super::imports::bytes_to_hex(&self.0)
    }
}

#[derive(Clone, Debug)]
pub(super) struct FrameVmTransactionId([u8; 32]);

impl FrameVmTransactionId {
    pub(super) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(super) fn hex(&self) -> String {
        super::imports::bytes_to_hex(&self.0)
    }
}

#[derive(Clone, Debug)]
pub(super) struct FrameVmExportRequestArtifact {
    path: PathBuf,
    payload_hash: ArtifactHash,
    payload_size: usize,
}

impl FrameVmExportRequestArtifact {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn with_path(&self, path: PathBuf) -> Self {
        Self {
            path,
            payload_hash: self.payload_hash.clone(),
            payload_size: self.payload_size,
        }
    }

    pub(super) fn payload_hash(&self) -> &ArtifactHash {
        &self.payload_hash
    }

    pub(super) fn payload_size(&self) -> usize {
        self.payload_size
    }
}

#[derive(Clone, Debug)]
pub(super) struct FrameVmExportManifestArtifact {
    path: PathBuf,
    payload_hash: ArtifactHash,
    payload_size: usize,
    raw_symbol_compatibility: RawSymbolCompatibilityContext,
}

impl FrameVmExportManifestArtifact {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn with_path(&self, path: PathBuf) -> Self {
        Self {
            path,
            payload_hash: self.payload_hash.clone(),
            payload_size: self.payload_size,
            raw_symbol_compatibility: self.raw_symbol_compatibility.clone(),
        }
    }

    pub(super) fn payload_hash(&self) -> &ArtifactHash {
        &self.payload_hash
    }

    pub(super) fn payload_size(&self) -> usize {
        self.payload_size
    }

    pub(super) fn raw_symbol_compatibility(&self) -> &RawSymbolCompatibilityContext {
        &self.raw_symbol_compatibility
    }
}

#[derive(Clone, Debug)]
pub(super) struct FrameVmTransactionIdentity {
    transaction_id: FrameVmTransactionId,
    host_elf_hash: ArtifactHash,
    actual_imports_hash: ArtifactHash,
    export_manifest_hash: ArtifactHash,
    hash_inputs: Vec<TransactionHashInput>,
    raw_symbol_compatibility: RawSymbolCompatibilityContext,
}

impl FrameVmTransactionIdentity {
    pub(super) fn transaction_id(&self) -> &FrameVmTransactionId {
        &self.transaction_id
    }

    pub(super) fn host_elf_hash(&self) -> &ArtifactHash {
        &self.host_elf_hash
    }

    pub(super) fn actual_imports_hash(&self) -> &ArtifactHash {
        &self.actual_imports_hash
    }

    pub(super) fn export_manifest_hash(&self) -> &ArtifactHash {
        &self.export_manifest_hash
    }

    pub(super) fn hash_inputs(&self) -> &[TransactionHashInput] {
        &self.hash_inputs
    }

    pub(super) fn raw_symbol_compatibility(&self) -> &RawSymbolCompatibilityContext {
        &self.raw_symbol_compatibility
    }
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct TransactionHashInput {
    name: String,
    value: String,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct RawSymbolCompatibilityContext {
    rustc: String,
    rust_metadata: String,
    symbol_mangling_version: String,
    framevm_target: String,
    kernel_target_arch: String,
    profile: String,
    no_default_features: bool,
    features: Vec<String>,
    shared_rustflags: Vec<String>,
    cargo_common_args: Vec<String>,
    build_std: String,
    framevm_crate_type: &'static str,
    host_crate_type: &'static str,
    dependency_graph_identity: String,
    provider_cargo_unit_identity: String,
    provider_identity_rule: &'static str,
}

#[derive(Clone, Debug)]
pub(super) struct FrameVmArtifactSetMetadata {
    transaction_id: FrameVmTransactionId,
    host_elf_hash: ArtifactHash,
    actual_imports_hash: ArtifactHash,
    source_hash: String,
    stage_input_identities: FrameVmStageInputIdentities,
    export_manifest_hash: ArtifactHash,
    framevm_o_hash: ArtifactHash,
    framevm_symbols_hash: String,
    framevm_metadata_hash: String,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct FrameVmStageInputIdentities {
    pub(super) service_object: String,
    pub(super) host_symbols: String,
    pub(super) service_check: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct FrameVmServiceCheckCacheRecord {
    pub(super) contract: String,
    pub(super) input_hash: String,
    pub(super) config_hash: String,
    pub(super) trim_manifest_hash: String,
    pub(super) status: String,
}

impl FrameVmServiceCheckCacheRecord {
    pub(super) fn new(input_hash: String, config_hash: String, trim_manifest_hash: String) -> Self {
        Self {
            contract: CONTRACT_NAME.to_string(),
            input_hash,
            config_hash,
            trim_manifest_hash,
            status: "success".to_string(),
        }
    }

    pub(super) fn is_success_for(&self, input_hash: &str) -> bool {
        self.contract == CONTRACT_NAME && self.status == "success" && self.input_hash == input_hash
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct FrameVmBootCarrierInputManifest {
    pub(super) contract: String,
    pub(super) input_hash: String,
    pub(super) host_boot_artifact_hash: String,
    pub(super) initramfs_hash: String,
    pub(super) framevm_symbols_hash: String,
    pub(super) run_config_hash: String,
}

#[derive(Serialize)]
struct BootCarrierRunConfigIdentity<'a> {
    boot_method: &'a crate::config::scheme::BootMethod,
    boot_kcmdline: &'a [String],
    grub_boot_protocol: &'a crate::config::scheme::BootProtocol,
    grub_display_menu: bool,
}

impl FrameVmBootCarrierInputManifest {
    pub(super) fn is_current(&self, current: &Self) -> bool {
        self.contract == CONTRACT_NAME && self.input_hash == current.input_hash
    }
}

impl FrameVmArtifactSetMetadata {
    pub(super) fn new(
        identity: &FrameVmTransactionIdentity,
        object: &FrameVmObjectArtifact,
        symbols: &FrameVmSymbolsArtifact,
        metadata: &FrameVmMetadataArtifact,
        source_hash: String,
        stage_input_identities: FrameVmStageInputIdentities,
    ) -> Result<Self, FrameVmStageError> {
        Ok(Self {
            transaction_id: identity.transaction_id.clone(),
            host_elf_hash: identity.host_elf_hash.clone(),
            actual_imports_hash: identity.actual_imports_hash.clone(),
            source_hash,
            stage_input_identities,
            export_manifest_hash: identity.export_manifest_hash.clone(),
            framevm_o_hash: hash_file(&object.path)?,
            framevm_symbols_hash: symbols.payload_hash().hex(),
            framevm_metadata_hash: metadata.payload_hash().hex(),
        })
    }

    pub(super) fn bundle_manifest_entry(&self) -> BundleFrameVmArtifactSet {
        BundleFrameVmArtifactSet {
            transaction_id: self.transaction_id.hex(),
            host_elf_hash: self.host_elf_hash.hex(),
            actual_imports_hash: self.actual_imports_hash.hex(),
            framevm_source_hash: Some(self.source_hash.clone()),
            framevm_service_object_hash: Some(self.stage_input_identities.service_object.clone()),
            framevm_host_symbol_hash: Some(self.stage_input_identities.host_symbols.clone()),
            framevm_service_check_hash: Some(self.stage_input_identities.service_check.clone()),
            framevm_boot_carrier_hash: None,
            framevm_export_manifest_hash: self.export_manifest_hash.hex(),
            framevm_o_hash: self.framevm_o_hash.hex(),
            framevm_symbols_hash: self.framevm_symbols_hash.clone(),
            framevm_metadata_hash: self.framevm_metadata_hash.clone(),
        }
    }
}

#[derive(Serialize)]
struct ExportRequest {
    contract: &'static str,
    entries: Vec<ExportRequestEntry>,
}

#[derive(Serialize)]
struct ExportRequestEntry {
    raw_symbol_name: String,
    exported_symbol_name: String,
    origin_framevm_import: String,
}

#[derive(Serialize)]
struct ExportManifest<'a> {
    contract: &'static str,
    raw_symbol_compatibility: &'a RawSymbolCompatibilityContext,
    entries: Vec<ExportManifestEntry<'a>>,
}

#[derive(Serialize)]
struct ExportManifestEntry<'a> {
    origin_framevm_import: RawSymbolManifestEntry<'a>,
    exported_symbol_name: RawSymbolManifestEntry<'a>,
    value: u64,
    value_hex: String,
    size: u64,
    kind: &'a str,
    binding: &'a str,
}

#[derive(Serialize)]
struct RawSymbolManifestEntry<'a> {
    raw_symbol_name: String,
    raw_symbol_name_hex: String,
    raw_symbol_name_bytes: &'a [u8],
    demangled_symbol_name: String,
    diagnostic_normalized_name: String,
    owning_crate: Option<String>,
    owning_module: Option<String>,
}

pub(super) fn write_export_request(
    object: &FrameVmObjectArtifact,
) -> Result<FrameVmExportRequestArtifact, FrameVmStageError> {
    let output_path = object.report_dir.join(EXPORT_REQUEST_FILE_NAME);
    let request = ExportRequest {
        contract: CONTRACT_NAME,
        entries: object
            .actual_imports
            .iter()
            .map(|(raw_name, _)| ExportRequestEntry {
                raw_symbol_name: raw_name.display_lossy(),
                exported_symbol_name: raw_name.display_lossy(),
                origin_framevm_import: raw_name.display_lossy(),
            })
            .collect(),
    };
    let content = serde_json::to_vec_pretty(&request).map_err(|error| {
        FrameVmStageError::ImportValidation(format!(
            "failed to serialize FrameVM export request: {error}"
        ))
    })?;
    fs::write(&output_path, &content).map_err(|error| {
        FrameVmStageError::ImportValidation(format!(
            "failed to write FrameVM export request {}: {error}",
            output_path.display()
        ))
    })?;

    Ok(FrameVmExportRequestArtifact {
        path: output_path,
        payload_hash: hash_bytes(&content),
        payload_size: content.len(),
    })
}

pub(super) fn write_export_manifest(
    workspace_root: &Path,
    config: &FrameVmBuildConfig,
    object: &FrameVmObjectArtifact,
    validation: &HostImportValidation,
) -> Result<FrameVmExportManifestArtifact, FrameVmStageError> {
    let output_path = object.report_dir.join(EXPORT_MANIFEST_FILE_NAME);
    let raw_symbol_compatibility =
        build_raw_symbol_compatibility_context(workspace_root, config, validation)?;
    validate_raw_symbol_compatibility_context(&raw_symbol_compatibility)?;
    let content = encode_export_manifest(validation.matches(), &raw_symbol_compatibility)?;
    fs::write(&output_path, &content).map_err(|error| {
        FrameVmStageError::ImportValidation(format!(
            "failed to write FrameVM export manifest {}: {error}",
            output_path.display()
        ))
    })?;

    Ok(FrameVmExportManifestArtifact {
        path: output_path,
        payload_hash: hash_bytes(&content),
        payload_size: content.len(),
        raw_symbol_compatibility,
    })
}

pub(super) fn validate_export_manifest(
    validation: &HostImportValidation,
    actual_imports: &ActualHostImports,
    export_manifest: &FrameVmExportManifestArtifact,
) -> Result<(), FrameVmStageError> {
    if validation.matches().len() != actual_imports.len() {
        return Err(FrameVmStageError::ImportValidation(format!(
            "FrameVM export manifest has {} matched imports but final object requires {} imports",
            validation.matches().len(),
            actual_imports.len()
        )));
    }

    for ((expected_name, _), symbol_match) in actual_imports.iter().zip(validation.matches()) {
        if expected_name != symbol_match.import_name() {
            return Err(FrameVmStageError::ImportValidation(format!(
                "FrameVM export manifest import order mismatch: expected {}, got {}",
                expected_name,
                symbol_match.import_name()
            )));
        }
        if symbol_match.import_name() != symbol_match.exported_name() {
            return Err(FrameVmStageError::ImportValidation(format!(
                "FrameVM export manifest for {} uses exported host name {}; build must publish an exact runtime lookup key before packaging",
                symbol_match.import_name(),
                symbol_match.exported_name()
            )));
        }
    }

    if export_manifest.payload_size() == 0 {
        return Err(FrameVmStageError::ImportValidation(
            "FrameVM export manifest is empty".to_string(),
        ));
    }

    Ok(())
}

pub(super) fn compute_transaction_identity(
    workspace_root: &Path,
    validation: &HostImportValidation,
    export_manifest: &FrameVmExportManifestArtifact,
    actual_imports: &ActualHostImports,
) -> Result<FrameVmTransactionIdentity, FrameVmStageError> {
    let host_elf_hash = hash_file(validation.host_elf().path())?;
    let actual_imports_hash = hash_actual_import_set(actual_imports);
    let cargo_lock_hash = hash_file(&workspace_root.join("Cargo.lock"))?;
    let compatibility = export_manifest.raw_symbol_compatibility();

    let mut hasher = Sha256::new();
    let mut hash_inputs = Vec::new();
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "algorithm",
        TRANSACTION_ID_ALGORITHM,
    );
    record_hash_input(&mut hasher, &mut hash_inputs, "contract", CONTRACT_NAME);
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "framevm_target",
        &compatibility.framevm_target,
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "kernel_target_arch",
        &compatibility.kernel_target_arch,
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "profile",
        &compatibility.profile,
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "no_default_features",
        &compatibility.no_default_features.to_string(),
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "features",
        &compatibility.features.join("\0"),
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "shared_rustflags",
        &compatibility.shared_rustflags.join("\0"),
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "rust_metadata",
        &compatibility.rust_metadata,
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "symbol_mangling_version",
        &compatibility.symbol_mangling_version,
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "rustc",
        compatibility.rustc.trim(),
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "cargo_common_args",
        &compatibility.cargo_common_args.join("\0"),
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "build_std",
        &compatibility.build_std,
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "framevm_crate_type",
        compatibility.framevm_crate_type,
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "host_crate_type",
        compatibility.host_crate_type,
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "osdk_version",
        env!("CARGO_PKG_VERSION"),
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "cargo_lock_hash",
        &cargo_lock_hash.hex(),
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "dependency_graph_identity",
        &compatibility.dependency_graph_identity,
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "provider_cargo_unit_identity",
        &compatibility.provider_cargo_unit_identity,
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "host_elf_hash",
        &host_elf_hash.hex(),
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "actual_imports_hash",
        &actual_imports_hash.hex(),
    );
    record_hash_input(
        &mut hasher,
        &mut hash_inputs,
        "framevm_export_manifest_hash",
        &export_manifest.payload_hash().hex(),
    );

    Ok(FrameVmTransactionIdentity {
        transaction_id: hash_to_transaction_id(hasher),
        host_elf_hash,
        actual_imports_hash,
        export_manifest_hash: export_manifest.payload_hash().clone(),
        hash_inputs,
        raw_symbol_compatibility: compatibility.clone(),
    })
}

pub(super) fn validate_bundle_artifact_set(
    bundle_artifact_set: &BundleFrameVmArtifactSet,
    framevm_symbols_path: &Path,
    framevm_object_path: &Path,
    host_elf_path: &Path,
    actual_imports_hash: &str,
) -> Result<(), FrameVmStageError> {
    let actual_host_elf_hash = hash_file_for_run(host_elf_path, "host ELF")?.hex();
    require_manifest_match(
        "host_elf_hash",
        &bundle_artifact_set.host_elf_hash,
        &actual_host_elf_hash,
    )?;
    require_manifest_match(
        "actual_imports_hash",
        &bundle_artifact_set.actual_imports_hash,
        actual_imports_hash,
    )?;

    let actual_object_hash = hash_file_for_run(framevm_object_path, "framevm.o")?.hex();
    require_manifest_match(
        "framevm_o_hash",
        &bundle_artifact_set.framevm_o_hash,
        &actual_object_hash,
    )?;

    let actual_symbols_hash = hash_file_for_run(framevm_symbols_path, "framevm.symbols")?.hex();
    require_manifest_match(
        "framevm_symbols_hash",
        &bundle_artifact_set.framevm_symbols_hash,
        &actual_symbols_hash,
    )?;

    let metadata = metadata::inspect_embedded_metadata(framevm_object_path)?;
    require_manifest_match(
        "transaction_id",
        &bundle_artifact_set.transaction_id,
        &metadata.transaction_id,
    )?;
    require_manifest_match(
        "framevm_export_manifest_hash",
        &bundle_artifact_set.framevm_export_manifest_hash,
        &metadata.export_manifest_hash,
    )?;
    require_manifest_match(
        "embedded framevm_symbols_hash",
        &bundle_artifact_set.framevm_symbols_hash,
        &metadata.framevm_symbols_hash,
    )?;
    require_manifest_match(
        "framevm_metadata_hash",
        &bundle_artifact_set.framevm_metadata_hash,
        &metadata.payload_hash,
    )?;
    if metadata.loadable_payload_size == 0 {
        return Err(FrameVmStageError::Run(
            "framevm artifact-set metadata records an empty loadable payload".to_string(),
        ));
    }
    if metadata.retained_rlib_count == 0 || metadata.bundled_object_count == 0 {
        return Err(FrameVmStageError::Run(format!(
            "framevm artifact-set metadata has an empty dependency summary: retained_rlib_count={}, bundled_object_count={}",
            metadata.retained_rlib_count, metadata.bundled_object_count
        )));
    }
    Ok(())
}

pub(super) fn actual_imports_hash_hex(imports: &ActualHostImports) -> String {
    hash_actual_import_set(imports).hex()
}

pub(super) fn compute_framevm_source_hash(
    workspace_root: &Path,
    config: &FrameVmBuildConfig,
) -> Result<String, FrameVmStageError> {
    let features = sorted_features(&config.features);
    let shared_rustflags = rustflags::SHARED_RUSTFLAGS
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let cargo_common_args = COMMON_CARGO_ARGS
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    let mut hasher = Sha256::new();
    update_hash_field(&mut hasher, "contract", CONTRACT_NAME.as_bytes());
    update_hash_field(&mut hasher, "kind", b"framevm-source-hash");
    update_hash_field(&mut hasher, "framevm_target", config.target.as_bytes());
    update_hash_field(
        &mut hasher,
        "kernel_target_arch",
        config.osdk_config.target_arch.to_string().as_bytes(),
    );
    update_hash_field(
        &mut hasher,
        "profile",
        config.osdk_config.run.build.profile.as_bytes(),
    );
    update_hash_field(
        &mut hasher,
        "no_default_features",
        config.no_default_features.to_string().as_bytes(),
    );
    update_hash_field(
        &mut hasher,
        "skip_service_check",
        config.skip_service_check.to_string().as_bytes(),
    );
    update_hash_field(&mut hasher, "features", features.join("\0").as_bytes());
    update_hash_field(
        &mut hasher,
        "shared_rustflags",
        shared_rustflags.join("\0").as_bytes(),
    );
    update_hash_field(
        &mut hasher,
        "cargo_common_args",
        cargo_common_args.join("\0").as_bytes(),
    );
    update_hash_field(
        &mut hasher,
        "install_path",
        stable_relative_path(&config.install_path).as_bytes(),
    );

    let mut files = Vec::new();
    for root in FRAMEVM_SOURCE_HASH_ROOTS {
        collect_source_hash_files(workspace_root, &workspace_root.join(root), &mut files)?;
    }
    files.sort();

    for relative_path in files {
        let stable_path = stable_relative_path(&relative_path);
        update_hash_field(&mut hasher, "file", stable_path.as_bytes());
        let bytes = fs::read(workspace_root.join(&relative_path)).map_err(|error| {
            FrameVmStageError::Workspace(format!(
                "failed to read FrameVM source input {}: {error}",
                relative_path.display()
            ))
        })?;
        update_hash_field(&mut hasher, "content", &bytes);
    }

    Ok(super::imports::bytes_to_hex(&hasher.finalize()))
}

pub(super) fn compute_stage_input_identities(
    workspace_root: &Path,
    config: &FrameVmBuildConfig,
) -> Result<FrameVmStageInputIdentities, FrameVmStageError> {
    Ok(FrameVmStageInputIdentities {
        service_object: compute_source_hash_with_roots(
            workspace_root,
            config,
            "framevm-service-object-input",
            SERVICE_OBJECT_INPUT_ROOTS,
        )?,
        host_symbols: compute_source_hash_with_roots(
            workspace_root,
            config,
            "framevm-host-symbol-input",
            HOST_SYMBOL_INPUT_ROOTS,
        )?,
        service_check: compute_service_check_input_hash(workspace_root, config)?,
    })
}

pub(super) fn compute_service_check_input_hash(
    workspace_root: &Path,
    config: &FrameVmBuildConfig,
) -> Result<String, FrameVmStageError> {
    compute_source_hash_with_roots(
        workspace_root,
        config,
        "framevm-service-check-input",
        SERVICE_CHECK_INPUT_ROOTS,
    )
}

pub(super) fn service_check_config_hash(
    workspace_root: &Path,
) -> Result<String, FrameVmStageError> {
    hash_optional_file_hex(workspace_root, SERVICE_CHECK_CONFIG_PATH)
}

pub(super) fn service_check_trim_manifest_hash(
    workspace_root: &Path,
) -> Result<String, FrameVmStageError> {
    hash_optional_file_hex(workspace_root, SERVICE_CHECK_TRIM_MANIFEST_PATH)
}

pub(super) fn compute_boot_carrier_input_manifest(
    host_boot_artifact: &Path,
    initramfs: &Path,
    framevm_symbols: &Path,
    run_config: &Config,
) -> Result<FrameVmBootCarrierInputManifest, FrameVmStageError> {
    let host_boot_artifact_hash = hash_file(host_boot_artifact)?.hex();
    let initramfs_hash = hash_file(initramfs)?.hex();
    let framevm_symbols_hash = hash_file(framevm_symbols)?.hex();
    let carrier_run_config = BootCarrierRunConfigIdentity {
        boot_method: &run_config.run.boot.method,
        boot_kcmdline: &run_config.run.boot.kcmdline,
        grub_boot_protocol: &run_config.run.grub.boot_protocol,
        grub_display_menu: run_config.run.grub.display_grub_menu,
    };
    let run_config_bytes = serde_json::to_vec(&carrier_run_config).map_err(|error| {
        FrameVmStageError::Package(format!("failed to serialize run config identity: {error}"))
    })?;
    let run_config_hash = hash_bytes(&run_config_bytes).hex();

    let mut hasher = Sha256::new();
    update_hash_field(&mut hasher, "contract", CONTRACT_NAME.as_bytes());
    update_hash_field(&mut hasher, "kind", b"framevm-boot-carrier-input");
    update_hash_field(
        &mut hasher,
        "host_boot_artifact_hash",
        host_boot_artifact_hash.as_bytes(),
    );
    update_hash_field(&mut hasher, "initramfs_hash", initramfs_hash.as_bytes());
    update_hash_field(
        &mut hasher,
        "framevm_symbols_hash",
        framevm_symbols_hash.as_bytes(),
    );
    update_hash_field(&mut hasher, "run_config_hash", run_config_hash.as_bytes());

    Ok(FrameVmBootCarrierInputManifest {
        contract: CONTRACT_NAME.to_string(),
        input_hash: super::imports::bytes_to_hex(&hasher.finalize()),
        host_boot_artifact_hash,
        initramfs_hash,
        framevm_symbols_hash,
        run_config_hash,
    })
}

pub(super) fn read_boot_carrier_input_manifest(
    path: &Path,
) -> Result<Option<FrameVmBootCarrierInputManifest>, FrameVmStageError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|error| {
            FrameVmStageError::Package(format!(
                "failed to parse boot carrier manifest {}: {error}",
                path.display()
            ))
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(FrameVmStageError::Package(format!(
            "failed to read boot carrier manifest {}: {error}",
            path.display()
        ))),
    }
}

pub(super) fn write_boot_carrier_input_manifest(
    path: &Path,
    manifest: &FrameVmBootCarrierInputManifest,
) -> Result<(), FrameVmStageError> {
    let content = serde_json::to_vec_pretty(manifest).map_err(|error| {
        FrameVmStageError::Package(format!(
            "failed to serialize boot carrier manifest: {error}"
        ))
    })?;
    fs::write(path, content).map_err(|error| {
        FrameVmStageError::Package(format!(
            "failed to write boot carrier manifest {}: {error}",
            path.display()
        ))
    })
}

fn compute_source_hash_with_roots(
    workspace_root: &Path,
    config: &FrameVmBuildConfig,
    kind: &str,
    roots: &[&str],
) -> Result<String, FrameVmStageError> {
    let features = sorted_features(&config.features);
    let shared_rustflags = rustflags::SHARED_RUSTFLAGS
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let cargo_common_args = COMMON_CARGO_ARGS
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();

    let mut hasher = Sha256::new();
    update_hash_field(&mut hasher, "contract", CONTRACT_NAME.as_bytes());
    update_hash_field(&mut hasher, "kind", kind.as_bytes());
    update_hash_field(&mut hasher, "framevm_target", config.target.as_bytes());
    update_hash_field(
        &mut hasher,
        "kernel_target_arch",
        config.osdk_config.target_arch.to_string().as_bytes(),
    );
    update_hash_field(
        &mut hasher,
        "profile",
        config.osdk_config.run.build.profile.as_bytes(),
    );
    update_hash_field(
        &mut hasher,
        "no_default_features",
        config.no_default_features.to_string().as_bytes(),
    );
    update_hash_field(&mut hasher, "features", features.join("\0").as_bytes());
    update_hash_field(
        &mut hasher,
        "shared_rustflags",
        shared_rustflags.join("\0").as_bytes(),
    );
    update_hash_field(
        &mut hasher,
        "cargo_common_args",
        cargo_common_args.join("\0").as_bytes(),
    );
    update_hash_field(
        &mut hasher,
        "install_path",
        stable_relative_path(&config.install_path).as_bytes(),
    );

    let mut files = Vec::new();
    for root in roots {
        collect_source_hash_files(workspace_root, &workspace_root.join(root), &mut files)?;
    }
    files.sort();
    files.dedup();

    for relative_path in files {
        let stable_path = stable_relative_path(&relative_path);
        update_hash_field(&mut hasher, "file", stable_path.as_bytes());
        let bytes = fs::read(workspace_root.join(&relative_path)).map_err(|error| {
            FrameVmStageError::Workspace(format!(
                "failed to read FrameVM input {}: {error}",
                relative_path.display()
            ))
        })?;
        update_hash_field(&mut hasher, "content", &bytes);
    }

    Ok(super::imports::bytes_to_hex(&hasher.finalize()))
}

fn hash_optional_file_hex(
    workspace_root: &Path,
    relative_path: &str,
) -> Result<String, FrameVmStageError> {
    let path = workspace_root.join(relative_path);
    if !path.exists() {
        return Ok("missing".to_string());
    }
    Ok(hash_file(&path)?.hex())
}

fn collect_source_hash_files(
    workspace_root: &Path,
    path: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<(), FrameVmStageError> {
    if !path.exists() {
        return Ok(());
    }

    let metadata = fs::metadata(path).map_err(|error| {
        FrameVmStageError::Workspace(format!(
            "failed to inspect FrameVM source input {}: {error}",
            path.display()
        ))
    })?;
    if metadata.is_file() {
        files.push(
            path.strip_prefix(workspace_root)
                .unwrap_or(path)
                .to_path_buf(),
        );
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }

    let mut entries = fs::read_dir(path)
        .map_err(|error| {
            FrameVmStageError::Workspace(format!(
                "failed to list FrameVM source input {}: {error}",
                path.display()
            ))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            FrameVmStageError::Workspace(format!(
                "failed to read FrameVM source input {}: {error}",
                path.display()
            ))
        })?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        collect_source_hash_files(workspace_root, &entry.path(), files)?;
    }
    Ok(())
}

fn stable_relative_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn sorted_features(features: &[String]) -> Vec<String> {
    let mut features = features.to_vec();
    features.sort();
    features
}

fn hash_file_for_run(path: &Path, label: &str) -> Result<ArtifactHash, FrameVmStageError> {
    hash_file(path).map_err(|error| {
        FrameVmStageError::Run(format!(
            "failed to validate {label} artifact hash for {}: {error}",
            path.display()
        ))
    })
}

fn require_manifest_match(
    field: &str,
    expected: &str,
    actual: &str,
) -> Result<(), FrameVmStageError> {
    if expected == actual {
        return Ok(());
    }
    Err(FrameVmStageError::Run(format!(
        "FrameVM artifact-set {field} mismatch: manifest={expected}, actual={actual}"
    )))
}

fn build_raw_symbol_compatibility_context(
    workspace_root: &Path,
    config: &FrameVmBuildConfig,
    validation: &HostImportValidation,
) -> Result<RawSymbolCompatibilityContext, FrameVmStageError> {
    let rustc = rustc_identity()?;
    let cargo_lock_hash = hash_file(&workspace_root.join("Cargo.lock"))?;
    let host_elf_hash = hash_file(validation.host_elf().path())?;
    let mut features = config.features.clone();
    features.sort();
    let shared_rustflags = rustflags::SHARED_RUSTFLAGS
        .iter()
        .map(|flag| (*flag).to_string())
        .collect::<Vec<_>>();
    let rust_metadata = rustflag_value(&shared_rustflags, "-C metadata").ok_or_else(|| {
        FrameVmStageError::ImportValidation(
            "raw-symbol compatibility context is missing `-C metadata`".to_string(),
        )
    })?;
    let symbol_mangling_version = rustflag_value(&shared_rustflags, "-C symbol-mangling-version")
        .ok_or_else(|| {
        FrameVmStageError::ImportValidation(
            "raw-symbol compatibility context is missing `-C symbol-mangling-version`".to_string(),
        )
    })?;
    let cargo_common_args = COMMON_CARGO_ARGS
        .iter()
        .map(|arg| (*arg).to_string())
        .collect::<Vec<_>>();
    let dependency_graph_identity = format!("cargo-lock:{}", cargo_lock_hash.hex());
    let provider_cargo_unit_identity = provider_cargo_unit_identity(
        &rustc,
        &rust_metadata,
        &symbol_mangling_version,
        &config.target,
        &config.osdk_config.target_arch.to_string(),
        &config.osdk_config.run.build.profile,
        config.no_default_features,
        &features,
        &shared_rustflags,
        &cargo_common_args,
        &dependency_graph_identity,
        &host_elf_hash,
    );

    Ok(RawSymbolCompatibilityContext {
        rustc,
        rust_metadata,
        symbol_mangling_version,
        framevm_target: config.target.clone(),
        kernel_target_arch: config.osdk_config.target_arch.to_string(),
        profile: config.osdk_config.run.build.profile.clone(),
        no_default_features: config.no_default_features,
        features,
        shared_rustflags,
        cargo_common_args,
        build_std: "core,alloc".to_string(),
        framevm_crate_type: "lib-emit-obj",
        host_crate_type: "osdk-generated-kernel-bin",
        dependency_graph_identity,
        provider_cargo_unit_identity,
        provider_identity_rule: "exact raw symbols from the selected final host ELF built in this transaction",
    })
}

fn validate_raw_symbol_compatibility_context(
    context: &RawSymbolCompatibilityContext,
) -> Result<(), FrameVmStageError> {
    if context.rust_metadata.is_empty() {
        return Err(FrameVmStageError::ImportValidation(
            "raw-symbol compatibility `-C metadata` must not be empty".to_string(),
        ));
    }
    if context.symbol_mangling_version != "v0" {
        return Err(FrameVmStageError::ImportValidation(format!(
            "raw-symbol compatibility requires rust v0 symbol mangling, got {}",
            context.symbol_mangling_version
        )));
    }
    Ok(())
}

#[expect(clippy::too_many_arguments)]
fn provider_cargo_unit_identity(
    rustc: &str,
    rust_metadata: &str,
    symbol_mangling_version: &str,
    framevm_target: &str,
    kernel_target_arch: &str,
    profile: &str,
    no_default_features: bool,
    features: &[String],
    shared_rustflags: &[String],
    cargo_common_args: &[String],
    dependency_graph_identity: &str,
    host_elf_hash: &ArtifactHash,
) -> String {
    let mut hasher = Sha256::new();
    update_hash_field(&mut hasher, "contract", CONTRACT_NAME.as_bytes());
    update_hash_field(&mut hasher, "kind", b"provider-cargo-unit-identity");
    update_hash_field(&mut hasher, "rustc", rustc.trim().as_bytes());
    update_hash_field(&mut hasher, "rust_metadata", rust_metadata.as_bytes());
    update_hash_field(
        &mut hasher,
        "symbol_mangling_version",
        symbol_mangling_version.as_bytes(),
    );
    update_hash_field(&mut hasher, "framevm_target", framevm_target.as_bytes());
    update_hash_field(
        &mut hasher,
        "kernel_target_arch",
        kernel_target_arch.as_bytes(),
    );
    update_hash_field(&mut hasher, "profile", profile.as_bytes());
    update_hash_field(
        &mut hasher,
        "no_default_features",
        no_default_features.to_string().as_bytes(),
    );
    update_hash_field(&mut hasher, "features", features.join("\0").as_bytes());
    update_hash_field(
        &mut hasher,
        "shared_rustflags",
        shared_rustflags.join("\0").as_bytes(),
    );
    update_hash_field(
        &mut hasher,
        "cargo_common_args",
        cargo_common_args.join("\0").as_bytes(),
    );
    update_hash_field(
        &mut hasher,
        "dependency_graph_identity",
        dependency_graph_identity.as_bytes(),
    );
    update_hash_field(&mut hasher, "host_elf_hash", host_elf_hash.hex().as_bytes());
    hash_from_digest(hasher.finalize()).hex()
}

fn rustflag_value(flags: &[String], key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    flags
        .iter()
        .find_map(|flag| flag.strip_prefix(&prefix).map(str::to_string))
}

fn encode_export_manifest(
    matches: &[HostSymbolMatch],
    raw_symbol_compatibility: &RawSymbolCompatibilityContext,
) -> Result<Vec<u8>, FrameVmStageError> {
    let mut matches = matches.iter().collect::<Vec<_>>();
    matches.sort_by(|left, right| {
        left.import_name()
            .as_bytes()
            .cmp(right.import_name().as_bytes())
    });

    let manifest = ExportManifest {
        contract: CONTRACT_NAME,
        raw_symbol_compatibility,
        entries: matches
            .into_iter()
            .map(|symbol_match| ExportManifestEntry {
                origin_framevm_import: raw_symbol_manifest_entry(symbol_match.import_name()),
                exported_symbol_name: raw_symbol_manifest_entry(symbol_match.exported_name()),
                value: symbol_match.value(),
                value_hex: format!("0x{:x}", symbol_match.value()),
                size: symbol_match.size(),
                kind: symbol_match.kind(),
                binding: symbol_match.binding(),
            })
            .collect(),
    };
    serde_json::to_vec_pretty(&manifest).map_err(|error| {
        FrameVmStageError::ImportValidation(format!(
            "failed to serialize FrameVM export manifest: {error}"
        ))
    })
}

fn raw_symbol_manifest_entry(symbol: &RawSymbolName) -> RawSymbolManifestEntry<'_> {
    let raw_symbol_name = symbol.display_lossy();
    let demangled_symbol_name = demangled_symbol_name(&raw_symbol_name);
    let diagnostic_normalized_name = diagnostic_normalized_name(&demangled_symbol_name);
    let owning_crate = owning_crate(&diagnostic_normalized_name);
    let owning_module = owning_module(&diagnostic_normalized_name);
    RawSymbolManifestEntry {
        raw_symbol_name,
        raw_symbol_name_hex: symbol.hex(),
        raw_symbol_name_bytes: symbol.as_bytes(),
        demangled_symbol_name,
        diagnostic_normalized_name,
        owning_crate,
        owning_module,
    }
}

fn hash_actual_import_set(imports: &ActualHostImports) -> ArtifactHash {
    let mut hasher = Sha256::new();
    update_hash_field(&mut hasher, "contract", CONTRACT_NAME.as_bytes());
    update_hash_field(&mut hasher, "kind", b"actual-import-set");
    for (raw_name, _) in imports.iter() {
        update_hash_field(&mut hasher, "raw_symbol_name", raw_name.as_bytes());
    }
    hash_from_digest(hasher.finalize())
}

fn rustc_identity() -> Result<String, FrameVmStageError> {
    process::capture_stdout(
        "rustc",
        ["-Vv"],
        "querying rustc identity",
        FrameVmStageError::Workspace,
    )
}

fn hash_file(path: &Path) -> Result<ArtifactHash, FrameVmStageError> {
    let mut file = fs::File::open(path).map_err(|error| {
        FrameVmStageError::ImportValidation(format!("failed to open {}: {error}", path.display()))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| {
            FrameVmStageError::ImportValidation(format!(
                "failed to read {} while hashing: {error}",
                path.display()
            ))
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hash_from_digest(hasher.finalize()))
}

fn hash_bytes(bytes: &[u8]) -> ArtifactHash {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hash_from_digest(hasher.finalize())
}

fn hash_to_transaction_id(hasher: Sha256) -> FrameVmTransactionId {
    let hash = hash_from_digest(hasher.finalize());
    FrameVmTransactionId(hash.0)
}

fn hash_from_digest(digest: impl AsRef<[u8]>) -> ArtifactHash {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest.as_ref());
    ArtifactHash(hash)
}

fn update_hash_field(hasher: &mut Sha256, label: &str, value: &[u8]) {
    hasher.update((label.len() as u32).to_le_bytes());
    hasher.update(label.as_bytes());
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn record_hash_input(
    hasher: &mut Sha256,
    inputs: &mut Vec<TransactionHashInput>,
    name: &str,
    value: &str,
) {
    update_hash_field(hasher, name, value.as_bytes());
    inputs.push(TransactionHashInput {
        name: name.to_string(),
        value: value.to_string(),
    });
}

fn demangled_symbol_name(raw_symbol_name: &str) -> String {
    rustc_demangle::try_demangle(raw_symbol_name)
        .map(|symbol| symbol.to_string())
        .unwrap_or_else(|_| raw_symbol_name.to_string())
}

fn diagnostic_normalized_name(demangled_symbol_name: &str) -> String {
    demangled_symbol_name.to_string()
}

fn owning_crate(diagnostic_name: &str) -> Option<String> {
    diagnostic_name
        .split("::")
        .next()
        .filter(|crate_name| !crate_name.is_empty())
        .map(str::to_string)
}

fn owning_module(diagnostic_name: &str) -> Option<String> {
    let mut parts = diagnostic_name.split("::").collect::<Vec<_>>();
    if parts.len() <= 2 {
        return None;
    }
    parts.pop();
    Some(parts.join("::"))
}
