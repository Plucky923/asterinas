// SPDX-License-Identifier: MPL-2.0

//! FrameVM artifact-set transaction orchestration.

use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::{Instant, SystemTime},
};

use crate::{
    arch::Arch,
    bundle::Bundle,
    commands::{
        BundleBuildOptions, DEFAULT_TARGET_RELPATH, FinalCrateRetention, KernelSymbolsModule,
        create_base_and_cached_build_with_options, refresh_grub_bootdev_image_with_framevm_symbols,
    },
    config::{Config, scheme::ActionChoice},
    util::{get_cargo_metadata, get_kernel_crate, hard_link_or_copy},
};

use super::{
    host::{self, HostElfArtifact},
    identity::{self, FrameVmArtifactSetMetadata},
    imports, metadata,
    object::{self, FrameVmObjectArtifact, ObjectBuildContext},
    package::{self, InitramfsArtifact},
    policy::FrameVmPolicy,
    process, report, retention, symbols,
    types::{FrameVmBuildConfig, FrameVmBuildOutcome, FrameVmRunOutcome, FrameVmStageError},
};

const HOST_ARTIFACT_SOURCE_ROOTS: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    "kernel",
    "ostd",
];

pub(super) struct FrameVmTransaction {
    config: FrameVmBuildConfig,
    workspace_root: PathBuf,
    cargo_target_dir: PathBuf,
    osdk_output_dir: PathBuf,
    bundle_path: PathBuf,
}

struct ValidatedFrameVmArtifactSet {
    object: FrameVmObjectArtifact,
    symbols: symbols::FrameVmSymbolsArtifact,
    initramfs: InitramfsArtifact,
    bundle: Bundle,
    bundle_path: PathBuf,
}

struct PublishedFrameVmArtifacts {
    object: FrameVmObjectArtifact,
    symbols: symbols::FrameVmSymbolsArtifact,
    metadata: metadata::FrameVmMetadataArtifact,
    export_request: identity::FrameVmExportRequestArtifact,
    export_manifest: identity::FrameVmExportManifestArtifact,
    object_guard: PublishedFileGuard,
}

struct TimedStageResult<T> {
    value: Result<T, FrameVmStageError>,
    elapsed_ms: u128,
}

impl FrameVmTransaction {
    pub(super) fn new(config: FrameVmBuildConfig) -> Result<Self, FrameVmStageError> {
        if config.osdk_config.target_arch != Arch::X86_64 {
            return Err(FrameVmStageError::Workspace(format!(
                "framevm currently supports target_arch=x86_64 only, got {}",
                config.osdk_config.target_arch
            )));
        }

        let workspace_root = workspace_root()?;
        let cargo_target_dir = object::cargo_target_directory();
        let osdk_output_dir = cargo_target_dir.join(DEFAULT_TARGET_RELPATH);
        let bundle_path = osdk_output_dir.join(get_kernel_crate().name);
        Ok(Self {
            config,
            workspace_root,
            cargo_target_dir,
            osdk_output_dir,
            bundle_path,
        })
    }

    pub(super) fn build_artifact_set(&self) -> Result<FrameVmBuildOutcome, FrameVmStageError> {
        let mut timings = report::StageTimings::new();
        if let Some(outcome) = timings.measure("current_artifact_set_validation", || {
            self.try_load_current_build_artifact_set()
        })? {
            if let Some(report_dir) = self.framevm_object_path().parent() {
                report::write_stage_timing_report(report_dir, "make_framevm", &timings)?;
            }
            return Ok(outcome);
        }

        if let Some(artifact_set) = timings.measure("framevm_only_artifact_refresh", || {
            self.try_build_framevm_only_artifact_set()
        })? {
            if let Some(report_dir) = self.framevm_object_path().parent() {
                report::write_stage_timing_report(report_dir, "make_framevm", &timings)?;
            }
            return Ok(FrameVmBuildOutcome {
                object: artifact_set.object.path,
                symbols: artifact_set.symbols.path().to_path_buf(),
                initramfs: artifact_set.initramfs.path,
                bundle: artifact_set.bundle_path,
            });
        }

        let artifact_set = timings.measure("full_artifact_set_build", || {
            self.build_validated_artifact_set()
        })?;
        Ok(FrameVmBuildOutcome {
            object: artifact_set.object.path,
            symbols: artifact_set.symbols.path().to_path_buf(),
            initramfs: artifact_set.initramfs.path,
            bundle: artifact_set.bundle_path,
        })
    }

    pub(super) fn run_artifact_set(
        &self,
        no_build: bool,
    ) -> Result<FrameVmRunOutcome, FrameVmStageError> {
        let mut timings = report::StageTimings::new();
        let (bundle, runtime_config) = if no_build {
            timings.measure("no_build_artifact_set_validation", || {
                match self.try_load_existing_bundle_for_run(true, None)? {
                    Some(artifact_set) => Ok(artifact_set),
                    None => Err(FrameVmStageError::Run(format!(
                        "no reusable framevm bundle found at {}",
                        self.bundle_path.display()
                    ))),
                }
            })?
        } else {
            timings.measure("artifact_set_selection_or_build", || {
                if let Some(existing_artifact_set) = self.try_load_current_bundle_for_run()? {
                    Ok(existing_artifact_set)
                } else if let Some(artifact_set) = self.try_build_framevm_only_artifact_set()? {
                    let initramfs_path = artifact_set
                        .bundle
                        .initramfs_path()
                        .unwrap_or_else(|| artifact_set.initramfs.path.clone());
                    let runtime_config = self.runtime_config(&initramfs_path);
                    Ok((artifact_set.bundle, runtime_config))
                } else {
                    let artifact_set = self.build_validated_artifact_set()?;
                    let initramfs_path = artifact_set
                        .bundle
                        .initramfs_path()
                        .unwrap_or_else(|| artifact_set.initramfs.path.clone());
                    let runtime_config = self.runtime_config(&initramfs_path);
                    Ok((artifact_set.bundle, runtime_config))
                }
            })?
        };

        bundle
            .can_run_with_config(&runtime_config, ActionChoice::Run)
            .map_err(|error| {
                FrameVmStageError::Run(format!(
                    "selected bundle is not compatible with framevm runtime config: {error}"
                ))
            })?;

        let success_markers = self.config.load_action.success_markers();
        if self.config.load_action.is_interactive() {
            timings.measure("qemu_interactive_run", || {
                let exit_status = bundle.run_qemu_and_wait(&runtime_config, ActionChoice::Run);
                if exit_status.success() {
                    Ok(())
                } else {
                    Err(FrameVmStageError::Run(format!(
                        "interactive qemu exited with status {:?}",
                        exit_status.code()
                    )))
                }
            })?;
        } else {
            timings.measure("qemu_launch_until_success", || {
                bundle
                    .run_qemu_until_log_match(
                        &runtime_config,
                        ActionChoice::Run,
                        self.config.load_action.success_timeout(),
                        |qemu_log| framevm_load_completed(qemu_log, success_markers),
                        |qemu_log| framevm_load_failure_summary(qemu_log, success_markers),
                    )
                    .map_err(FrameVmStageError::Run)
            })?;
        }
        if let Some(report_dir) = self.framevm_object_path().parent() {
            report::write_stage_timing_report(report_dir, "make_run_framevm", &timings)?;
        }

        Ok(FrameVmRunOutcome { success_markers })
    }

    fn build_validated_artifact_set(
        &self,
    ) -> Result<ValidatedFrameVmArtifactSet, FrameVmStageError> {
        let mut timings = report::StageTimings::new();
        let final_object_path = self.framevm_object_path();
        let final_report_dir = final_object_path
            .parent()
            .ok_or_else(|| {
                FrameVmStageError::ObjectBuild(format!(
                    "framevm object output has no parent: {}",
                    final_object_path.display()
                ))
            })?
            .to_path_buf();
        let staging_dir = self.prepare_staging_dir(&final_report_dir)?;
        let rollback_dir = staging_dir.join("rollback");
        fs::create_dir_all(&rollback_dir).map_err(|error| {
            FrameVmStageError::Package(format!(
                "failed to create framevm rollback directory {}: {error}",
                rollback_dir.display()
            ))
        })?;
        let initramfs_path = package::framevm_initramfs_path(&self.workspace_root);
        let mut initramfs_guard =
            PublishedFileGuard::protect(&initramfs_path, &rollback_dir, "initramfs")?;
        let staging_bundle_path = staging_dir.join("bundle");
        let mut staging_config = self.config.clone();
        staging_config.object_output = Some(staging_dir.join("framevm.o"));

        let object =
            self.run_service_check_and_build_object_in_parallel(&staging_config, &mut timings)?;
        let export_request = timings.measure("export_request_generation", || {
            identity::write_export_request(&object)
        })?;
        let bootstrap_initramfs = timings.measure("bootstrap_initramfs_packaging", || {
            package::package_initramfs(
                &self.workspace_root,
                &staging_config.osdk_config,
                &staging_config,
                &object,
            )
        })?;
        let runtime_config = self.runtime_config(&bootstrap_initramfs.path);
        let policy = timings.measure("host_policy_load", FrameVmPolicy::load_default)?;
        let host_symbol_files = timings.measure("pre_host_symbol_rlib_selection", || {
            retention::find_policy_rlib_candidates(
                &self.cargo_target_dir,
                &staging_config.target,
                &staging_config.osdk_config.run.build.profile,
                &policy.host_symbols.rlibs,
            )
        })?;
        let host_retention_request = timings.measure("pre_host_final_retention_request", || {
            retention::pre_host_final_retention_request(
                super::rustflags::SHARED_RUSTFLAGS,
                &object.actual_imports,
                &host_symbol_files,
                &staging_dir.join("pre-host-retention.rsp"),
            )
        })?;
        let host_rustflag_refs = host_retention_request
            .rustflags()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        timings.measure("pre_host_cached_host_elf_clean", || {
            self.remove_cached_host_elf_by_file_name(
                &get_kernel_crate().name,
                self.config.osdk_config.target_arch.triple(),
                &staging_config.osdk_config.run.build.profile,
            )
        })?;
        let mut bundle = timings.measure_value("host_bundle_build", || {
            self.build_host_bundle(&runtime_config, &staging_bundle_path, &host_rustflag_refs)
        });
        let host_elf = timings.measure("final_host_artifact_selection", || {
            host_elf_artifact(&bundle)
        })?;
        let mut host_validation = timings.measure("final_host_validation", || {
            host::validate_actual_imports(host_elf, &object.actual_imports)
        })?;
        if !host_validation.is_exact_match() {
            timings.measure("pre_host_final_validation_report", || {
                report::write_final_host_validation_report(&object, &host_validation)?;
                copy_file_atomically(
                    &object.report_dir.join("final-host-validation-report.json"),
                    &object
                        .report_dir
                        .join("pre-host-final-validation-report.json"),
                )
            })?;
            let pre_host_exact_aliases_published = timings
                .measure("pre_host_exact_host_alias_publication", || {
                    host::publish_exact_import_aliases(&host_validation)
                })?;
            if pre_host_exact_aliases_published {
                bundle.refresh_aster_bin_metadata();
                let host_elf = timings
                    .measure("final_host_artifact_selection_after_pre_host_alias", || {
                        host_elf_artifact(&bundle)
                    })?;
                host_validation = timings
                    .measure("final_host_revalidation_after_pre_host_alias", || {
                        host::validate_actual_imports(host_elf, &object.actual_imports)
                    })?;
            }
        }
        if !host_validation.is_exact_match() {
            let host_symbol_files =
                timings.measure("fallback_host_symbol_rlib_selection", || {
                    retention::find_policy_rlib_candidates(
                        &self.cargo_target_dir,
                        &staging_config.target,
                        &staging_config.osdk_config.run.build.profile,
                        &policy.host_symbols.rlibs,
                    )
                })?;
            let refined_host_rustflags =
                timings.measure("fallback_host_retention_request", || {
                    retention::final_host_retention_request(
                        super::rustflags::SHARED_RUSTFLAGS,
                        &object.actual_imports,
                        &host_symbol_files,
                        host_validation.host_elf().path(),
                        &staging_dir.join("fallback-host-retention.rsp"),
                    )
                })?;
            if refined_host_rustflags.requested_symbols()
                != host_retention_request.requested_symbols()
            {
                self.remove_cached_host_elf_for_rebuild(
                    host_validation.host_elf().path(),
                    &staging_config.target,
                    &staging_config.osdk_config.run.build.profile,
                )?;
                remove_dir_if_exists(&staging_bundle_path)?;
                let refined_host_rustflag_refs = refined_host_rustflags
                    .rustflags()
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                bundle = timings.measure_value("fallback_host_bundle_rebuild", || {
                    self.build_host_bundle(
                        &runtime_config,
                        &staging_bundle_path,
                        &refined_host_rustflag_refs,
                    )
                });
                let host_elf = timings
                    .measure("final_host_artifact_selection_after_fallback", || {
                        host_elf_artifact(&bundle)
                    })?;
                host_validation = timings
                    .measure("final_host_revalidation_after_fallback", || {
                        host::validate_actual_imports(host_elf, &object.actual_imports)
                    })?;
            }
        }
        let exact_aliases_published = if !host_validation.is_exact_match() {
            timings.measure("exact_host_alias_publication", || {
                host::publish_exact_import_aliases(&host_validation)
            })?
        } else {
            false
        };
        if exact_aliases_published {
            bundle.refresh_aster_bin_metadata();
            let host_elf = timings.measure("final_host_artifact_selection_after_alias", || {
                host_elf_artifact(&bundle)
            })?;
            host_validation = timings.measure("final_host_revalidation_after_alias", || {
                host::validate_actual_imports(host_elf, &object.actual_imports)
            })?;
        }
        timings.measure("final_host_validation_report", || {
            report::write_final_host_validation_report(&object, &host_validation)
        })?;
        if !host_validation.is_exact_match() {
            return Err(FrameVmStageError::ImportValidation(
                final_host_validation_error(&host_validation),
            ));
        }
        let symbols = timings.measure("symbol_table_generation", || {
            symbols::write_framevm_symbols(&object, &host_validation)
        })?;
        let export_manifest = timings.measure("export_manifest_generation", || {
            identity::write_export_manifest(
                &self.workspace_root,
                &self.config,
                &object,
                &host_validation,
            )
        })?;
        timings.measure("export_manifest_validation", || {
            identity::validate_export_manifest(
                &host_validation,
                &object.actual_imports,
                &export_manifest,
            )
        })?;
        let transaction_identity = timings.measure("transaction_identity", || {
            identity::compute_transaction_identity(
                &self.workspace_root,
                &host_validation,
                &export_manifest,
                &object.actual_imports,
            )
        })?;
        let metadata = timings.measure("metadata_embedding", || {
            metadata::embed_framevm_metadata(
                &object,
                &symbols,
                &transaction_identity,
                &export_manifest,
            )
        })?;
        let published_artifacts = timings.measure("artifact_publish", || {
            self.publish_staged_artifacts(
                &staging_dir,
                &final_object_path,
                &object,
                &symbols,
                &metadata,
                &export_request,
                &export_manifest,
                &rollback_dir,
            )
        })?;
        let PublishedFrameVmArtifacts {
            object,
            symbols,
            metadata,
            export_request,
            export_manifest,
            mut object_guard,
        } = published_artifacts;
        let stage_input_identities = timings.measure("stage_input_identities", || {
            identity::compute_stage_input_identities(&self.workspace_root, &self.config)
        })?;
        let artifact_set_metadata = timings.measure("artifact_set_metadata", || {
            let source_hash =
                identity::compute_framevm_source_hash(&self.workspace_root, &self.config)?;
            FrameVmArtifactSetMetadata::new(
                &transaction_identity,
                &object,
                &symbols,
                &metadata,
                source_hash,
                stage_input_identities.clone(),
            )
        })?;
        let initramfs = timings.measure("final_initramfs_packaging", || {
            package::package_initramfs(
                &self.workspace_root,
                &self.config.osdk_config,
                &self.config,
                &object,
            )
        })?;
        let runtime_config = self.runtime_config(&initramfs.path);
        let mut bundle_runtime_config = runtime_config.clone();
        bundle.update_config(&mut bundle_runtime_config, ActionChoice::Run);
        self.refresh_or_reuse_boot_carrier(
            &mut bundle,
            &staging_bundle_path,
            &bundle_runtime_config,
            symbols.path(),
            &mut timings,
        )?;
        let mut bundle_artifact_set = artifact_set_metadata.bundle_manifest_entry();
        bundle_artifact_set.framevm_boot_carrier_hash = Some(
            self.compute_boot_carrier_input_manifest(
                &bundle,
                &bundle_runtime_config,
                symbols.path(),
            )?
            .input_hash,
        );
        bundle.replace_framevm_artifact_set(bundle_artifact_set);
        timings.measure("build_index_report", || {
            report::write_build_index(
                &object,
                &symbols,
                &metadata,
                &export_manifest,
                &export_request,
                &transaction_identity,
                &artifact_set_metadata,
                &stage_input_identities,
                &initramfs,
                &self.bundle_path,
            )
        })?;
        let mut bundle_guard = timings.measure("bundle_publish", || {
            PublishedDirectoryGuard::replace(&staging_bundle_path, &self.bundle_path, &rollback_dir)
        })?;
        let bundle = self.load_published_bundle_with_runtime_config(&runtime_config)?;
        report::write_stage_timing_report(&object.report_dir, "make_framevm", &timings)?;

        object_guard.commit();
        initramfs_guard.commit();
        bundle_guard.commit();
        remove_dir_if_exists(&staging_dir)?;

        Ok(ValidatedFrameVmArtifactSet {
            object,
            symbols,
            initramfs,
            bundle,
            bundle_path: self.bundle_path.clone(),
        })
    }

    fn try_load_current_bundle_for_run(
        &self,
    ) -> Result<Option<(Bundle, Config)>, FrameVmStageError> {
        let Some(bundle) = Bundle::load(&self.bundle_path, true) else {
            return Ok(None);
        };
        let Some(artifact_set) = bundle.framevm_artifact_set() else {
            return Ok(None);
        };
        let Some(recorded_source_hash) = artifact_set.framevm_source_hash.as_deref() else {
            return Ok(None);
        };

        let current_source_hash =
            identity::compute_framevm_source_hash(&self.workspace_root, &self.config)?;
        if recorded_source_hash != current_source_hash {
            return Ok(None);
        }

        if self
            .try_load_existing_bundle_for_run(false, Some(&current_source_hash))?
            .is_some()
        {
            return self.try_refresh_boot_carrier_for_current_artifacts(&current_source_hash);
        }

        self.try_refresh_boot_carrier_for_current_artifacts(&current_source_hash)
    }

    fn try_build_framevm_only_artifact_set(
        &self,
    ) -> Result<Option<ValidatedFrameVmArtifactSet>, FrameVmStageError> {
        let Some(existing_bundle) = Bundle::load(&self.bundle_path, true) else {
            return Ok(None);
        };
        if existing_bundle.framevm_artifact_set().is_none()
            || existing_bundle.framevm_symbols_path().is_none()
            || existing_bundle.aster_bin_path().is_none()
        {
            return Ok(None);
        }
        let Some(existing_initramfs) = self.runnable_initramfs_for_bundle(&existing_bundle) else {
            return Ok(None);
        };
        let existing_runtime_config = self.runtime_config_from_existing_bundle(&existing_initramfs);
        if existing_bundle
            .can_run_with_config(&existing_runtime_config, ActionChoice::Run)
            .is_err()
        {
            return Ok(None);
        }
        if !self.host_artifact_is_fresh_for_framevm_only_refresh(&existing_bundle)? {
            return Ok(None);
        }
        self.run_service_check()?;

        let final_object_path = self.framevm_object_path();
        let final_report_dir = final_object_path
            .parent()
            .ok_or_else(|| {
                FrameVmStageError::ObjectBuild(format!(
                    "framevm object output has no parent: {}",
                    final_object_path.display()
                ))
            })?
            .to_path_buf();
        let staging_dir = self.prepare_staging_dir(&final_report_dir)?;
        let rollback_dir = staging_dir.join("rollback");
        fs::create_dir_all(&rollback_dir).map_err(|error| {
            FrameVmStageError::Package(format!(
                "failed to create framevm rollback directory {}: {error}",
                rollback_dir.display()
            ))
        })?;
        let mut refresh_timings = report::StageTimings::new();
        let staging_bundle_path = staging_dir.join("bundle");
        refresh_timings.measure("existing_bundle_stage", || {
            copy_dir_recursively(&self.bundle_path, &staging_bundle_path)
        })?;

        let mut staging_config = self.config.clone();
        staging_config.object_output = Some(staging_dir.join("framevm.o"));
        let object = refresh_timings.measure("framevm_object_build_and_link", || {
            object::build_framevm_object(&ObjectBuildContext {
                workspace_root: &self.workspace_root,
                cargo_target_dir: &self.cargo_target_dir,
                build: &staging_config.osdk_config.run.build,
                config: &staging_config,
            })
        })?;
        let export_request = refresh_timings.measure("export_request_generation", || {
            identity::write_export_request(&object)
        })?;

        let host_elf = host_elf_artifact(&existing_bundle)?;
        let host_validation = refresh_timings.measure("existing_host_validation", || {
            host::validate_actual_imports(host_elf, &object.actual_imports)
        })?;
        refresh_timings.measure("existing_host_validation_report", || {
            report::write_final_host_validation_report(&object, &host_validation)
        })?;
        if !host_validation.is_exact_match() {
            report::write_stage_timing_report(
                &object.report_dir,
                "framevm_only_refresh",
                &refresh_timings,
            )?;
            remove_dir_if_exists(&staging_dir)?;
            return Ok(None);
        }

        let old_artifact_set = existing_bundle.framevm_artifact_set().ok_or_else(|| {
            FrameVmStageError::Run(
                "existing framevm bundle does not contain framevm artifact-set metadata"
                    .to_string(),
            )
        })?;
        let actual_imports_hash = identity::actual_imports_hash_hex(&object.actual_imports);
        let symbols = if old_artifact_set.actual_imports_hash == actual_imports_hash {
            let symbols_path = existing_bundle.framevm_symbols_path().ok_or_else(|| {
                FrameVmStageError::Run(
                    "existing framevm bundle does not contain framevm.symbols".to_string(),
                )
            })?;
            let staging_symbols_path = staging_dir.join("framevm.symbols");
            refresh_timings.measure("existing_symbol_table_stage", || {
                copy_file_atomically(&symbols_path, &staging_symbols_path)?;
                symbols::inspect_framevm_symbols(&staging_symbols_path)
            })?
        } else {
            refresh_timings.measure("symbol_table_generation", || {
                symbols::write_framevm_symbols(&object, &host_validation)
            })?
        };
        let export_manifest = refresh_timings.measure("export_manifest_generation", || {
            identity::write_export_manifest(
                &self.workspace_root,
                &self.config,
                &object,
                &host_validation,
            )
        })?;
        refresh_timings.measure("export_manifest_validation", || {
            identity::validate_export_manifest(
                &host_validation,
                &object.actual_imports,
                &export_manifest,
            )
        })?;
        let transaction_identity = refresh_timings.measure("transaction_identity", || {
            identity::compute_transaction_identity(
                &self.workspace_root,
                &host_validation,
                &export_manifest,
                &object.actual_imports,
            )
        })?;
        let metadata = refresh_timings.measure("metadata_embedding", || {
            metadata::embed_framevm_metadata(
                &object,
                &symbols,
                &transaction_identity,
                &export_manifest,
            )
        })?;
        let published_artifacts = refresh_timings.measure("artifact_publish", || {
            self.publish_staged_artifacts(
                &staging_dir,
                &final_object_path,
                &object,
                &symbols,
                &metadata,
                &export_request,
                &export_manifest,
                &rollback_dir,
            )
        })?;
        let PublishedFrameVmArtifacts {
            object,
            symbols,
            metadata,
            export_request,
            export_manifest,
            mut object_guard,
        } = published_artifacts;
        let stage_input_identities = refresh_timings.measure("stage_input_identities", || {
            identity::compute_stage_input_identities(&self.workspace_root, &self.config)
        })?;
        let artifact_set_metadata = refresh_timings.measure("artifact_set_metadata", || {
            let source_hash =
                identity::compute_framevm_source_hash(&self.workspace_root, &self.config)?;
            FrameVmArtifactSetMetadata::new(
                &transaction_identity,
                &object,
                &symbols,
                &metadata,
                source_hash,
                stage_input_identities.clone(),
            )
        })?;
        let initramfs_path = package::framevm_initramfs_path(&self.workspace_root);
        let mut initramfs_guard =
            PublishedFileGuard::protect(&initramfs_path, &rollback_dir, "initramfs")?;
        let initramfs = refresh_timings.measure("final_initramfs_packaging", || {
            package::package_initramfs(
                &self.workspace_root,
                &self.config.osdk_config,
                &self.config,
                &object,
            )
        })?;
        let runtime_config = self.runtime_config(&initramfs.path);
        let mut bundle = refresh_timings.measure("staged_bundle_load", || {
            Bundle::load(&staging_bundle_path, true).ok_or_else(|| {
                FrameVmStageError::Package(format!(
                    "staged framevm bundle at {} failed validation",
                    staging_bundle_path.display()
                ))
            })
        })?;
        let mut bundle_runtime_config = runtime_config.clone();
        bundle.update_config(&mut bundle_runtime_config, ActionChoice::Run);
        self.refresh_or_reuse_boot_carrier(
            &mut bundle,
            &staging_bundle_path,
            &bundle_runtime_config,
            symbols.path(),
            &mut refresh_timings,
        )?;
        let mut bundle_artifact_set = artifact_set_metadata.bundle_manifest_entry();
        bundle_artifact_set.framevm_boot_carrier_hash = Some(
            self.compute_boot_carrier_input_manifest(
                &bundle,
                &bundle_runtime_config,
                symbols.path(),
            )?
            .input_hash,
        );
        bundle.replace_framevm_artifact_set(bundle_artifact_set);
        refresh_timings.measure("build_index_report", || {
            report::write_build_index(
                &object,
                &symbols,
                &metadata,
                &export_manifest,
                &export_request,
                &transaction_identity,
                &artifact_set_metadata,
                &stage_input_identities,
                &initramfs,
                &self.bundle_path,
            )
        })?;
        let mut bundle_guard = refresh_timings.measure("bundle_publish", || {
            PublishedDirectoryGuard::replace(&staging_bundle_path, &self.bundle_path, &rollback_dir)
        })?;
        let bundle = refresh_timings.measure("published_bundle_load", || {
            self.load_published_bundle_with_runtime_config(&runtime_config)
        })?;
        report::write_stage_timing_report(
            &object.report_dir,
            "framevm_only_refresh",
            &refresh_timings,
        )?;

        object_guard.commit();
        initramfs_guard.commit();
        bundle_guard.commit();
        remove_dir_if_exists(&staging_dir)?;

        Ok(Some(ValidatedFrameVmArtifactSet {
            object,
            symbols,
            initramfs,
            bundle,
            bundle_path: self.bundle_path.clone(),
        }))
    }

    fn try_refresh_boot_carrier_for_current_artifacts(
        &self,
        current_source_hash: &str,
    ) -> Result<Option<(Bundle, Config)>, FrameVmStageError> {
        let object_output = self.framevm_object_path();
        if !object_output.exists() {
            return Ok(None);
        }

        let Some(bundle) = Bundle::load(&self.bundle_path, true) else {
            return Ok(None);
        };
        let artifact_set = match bundle.framevm_artifact_set() {
            Some(artifact_set) => artifact_set,
            None => return Ok(None),
        };
        if artifact_set.framevm_source_hash.as_deref() != Some(current_source_hash) {
            return Ok(None);
        }

        validate_existing_framevm_artifact_set(&bundle, &object_output)?;
        let initramfs = self.runnable_initramfs_for_bundle(&bundle).ok_or_else(|| {
            FrameVmStageError::Run(
                "existing framevm bundle does not identify a runnable initramfs".to_string(),
            )
        })?;
        let runtime_config = self.runtime_config_from_existing_bundle(&initramfs);
        let symbols_path = bundle.framevm_symbols_path().ok_or_else(|| {
            FrameVmStageError::Run(
                "existing framevm bundle does not contain framevm.symbols".to_string(),
            )
        })?;

        let final_report_dir = object_output
            .parent()
            .ok_or_else(|| {
                FrameVmStageError::ObjectBuild(format!(
                    "framevm object output has no parent: {}",
                    object_output.display()
                ))
            })?
            .to_path_buf();
        let staging_dir = self.prepare_staging_dir(&final_report_dir)?;
        let rollback_dir = staging_dir.join("rollback");
        fs::create_dir_all(&rollback_dir).map_err(|error| {
            FrameVmStageError::Package(format!(
                "failed to create framevm rollback directory {}: {error}",
                rollback_dir.display()
            ))
        })?;
        let staging_bundle_path = staging_dir.join("bundle");
        copy_dir_recursively(&self.bundle_path, &staging_bundle_path)?;
        let mut staging_bundle = Bundle::load(&staging_bundle_path, true).ok_or_else(|| {
            FrameVmStageError::Package(format!(
                "staged framevm bundle at {} failed validation",
                staging_bundle_path.display()
            ))
        })?;
        let mut bundle_runtime_config = runtime_config.clone();
        staging_bundle.update_config(&mut bundle_runtime_config, ActionChoice::Run);
        let mut timings = report::StageTimings::new();
        self.refresh_or_reuse_boot_carrier(
            &mut staging_bundle,
            &staging_bundle_path,
            &bundle_runtime_config,
            &symbols_path,
            &mut timings,
        )?;

        let mut bundle_guard = PublishedDirectoryGuard::replace(
            &staging_bundle_path,
            &self.bundle_path,
            &rollback_dir,
        )?;
        let bundle = self.load_published_bundle_with_runtime_config(&runtime_config)?;
        report::write_stage_timing_report(&final_report_dir, "boot_carrier_refresh", &timings)?;
        bundle_guard.commit();
        remove_dir_if_exists(&staging_dir)?;

        Ok(Some((bundle, runtime_config)))
    }

    fn try_load_current_build_artifact_set(
        &self,
    ) -> Result<Option<FrameVmBuildOutcome>, FrameVmStageError> {
        let object_output = self.framevm_object_path();
        if !object_output.exists() {
            return Ok(None);
        }

        let Some(bundle) = Bundle::load(&self.bundle_path, true) else {
            return Ok(None);
        };
        validate_existing_framevm_artifact_set(&bundle, &object_output)?;

        let artifact_set = bundle.framevm_artifact_set().ok_or_else(|| {
            FrameVmStageError::Run(
                "existing framevm bundle does not contain framevm artifact-set metadata"
                    .to_string(),
            )
        })?;
        let Some(recorded_source_hash) = artifact_set.framevm_source_hash.as_deref() else {
            return Ok(None);
        };
        let current_source_hash =
            identity::compute_framevm_source_hash(&self.workspace_root, &self.config)?;
        if recorded_source_hash != current_source_hash {
            return Ok(None);
        }

        let symbols = bundle.framevm_symbols_path().ok_or_else(|| {
            FrameVmStageError::Run(
                "existing framevm bundle does not contain framevm.symbols".to_string(),
            )
        })?;
        let initramfs = bundle.config().run.boot.initramfs.clone().ok_or_else(|| {
            FrameVmStageError::Run(
                "existing framevm bundle does not identify a runnable initramfs".to_string(),
            )
        })?;

        Ok(Some(FrameVmBuildOutcome {
            object: object_output,
            symbols,
            initramfs,
            bundle: self.bundle_path.clone(),
        }))
    }

    fn run_service_check(&self) -> Result<(), FrameVmStageError> {
        if self.config.skip_service_check {
            return Ok(());
        }

        let input_hash =
            identity::compute_service_check_input_hash(&self.workspace_root, &self.config)?;
        if let Some(record) = self.read_service_check_cache_record()?
            && record.is_success_for(&input_hash)
        {
            return Ok(());
        }

        let mut command = process::command("cargo");
        command
            .arg("run")
            .arg("--quiet")
            .arg("-p")
            .arg("framevm-service-check")
            .arg("--")
            .arg("tools/framevm-service-check/config.toml")
            .current_dir(&self.workspace_root);
        process::run_status(
            command,
            "checking framevm service boundary",
            FrameVmStageError::ServiceCheck,
        )?;
        self.write_service_check_cache_record(input_hash)
    }

    fn run_service_check_and_build_object_in_parallel(
        &self,
        staging_config: &FrameVmBuildConfig,
        timings: &mut report::StageTimings,
    ) -> Result<FrameVmObjectArtifact, FrameVmStageError> {
        let (service_check, object_build) = thread::scope(|scope| {
            let service_check = scope.spawn(|| {
                let started_at = Instant::now();
                TimedStageResult {
                    value: self.run_service_check(),
                    elapsed_ms: started_at.elapsed().as_millis(),
                }
            });
            let object_build = scope.spawn(|| {
                let started_at = Instant::now();
                TimedStageResult {
                    value: object::build_framevm_object(&ObjectBuildContext {
                        workspace_root: &self.workspace_root,
                        cargo_target_dir: &self.cargo_target_dir,
                        build: &staging_config.osdk_config.run.build,
                        config: staging_config,
                    }),
                    elapsed_ms: started_at.elapsed().as_millis(),
                }
            });
            let service_check = service_check.join().unwrap_or_else(|_| TimedStageResult {
                value: Err(FrameVmStageError::ServiceCheck(
                    "framevm service check worker panicked".to_string(),
                )),
                elapsed_ms: 0,
            });
            let object_build = object_build.join().unwrap_or_else(|_| TimedStageResult {
                value: Err(FrameVmStageError::ObjectBuild(
                    "framevm object build worker panicked".to_string(),
                )),
                elapsed_ms: 0,
            });
            (service_check, object_build)
        });

        timings.record("service_check", service_check.elapsed_ms);
        timings.record("framevm_object_build_and_link", object_build.elapsed_ms);
        service_check.value?;
        object_build.value
    }

    fn service_check_cache_path(&self) -> Result<PathBuf, FrameVmStageError> {
        let object_path = self.framevm_object_path();
        let report_dir = object_path.parent().ok_or_else(|| {
            FrameVmStageError::ObjectBuild(format!(
                "framevm object output has no parent: {}",
                object_path.display()
            ))
        })?;
        Ok(report_dir.join("framevm-service-check-cache.json"))
    }

    fn read_service_check_cache_record(
        &self,
    ) -> Result<Option<identity::FrameVmServiceCheckCacheRecord>, FrameVmStageError> {
        let path = self.service_check_cache_path()?;
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|error| {
                FrameVmStageError::ServiceCheck(format!(
                    "failed to parse service-check cache {}: {error}",
                    path.display()
                ))
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(FrameVmStageError::ServiceCheck(format!(
                "failed to read service-check cache {}: {error}",
                path.display()
            ))),
        }
    }

    fn write_service_check_cache_record(
        &self,
        input_hash: String,
    ) -> Result<(), FrameVmStageError> {
        let path = self.service_check_cache_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                FrameVmStageError::ServiceCheck(format!(
                    "failed to create service-check cache directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        let record = identity::FrameVmServiceCheckCacheRecord::new(
            input_hash,
            identity::service_check_config_hash(&self.workspace_root)?,
            identity::service_check_trim_manifest_hash(&self.workspace_root)?,
        );
        let content = serde_json::to_vec_pretty(&record).map_err(|error| {
            FrameVmStageError::ServiceCheck(format!(
                "failed to serialize service-check cache: {error}"
            ))
        })?;
        fs::write(&path, content).map_err(|error| {
            FrameVmStageError::ServiceCheck(format!(
                "failed to write service-check cache {}: {error}",
                path.display()
            ))
        })
    }

    fn host_artifact_is_fresh_for_framevm_only_refresh(
        &self,
        bundle: &Bundle,
    ) -> Result<bool, FrameVmStageError> {
        let host_elf = bundle.aster_bin_path().ok_or_else(|| {
            FrameVmStageError::Run(
                "existing framevm bundle does not contain a final host ELF".to_string(),
            )
        })?;
        let host_modified = fs::metadata(&host_elf)
            .and_then(|metadata| metadata.modified())
            .map_err(|error| {
                FrameVmStageError::Package(format!(
                    "failed to inspect host ELF {}: {error}",
                    host_elf.display()
                ))
            })?;

        for root in HOST_ARTIFACT_SOURCE_ROOTS {
            let source_path = self.workspace_root.join(root);
            let Some(source_modified) = latest_modified_time(&source_path)? else {
                continue;
            };
            if source_modified > host_modified {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn build_host_bundle(
        &self,
        runtime_config: &Config,
        bundle_path: &Path,
        rustflags: &[&str],
    ) -> Bundle {
        create_base_and_cached_build_with_options(
            get_kernel_crate(),
            bundle_path,
            &self.osdk_output_dir,
            &self.cargo_target_dir,
            runtime_config,
            ActionChoice::Run,
            rustflags,
            BundleBuildOptions {
                final_crate_retention: FinalCrateRetention::DemandDrivenOnly,
                kernel_symbols_module: KernelSymbolsModule::Omit,
                quiet_cargo_success: true,
            },
        )
    }

    fn remove_cached_host_elf_for_rebuild(
        &self,
        host_elf: &Path,
        target: &str,
        profile: &str,
    ) -> Result<(), FrameVmStageError> {
        let file_name = host_elf.file_name().ok_or_else(|| {
            FrameVmStageError::Package(format!(
                "host ELF path has no file name: {}",
                host_elf.display()
            ))
        })?;
        self.remove_cached_host_elf_by_file_name(&file_name.to_string_lossy(), target, profile)
    }

    fn remove_cached_host_elf_by_file_name(
        &self,
        file_name: &str,
        target: &str,
        profile: &str,
    ) -> Result<(), FrameVmStageError> {
        let cached_host_elf = self
            .cargo_target_dir
            .join(target)
            .join(cargo_profile_directory(profile))
            .join(file_name);
        remove_file_if_exists(&cached_host_elf)?;

        let mut dep_info = cached_host_elf;
        dep_info.set_extension("d");
        remove_file_if_exists(&dep_info)
    }

    fn try_load_existing_bundle_for_run(
        &self,
        strict: bool,
        current_source_hash: Option<&str>,
    ) -> Result<Option<(Bundle, Config)>, FrameVmStageError> {
        let object_output = self.framevm_object_path();
        if !object_output.exists() {
            return Ok(None);
        }

        let Some(bundle) = Bundle::load(&self.bundle_path, true) else {
            return Ok(None);
        };
        if bundle.framevm_symbols_path().is_none() {
            if strict {
                return Err(FrameVmStageError::Run(
                    "existing framevm bundle does not contain framevm.symbols".to_string(),
                ));
            }
            return Ok(None);
        }
        let compatibility = validate_existing_framevm_artifact_set(&bundle, &object_output);
        if let Err(error) = compatibility {
            if strict {
                return Err(error);
            }
            return Ok(None);
        }
        let artifact_set = bundle.framevm_artifact_set().ok_or_else(|| {
            FrameVmStageError::Run(
                "existing framevm bundle does not contain framevm artifact-set metadata"
                    .to_string(),
            )
        })?;
        let Some(recorded_source_hash) = artifact_set.framevm_source_hash.as_deref() else {
            if strict {
                return Err(FrameVmStageError::Run(
                    "existing framevm bundle does not contain framevm_source_hash".to_string(),
                ));
            }
            return Ok(None);
        };
        let current_source_hash = match current_source_hash {
            Some(current_source_hash) => current_source_hash.to_owned(),
            None => identity::compute_framevm_source_hash(&self.workspace_root, &self.config)?,
        };
        if recorded_source_hash != current_source_hash {
            if strict {
                return Err(FrameVmStageError::Run(
                    "existing framevm bundle framevm_source_hash does not match current sources"
                        .to_string(),
                ));
            }
            return Ok(None);
        }
        let initramfs = self.runnable_initramfs_for_bundle(&bundle).ok_or_else(|| {
            FrameVmStageError::Run(
                "existing framevm bundle does not identify a runnable initramfs".to_string(),
            )
        })?;
        let runtime_config = self.runtime_config_from_existing_bundle(&initramfs);
        match bundle.can_run_with_config(&runtime_config, ActionChoice::Run) {
            Ok(()) => Ok(Some((bundle, runtime_config))),
            Err(error) if strict => Err(FrameVmStageError::Run(format!(
                "existing framevm bundle is not compatible with current config: {error}"
            ))),
            Err(_) => Ok(None),
        }
    }

    fn runtime_config(&self, initramfs: &PathBuf) -> Config {
        let mut config = self.config.osdk_config.clone();
        config.run.boot.initramfs = Some(initramfs.clone());
        replace_init_args(
            &mut config.run.boot.kcmdline,
            self.config.load_action.init_args(),
        );
        config
    }

    fn runtime_config_from_existing_bundle(&self, initramfs: &PathBuf) -> Config {
        let mut config = self.config.osdk_config.clone();
        config.run.boot.initramfs = Some(initramfs.clone());
        replace_init_args(
            &mut config.run.boot.kcmdline,
            self.config.load_action.init_args(),
        );
        config
    }

    fn runnable_initramfs_for_bundle(&self, bundle: &Bundle) -> Option<PathBuf> {
        self.config
            .osdk_config
            .run
            .boot
            .initramfs
            .clone()
            .filter(|path| path.exists())
            .or_else(|| bundle.initramfs_path())
            .or_else(|| {
                bundle
                    .config()
                    .run
                    .boot
                    .initramfs
                    .clone()
                    .filter(|path| path.exists())
            })
    }

    fn load_published_bundle_with_runtime_config(
        &self,
        runtime_config: &Config,
    ) -> Result<Bundle, FrameVmStageError> {
        let mut bundle = Bundle::load(&self.bundle_path, true).ok_or_else(|| {
            FrameVmStageError::Package(format!(
                "published framevm bundle at {} failed validation",
                self.bundle_path.display()
            ))
        })?;
        let mut bundle_runtime_config = runtime_config.clone();
        bundle.update_config(&mut bundle_runtime_config, ActionChoice::Run);
        Bundle::load(&self.bundle_path, true).ok_or_else(|| {
            FrameVmStageError::Package(format!(
                "published framevm bundle at {} failed validation after config refresh",
                self.bundle_path.display()
            ))
        })
    }

    fn framevm_object_path(&self) -> PathBuf {
        let object_path = self
            .config
            .object_output
            .clone()
            .unwrap_or_else(|| object::default_object_output(&self.workspace_root));
        workspace_absolute_path(&self.workspace_root, object_path)
    }

    fn prepare_staging_dir(&self, final_report_dir: &Path) -> Result<PathBuf, FrameVmStageError> {
        let staging_dir = final_report_dir.join(format!(".framevm-staging-{}", std::process::id()));
        remove_stale_framevm_staging_dirs(final_report_dir, &staging_dir)?;
        remove_dir_if_exists(&staging_dir)?;
        fs::create_dir_all(&staging_dir).map_err(|error| {
            FrameVmStageError::Package(format!(
                "failed to create framevm staging directory {}: {error}",
                staging_dir.display()
            ))
        })?;
        Ok(staging_dir)
    }

    fn refresh_or_reuse_boot_carrier(
        &self,
        bundle: &mut Bundle,
        bundle_dir: &Path,
        runtime_config: &Config,
        symbols_path: &Path,
        timings: &mut report::StageTimings,
    ) -> Result<(), FrameVmStageError> {
        let started_at = Instant::now();
        let current_manifest =
            self.compute_boot_carrier_input_manifest(bundle, runtime_config, symbols_path)?;
        let manifest_path = self.boot_carrier_manifest_path(bundle_dir);
        let can_reuse = identity::read_boot_carrier_input_manifest(&manifest_path)?
            .is_some_and(|recorded| recorded.is_current(&current_manifest))
            && bundle.vm_image_path().is_some_and(|path| path.exists())
            && bundle
                .framevm_symbols_path()
                .is_some_and(|path| path.exists());
        if can_reuse {
            timings.record("boot_carrier_reuse", started_at.elapsed().as_millis());
            return Ok(());
        }

        refresh_grub_bootdev_image_with_framevm_symbols(
            bundle,
            &self.osdk_output_dir,
            runtime_config,
            ActionChoice::Run,
            symbols_path,
        )
        .map_err(FrameVmStageError::Package)?;
        identity::write_boot_carrier_input_manifest(&manifest_path, &current_manifest)?;
        timings.record("boot_carrier_refresh", started_at.elapsed().as_millis());
        Ok(())
    }

    fn compute_boot_carrier_input_manifest(
        &self,
        bundle: &Bundle,
        runtime_config: &Config,
        symbols_path: &Path,
    ) -> Result<identity::FrameVmBootCarrierInputManifest, FrameVmStageError> {
        let host_boot_artifact = bundle.aster_bin_path().ok_or_else(|| {
            FrameVmStageError::Package(
                "selected bundle does not contain a host kernel ELF".to_string(),
            )
        })?;
        let initramfs = runtime_config
            .run
            .boot
            .initramfs
            .as_deref()
            .ok_or_else(|| {
                FrameVmStageError::Package(
                    "FrameVM boot carrier requires a configured initramfs".to_string(),
                )
            })?;
        identity::compute_boot_carrier_input_manifest(
            &host_boot_artifact,
            initramfs,
            symbols_path,
            runtime_config,
        )
    }

    fn boot_carrier_manifest_path(&self, bundle_dir: &Path) -> PathBuf {
        bundle_dir.join("framevm-boot-carrier-input.json")
    }

    fn publish_staged_artifacts(
        &self,
        staging_dir: &Path,
        final_object_path: &Path,
        object: &FrameVmObjectArtifact,
        symbols: &symbols::FrameVmSymbolsArtifact,
        metadata: &metadata::FrameVmMetadataArtifact,
        export_request: &identity::FrameVmExportRequestArtifact,
        export_manifest: &identity::FrameVmExportManifestArtifact,
        rollback_dir: &Path,
    ) -> Result<PublishedFrameVmArtifacts, FrameVmStageError> {
        let final_report_dir = final_object_path.parent().ok_or_else(|| {
            FrameVmStageError::ObjectBuild(format!(
                "framevm object output has no parent: {}",
                final_object_path.display()
            ))
        })?;
        fs::create_dir_all(final_report_dir).map_err(|error| {
            FrameVmStageError::Package(format!(
                "failed to create framevm report directory {}: {error}",
                final_report_dir.display()
            ))
        })?;
        remove_stale_framevm_intermediates(final_report_dir)?;

        for entry in fs::read_dir(staging_dir).map_err(|error| {
            FrameVmStageError::Package(format!(
                "failed to read framevm staging directory {}: {error}",
                staging_dir.display()
            ))
        })? {
            let path = entry
                .map_err(|error| {
                    FrameVmStageError::Package(format!(
                        "failed to read framevm staging entry in {}: {error}",
                        staging_dir.display()
                    ))
                })?
                .path();
            if !path.is_file() || path == object.path {
                continue;
            }
            let file_name = path.file_name().ok_or_else(|| {
                FrameVmStageError::Package(format!(
                    "framevm staging path has no file name: {}",
                    path.display()
                ))
            })?;
            copy_file_atomically(&path, &final_report_dir.join(file_name))?;
        }

        let object_guard =
            PublishedFileGuard::protect(final_object_path, rollback_dir, "framevm.o")?;
        copy_file_atomically(&object.path, final_object_path)?;

        Ok(PublishedFrameVmArtifacts {
            object: object.with_published_paths(
                final_object_path.to_path_buf(),
                final_report_dir.to_path_buf(),
            ),
            symbols: symbols.with_path(published_path(final_report_dir, symbols.path())?),
            metadata: metadata.with_path(published_path(final_report_dir, metadata.path())?),
            export_request: export_request
                .with_path(published_path(final_report_dir, export_request.path())?),
            export_manifest: export_manifest
                .with_path(published_path(final_report_dir, export_manifest.path())?),
            object_guard,
        })
    }
}

fn remove_stale_framevm_intermediates(report_dir: &Path) -> Result<(), FrameVmStageError> {
    for entry in fs::read_dir(report_dir).map_err(|error| {
        FrameVmStageError::Package(format!(
            "failed to read framevm report directory {}: {error}",
            report_dir.display()
        ))
    })? {
        let path = entry
            .map_err(|error| {
                FrameVmStageError::Package(format!(
                    "failed to read entry under {}: {error}",
                    report_dir.display()
                ))
            })?
            .path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if path.is_file() && is_stale_framevm_intermediate(file_name) {
            fs::remove_file(&path).map_err(|error| {
                FrameVmStageError::Package(format!(
                    "failed to remove stale framevm intermediate {}: {error}",
                    path.display()
                ))
            })?;
        }
    }
    Ok(())
}

fn is_stale_framevm_intermediate(file_name: &str) -> bool {
    (file_name.starts_with("framevm-initial-")
        && (file_name.ends_with(".o") || file_name.ends_with(".d")))
        || (file_name.starts_with("libframevm-")
            && (file_name.ends_with(".rlib") || file_name.ends_with(".rmeta")))
}

fn remove_stale_framevm_staging_dirs(
    report_dir: &Path,
    current_staging_dir: &Path,
) -> Result<(), FrameVmStageError> {
    if !report_dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(report_dir).map_err(|error| {
        FrameVmStageError::Package(format!(
            "failed to read framevm report directory {}: {error}",
            report_dir.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            FrameVmStageError::Package(format!(
                "failed to read entry under {}: {error}",
                report_dir.display()
            ))
        })?;
        let path = entry.path();
        if path == current_staging_dir || !path.is_dir() {
            continue;
        }

        let Some(pid) = staging_dir_process_id(&path) else {
            continue;
        };
        if framevm_staging_owner_is_live(pid) {
            continue;
        }

        remove_dir_if_exists(&path)?;
    }

    Ok(())
}

fn staging_dir_process_id(path: &Path) -> Option<u32> {
    let file_name = path.file_name()?.to_str()?;
    let pid = file_name.strip_prefix(".framevm-staging-")?;
    pid.parse().ok()
}

fn framevm_staging_owner_is_live(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

struct PublishedFileGuard {
    path: PathBuf,
    backup: Option<PathBuf>,
    committed: bool,
}

impl PublishedFileGuard {
    fn protect(path: &Path, rollback_dir: &Path, label: &str) -> Result<Self, FrameVmStageError> {
        fs::create_dir_all(rollback_dir).map_err(|error| {
            FrameVmStageError::Package(format!(
                "failed to create framevm rollback directory {}: {error}",
                rollback_dir.display()
            ))
        })?;
        let backup = rollback_dir.join(format!("{label}.backup"));
        remove_file_if_exists(&backup)?;
        let backup = if fs::symlink_metadata(path).is_ok() {
            fs::rename(path, &backup).map_err(|error| {
                FrameVmStageError::Package(format!(
                    "failed to protect published framevm file {}: {error}",
                    path.display()
                ))
            })?;
            Some(backup)
        } else {
            None
        };
        Ok(Self {
            path: path.to_path_buf(),
            backup,
            committed: false,
        })
    }

    fn commit(&mut self) {
        if let Some(backup) = self.backup.take() {
            let _ = fs::remove_file(backup);
        }
        self.committed = true;
    }
}

impl Drop for PublishedFileGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let _ = remove_file_or_symlink(&self.path);
        if let Some(backup) = self.backup.take() {
            let _ = fs::rename(backup, &self.path);
        }
    }
}

struct PublishedDirectoryGuard {
    path: PathBuf,
    backup: Option<PathBuf>,
    committed: bool,
}

impl PublishedDirectoryGuard {
    fn replace(
        staging_path: &Path,
        published_path: &Path,
        rollback_dir: &Path,
    ) -> Result<Self, FrameVmStageError> {
        fs::create_dir_all(rollback_dir).map_err(|error| {
            FrameVmStageError::Package(format!(
                "failed to create framevm rollback directory {}: {error}",
                rollback_dir.display()
            ))
        })?;
        let backup = rollback_dir.join("bundle.backup");
        remove_dir_if_exists(&backup)?;
        let backup = if fs::symlink_metadata(published_path).is_ok() {
            fs::rename(published_path, &backup).map_err(|error| {
                FrameVmStageError::Package(format!(
                    "failed to protect published framevm bundle {}: {error}",
                    published_path.display()
                ))
            })?;
            Some(backup)
        } else {
            None
        };
        if let Err(error) = fs::rename(staging_path, published_path) {
            if let Some(backup) = &backup {
                let _ = fs::rename(backup, published_path);
            }
            return Err(FrameVmStageError::Package(format!(
                "failed to publish framevm bundle {}: {error}",
                published_path.display()
            )));
        }
        Ok(Self {
            path: published_path.to_path_buf(),
            backup,
            committed: false,
        })
    }

    fn commit(&mut self) {
        if let Some(backup) = self.backup.take() {
            let _ = fs::remove_dir_all(backup);
        }
        self.committed = true;
    }
}

impl Drop for PublishedDirectoryGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let _ = remove_dir_if_exists(&self.path);
        if let Some(backup) = self.backup.take() {
            let _ = fs::rename(backup, &self.path);
        }
    }
}

fn workspace_root() -> Result<PathBuf, FrameVmStageError> {
    let metadata = get_cargo_metadata(None::<&str>, None::<&[&str]>).ok_or_else(|| {
        FrameVmStageError::Workspace("failed to query cargo metadata".to_string())
    })?;
    metadata
        .get("workspace_root")
        .and_then(|root| root.as_str())
        .map(PathBuf::from)
        .ok_or_else(|| {
            FrameVmStageError::Workspace(
                "cargo metadata did not contain workspace_root".to_string(),
            )
        })
}

fn workspace_absolute_path(workspace_root: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        workspace_root.join(path)
    }
}

fn latest_modified_time(path: &Path) -> Result<Option<SystemTime>, FrameVmStageError> {
    if !path.exists() {
        return Ok(None);
    }

    let metadata = fs::metadata(path).map_err(|error| {
        FrameVmStageError::Package(format!(
            "failed to inspect host source input {}: {error}",
            path.display()
        ))
    })?;
    if metadata.is_file() {
        return metadata.modified().map(Some).map_err(|error| {
            FrameVmStageError::Package(format!(
                "failed to read modified time for host source input {}: {error}",
                path.display()
            ))
        });
    }
    if !metadata.is_dir() {
        return Ok(None);
    }

    let mut latest = metadata.modified().map(Some).map_err(|error| {
        FrameVmStageError::Package(format!(
            "failed to read modified time for host source input {}: {error}",
            path.display()
        ))
    })?;
    let entries = fs::read_dir(path)
        .map_err(|error| {
            FrameVmStageError::Package(format!(
                "failed to list host source input {}: {error}",
                path.display()
            ))
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            FrameVmStageError::Package(format!(
                "failed to read host source input {}: {error}",
                path.display()
            ))
        })?;

    for entry in entries {
        if let Some(modified) = latest_modified_time(&entry.path())?
            && latest.is_none_or(|current| modified > current)
        {
            latest = Some(modified);
        }
    }

    Ok(latest)
}

fn replace_init_args(kcmdline: &mut Vec<String>, init_args: Vec<String>) {
    let separator = kcmdline
        .iter()
        .position(|arg| arg == "--")
        .map(|index| index + 1)
        .unwrap_or_else(|| {
            kcmdline.push("--".to_string());
            kcmdline.len()
        });
    kcmdline.truncate(separator);
    kcmdline.extend(init_args);
}

fn published_path(output_dir: &Path, source_path: &Path) -> Result<PathBuf, FrameVmStageError> {
    let file_name = source_path.file_name().ok_or_else(|| {
        FrameVmStageError::Package(format!(
            "framevm artifact path has no file name: {}",
            source_path.display()
        ))
    })?;
    Ok(output_dir.join(file_name))
}

fn copy_file_atomically(source: &Path, destination: &Path) -> Result<(), FrameVmStageError> {
    let parent = destination.parent().ok_or_else(|| {
        FrameVmStageError::Package(format!(
            "destination has no parent: {}",
            destination.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        FrameVmStageError::Package(format!(
            "failed to create destination directory {}: {error}",
            parent.display()
        ))
    })?;
    let file_name = destination.file_name().ok_or_else(|| {
        FrameVmStageError::Package(format!(
            "destination has no file name: {}",
            destination.display()
        ))
    })?;
    let temp_name = format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        std::process::id()
    );
    let temp_path = parent.join(temp_name);
    remove_file_if_exists(&temp_path)?;
    fs::copy(source, &temp_path).map_err(|error| {
        FrameVmStageError::Package(format!(
            "failed to copy {} to {}: {error}",
            source.display(),
            temp_path.display()
        ))
    })?;
    fs::rename(&temp_path, destination).map_err(|error| {
        let _ = fs::remove_file(&temp_path);
        FrameVmStageError::Package(format!(
            "failed to publish {} as {}: {error}",
            temp_path.display(),
            destination.display()
        ))
    })
}

fn copy_dir_recursively(source: &Path, destination: &Path) -> Result<(), FrameVmStageError> {
    remove_dir_if_exists(destination)?;
    fs::create_dir_all(destination).map_err(|error| {
        FrameVmStageError::Package(format!(
            "failed to create directory {}: {error}",
            destination.display()
        ))
    })?;
    for entry in fs::read_dir(source).map_err(|error| {
        FrameVmStageError::Package(format!(
            "failed to read directory {}: {error}",
            source.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            FrameVmStageError::Package(format!(
                "failed to read directory entry in {}: {error}",
                source.display()
            ))
        })?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type().map_err(|error| {
            FrameVmStageError::Package(format!(
                "failed to inspect {}: {error}",
                source_path.display()
            ))
        })?;
        if file_type.is_dir() {
            copy_dir_recursively(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            hard_link_or_copy(&source_path, &destination_path).map_err(|error| {
                FrameVmStageError::Package(format!(
                    "failed to copy or link {} to {}: {error}",
                    source_path.display(),
                    destination_path.display()
                ))
            })?;
        }
    }
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<(), FrameVmStageError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(FrameVmStageError::Package(format!(
            "failed to remove {}: {error}",
            path.display()
        ))),
    }
}

fn cargo_profile_directory(profile: &str) -> &str {
    if profile == "dev" { "debug" } else { profile }
}

fn remove_file_or_symlink(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn remove_dir_if_exists(path: &Path) -> Result<(), FrameVmStageError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(FrameVmStageError::Package(format!(
            "failed to remove directory {}: {error}",
            path.display()
        ))),
    }
}

fn framevm_load_completed(qemu_log: &str, success_markers: &[&str]) -> bool {
    success_markers
        .iter()
        .all(|success_marker| qemu_log.contains(success_marker))
}

fn framevm_load_failure_summary(qemu_log: &str, success_markers: &[&str]) -> String {
    let missing_markers = success_markers
        .iter()
        .copied()
        .filter(|success_marker| !qemu_log.contains(success_marker))
        .collect::<Vec<_>>();
    let missing_markers = if missing_markers.is_empty() {
        "none".to_string()
    } else {
        missing_markers.join(", ")
    };
    let terminal_status = qemu_log
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| line.contains("FrameVM terminal status:"))
        .unwrap_or("no framevm terminal status observed");
    let console_bridge_status =
        if qemu_log.contains("FRAMEVM_VM_ID=") || qemu_log.contains("FRAMEVM_GUEST_CID=") {
            "console bridge observed framevm identity"
        } else if qemu_log.contains("FRAMEVM_START failure status:") {
            "console bridge did not reach started framevm identity"
        } else {
            "no framevm console bridge identity observed"
        };

    format!(
        "missing framevm markers: {missing_markers}; {terminal_status}; {console_bridge_status}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_stale_framevm_staging_dirs_skips_current_and_live_owner() {
        let temp_dir = tempfile::tempdir().unwrap();
        let report_dir = temp_dir.path();
        let stale_staging_dir = report_dir.join(".framevm-staging-4294967295");
        let live_staging_dir = report_dir.join(format!(".framevm-staging-{}", std::process::id()));
        let current_staging_dir = report_dir.join(".framevm-staging-123456789");
        let unrelated_dir = report_dir.join("service-target");

        fs::create_dir_all(&stale_staging_dir).unwrap();
        fs::create_dir_all(&live_staging_dir).unwrap();
        fs::create_dir_all(&current_staging_dir).unwrap();
        fs::create_dir_all(&unrelated_dir).unwrap();

        remove_stale_framevm_staging_dirs(report_dir, &current_staging_dir).unwrap();

        assert!(!stale_staging_dir.exists());
        assert!(live_staging_dir.exists());
        assert!(current_staging_dir.exists());
        assert!(unrelated_dir.exists());
    }

    #[test]
    fn staging_dir_process_id_accepts_only_framevm_staging_dirs() {
        assert_eq!(
            staging_dir_process_id(Path::new(".framevm-staging-1234")),
            Some(1234)
        );
        assert_eq!(
            staging_dir_process_id(Path::new("framevm-staging-1234")),
            None
        );
        assert_eq!(
            staging_dir_process_id(Path::new(".framevm-staging-not-a-pid")),
            None
        );
    }

    #[test]
    fn workspace_absolute_path_resolves_relative_paths_from_workspace_root() {
        let workspace_root = Path::new("/workspace");

        assert_eq!(
            workspace_absolute_path(workspace_root, PathBuf::from("build/framevm/framevm.o")),
            PathBuf::from("/workspace/build/framevm/framevm.o")
        );
        assert_eq!(
            workspace_absolute_path(workspace_root, PathBuf::from("/tmp/framevm.o")),
            PathBuf::from("/tmp/framevm.o")
        );
    }

    #[test]
    fn latest_modified_time_walks_nested_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let nested_dir = temp_dir.path().join("kernel/src");
        fs::create_dir_all(&nested_dir).unwrap();
        let source_file = nested_dir.join("vmm.rs");
        fs::write(&source_file, b"host source").unwrap();

        let source_modified = fs::metadata(&source_file).unwrap().modified().unwrap();
        let latest = latest_modified_time(temp_dir.path()).unwrap().unwrap();

        assert!(latest >= source_modified);
    }

    #[test]
    fn framevm_load_failure_summary_reports_missing_markers() {
        let summary = framevm_load_failure_summary(
            "FRAMEVM_BOOT_OK\nFrameVM terminal status: exited-success code=0 reason=1\n",
            &["FRAMEVM_BOOT_OK", "FRAMEVM_ROOTFS_OK"],
        );

        assert_eq!(
            summary,
            "missing framevm markers: FRAMEVM_ROOTFS_OK; FrameVM terminal status: exited-success code=0 reason=1; no framevm console bridge identity observed"
        );
    }

    #[test]
    fn framevm_load_failure_summary_reports_missing_terminal_status() {
        let summary = framevm_load_failure_summary("", &["FRAMEVM_LOAD_OK"]);

        assert_eq!(
            summary,
            "missing framevm markers: FRAMEVM_LOAD_OK; no framevm terminal status observed; no framevm console bridge identity observed"
        );
    }

    #[test]
    fn framevm_load_failure_summary_reports_console_bridge_identity() {
        let summary = framevm_load_failure_summary(
            "FRAMEVM_VM_ID=7\nFRAMEVM_GUEST_CID=10\n",
            &["FRAMEVM_LOAD_OK"],
        );

        assert_eq!(
            summary,
            "missing framevm markers: FRAMEVM_LOAD_OK; no framevm terminal status observed; console bridge observed framevm identity"
        );
    }
}

fn host_elf_artifact(bundle: &Bundle) -> Result<HostElfArtifact, FrameVmStageError> {
    let path = bundle.aster_bin_path().ok_or_else(|| {
        FrameVmStageError::ImportValidation(
            "selected host bundle does not contain a final host ELF".to_string(),
        )
    })?;
    Ok(HostElfArtifact::new(path))
}

fn validate_existing_framevm_artifact_set(
    bundle: &Bundle,
    framevm_object_path: &std::path::Path,
) -> Result<(), FrameVmStageError> {
    let symbols_path = bundle.framevm_symbols_path().ok_or_else(|| {
        FrameVmStageError::Run(
            "existing framevm bundle does not contain framevm.symbols".to_string(),
        )
    })?;
    let host_elf_path = bundle.aster_bin_path().ok_or_else(|| {
        FrameVmStageError::Run(
            "existing framevm bundle does not contain a final host ELF".to_string(),
        )
    })?;
    let artifact_set = bundle.framevm_artifact_set().ok_or_else(|| {
        FrameVmStageError::Run(
            "existing framevm bundle does not contain framevm artifact-set metadata".to_string(),
        )
    })?;
    let actual_imports = imports::collect_actual_host_imports(framevm_object_path)?;
    let actual_imports_hash = identity::actual_imports_hash_hex(&actual_imports);
    identity::validate_bundle_artifact_set(
        artifact_set,
        &symbols_path,
        framevm_object_path,
        &host_elf_path,
        &actual_imports_hash,
    )?;

    let host_validation =
        host::validate_actual_imports(HostElfArtifact::new(host_elf_path), &actual_imports)
            .map_err(|error| FrameVmStageError::Run(error.to_string()))?;
    if !host_validation.is_exact_match() {
        return Err(FrameVmStageError::Run(format!(
            "existing framevm bundle failed final-host import validation: {}",
            final_host_validation_error(&host_validation)
        )));
    }
    Ok(())
}

fn final_host_validation_error(validation: &host::HostImportValidation) -> String {
    let mut errors = Vec::new();
    if !validation.missing_imports().is_empty() {
        let symbols = validation
            .missing_imports()
            .iter()
            .take(8)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        errors.push(format!(
            "final host ELF is missing {} framevm import(s): {}",
            validation.missing_imports().len(),
            symbols
        ));
    }
    if !validation.ambiguous_imports().is_empty() {
        let symbols = validation
            .ambiguous_imports()
            .iter()
            .take(8)
            .map(|symbol| symbol.import_name().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        errors.push(format!(
            "final host ELF has {} ambiguous framevm import match(es): {}",
            validation.ambiguous_imports().len(),
            symbols
        ));
    }
    errors.join("; ")
}
