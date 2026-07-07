// SPDX-License-Identifier: MPL-2.0

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs, io,
    path::{Path, PathBuf},
};

use quote::ToTokens;
use syn::{
    Attribute, File, GenericParam, Generics, ImplItem, Item, ItemFn, ItemMod, ItemUse,
    Path as SynPath, ReturnType, Type, UseTree, Visibility,
    visit::{self, Visit},
};

type CheckResult<T> = Result<T, CheckError>;

const LEGACY_HIGH_LEVEL_FRAMEV_MODULES: &[&str] =
    &["framev_sock", "framev_rng", "framev_console", "framev_blk"];

const LEGACY_FRAMEV_CONFIG_MARKERS: &[&str] = &[
    "aster_framevsock",
    "framev_sock",
    "framev_rng",
    "framev_console",
    "framev_blk",
];

const LEGACY_FRAMEV_POLICY_MARKERS: &[&str] = &[
    "aster_framevsock",
    "aster_framevsock::",
    "framev_sock",
    "framev_sock::",
    "framev_rng",
    "framev_rng::",
    "framev_console",
    "framev_console::",
    "framev_blk",
    "framev_blk::",
];

const LEGACY_FRAMEV_PACKAGE_NAMES: &[&str] = &["aster-framevsock", "framev-console", "framev-rng"];

const SERVICE_ALLOWED_SHARED_ASTER_CRATES: &[&str] =
    &["aster-rights", "aster-rights-proc", "aster-util"];

const FRAMEV_DEVICE_MODEL_OWNED_ITEM_NAMES: &[&str] = &[
    "BatchCompletionObserver",
    "CleanupOutcome",
    "CleanupState",
    "CommonError",
    "CompletionInfo",
    "ConsumedResource",
    "ControlPathAuthority",
    "DeviceGeneration",
    "DeviceState",
    "DeviceStatus",
    "FrameVDevice",
    "FrameVDeviceDescriptor",
    "FrameVDeviceError",
    "FrameVDeviceId",
    "FrameVDeviceInfo",
    "FrameVDeviceType",
    "FrameVRequest",
    "FrameVResource",
    "FrameVRingLayout",
    "Free",
    "InvalidIrqLine",
    "IrqAccepted",
    "IrqDelivery",
    "IrqLine",
    "IrqTarget",
    "OperationError",
    "OperationResult",
    "OwnedResource",
    "PollOutcome",
    "ReadOnly",
    "ReadWrite",
    "ReceiverEndpoint",
    "ReclaimOutcome",
    "ResourceAccessMode",
    "ResourceResult",
    "ReturnedResource",
    "RingAuthorities",
    "RingSlot",
    "SubmitOutcome",
    "Submitted",
    "SubmittedResource",
    "SubmitterEndpoint",
    "WriteOnly",
];

const FORBIDDEN_HOST_MANAGEMENT_FACADE_EXPORT_PATTERNS: &[&str] = &[
    "pub mod vm",
    "pub mod vmm",
    "create_framevm",
    "destroy_framevm",
    "list_framevms",
    "FrameVmFile",
    "FrameVcpuId",
    "VmId",
];

#[derive(Debug)]
struct CheckError {
    message: String,
}

impl CheckError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl From<io::Error> for CheckError {
    fn from(error: io::Error) -> Self {
        Self::new(error.to_string())
    }
}

#[derive(Clone, Debug)]
struct Config {
    service_path: PathBuf,
    kernel_src_path: PathBuf,
    facade_path: PathBuf,
    host_ostd_path: PathBuf,
    framevisor_backend_device_root: PathBuf,
    trim_manifest_path: PathBuf,
    component_metadata_path: PathBuf,
    kernel_component_profile: String,
    framevm_component_profile: String,
    source_trim_enforcement: SourceTrimEnforcement,
    entry_trim_files: BTreeSet<PathBuf>,
    forbidden_service_subtrees: Vec<PathBuf>,
    service_local_module_aliases: BTreeSet<String>,
    host_only_component_packages: BTreeSet<String>,
    framev_common_crate_roots: Vec<PathBuf>,
    framev_frontend_crates: Vec<FrontendCrateConfig>,
    service_side_trimmed_comps: Vec<TrimmedCompConfig>,
    excluded_path_prefixes: Vec<String>,
    allowed_provider_facade_paths: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct TrimmedCompConfig {
    name: String,
    service_path: PathBuf,
    kernel_path: PathBuf,
    package: String,
    dependency_key: String,
}

#[derive(Clone, Debug)]
struct FrontendCrateConfig {
    name: String,
    path: PathBuf,
    package: String,
    common_package: String,
    allowed_service_dependencies: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SourceTrimEnforcement {
    Migration,
    Final,
}

impl SourceTrimEnforcement {
    fn parse(value: &str) -> CheckResult<Self> {
        match value {
            "migration" => Ok(Self::Migration),
            "final" => Ok(Self::Final),
            _ => Err(CheckError::new(format!(
                "source_trim_enforcement must be `migration` or `final`, got `{value}`"
            ))),
        }
    }

    fn is_final(self) -> bool {
        self == Self::Final
    }
}

#[derive(Clone, Debug, Default)]
struct TrimManifest {
    entries: BTreeMap<PathBuf, TrimManifestEntry>,
}

#[derive(Clone, Debug)]
struct TrimManifestEntry {
    kernel_path: PathBuf,
    kind: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ItemShape {
    kind: &'static str,
    shape: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Shape {
    Function(FunctionShape),
    Item { kind: &'static str },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FunctionShape {
    generics: Vec<String>,
    inputs: Vec<String>,
    output: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct PublicApi {
    exact: BTreeMap<String, Shape>,
    module_prefixes: BTreeSet<String>,
}

impl PublicApi {
    fn insert_module(&mut self, path: &[String]) {
        if !path.is_empty() {
            self.module_prefixes.insert(path.join("::"));
        }
    }

    fn insert_item(&mut self, path: &[String], shape: Shape) {
        if !path.is_empty() {
            self.exact.insert(path.join("::"), shape);
        }
    }

    fn contains_public_path(&self, path: &str) -> bool {
        self.exact.contains_key(path)
            || self.module_prefixes.contains(path)
            || ancestors(path).into_iter().any(|ancestor| {
                self.exact.contains_key(&ancestor) || self.module_prefixes.contains(&ancestor)
            })
    }
}

#[derive(Clone, Debug, Default)]
struct UsedOstd {
    paths: BTreeSet<String>,
    aliases: BTreeMap<String, Vec<String>>,
    prelude_glob: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {}", error.message);
        std::process::exit(1);
    }
}

fn run() -> CheckResult<()> {
    let repo_root = env::current_dir()?;
    let config_path = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tools/framevm-service-check/config.toml"));
    let config = read_config(&repo_root, &config_path)?;

    validate_configured_roots(&repo_root, &config)?;
    let trim_manifest = validate_trim_manifest(&repo_root, &config)?;
    validate_workspace_dependency(&repo_root, &config)?;
    validate_service_manifest(&repo_root, &config)?;
    validate_trimmed_comp_manifests(&repo_root, &config)?;
    validate_component_profiles(&repo_root, &config)?;
    validate_legacy_framev_package_absence(&repo_root)?;
    validate_framev_common_crates(&repo_root, &config)?;
    validate_framev_frontend_crates(&repo_root, &config)?;
    validate_framev_frontend_source_boundaries(&repo_root, &config)?;
    validate_framevisor_backend_placement(&repo_root, &config)?;
    validate_framevisor_ostd_style_module_boundaries(&repo_root)?;
    validate_framevisor_ostd_host_management_absence(&repo_root, &config)?;
    validate_framevisor_task_scheduler_layout(&repo_root)?;
    validate_frame_sched_group_contract(&repo_root)?;
    validate_iht_callback_discipline_comments(&repo_root)?;
    validate_iht_has_no_direct_device_data_path(&repo_root)?;
    validate_framevm_component_profile_usage(&repo_root, &config)?;

    let service_src = repo_root.join(&config.service_path).join("src");
    let facade_src = repo_root.join(&config.facade_path).join("src");
    let host_src = repo_root.join(&config.host_ostd_path).join("src");

    let service_files = rust_files(&service_src)?;
    check_banned_service_refs(&service_files)?;
    check_framevm_cpu_local_boundary(&repo_root, &config, &service_files)?;
    check_forbidden_service_subtrees(&repo_root, &config, &service_files)?;
    check_retained_layout(&repo_root, &config, &service_files)?;
    check_trimmed_comp_layout(&repo_root, &config)?;
    check_framev_sock_rx_callback_boundary(&repo_root, &config)?;
    check_no_parallel_softirq_framework(&repo_root, &config, &service_files)?;
    check_low_level_framev_usage_boundary(&repo_root, &config, &service_files)?;
    check_high_level_framev_facade_absence(&repo_root, &config, &service_files)?;
    check_vfs_ext2_framev_protocol_boundary(&repo_root, &config)?;
    check_legacy_framev_policy_marker_absence(&repo_root)?;
    check_retained_differences(&repo_root, &config, &service_files, &trim_manifest)?;
    check_final_source_layout(&repo_root, &config, &service_files)?;
    check_final_superseded_implementation_paths(&repo_root, &config)?;
    check_final_facade_boundary(&repo_root, &config, &service_files)?;
    check_final_rootfs_artifact_policy(&repo_root, &config)?;
    check_legacy_framevm_test_entrypoint_absence(&repo_root)?;
    check_final_service_local_rootfs_adapters(&config, &service_files)?;
    check_final_framevm_interactive_shell_policy(&repo_root, &config, &service_files)?;
    check_lib_entry_policy(&repo_root, &config)?;
    check_final_entry_init_policy(&repo_root, &config)?;

    let mut used = UsedOstd::default();
    for file in &service_files {
        collect_used_ostd(file, &mut used)?;
    }
    if used.prelude_glob {
        collect_used_prelude_items(&repo_root, &config, &service_files, &mut used)?;
    }

    let facade_api = collect_public_api(&facade_src)?;
    let host_api = collect_public_api(&host_src)?;
    check_used_ostd_shape(&used, &facade_api, &host_api, &config)?;

    println!(
        "framevm-service-check: checked {} service Rust files and {} OSTD paths",
        service_files.len(),
        used.paths.len()
    );
    Ok(())
}

fn read_config(repo_root: &Path, config_path: &Path) -> CheckResult<Config> {
    let path = repo_root.join(config_path);
    let value = read_toml(&path)?;
    validate_no_legacy_framev_config_markers(&value, &path)?;
    Ok(Config {
        service_path: required_string(&value, "service_path")?.into(),
        kernel_src_path: required_string(&value, "kernel_src_path")?.into(),
        facade_path: required_string(&value, "facade_path")?.into(),
        host_ostd_path: required_string(&value, "host_ostd_path")?.into(),
        framevisor_backend_device_root: required_string(&value, "framevisor_backend_device_root")?
            .into(),
        trim_manifest_path: required_string(&value, "trim_manifest_path")?.into(),
        component_metadata_path: required_string(&value, "component_metadata_path")?.into(),
        kernel_component_profile: required_string(&value, "kernel_component_profile")?,
        framevm_component_profile: required_string(&value, "framevm_component_profile")?,
        source_trim_enforcement: SourceTrimEnforcement::parse(&required_string(
            &value,
            "source_trim_enforcement",
        )?)?,
        entry_trim_files: required_path_set(&value, "entry_trim_files")?,
        forbidden_service_subtrees: required_path_array(&value, "forbidden_service_subtrees")?,
        service_local_module_aliases: required_string_set(&value, "service_local_module_aliases")?,
        host_only_component_packages: required_string_set(&value, "host_only_component_packages")?,
        framev_common_crate_roots: required_path_array(&value, "framev_common_crate_roots")?,
        framev_frontend_crates: required_frontend_crate_configs(&value)?,
        service_side_trimmed_comps: required_trimmed_comp_configs(&value)?,
        excluded_path_prefixes: required_array(&value, "excluded_path_prefixes")?,
        allowed_provider_facade_paths: required_string_set(
            &value,
            "allowed_provider_facade_paths",
        )?,
    })
}

fn validate_no_legacy_framev_config_markers(
    value: &toml::Value,
    config_path: &Path,
) -> CheckResult<()> {
    let Some(table) = value.as_table() else {
        return Ok(());
    };
    for (key, value) in table {
        if key == "forbidden_high_level_framev_modules" {
            return Err(CheckError::new(format!(
                "{} must not carry removed legacy FrameV marker list `{key}`; high-level facade names are hard-forbidden by the checker",
                config_path.display()
            )));
        }
        reject_legacy_framev_config_markers_in_value(config_path, key, value)?;
    }
    Ok(())
}

fn reject_legacy_framev_config_markers_in_value(
    config_path: &Path,
    key: &str,
    value: &toml::Value,
) -> CheckResult<()> {
    match value {
        toml::Value::String(text) => {
            if LEGACY_FRAMEV_CONFIG_MARKERS.contains(&text.as_str()) {
                return Err(CheckError::new(format!(
                    "{} config key `{key}` contains removed legacy FrameV marker `{text}`",
                    config_path.display()
                )));
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                reject_legacy_framev_config_markers_in_value(config_path, key, item)?;
            }
        }
        toml::Value::Table(table) => {
            for value in table.values() {
                reject_legacy_framev_config_markers_in_value(config_path, key, value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_configured_roots(repo_root: &Path, config: &Config) -> CheckResult<()> {
    for (name, path) in [
        ("service_path", &config.service_path),
        ("kernel_src_path", &config.kernel_src_path),
        ("facade_path", &config.facade_path),
        ("host_ostd_path", &config.host_ostd_path),
        (
            "framevisor_backend_device_root",
            &config.framevisor_backend_device_root,
        ),
    ] {
        let full_path = repo_root.join(path);
        if !full_path.exists() {
            return Err(CheckError::new(format!(
                "configured {name} `{}` does not exist",
                path.display()
            )));
        }
    }
    for comp in &config.service_side_trimmed_comps {
        for (name, path) in [
            (
                "service_side_trimmed_comps.service_path",
                &comp.service_path,
            ),
            ("service_side_trimmed_comps.kernel_path", &comp.kernel_path),
        ] {
            let full_path = repo_root.join(path);
            if !full_path.exists() {
                return Err(CheckError::new(format!(
                    "configured {name} `{}` for comp `{}` does not exist",
                    path.display(),
                    comp.name
                )));
            }
        }
    }
    for path in &config.framev_common_crate_roots {
        let full_path = repo_root.join(path);
        if !full_path.exists() {
            return Err(CheckError::new(format!(
                "configured framev_common_crate_roots entry `{}` does not exist",
                path.display()
            )));
        }
    }
    for frontend in &config.framev_frontend_crates {
        let full_path = repo_root.join(&frontend.path);
        if !full_path.exists() {
            return Err(CheckError::new(format!(
                "configured framev_frontend_crates path `{}` for frontend `{}` does not exist",
                frontend.path.display(),
                frontend.name
            )));
        }
    }

    if config.entry_trim_files.is_empty() {
        return Err(CheckError::new(
            "entry_trim_files must list FrameVM entry-trim files",
        ));
    }
    if config.forbidden_service_subtrees.is_empty() {
        return Err(CheckError::new(
            "forbidden_service_subtrees must list final forbidden service-local source trees",
        ));
    }
    if config.service_local_module_aliases.is_empty() {
        return Err(CheckError::new(
            "service_local_module_aliases must list final forbidden module aliases",
        ));
    }

    let manifest_path = repo_root.join(&config.trim_manifest_path);
    if !manifest_path.exists() {
        return Err(CheckError::new(format!(
            "configured trim_manifest_path `{}` does not exist",
            config.trim_manifest_path.display()
        )));
    }
    let component_metadata_path = repo_root.join(&config.component_metadata_path);
    if !component_metadata_path.exists() {
        return Err(CheckError::new(format!(
            "configured component_metadata_path `{}` does not exist",
            config.component_metadata_path.display()
        )));
    }
    Ok(())
}

fn validate_trim_manifest(repo_root: &Path, config: &Config) -> CheckResult<TrimManifest> {
    let manifest_path = repo_root.join(&config.trim_manifest_path);
    let manifest = read_toml(&manifest_path)?;
    let Some(entries) = manifest.get("entries").and_then(toml::Value::as_array) else {
        return Err(CheckError::new(format!(
            "{} missing `entries` array",
            config.trim_manifest_path.display()
        )));
    };

    let mut manifest = TrimManifest::default();
    for entry in entries {
        let entry = entry.as_table().ok_or_else(|| {
            CheckError::new(format!(
                "{} entries must be tables",
                config.trim_manifest_path.display()
            ))
        })?;
        let service_path = manifest_entry_string(entry, "service_path")?;
        let kernel_path = manifest_entry_string(entry, "kernel_path")?;
        let kind = manifest_entry_string(entry, "kind")?;
        let reason = manifest_entry_string(entry, "reason")?;
        validate_manifest_file_path(&service_path, "service_path")?;
        validate_manifest_file_path(&kernel_path, "kernel_path")?;
        validate_manifest_kind(&kind)?;
        if reason.trim().is_empty() {
            return Err(CheckError::new(
                "trim manifest entry reason must be non-empty",
            ));
        }

        let expected_kernel_path =
            expected_kernel_path_for_manifest_entry(config, Path::new(&service_path))?;
        if normalize_path(&kernel_path) != normalize_path(&expected_kernel_path.to_string_lossy()) {
            return Err(CheckError::new(format!(
                "trim manifest entry `{service_path}` maps to `{kernel_path}`, expected `{}`",
                expected_kernel_path.display()
            )));
        }

        let service_path = PathBuf::from(service_path);
        let kernel_path = PathBuf::from(kernel_path);
        let full_service_path = repo_root.join(&service_path);
        let full_kernel_path = repo_root.join(&kernel_path);
        if !full_service_path.exists() {
            return Err(CheckError::new(format!(
                "trim manifest entry service_path `{}` does not exist",
                service_path.display()
            )));
        }
        if !full_kernel_path.exists() {
            return Err(CheckError::new(format!(
                "trim manifest entry kernel_path `{}` does not exist",
                kernel_path.display()
            )));
        }
        if !retained_source_differs(&full_service_path, &full_kernel_path)? {
            return Err(CheckError::new(format!(
                "trim manifest entry `{}` is stale because the files no longer differ",
                service_path.display()
            )));
        }
        if manifest
            .entries
            .insert(
                service_path.clone(),
                TrimManifestEntry { kernel_path, kind },
            )
            .is_some()
        {
            return Err(CheckError::new(format!(
                "duplicate trim manifest entry for `{}`",
                service_path.display()
            )));
        }
    }
    Ok(manifest)
}

fn manifest_entry_string(
    entry: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> CheckResult<String> {
    entry
        .get(key)
        .and_then(toml::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| CheckError::new(format!("trim manifest entry missing string `{key}`")))
}

fn validate_manifest_file_path(path: &str, key: &str) -> CheckResult<()> {
    if path.contains('*') || path.ends_with('/') || Path::new(path).extension().is_none() {
        return Err(CheckError::new(format!(
            "trim manifest `{key}` must be a concrete file path, got `{path}`"
        )));
    }
    Ok(())
}

fn validate_manifest_kind(kind: &str) -> CheckResult<()> {
    let allowed = [
        "entry-trim",
        "unsupported-feature-trim",
        "mechanical-adaptation",
        "provider-substitution",
        "test-only-or-doc",
    ];
    if allowed.contains(&kind) {
        return Ok(());
    }
    Err(CheckError::new(format!(
        "trim manifest kind `{kind}` is not allowed"
    )))
}

fn validate_workspace_dependency(repo_root: &Path, config: &Config) -> CheckResult<()> {
    let manifest = read_toml(&repo_root.join("Cargo.toml"))?;
    let deps = manifest
        .get("workspace")
        .and_then(|value| value.get("dependencies"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| CheckError::new("missing [workspace.dependencies]"))?;

    let facade = deps
        .get("aster-framevisor-ostd")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| CheckError::new("missing workspace dependency `aster-framevisor-ostd`"))?;
    let path = facade
        .get("path")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            CheckError::new("workspace dependency `aster-framevisor-ostd` must have a path")
        })?;
    if normalize_path(path) != normalize_path(&config.facade_path.to_string_lossy()) {
        return Err(CheckError::new(format!(
            "workspace dependency `aster-framevisor-ostd` points to `{path}`, expected `{}`",
            config.facade_path.display()
        )));
    }

    if deps
        .get("ostd")
        .and_then(toml::Value::as_table)
        .and_then(|dep| dep.get("package"))
        .and_then(toml::Value::as_str)
        == Some("aster-framevisor-ostd")
    {
        return Err(CheckError::new(
            "root workspace dependency `ostd` must not alias `aster-framevisor-ostd`",
        ));
    }

    Ok(())
}

fn validate_service_manifest(repo_root: &Path, config: &Config) -> CheckResult<()> {
    let manifest_path = repo_root.join(&config.service_path).join("Cargo.toml");
    let manifest = read_toml(&manifest_path)?;
    let deps = manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| CheckError::new("service Cargo.toml missing [dependencies]"))?;

    for section_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(section) = manifest.get(section_name).and_then(toml::Value::as_table) {
            reject_dependency(section_name, section, "aster-framevisor")?;
            reject_dependency(section_name, section, "host_ostd")?;
            reject_dependency(section_name, section, "host-ostd")?;
            validate_service_dependency_boundary(section_name, section, &manifest_path, config)?;
        }
    }

    let ostd = deps
        .get("ostd")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| CheckError::new("service dependency `ostd` must be a table dependency"))?;
    if ostd.get("package").and_then(toml::Value::as_str) != Some("aster-framevisor-ostd") {
        return Err(CheckError::new(
            "service dependency `ostd` must resolve to package `aster-framevisor-ostd`",
        ));
    }
    let path = ostd
        .get("path")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            CheckError::new("service dependency `ostd` must point to the configured facade path")
        })?;
    let facade_from_service = normalize_path(
        &normalize_relative_path(&config.service_path.join(path))
            .to_string_lossy()
            .replace('\\', "/"),
    );
    let expected_facade = normalize_path(&config.facade_path.to_string_lossy());
    if facade_from_service != expected_facade {
        return Err(CheckError::new(format!(
            "service dependency `ostd` points to `{facade_from_service}`, expected `{expected_facade}`"
        )));
    }

    Ok(())
}

fn validate_service_dependency_boundary(
    section_name: &str,
    section: &toml::map::Map<String, toml::Value>,
    manifest_path: &Path,
    config: &Config,
) -> CheckResult<()> {
    for (key, value) in section {
        let resolved = dependency_resolved_package_name(key, value);
        if config.host_only_component_packages.contains(&resolved)
            || HOST_ONLY_KERNEL_COMPS.contains(&resolved.as_str())
        {
            return Err(CheckError::new(format!(
                "{} {section_name} dependency `{key}` resolves to host-only kernel comp `{resolved}`",
                manifest_path.display()
            )));
        }
        if !resolved.starts_with("aster-") {
            continue;
        }
        if key == "ostd" && resolved == "aster-framevisor-ostd" {
            continue;
        }
        if SERVICE_ALLOWED_SHARED_ASTER_CRATES.contains(&resolved.as_str()) {
            continue;
        }
        if resolved.starts_with("aster-framevm-") {
            continue;
        }
        if config.service_side_trimmed_comps.iter().any(|comp| {
            key == &comp.dependency_key
                && (resolved == comp.package || resolved == comp.dependency_key)
        }) {
            continue;
        }
        return Err(CheckError::new(format!(
            "{} {section_name} dependency `{key}` resolves to host kernel comp `{resolved}`; use a service-side trimmed comp or an allowed FrameV common/model crate",
            manifest_path.display()
        )));
    }
    Ok(())
}

fn validate_legacy_framev_package_absence(repo_root: &Path) -> CheckResult<()> {
    let root_manifest = read_toml(&repo_root.join("Cargo.toml"))?;
    for member in workspace_path_entries(&root_manifest, "members")? {
        let manifest_path = repo_root.join(&member).join("Cargo.toml");
        if !manifest_path.exists() {
            continue;
        }
        let manifest = read_toml(&manifest_path)?;
        let package_name = manifest_package_name(&manifest, &manifest_path)?;
        if LEGACY_FRAMEV_PACKAGE_NAMES.contains(&package_name) {
            return Err(CheckError::new(format!(
                "{} uses removed legacy FrameV package name `{package_name}`",
                manifest_path.display()
            )));
        }
        reject_legacy_framev_dependencies(&manifest_path, &manifest)?;
    }
    Ok(())
}

fn reject_legacy_framev_dependencies(
    manifest_path: &Path,
    manifest: &toml::Value,
) -> CheckResult<()> {
    for section_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(section) = manifest.get(section_name).and_then(toml::Value::as_table) else {
            continue;
        };
        for (key, value) in section {
            let resolved = dependency_resolved_package_name(key, value);
            if LEGACY_FRAMEV_PACKAGE_NAMES.contains(&key.as_str())
                || LEGACY_FRAMEV_PACKAGE_NAMES.contains(&resolved.as_str())
            {
                return Err(CheckError::new(format!(
                    "{} {section_name} dependency `{key}` resolves to removed legacy FrameV package `{resolved}`",
                    manifest_path.display()
                )));
            }
        }
    }
    Ok(())
}

fn validate_trimmed_comp_manifests(repo_root: &Path, config: &Config) -> CheckResult<()> {
    let root_manifest = read_toml(&repo_root.join("Cargo.toml"))?;
    let workspace_members = workspace_path_entries(&root_manifest, "members")?;
    let workspace_default_members = workspace_path_entries(&root_manifest, "default-members")?;

    let service_manifest = read_toml(&repo_root.join(&config.service_path).join("Cargo.toml"))?;
    let service_deps = service_manifest
        .get("dependencies")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| CheckError::new("service Cargo.toml missing [dependencies]"))?;

    for comp in &config.service_side_trimmed_comps {
        let normalized_service_path = normalize_path(&comp.service_path.to_string_lossy());
        if !workspace_members.contains(&normalized_service_path) {
            return Err(CheckError::new(format!(
                "service-side trimmed comp `{}` path `{normalized_service_path}` must be in workspace members",
                comp.name
            )));
        }
        if !workspace_default_members.contains(&normalized_service_path) {
            return Err(CheckError::new(format!(
                "service-side trimmed comp `{}` path `{normalized_service_path}` must be in workspace default-members",
                comp.name
            )));
        }

        let manifest_path = repo_root.join(&comp.service_path).join("Cargo.toml");
        let manifest = read_toml(&manifest_path)?;
        validate_workspace_lints(&manifest, &manifest_path)?;
        let package_name = manifest
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                CheckError::new(format!(
                    "{} missing [package].name",
                    manifest_path.display()
                ))
            })?;
        if package_name != comp.package {
            return Err(CheckError::new(format!(
                "{} package name `{package_name}` does not match configured `{}`",
                manifest_path.display(),
                comp.package
            )));
        }
        if comp.package != format!("aster-framevm-{}", comp.name) {
            return Err(CheckError::new(format!(
                "service-side trimmed comp `{}` package `{}` must be `aster-framevm-{}`",
                comp.name, comp.package, comp.name
            )));
        }

        let deps = manifest
            .get("dependencies")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| {
                CheckError::new(format!(
                    "{} missing [dependencies]",
                    manifest_path.display()
                ))
            })?;
        validate_facade_ostd_dependency(&manifest_path, deps)?;
        for section_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(section) = manifest.get(section_name).and_then(toml::Value::as_table) {
                reject_dependency(section_name, section, "aster-framevisor")?;
                reject_dependency(section_name, section, "host_ostd")?;
                reject_dependency(section_name, section, "host-ostd")?;
                for forbidden in HOST_ONLY_KERNEL_COMPS {
                    reject_dependency(section_name, section, forbidden)?;
                }
            }
        }

        let Some(service_dep) = service_deps.get(&comp.dependency_key) else {
            return Err(CheckError::new(format!(
                "service manifest missing dependency key `{}` for service-side comp `{}`",
                comp.dependency_key, comp.name
            )));
        };
        let package = service_dep
            .as_table()
            .and_then(|table| table.get("package"))
            .and_then(toml::Value::as_str);
        if package != Some(comp.package.as_str()) {
            return Err(CheckError::new(format!(
                "service dependency `{}` must point to package `{}`",
                comp.dependency_key, comp.package
            )));
        }
    }
    Ok(())
}

fn validate_component_profiles(repo_root: &Path, config: &Config) -> CheckResult<()> {
    let metadata_path = repo_root.join(&config.component_metadata_path);
    let metadata = read_toml(&metadata_path)?;
    let component_packages = component_package_entries(&metadata, &config.component_metadata_path)?;
    let profiles = metadata
        .get("profiles")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            CheckError::new(format!(
                "{} missing [profiles]",
                config.component_metadata_path.display()
            ))
        })?;
    let kernel_profile = component_profile_entries(
        profiles,
        &config.kernel_component_profile,
        &config.component_metadata_path,
    )?;
    validate_profile_entries_exist(
        &kernel_profile,
        &component_packages,
        &config.kernel_component_profile,
    )?;
    if kernel_profile.is_empty() {
        return Err(CheckError::new(format!(
            "component profile `{}` must not be empty",
            config.kernel_component_profile
        )));
    }

    let framevm_profile = component_profile_entries(
        profiles,
        &config.framevm_component_profile,
        &config.component_metadata_path,
    )?;
    validate_profile_entries_exist(
        &framevm_profile,
        &component_packages,
        &config.framevm_component_profile,
    )?;
    if framevm_profile.is_empty() {
        return Err(CheckError::new(format!(
            "component profile `{}` must not be empty",
            config.framevm_component_profile
        )));
    }

    for comp in &config.service_side_trimmed_comps {
        if !framevm_profile.contains(&comp.package) {
            return Err(CheckError::new(format!(
                "FrameVM component profile `{}` missing service-side package `{}`",
                config.framevm_component_profile, comp.package
            )));
        }
    }
    for frontend in &config.framev_frontend_crates {
        if !framevm_profile.contains(&frontend.package) {
            return Err(CheckError::new(format!(
                "FrameVM component profile `{}` missing FrameV frontend package `{}`",
                config.framevm_component_profile, frontend.package
            )));
        }
    }
    for package in &config.host_only_component_packages {
        if framevm_profile.contains(package) {
            return Err(CheckError::new(format!(
                "FrameVM component profile `{}` must not include host-only package `{package}`",
                config.framevm_component_profile
            )));
        }
    }
    if framevm_profile.is_superset(&kernel_profile) {
        return Err(CheckError::new(format!(
            "FrameVM component profile `{}` must not be a superset of kernel profile `{}`",
            config.framevm_component_profile, config.kernel_component_profile
        )));
    }
    Ok(())
}

fn validate_framevm_component_profile_usage(repo_root: &Path, config: &Config) -> CheckResult<()> {
    let init_path = repo_root.join(&config.service_path).join("src/init.rs");
    let source = fs::read_to_string(&init_path)?;
    if !source.contains("use component::InitStage") {
        return Err(CheckError::new(format!(
            "{} must import `component::InitStage` for kernel-shaped component initialization",
            init_path.display()
        )));
    }
    if source.contains("component::parse_metadata!") || source.contains("component::init_all(") {
        return Err(CheckError::new(format!(
            "{} must use the service-local FrameVM component profile dispatcher instead of extending global component metadata parsing",
            init_path.display()
        )));
    }

    if !source.contains("fn init_framevm_components(stage: InitStage)")
        || !source.contains("fn init_framevm_component_profile(stage: InitStage)")
    {
        return Err(CheckError::new(format!(
            "{} must define the service-local FrameVM component profile dispatcher",
            init_path.display()
        )));
    }

    let bootstrap = find_required_init_stage(&source, &init_path, "Bootstrap")?;
    let kthread = find_required_init_stage(&source, &init_path, "Kthread")?;
    let process = find_required_init_stage(&source, &init_path, "Process")?;
    if !(bootstrap < kthread && kthread < process) {
        return Err(CheckError::new(format!(
            "{} must initialize FrameVM components in Bootstrap, Kthread, Process order",
            init_path.display()
        )));
    }
    for comp in &config.service_side_trimmed_comps {
        let crate_ident = dependency_key_to_crate_ident(&comp.dependency_key);
        let init_call = format!("{crate_ident}::init_for_framevm_component_profile()");
        if !source.contains(&init_call) {
            return Err(CheckError::new(format!(
                "{} must initialize service-side component package `{}` through `{init_call}`",
                init_path.display(),
                comp.package
            )));
        }
        if comp.name == "block" {
            let process_init_call =
                format!("{crate_ident}::init_process_for_framevm_component_profile()");
            if !source.contains(&process_init_call) {
                return Err(CheckError::new(format!(
                    "{} must initialize service-side component package `{}` process stage through `{process_init_call}`",
                    init_path.display(),
                    comp.package
                )));
            }
        }
    }
    for frontend in &config.framev_frontend_crates {
        let crate_ident = package_to_crate_ident(&frontend.package);
        let init_call = format!("{crate_ident}::init_for_framevm_component_profile()");
        if !source.contains(&init_call) {
            return Err(CheckError::new(format!(
                "{} must initialize FrameV frontend package `{}` through `{init_call}`",
                init_path.display(),
                frontend.package
            )));
        }
    }
    Ok(())
}

fn dependency_key_to_crate_ident(dependency_key: &str) -> String {
    package_to_crate_ident(dependency_key)
}

fn package_to_crate_ident(package: &str) -> String {
    package.replace('-', "_")
}

fn validate_framev_common_crates(repo_root: &Path, config: &Config) -> CheckResult<()> {
    let root_manifest = read_toml(&repo_root.join("Cargo.toml"))?;
    let workspace_members = workspace_path_entries(&root_manifest, "members")?;
    let workspace_default_members = workspace_path_entries(&root_manifest, "default-members")?;

    let metadata = read_toml(&repo_root.join(&config.component_metadata_path))?;
    let component_packages = component_package_entries(&metadata, &config.component_metadata_path)?;

    for crate_root in &config.framev_common_crate_roots {
        let normalized_root = normalize_path(&crate_root.to_string_lossy());
        if !workspace_members.contains(&normalized_root) {
            return Err(CheckError::new(format!(
                "FrameV common/model crate `{normalized_root}` must be in workspace members"
            )));
        }
        if !workspace_default_members.contains(&normalized_root) {
            return Err(CheckError::new(format!(
                "FrameV common/model crate `{normalized_root}` must be in workspace default-members"
            )));
        }

        let manifest_path = repo_root.join(crate_root).join("Cargo.toml");
        let manifest = read_toml(&manifest_path)?;
        let package_name = manifest_package_name(&manifest, &manifest_path)?;
        if package_name != "framev-device"
            && !(package_name.starts_with("framev-") && package_name.ends_with("-common"))
        {
            return Err(CheckError::new(format!(
                "{} package `{package_name}` must use canonical FrameV common/model naming",
                manifest_path.display()
            )));
        }
        if component_packages.contains(package_name) {
            return Err(CheckError::new(format!(
                "FrameV common/model package `{package_name}` must not appear in component metadata without init hooks"
            )));
        }
        validate_workspace_lints(&manifest, &manifest_path)?;
        validate_framev_common_dependencies(&manifest, &manifest_path, package_name)?;
        validate_framev_common_source_boundary(repo_root, crate_root, package_name)?;
    }

    Ok(())
}

fn validate_framev_common_source_boundary(
    repo_root: &Path,
    crate_root: &Path,
    package_name: &str,
) -> CheckResult<()> {
    if package_name == "framev-device" {
        return Ok(());
    }

    for file in rust_files(&repo_root.join(crate_root).join("src"))? {
        reject_source_patterns(
            &file,
            &fs::read_to_string(&file)?,
            &[
                "IhtContext",
                "FrameSchedGroup",
                "try_pick_inner",
                "has_deliverable_work",
                "VcpuRequest",
                "IhtDrainOutcome",
                "enqueue_virtual_irq",
                "register_persistent_handler",
                "register_handler",
            ],
            "FrameV common/model crates are device-class protocol code and must not depend on IHT internals, IHT request types, or scheduler policy",
        )?;
        let parsed = parse_rust_file(&file)?;
        for item in parsed.items {
            if let Some(name) = defined_item_name(&item)
                && FRAMEV_DEVICE_MODEL_OWNED_ITEM_NAMES.contains(&name.as_str())
            {
                return Err(CheckError::new(format!(
                    "{} package `{package_name}` defines FrameV common model item `{name}`; consume it from `framev-device` instead of redefining descriptor, lifecycle, notification, ring, resource, or completion semantics",
                    file.display()
                )));
            }
        }
    }

    Ok(())
}

fn validate_framev_common_dependencies(
    manifest: &toml::Value,
    manifest_path: &Path,
    package_name: &str,
) -> CheckResult<()> {
    for section_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(section) = manifest.get(section_name).and_then(toml::Value::as_table) else {
            continue;
        };
        for (key, value) in section {
            let resolved = dependency_resolved_package_name(key, value);
            let forbidden = [
                "ostd",
                "aster-framevisor",
                "aster-framevisor-ostd",
                "component",
            ];
            if forbidden.contains(&resolved.as_str()) {
                return Err(CheckError::new(format!(
                    "{} {section_name} dependency `{key}` resolves to forbidden package `{resolved}`",
                    manifest_path.display()
                )));
            }
            if resolved.ends_with("-frontend") {
                return Err(CheckError::new(format!(
                    "{} {section_name} dependency `{key}` must not depend on frontend package `{resolved}`",
                    manifest_path.display()
                )));
            }
        }
    }

    if package_name != "framev-device"
        && !manifest_dependency_resolves_to(manifest, "dependencies", "framev-device")
    {
        return Err(CheckError::new(format!(
            "{} package `{package_name}` must depend on `framev-device`",
            manifest_path.display()
        )));
    }

    Ok(())
}

fn validate_framev_frontend_crates(repo_root: &Path, config: &Config) -> CheckResult<()> {
    let root_manifest = read_toml(&repo_root.join("Cargo.toml"))?;
    let workspace_members = workspace_path_entries(&root_manifest, "members")?;
    let workspace_default_members = workspace_path_entries(&root_manifest, "default-members")?;
    let service_dependency_keys = config
        .service_side_trimmed_comps
        .iter()
        .map(|comp| comp.dependency_key.as_str())
        .collect::<BTreeSet<_>>();
    let configured_packages = config
        .framev_frontend_crates
        .iter()
        .map(|frontend| frontend.package.as_str())
        .collect::<BTreeSet<_>>();

    for frontend in &config.framev_frontend_crates {
        let normalized_root = normalize_path(&frontend.path.to_string_lossy());
        if !workspace_members.contains(&normalized_root) {
            return Err(CheckError::new(format!(
                "FrameV frontend crate `{normalized_root}` must be in workspace members"
            )));
        }
        if !workspace_default_members.contains(&normalized_root) {
            return Err(CheckError::new(format!(
                "FrameV frontend crate `{normalized_root}` must be in workspace default-members"
            )));
        }

        let manifest_path = repo_root.join(&frontend.path).join("Cargo.toml");
        let manifest = read_toml(&manifest_path)?;
        validate_workspace_lints(&manifest, &manifest_path)?;
        let package_name = manifest_package_name(&manifest, &manifest_path)?;
        if package_name != frontend.package {
            return Err(CheckError::new(format!(
                "{} package `{package_name}` does not match configured frontend package `{}`",
                manifest_path.display(),
                frontend.package
            )));
        }
        validate_framev_frontend_package_name(package_name, &manifest_path)?;

        let deps = manifest
            .get("dependencies")
            .and_then(toml::Value::as_table)
            .ok_or_else(|| {
                CheckError::new(format!(
                    "{} missing [dependencies]",
                    manifest_path.display()
                ))
            })?;
        validate_framev_frontend_ostd_dependency(&manifest_path, deps, frontend)?;
        validate_framev_frontend_required_dependencies(&manifest, &manifest_path, frontend)?;

        for section_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
            let Some(section) = manifest.get(section_name).and_then(toml::Value::as_table) else {
                continue;
            };
            validate_framev_frontend_dependency_set(
                section_name,
                section,
                &manifest_path,
                frontend,
                &service_dependency_keys,
                &configured_packages,
                config,
            )?;
        }
    }

    Ok(())
}

fn validate_framev_frontend_ostd_dependency(
    manifest_path: &Path,
    deps: &toml::map::Map<String, toml::Value>,
    frontend: &FrontendCrateConfig,
) -> CheckResult<()> {
    if frontend.package == "framev-bus" {
        validate_facade_ostd_dependency(manifest_path, deps)?;
        return Ok(());
    }

    if deps.get("ostd").is_some_and(|value| {
        dependency_resolved_package_name("ostd", value) == "aster-framevisor-ostd"
    }) {
        return Err(CheckError::new(format!(
            "{} concrete frontend package `{}` must depend on `framev-bus`, not directly on the OSTD facade",
            manifest_path.display(),
            frontend.package
        )));
    }
    Ok(())
}

fn validate_framev_frontend_package_name(
    package_name: &str,
    manifest_path: &Path,
) -> CheckResult<()> {
    if package_name == "framev-bus"
        || (package_name.starts_with("framev-") && package_name.ends_with("-frontend"))
    {
        return Ok(());
    }
    Err(CheckError::new(format!(
        "{} package `{package_name}` must be `framev-bus` or use `framev-*-frontend` naming",
        manifest_path.display()
    )))
}

fn validate_framev_frontend_required_dependencies(
    manifest: &toml::Value,
    manifest_path: &Path,
    frontend: &FrontendCrateConfig,
) -> CheckResult<()> {
    if !manifest_dependency_resolves_to(manifest, "dependencies", &frontend.common_package) {
        return Err(CheckError::new(format!(
            "{} frontend package `{}` must depend on common package `{}`",
            manifest_path.display(),
            frontend.package,
            frontend.common_package
        )));
    }
    if frontend.package != "framev-bus"
        && !manifest_dependency_resolves_to(manifest, "dependencies", "framev-bus")
    {
        return Err(CheckError::new(format!(
            "{} frontend package `{}` must depend on `framev-bus`",
            manifest_path.display(),
            frontend.package
        )));
    }
    Ok(())
}

fn validate_framev_frontend_dependency_set(
    section_name: &str,
    section: &toml::map::Map<String, toml::Value>,
    manifest_path: &Path,
    frontend: &FrontendCrateConfig,
    service_dependency_keys: &BTreeSet<&str>,
    configured_frontend_packages: &BTreeSet<&str>,
    config: &Config,
) -> CheckResult<()> {
    for (key, value) in section {
        let resolved = dependency_resolved_package_name(key, value);
        if resolved == "aster-framevisor"
            || resolved == "ostd"
            || resolved == "host-ostd"
            || (resolved == "aster-framevisor-ostd" && frontend.package != "framev-bus")
        {
            return Err(CheckError::new(format!(
                "{} {section_name} dependency `{key}` resolves to forbidden package `{resolved}`",
                manifest_path.display()
            )));
        }
        if config.host_only_component_packages.contains(&resolved) {
            return Err(CheckError::new(format!(
                "{} {section_name} dependency `{key}` resolves to host-only package `{resolved}`",
                manifest_path.display()
            )));
        }
        if resolved.ends_with("-backend") && resolved.starts_with("framev-") {
            return Err(CheckError::new(format!(
                "{} {section_name} dependency `{key}` resolves to forbidden backend package `{resolved}`",
                manifest_path.display()
            )));
        }
        if resolved.ends_with("-frontend")
            || (resolved != "framev-bus"
                && configured_frontend_packages.contains(resolved.as_str()))
        {
            return Err(CheckError::new(format!(
                "{} {section_name} dependency `{key}` must not depend on another frontend package `{resolved}`",
                manifest_path.display()
            )));
        }
        if service_dependency_keys.contains(key.as_str())
            && !frontend.allowed_service_dependencies.contains(key)
        {
            return Err(CheckError::new(format!(
                "{} {section_name} dependency `{key}` is a service-side trimmed comp dependency not allowlisted for frontend `{}`",
                manifest_path.display(),
                frontend.package
            )));
        }
    }
    Ok(())
}

fn validate_framev_frontend_source_boundaries(
    repo_root: &Path,
    config: &Config,
) -> CheckResult<()> {
    for frontend in &config.framev_frontend_crates {
        let source_root = repo_root.join(&frontend.path).join("src");
        for file in rust_files(&source_root)? {
            let source = fs::read_to_string(&file)?;
            validate_framev_frontend_source_file(&file, frontend, &source)?;
        }
    }
    validate_framev_bus_source_boundary(repo_root, config)
}

fn validate_framev_bus_source_boundary(repo_root: &Path, config: &Config) -> CheckResult<()> {
    let Some(bus) = config
        .framev_frontend_crates
        .iter()
        .find(|frontend| frontend.package == "framev-bus")
    else {
        return Err(CheckError::new(
            "framev_frontend_crates must include `framev-bus`",
        ));
    };

    for file in rust_files(&repo_root.join(&bus.path).join("src"))? {
        let source = fs::read_to_string(&file)?;
        reject_source_patterns(
            &file,
            &source,
            &[
                "IhtContext",
                "FrameSchedGroup",
                "try_pick_inner",
                "has_deliverable_work",
                "VcpuRequest",
                "IhtDrainOutcome",
                "enqueue_virtual_irq",
                "register_persistent_handler",
                "register_handler",
                "ostd::framev_sock",
            ],
            "framev-bus must stay a transport discovery/binding layer and must not expose IHT, scheduler, IRQ-callback, or legacy high-level FrameV facade details",
        )?;
    }
    Ok(())
}

fn validate_framev_frontend_source_file(
    file: &Path,
    frontend: &FrontendCrateConfig,
    source: &str,
) -> CheckResult<()> {
    if frontend.package != "framev-bus" {
        reject_source_patterns(
            file,
            source,
            &[
                "framev.devices",
                "FrameVDeviceDescriptor",
                "decode_boot_arg",
                "ostd::framev",
            ],
            "concrete FrameV frontends must get device handles from framev-bus instead of parsing descriptors or using low-level OSTD primitives",
        )?;
    }

    reject_source_patterns(
        file,
        source,
        &[
            "IhtContext",
            "FrameSchedGroup",
            "try_pick_inner",
            "has_deliverable_work",
            "enqueue_virtual_irq",
            "register_persistent_handler",
            "register_handler",
            "ostd::framev_sock",
            "framev_sock::install_rx_callback",
        ],
        "FrameV frontend crates must not depend on IHT, IRQ callbacks, or legacy high-level OSTD FrameV facades",
    )
}

fn reject_source_patterns(
    file: &Path,
    source: &str,
    patterns: &[&str],
    reason: &str,
) -> CheckResult<()> {
    for pattern in patterns {
        if let Some(line) = source.lines().position(|line| line.contains(pattern)) {
            return Err(CheckError::new(format!(
                "{}:{} contains forbidden pattern `{pattern}`: {reason}",
                file.display(),
                line + 1
            )));
        }
    }
    Ok(())
}

fn require_source_patterns(
    file: &Path,
    source: &str,
    patterns: &[&str],
    reason: &str,
) -> CheckResult<()> {
    for pattern in patterns {
        if !source.contains(pattern) {
            return Err(CheckError::new(format!(
                "{} is missing required pattern `{pattern}`: {reason}",
                file.display()
            )));
        }
    }
    Ok(())
}

fn validate_framevisor_backend_placement(repo_root: &Path, config: &Config) -> CheckResult<()> {
    let expected_root = Path::new("kernel/comps/framevisor/src/device");
    if normalize_path(&config.framevisor_backend_device_root.to_string_lossy())
        != normalize_path(&expected_root.to_string_lossy())
    {
        return Err(CheckError::new(format!(
            "framevisor_backend_device_root must be `{}`",
            expected_root.display()
        )));
    }
    if !repo_root
        .join(&config.framevisor_backend_device_root)
        .join("mod.rs")
        .exists()
    {
        return Err(CheckError::new(format!(
            "FrameVisor backend device root `{}` must contain mod.rs",
            config.framevisor_backend_device_root.display()
        )));
    }

    let root_manifest = read_toml(&repo_root.join("Cargo.toml"))?;
    for member in workspace_path_entries(&root_manifest, "members")? {
        let manifest_path = repo_root.join(&member).join("Cargo.toml");
        if !manifest_path.exists() {
            continue;
        }
        let manifest = read_toml(&manifest_path)?;
        let package_name = manifest_package_name(&manifest, &manifest_path)?;
        if is_framev_backend_package(package_name) {
            return Err(CheckError::new(format!(
                "{} defines forbidden FrameVM-loaded backend package `{package_name}`",
                manifest_path.display()
            )));
        }
    }

    let metadata = read_toml(&repo_root.join(&config.component_metadata_path))?;
    for package in component_package_entries(&metadata, &config.component_metadata_path)? {
        if is_framev_backend_package(&package) {
            return Err(CheckError::new(format!(
                "component metadata must not load FrameV backend package `{package}`"
            )));
        }
    }
    Ok(())
}

fn is_framev_backend_package(package_name: &str) -> bool {
    package_name.starts_with("framev-") && package_name.ends_with("-backend")
}

fn validate_framevisor_ostd_style_module_boundaries(repo_root: &Path) -> CheckResult<()> {
    let framevisor_src = repo_root.join("kernel/comps/framevisor/src");
    for module in [
        "arch", "boot", "console", "cpu", "irq", "log", "mm", "panic", "power", "prelude", "sync",
        "task", "timer", "user", "util",
    ] {
        if !module_exists(&framevisor_src, module) {
            return Err(CheckError::new(format!(
                "FrameVisor is missing OSTD-shaped lower-half module `{module}`"
            )));
        }
    }

    for module in ["device", "iht", "vm", "vsock"] {
        let module_path = framevisor_src.join(module);
        if !module_path.join("mod.rs").exists() {
            return Err(CheckError::new(format!(
                "FrameVisor-specific module `{module}` must be an explicit module tree with mod.rs"
            )));
        }
    }

    for forbidden in [
        "fs",
        "net",
        "process",
        "sched",
        "scheduler",
        "syscall",
        "thread",
    ] {
        if module_exists(&framevisor_src, forbidden) {
            return Err(CheckError::new(format!(
                "FrameVisor must not grow kernel upper-half module `{forbidden}`; keep FrameVM service code kernel-shaped under services/aster-framevm/src"
            )));
        }
    }

    for forbidden_file in [
        "block.rs",
        "sock.rs",
        "rng_backend.rs",
        "console_backend.rs",
    ] {
        let path = framevisor_src.join(forbidden_file);
        if path.exists() {
            return Err(CheckError::new(format!(
                "{} must live under `kernel/comps/framevisor/src/device/**`",
                path.display()
            )));
        }
    }

    Ok(())
}

fn validate_framevisor_ostd_host_management_absence(
    repo_root: &Path,
    config: &Config,
) -> CheckResult<()> {
    let facade_src = repo_root.join(&config.facade_path).join("src");
    for file in rust_files(&facade_src)? {
        reject_source_patterns(
            &file,
            &fs::read_to_string(&file)?,
            FORBIDDEN_HOST_MANAGEMENT_FACADE_EXPORT_PATTERNS,
            "the FrameVM OSTD facade must expose copied-kernel OSTD-shaped APIs and low-level `ostd::framev` primitives, not host VM-management or backend internals",
        )?;
    }
    Ok(())
}

fn module_exists(root: &Path, module: &str) -> bool {
    root.join(format!("{module}.rs")).exists() || root.join(module).join("mod.rs").exists()
}

fn validate_framevisor_task_scheduler_layout(repo_root: &Path) -> CheckResult<()> {
    let task_root = repo_root.join("kernel/comps/framevisor/src/task");
    let legacy_file = task_root.join("scheduler.rs");
    if legacy_file.exists() {
        return Err(CheckError::new(format!(
            "{} must be split into `task/scheduler/mod.rs` and responsibility-focused submodules",
            legacy_file.display()
        )));
    }

    let scheduler_root = task_root.join("scheduler");
    for module in [
        "mod.rs",
        "cpu_scope.rs",
        "info.rs",
        "interrupt.rs",
        "queue.rs",
        "registry.rs",
        "timer.rs",
        "types.rs",
    ] {
        let path = scheduler_root.join(module);
        if !path.exists() {
            return Err(CheckError::new(format!(
                "FrameVisor scheduler layout missing `{}`",
                path.display()
            )));
        }
    }

    let mod_source = fs::read_to_string(scheduler_root.join("mod.rs"))?;
    for declaration in [
        "mod cpu_scope;",
        "pub mod info;",
        "mod interrupt;",
        "mod queue;",
        "mod registry;",
        "mod timer;",
        "mod types;",
    ] {
        if !mod_source.contains(declaration) {
            return Err(CheckError::new(format!(
                "FrameVisor scheduler mod.rs missing `{declaration}`"
            )));
        }
    }
    for public_api in [
        "pub use registry::inject_scheduler",
        "pub use timer::enable_preemption_on_cpu",
        "pub use types::{EnqueueFlags, LocalRunQueue, Scheduler, UpdateFlags}",
    ] {
        if !mod_source.contains(public_api) {
            return Err(CheckError::new(format!(
                "FrameVisor scheduler mod.rs must preserve public API re-export `{public_api}`"
            )));
        }
    }
    Ok(())
}

fn validate_frame_sched_group_contract(repo_root: &Path) -> CheckResult<()> {
    let path = repo_root.join("kernel/comps/framevisor/src/vm/frame_group.rs");
    let source = fs::read_to_string(&path)?;
    let function_start = source
        .find("pub fn try_pick_inner(&self) -> InnerPick")
        .ok_or_else(|| CheckError::new(format!("{} missing `try_pick_inner`", path.display())))?;
    let function_source = &source[function_start..];
    let iht_pick = function_source
        .find("self.iht_context.has_deliverable_work()")
        .ok_or_else(|| {
            CheckError::new(format!(
                "{} `try_pick_inner` must check IHT deliverable work",
                path.display()
            ))
        })?;
    let service_pick = function_source
        .find("self.try_pick_service()")
        .ok_or_else(|| {
            CheckError::new(format!(
                "{} `try_pick_inner` must check service work",
                path.display()
            ))
        })?;
    if iht_pick > service_pick {
        return Err(CheckError::new(format!(
            "{} `try_pick_inner` must remain IHT-first before service selection",
            path.display()
        )));
    }

    let comment_window = &source[..function_start];
    if !comment_window.contains("IHT-first is part of the FrameSchedGroup")
        || !comment_window.contains("Do not")
    {
        return Err(CheckError::new(format!(
            "{} `try_pick_inner` must document the IHT-first scheduling contract",
            path.display()
        )));
    }
    Ok(())
}

fn validate_iht_callback_discipline_comments(repo_root: &Path) -> CheckResult<()> {
    let frame_group_path = repo_root.join("kernel/comps/framevisor/src/vm/frame_group.rs");
    let frame_group_source = fs::read_to_string(&frame_group_path)?;
    require_comment_before(
        &frame_group_path,
        &frame_group_source,
        "pub fn try_pick_inner(&self) -> InnerPick",
        &[
            "IHT-first is part of the FrameSchedGroup",
            "notification/control",
            "data-path",
        ],
    )?;

    let iht_path = repo_root.join("kernel/comps/framevisor/src/iht/mod.rs");
    let iht_source = fs::read_to_string(&iht_path)?;
    require_comment_before(
        &iht_path,
        &iht_source,
        "crate::irq::dispatch_framev_irq_line(vm_id, irq_line, self.id.vcpu_index())",
        &["notification/control", "data-path", "service-owned work"],
    )?;
    require_comment_before(
        &iht_path,
        &iht_source,
        "callback.call();",
        &["notification-only", "bounded", "service runtime"],
    )?;

    let irq_path = repo_root.join("kernel/comps/framevisor/src/irq/mod.rs");
    let irq_source = fs::read_to_string(&irq_path)?;
    require_comment_before(
        &irq_path,
        &irq_source,
        "let Some(vm) = vm::get_vm_by_id(vm_id) else",
        &["notification/control handoff", "service runtime", "bounded"],
    )
}

fn validate_iht_has_no_direct_device_data_path(repo_root: &Path) -> CheckResult<()> {
    let iht_path = repo_root.join("kernel/comps/framevisor/src/iht/mod.rs");
    if !iht_path.exists() {
        return Ok(());
    }
    reject_source_patterns(
        &iht_path,
        &fs::read_to_string(&iht_path)?,
        &[
            "process_blk_request",
            "handle_block_request",
            "complete_blk_request",
            "drain_inbound_requests",
            "handle_rx_notification",
            "fill_rng",
            "read_entropy",
            "console_write",
            "console_read",
        ],
        "IHT may deliver notification/control work and wake service-owned work, but must not run FrameV device data-path handlers directly",
    )
}

fn require_comment_before(
    path: &Path,
    source: &str,
    anchor: &str,
    required: &[&str],
) -> CheckResult<()> {
    let index = source.find(anchor).ok_or_else(|| {
        CheckError::new(format!(
            "{} missing callback-discipline anchor `{anchor}`",
            path.display()
        ))
    })?;
    let window_start = index.saturating_sub(900);
    let comment_window = &source[window_start..index];
    for phrase in required {
        if !comment_window.contains(phrase) {
            return Err(CheckError::new(format!(
                "{} missing IHT callback-discipline comment phrase `{phrase}` before `{anchor}`",
                path.display()
            )));
        }
    }
    Ok(())
}

fn validate_workspace_lints(manifest: &toml::Value, manifest_path: &Path) -> CheckResult<()> {
    if manifest
        .get("lints")
        .and_then(|lints| lints.get("workspace"))
        .and_then(toml::Value::as_bool)
        != Some(true)
    {
        return Err(CheckError::new(format!(
            "{} must contain `[lints] workspace = true`",
            manifest_path.display()
        )));
    }
    Ok(())
}

fn workspace_path_entries(manifest: &toml::Value, key: &str) -> CheckResult<BTreeSet<String>> {
    let entries = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get(key))
        .and_then(toml::Value::as_array)
        .ok_or_else(|| CheckError::new(format!("root Cargo.toml missing [workspace].{key}")))?;
    entries
        .iter()
        .map(|entry| {
            entry.as_str().map(normalize_path).ok_or_else(|| {
                CheckError::new(format!("[workspace].{key} entries must be strings"))
            })
        })
        .collect()
}

fn manifest_package_name<'a>(
    manifest: &'a toml::Value,
    manifest_path: &Path,
) -> CheckResult<&'a str> {
    manifest
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| {
            CheckError::new(format!(
                "{} missing [package].name",
                manifest_path.display()
            ))
        })
}

fn dependency_resolved_package_name(key: &str, value: &toml::Value) -> String {
    value
        .as_table()
        .and_then(|table| table.get("package"))
        .and_then(toml::Value::as_str)
        .unwrap_or(key)
        .to_owned()
}

fn manifest_dependency_resolves_to(
    manifest: &toml::Value,
    section_name: &str,
    package_name: &str,
) -> bool {
    manifest
        .get(section_name)
        .and_then(toml::Value::as_table)
        .is_some_and(|section| {
            section
                .iter()
                .any(|(key, value)| dependency_resolved_package_name(key, value) == package_name)
        })
}

fn manifest_dependency_key_or_resolves_to(
    manifest: &toml::Value,
    section_name: &str,
    dependency_name: &str,
) -> bool {
    manifest
        .get(section_name)
        .and_then(toml::Value::as_table)
        .is_some_and(|section| {
            section.iter().any(|(key, value)| {
                key == dependency_name
                    || dependency_resolved_package_name(key, value) == dependency_name
            })
        })
}

fn find_required_init_stage(source: &str, init_path: &Path, stage: &str) -> CheckResult<usize> {
    let pattern = format!("init_framevm_components(InitStage::{stage})");
    source
        .find(&pattern)
        .ok_or_else(|| CheckError::new(format!("{} must call `{pattern}`", init_path.display())))
}

fn component_package_entries(
    metadata: &toml::Value,
    metadata_path: &Path,
) -> CheckResult<BTreeSet<String>> {
    metadata
        .get("components")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            CheckError::new(format!("{} missing [components]", metadata_path.display()))
        })?
        .values()
        .map(|entry| {
            entry
                .as_table()
                .and_then(|table| table.get("name"))
                .and_then(toml::Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    CheckError::new(format!(
                        "{} component entries must contain string `name`",
                        metadata_path.display()
                    ))
                })
        })
        .collect()
}

fn validate_profile_entries_exist(
    profile_entries: &BTreeSet<String>,
    component_packages: &BTreeSet<String>,
    profile: &str,
) -> CheckResult<()> {
    for package in profile_entries {
        if !component_packages.contains(package) {
            return Err(CheckError::new(format!(
                "component profile `{profile}` contains unknown package `{package}`"
            )));
        }
    }
    Ok(())
}

fn component_profile_entries(
    profiles: &toml::map::Map<String, toml::Value>,
    profile: &str,
    metadata_path: &Path,
) -> CheckResult<BTreeSet<String>> {
    let entries = profiles
        .get(profile)
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            CheckError::new(format!(
                "{} missing component profile `{profile}`",
                metadata_path.display()
            ))
        })?;
    let mut seen = BTreeSet::new();
    for entry in entries {
        let package = entry.as_str().map(ToOwned::to_owned).ok_or_else(|| {
            CheckError::new(format!(
                "{} profile `{profile}` entries must be strings",
                metadata_path.display()
            ))
        })?;
        if !seen.insert(package.clone()) {
            return Err(CheckError::new(format!(
                "{} profile `{profile}` contains duplicate package `{package}`",
                metadata_path.display()
            )));
        }
    }
    Ok(seen)
}

fn validate_facade_ostd_dependency(
    manifest_path: &Path,
    deps: &toml::map::Map<String, toml::Value>,
) -> CheckResult<()> {
    let ostd = deps
        .get("ostd")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            CheckError::new(format!(
                "{} dependency `ostd` must be a table dependency",
                manifest_path.display()
            ))
        })?;
    if ostd.get("package").and_then(toml::Value::as_str) != Some("aster-framevisor-ostd") {
        return Err(CheckError::new(format!(
            "{} dependency `ostd` must resolve to package `aster-framevisor-ostd`",
            manifest_path.display()
        )));
    }
    Ok(())
}

const HOST_ONLY_KERNEL_COMPS: &[&str] = &[
    "aster-i8042",
    "aster-mlsdisk",
    "aster-nvme",
    "aster-pci",
    "aster-uart",
    "aster-virtio",
];

fn reject_dependency(
    section_name: &str,
    section: &toml::map::Map<String, toml::Value>,
    forbidden: &str,
) -> CheckResult<()> {
    for (name, value) in section {
        let package = value
            .as_table()
            .and_then(|table| table.get("package"))
            .and_then(toml::Value::as_str);
        if name == forbidden || package == Some(forbidden) {
            return Err(CheckError::new(format!(
                "service {section_name} must not depend directly on `{forbidden}`"
            )));
        }
    }
    Ok(())
}

fn check_banned_service_refs(files: &[PathBuf]) -> CheckResult<()> {
    let banned = [
        "aster_framevisor::",
        "host_ostd::",
        "aster_framevisor_ostd::",
    ];
    for file in files {
        let source = fs::read_to_string(file)?;
        for pattern in banned {
            if let Some(line) = source.lines().position(|line| line.contains(pattern)) {
                return Err(CheckError::new(format!(
                    "{}:{} contains forbidden service reference `{pattern}`",
                    file.display(),
                    line + 1
                )));
            }
        }
    }
    Ok(())
}

fn check_framevm_cpu_local_boundary(
    repo_root: &Path,
    config: &Config,
    service_files: &[PathBuf],
) -> CheckResult<()> {
    let mut loaded_files = service_files.to_vec();
    for comp in &config.service_side_trimmed_comps {
        loaded_files.extend(rust_files(&repo_root.join(&comp.service_path).join("src"))?);
    }
    for frontend in &config.framev_frontend_crates {
        loaded_files.extend(rust_files(&repo_root.join(&frontend.path).join("src"))?);
    }
    loaded_files.sort();
    loaded_files.dedup();

    for file in loaded_files {
        let source = fs::read_to_string(&file)?;
        reject_source_patterns(
            &file,
            &source,
            &[
                "host_ostd::cpu::local",
                "host_ostd::cpu_local",
                "host_ostd::cpu_local_cell",
                "alloc_cpu_local",
                "CpuLocalBox",
                "DynCpuLocal",
                "DynamicStorage",
                "dyn_cpu_local",
                "static_cpu_local",
            ],
            "FrameVM-loaded code must use the local `ostd` CPU-local facade and must not import Host OSTD CPU-local allocation APIs",
        )?;
    }

    let facade_lib = repo_root.join(&config.facade_path).join("src/lib.rs");
    let facade_source = fs::read_to_string(&facade_lib)?;
    reject_source_patterns(
        &facade_lib,
        &facade_source,
        &[
            "pub use host_ostd::cpu::local",
            "pub use host_ostd::cpu_local",
            "pub use host_ostd::cpu_local_cell",
        ],
        "aster-framevisor-ostd must provide FrameVM CPU-local storage through the FrameVisor facade instead of re-exporting Host OSTD CPU-local providers",
    )?;

    let framevisor_cpu_local = repo_root.join("kernel/comps/framevisor/src/cpu/local.rs");
    let framevisor_cpu_local_source = fs::read_to_string(&framevisor_cpu_local)?;
    require_source_patterns(
        &framevisor_cpu_local,
        &framevisor_cpu_local_source,
        &[
            "impl<T> StaticCpuLocal<T>\nwhere\n    T: Send + Sync + 'static,",
            "pub struct CpuLocalGuard<'a, T: Send + Sync + 'static>",
            "impl<T: Send + Sync + 'static> Deref for CpuLocalGuard<'_, T>",
            "pub struct CpuLocalRemoteGuard<T: Send + Sync + 'static>",
            "impl<T: Send + Sync + 'static> Deref for CpuLocalRemoteGuard<T>",
        ],
        "FrameVM static CPU-local references must be exposed only for `Sync` payloads; non-`Sync` payloads must use synchronized value-operation adaptations instead of Host OSTD-style unlocked references",
    )
}

fn check_retained_layout(repo_root: &Path, config: &Config, files: &[PathBuf]) -> CheckResult<()> {
    let service_root = repo_root.join(&config.service_path);
    let service_src = repo_root.join(&config.service_path).join("src");
    let kernel_src = repo_root.join(&config.kernel_src_path);
    for file in files {
        let service_relative = file.strip_prefix(&service_root).map_err(|_| {
            CheckError::new(format!("{} is not under service root", file.display()))
        })?;
        if config.entry_trim_files.contains(service_relative) {
            continue;
        }

        if config
            .forbidden_service_subtrees
            .iter()
            .any(|subtree| service_relative.starts_with(subtree))
        {
            if config.source_trim_enforcement.is_final() {
                return Err(CheckError::new(format!(
                    "final FrameVM source trim forbids service-local source `{}`",
                    file.display()
                )));
            }
            continue;
        }

        let relative = file
            .strip_prefix(&service_src)
            .map_err(|_| CheckError::new(format!("{} is not under service src", file.display())))?;
        let kernel_path = kernel_src.join(relative);
        if !kernel_path.exists() {
            if !config.source_trim_enforcement.is_final() {
                continue;
            }
            return Err(CheckError::new(format!(
                "retained service file `{}` has no corresponding kernel source `{}`",
                file.display(),
                kernel_path.display()
            )));
        }
    }
    Ok(())
}

fn check_trimmed_comp_layout(repo_root: &Path, config: &Config) -> CheckResult<()> {
    for comp in &config.service_side_trimmed_comps {
        let service_src = repo_root.join(&comp.service_path).join("src");
        let kernel_src = repo_root.join(&comp.kernel_path).join("src");
        for file in rust_files(&service_src)? {
            let relative = file.strip_prefix(&service_src).map_err(|_| {
                CheckError::new(format!("{} is not under trimmed comp src", file.display()))
            })?;
            let kernel_path = kernel_src.join(relative);
            if !kernel_path.exists() {
                return Err(CheckError::new(format!(
                    "trimmed comp file `{}` has no corresponding kernel comp source `{}`",
                    file.display(),
                    kernel_path.display()
                )));
            }
        }
    }
    Ok(())
}

fn check_framev_sock_rx_callback_boundary(repo_root: &Path, config: &Config) -> CheckResult<()> {
    let vsock_init_path = repo_root
        .join(&config.service_path)
        .join("src/net/socket/vsock/mod.rs");
    let stream_path = repo_root
        .join(&config.service_path)
        .join("src/net/socket/vsock/stream/mod.rs");
    if !vsock_init_path.exists() || !stream_path.exists() {
        return Ok(());
    }

    let vsock_init = fs::read_to_string(&vsock_init_path)?;
    if vsock_init.contains("install_rx_callback(stream::handle_rx_notification)")
        || vsock_init.contains("install_rx_callback(listen::drain_inbound_requests)")
    {
        return Err(CheckError::new(format!(
            "{} registers direct FrameV-sock RX data-path work in the IHT callback",
            vsock_init_path.display()
        )));
    }
    if !vsock_init.contains("stream::init_rx_taskless()")
        || !vsock_init.contains("install_rx_callback(stream::schedule_rx_notification)")
    {
        return Err(CheckError::new(format!(
            "{} must initialize FrameV-sock RX Taskless and register only the scheduling callback",
            vsock_init_path.display()
        )));
    }

    let stream = fs::read_to_string(&stream_path)?;
    if stream.contains("fn handle_rx_notification") {
        return Err(CheckError::new(format!(
            "{} must not keep the legacy direct RX notification handler",
            stream_path.display()
        )));
    }
    for pattern in [
        "Taskless::new(process_rx_notification)",
        "pub(super) fn schedule_rx_notification()",
        ".schedule();",
        "fn process_rx_notification()",
        "if listen::drain_inbound_requests()",
        "schedule_rx_notification();",
    ] {
        if !stream.contains(pattern) {
            return Err(CheckError::new(format!(
                "{} missing FrameV-sock Taskless RX boundary pattern `{pattern}`",
                stream_path.display()
            )));
        }
    }
    Ok(())
}

fn check_no_parallel_softirq_framework(
    repo_root: &Path,
    config: &Config,
    service_files: &[PathBuf],
) -> CheckResult<()> {
    let service_root = repo_root.join(&config.service_path);
    for file in service_files {
        let relative = file.strip_prefix(&service_root).map_err(|_| {
            CheckError::new(format!("{} is not under service root", file.display()))
        })?;
        let source = fs::read_to_string(file)?;
        for pattern in [
            "struct SoftIrqLine",
            "struct Taskless",
            "enum SoftIrq",
            "mod softirq",
            "mod taskless",
            "fn taskless_softirq_handler",
            "static TASKLESS_LIST",
            "static TASKLESS_URGENT_LIST",
        ] {
            if source.contains(pattern) {
                return Err(CheckError::new(format!(
                    "{} defines `{pattern}`; service-local softirq/taskless framework code must live only under `services/aster-framevm/comps/softirq`",
                    relative.display()
                )));
            }
        }
    }
    Ok(())
}

fn check_low_level_framev_usage_boundary(
    repo_root: &Path,
    config: &Config,
    service_files: &[PathBuf],
) -> CheckResult<()> {
    for file in service_files {
        reject_runtime_ostd_framev_use(file)?;
    }

    for frontend in &config.framev_frontend_crates {
        if frontend.package == "framev-bus" {
            continue;
        }
        for file in rust_files(&repo_root.join(&frontend.path).join("src"))? {
            reject_runtime_ostd_framev_use(&file)?;
        }
    }
    Ok(())
}

fn check_vfs_ext2_framev_protocol_boundary(repo_root: &Path, config: &Config) -> CheckResult<()> {
    let service_src = repo_root.join(&config.service_path).join("src");
    for root in [
        service_src.join("fs"),
        service_src.join("rootfs"),
        service_src.join("vfs"),
    ] {
        if !root.exists() {
            continue;
        }
        for file in rust_files(&root)? {
            reject_source_patterns(
                &file,
                &fs::read_to_string(&file)?,
                &[
                    "framev_blk",
                    "framev-blk",
                    "FrameVBlk",
                    "framev_bus",
                    "framev-bus",
                    "BlockRequestCompletion",
                    "BlockRequestResource",
                    "BlockReturnedResource",
                ],
                "VFS, ext2, rootfs, and page-cache code must stay kernel-shaped and issue I/O through aster-block, not FrameV-blk protocol or transport types",
            )?;
        }
    }
    Ok(())
}

fn check_legacy_framev_policy_marker_absence(repo_root: &Path) -> CheckResult<()> {
    let policy_path = repo_root.join("osdk/src/framevm/policy.toml");
    if !policy_path.exists() {
        return Ok(());
    }
    let policy = read_toml(&policy_path)?;
    reject_legacy_framev_policy_markers_in_value(&policy_path, &policy)
}

fn reject_legacy_framev_policy_markers_in_value(
    policy_path: &Path,
    value: &toml::Value,
) -> CheckResult<()> {
    match value {
        toml::Value::String(text) => {
            if LEGACY_FRAMEV_POLICY_MARKERS.contains(&text.as_str()) {
                return Err(CheckError::new(format!(
                    "{} contains removed legacy FrameV policy marker `{text}`; use canonical FrameV package-role names",
                    policy_path.display()
                )));
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                reject_legacy_framev_policy_markers_in_value(policy_path, item)?;
            }
        }
        toml::Value::Table(table) => {
            for value in table.values() {
                reject_legacy_framev_policy_markers_in_value(policy_path, value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn check_high_level_framev_facade_absence(
    repo_root: &Path,
    config: &Config,
    service_files: &[PathBuf],
) -> CheckResult<()> {
    let facade_lib = repo_root.join(&config.facade_path).join("src/lib.rs");
    if facade_lib.exists() {
        let parsed = parse_rust_file(&facade_lib)?;
        for item in parsed.items {
            if let Item::Mod(item_mod) = item {
                let name = item_mod.ident.to_string();
                if is_public(&item_mod.vis)
                    && LEGACY_HIGH_LEVEL_FRAMEV_MODULES.contains(&name.as_str())
                {
                    return Err(CheckError::new(format!(
                        "{} exposes forbidden high-level FrameV facade module `{name}`; use low-level `ostd::framev::*` only through `framev-bus`",
                        facade_lib.display()
                    )));
                }
            }
        }
    }

    for file in service_files {
        let source = fs::read_to_string(file)?;
        for module in LEGACY_HIGH_LEVEL_FRAMEV_MODULES {
            let pattern = format!("ostd::{module}");
            if let Some(line) = source.lines().position(|line| line.contains(&pattern)) {
                return Err(CheckError::new(format!(
                    "{}:{} imports forbidden high-level FrameV facade path `{pattern}`",
                    file.display(),
                    line + 1
                )));
            }
        }
    }
    Ok(())
}

fn reject_runtime_ostd_framev_use(file: &Path) -> CheckResult<()> {
    let source = fs::read_to_string(file)?;
    if let Some(line) = source
        .lines()
        .position(|line| line.contains("ostd::framev::"))
    {
        return Err(CheckError::new(format!(
            "{}:{} uses low-level `ostd::framev`; only `framev-bus` may consume FrameV primitives directly",
            file.display(),
            line + 1
        )));
    }
    Ok(())
}

fn check_final_rootfs_artifact_policy(repo_root: &Path, config: &Config) -> CheckResult<()> {
    if !config.source_trim_enforcement.is_final() {
        return Ok(());
    }

    let initramfs_path = repo_root.join("test/initramfs/nix/initramfs.nix");
    if initramfs_path.exists() {
        let source = fs::read_to_string(&initramfs_path)?;
        reject_source_patterns(
            &initramfs_path,
            &source,
            &["/framevm/rootfs.cpio", "rootfs.cpio.gz"],
            "completed FrameVM packaging must install `/framevm/rootfs.ext2`, not a CPIO rootfs artifact",
        )?;
        if !source.contains("/framevm/rootfs.ext2") {
            return Err(CheckError::new(format!(
                "{} must install `/framevm/rootfs.ext2` in final source-trim mode",
                initramfs_path.display()
            )));
        }
    }

    let rootfs_image_path = repo_root.join("test/initramfs/nix/framevm-rootfs-image.nix");
    if rootfs_image_path.exists() {
        reject_source_patterns(
            &rootfs_image_path,
            &fs::read_to_string(&rootfs_image_path)?,
            &["cpio", "gzip", "newc"],
            "completed FrameVM rootfs fixture must be a raw ext2 image, not an initramfs CPIO image",
        )?;
    }

    let policy_path = repo_root.join("osdk/src/framevm/policy.toml");
    if policy_path.exists() {
        reject_source_patterns(
            &policy_path,
            &fs::read_to_string(&policy_path)?,
            &["cpio_decoder"],
            "completed FrameVM service bundling policy must not retain rootfs-only CPIO decoder allowances",
        )?;
    }

    let loader_path = repo_root.join("kernel/src/vmm/mod.rs");
    if loader_path.exists() {
        reject_source_patterns(
            &loader_path,
            &fs::read_to_string(&loader_path)?,
            &[
                "/framevm/rootfs.cpio",
                "rootfs.cpio.gz",
                "decode_framevm_rootfs",
                "read_framevm_rootfs",
            ],
            "completed host loader must not load or decode a FrameVM CPIO rootfs fallback",
        )?;
    }
    Ok(())
}

fn check_legacy_framevm_test_entrypoint_absence(repo_root: &Path) -> CheckResult<()> {
    for path in [
        "test/initramfs/nix/initramfs.nix",
        "test/initramfs/nix/default.nix",
        "test/initramfs/nix/packages.nix",
    ] {
        let path = repo_root.join(path);
        if path.exists() {
            reject_source_patterns(
                &path,
                &fs::read_to_string(&path)?,
                &[
                    "/test/framevm_load.sh",
                    "/test/framev_vsock_test.sh",
                    "/test/framevm_shell.sh",
                ],
                "FrameVM test scripts must be installed only under `/test/framevm/**`",
            )?;
        }
    }

    let makefile = repo_root.join("Makefile");
    if makefile.exists() {
        reject_source_patterns(
            &makefile,
            &fs::read_to_string(&makefile)?,
            &["framev_vsock_test:"],
            "FrameV sock coverage must run through `make run_framevm AUTO_TEST=device`, not a long-term top-level target",
        )?;
    }

    for path in ["osdk/src/framevm", "osdk/src"] {
        let path = repo_root.join(path);
        if !path.exists() {
            continue;
        }
        for file in rust_and_toml_files(&path)? {
            reject_source_patterns(
                &file,
                &fs::read_to_string(&file)?,
                &[
                    "/test/framevm_load.sh",
                    "/test/framev_vsock_test.sh",
                    "/test/framevm_shell.sh",
                ],
                "OSDK FrameVM default load paths must use the unified `/test/framevm/**` runner",
            )?;
        }
    }
    Ok(())
}

fn check_final_service_local_rootfs_adapters(
    config: &Config,
    service_files: &[PathBuf],
) -> CheckResult<()> {
    if !config.source_trim_enforcement.is_final() {
        return Ok(());
    }

    for file in service_files {
        if file.ends_with("fs/fs_impls/procfs/template/dir.rs") {
            continue;
        }

        reject_source_patterns(
            file,
            &fs::read_to_string(file)?,
            &[
                "OpenFileState",
                "RootRegularFile",
                "RootDirectoryFile",
                "RootPathFile",
                "RootFile",
                "RootDir",
                "RootDirEntry",
            ],
            "completed FrameVM filesystem code must use copied kernel VFS/file/pipe abstractions instead of service-local rootfs adapters",
        )?;
    }
    Ok(())
}

fn check_final_framevm_interactive_shell_policy(
    repo_root: &Path,
    config: &Config,
    service_files: &[PathBuf],
) -> CheckResult<()> {
    if !config.source_trim_enforcement.is_final() {
        return Ok(());
    }

    for file in service_files {
        let source = fs::read_to_string(file)?;
        reject_source_patterns(
            file,
            &source,
            &["ConsoleFile", "ConsoleEndpoint"],
            "completed FrameVM guest console must be a TTY backed by FrameV-console; raw guest-visible console files are forbidden",
        )?;

        if file
            .components()
            .any(|component| component.as_os_str() == "procfs")
        {
            reject_source_patterns(
                file,
                &source,
                &[
                    "TaskDirOps",
                    "Cgroup",
                    "cgroup",
                    "FdDirOps",
                    "MapsFileOps",
                    "MountInfo",
                    "SysDirOps",
                    "CpuInfoFileOps",
                    "LoadAvgFileOps",
                    "MemInfoFileOps",
                    "StatFileOps as Global",
                    "softirq",
                    "FrameVisor",
                ],
                "FrameVM procfs must expose only the explicitly supported guest process inspection surface",
            )?;
        }
    }

    let rootfs_image_path = repo_root.join("test/initramfs/nix/framevm-rootfs-image.nix");
    if rootfs_image_path.exists() {
        let source = fs::read_to_string(&rootfs_image_path)?;
        reject_source_patterns(
            &rootfs_image_path,
            &source,
            &[
                "run_initial_script_from_stdin",
                "sleep_for_initial_input",
                "fcntl(STDIN_FILENO",
                "O_NONBLOCK",
                "framevm-init-script",
            ],
            "FrameVM rootfs init must not sniff stdin to select tests or boot scripts",
        )?;
        require_source_patterns(
            &rootfs_image_path,
            &source,
            &["/bin/framevm-test-runner", "TIOCSCTTY", "FRAMEVM_TEST"],
            "FrameVM rootfs must provide a TTY-backed init path and cmdline-selected test runner",
        )?;
    }

    let framevm_test_dir = repo_root.join("test/initramfs/src/framevm");
    if framevm_test_dir.exists() {
        let mut scripts = Vec::new();
        collect_files_with_extensions(&framevm_test_dir, &["sh"], &mut scripts)?;
        for script in scripts {
            let source = fs::read_to_string(&script)?;
            reject_source_patterns(
                &script,
                &source,
                &[
                    "printf 'exit\\n' | framevmctl run",
                    "printf 'exit",
                    "| framevmctl run",
                    "run_initial_script_from_stdin",
                ],
                "FrameVM host tests must select guest behavior through framevmctl --append, not guest console stdin",
            )?;
        }
    }

    Ok(())
}

fn check_lib_entry_policy(repo_root: &Path, config: &Config) -> CheckResult<()> {
    let lib_path = repo_root.join(&config.service_path).join("src/lib.rs");
    let source = fs::read_to_string(&lib_path)?;
    for pattern in ["extern \"Rust\" fn __ostd_main() -> !", "init::main();"] {
        if !source.contains(pattern) {
            return Err(CheckError::new(format!(
                "{} must keep FrameVM crate entry as a non-returning kernel-shaped entry that delegates to `init::main()`",
                lib_path.display()
            )));
        }
    }
    reject_source_patterns(
        &lib_path,
        &source,
        &["__ostd_dynamic_main"],
        "completed FrameVM crate entry must not return to the dynamic service loader",
    )?;
    reject_source_patterns(
        &lib_path,
        &source,
        &[
            "framev_bus::init_descriptor",
            "framev_bus::init_devices",
            "framev::init_descriptor",
            "framev::init_devices",
            "console::init()",
            "device::init()",
            "net::socket::vsock::init()",
        ],
        "FrameVM crate entry must not manually initialize FrameV frontends or upper subsystems",
    )
}

fn check_final_entry_init_policy(repo_root: &Path, config: &Config) -> CheckResult<()> {
    if !config.source_trim_enforcement.is_final() {
        return Ok(());
    }

    let init_path = repo_root.join(&config.service_path).join("src/init.rs");
    let init_source = fs::read_to_string(&init_path)?;
    if !init_source.contains("aster_cmdline::") {
        return Err(CheckError::new(format!(
            "{} must use service-side `aster-cmdline` for root/init selection",
            init_path.display()
        )));
    }
    reject_source_patterns(
        &init_path,
        &init_source,
        &["let init_program = \"/init\"", "String::from(\"/init\")"],
        "completed FrameVM init must get the init path from the copied kernel cmdline provider instead of hard-coding `/init`",
    )?;
    for pattern in [
        "framev::init_descriptor()",
        "framev::init_devices()",
        "console::init()",
        "device::init()",
        "net::socket::vsock::init()",
    ] {
        reject_source_patterns(
            &init_path,
            &init_source,
            &[pattern],
            "completed FrameVM entry must initialize subsystems through component profiles rather than manual frontend calls",
        )?;
    }
    if !init_source.contains("logo_ascii_art::get_gradient_color_version()")
        && !init_source.contains("logo_ascii_art::get_framevm_gradient_color_version()")
    {
        return Err(CheckError::new(format!(
            "{} must print the FrameVM banner through the shared `logo-ascii-art` mechanism",
            init_path.display()
        )));
    }
    for pattern in [
        "FrameVM",
        "init_framevm_components(InitStage::Bootstrap)",
        "init_framevm_components(InitStage::Kthread)",
        "init_framevm_components(InitStage::Process)",
    ] {
        if !init_source.contains(pattern) {
            return Err(CheckError::new(format!(
                "{} missing final entry policy pattern `{pattern}`",
                init_path.display()
            )));
        }
    }

    let service_manifest = read_toml(&repo_root.join(&config.service_path).join("Cargo.toml"))?;
    for dependency in ["aster-cmdline", "logo-ascii-art"] {
        if !manifest_dependency_key_or_resolves_to(&service_manifest, "dependencies", dependency) {
            return Err(CheckError::new(format!(
                "service manifest must depend on `{dependency}` for final entry initialization policy"
            )));
        }
    }
    Ok(())
}

fn check_retained_differences(
    repo_root: &Path,
    config: &Config,
    files: &[PathBuf],
    trim_manifest: &TrimManifest,
) -> CheckResult<()> {
    if !config.source_trim_enforcement.is_final() {
        return Ok(());
    }

    let service_root = repo_root.join(&config.service_path);
    for file in files {
        let service_relative = file.strip_prefix(&service_root).map_err(|_| {
            CheckError::new(format!("{} is not under service root", file.display()))
        })?;
        if config
            .forbidden_service_subtrees
            .iter()
            .any(|subtree| service_relative.starts_with(subtree))
        {
            continue;
        }

        let service_manifest_path = config.service_path.join(service_relative);
        let kernel_manifest_path =
            expected_kernel_path_for_manifest_entry(config, &service_manifest_path)?;
        let full_kernel_path = repo_root.join(&kernel_manifest_path);
        if !full_kernel_path.exists() {
            continue;
        }
        if !retained_source_differs(file, &full_kernel_path)? {
            continue;
        }
        let Some(entry) = trim_manifest.entries.get(&service_manifest_path) else {
            return Err(CheckError::new(format!(
                "retained source `{}` differs from `{}` without a trim manifest entry",
                service_manifest_path.display(),
                kernel_manifest_path.display()
            )));
        };
        if entry.kernel_path != kernel_manifest_path {
            return Err(CheckError::new(format!(
                "trim manifest entry for `{}` points to `{}`, expected `{}`",
                service_manifest_path.display(),
                entry.kernel_path.display(),
                kernel_manifest_path.display()
            )));
        }
        check_retained_item_shape(
            file,
            &full_kernel_path,
            &service_manifest_path,
            &kernel_manifest_path,
            entry,
        )?;
        check_retained_comment_text(
            file,
            &full_kernel_path,
            &service_manifest_path,
            &kernel_manifest_path,
            entry,
        )?;
    }
    Ok(())
}

fn check_retained_item_shape(
    service_file: &Path,
    kernel_file: &Path,
    service_manifest_path: &Path,
    kernel_manifest_path: &Path,
    entry: &TrimManifestEntry,
) -> CheckResult<()> {
    let service_shapes = item_shapes(service_file)?;
    let kernel_shapes = item_shapes(kernel_file)?;
    if matches!(
        entry.kind.as_str(),
        "entry-trim" | "provider-substitution" | "unsupported-feature-trim"
    ) {
        return Ok(());
    }

    for (name, kernel_shape) in &kernel_shapes {
        let Some(service_shape) = service_shapes.get(name) else {
            return Err(CheckError::new(format!(
                "retained source `{}` removes item `{name}` from `{}` without `unsupported-feature-trim` or `entry-trim`",
                service_manifest_path.display(),
                kernel_manifest_path.display()
            )));
        };
        if service_shape != kernel_shape {
            return Err(CheckError::new(format!(
                "retained source `{}` changes shape of item `{name}` from `{}` under `{}` manifest entry",
                service_manifest_path.display(),
                kernel_manifest_path.display(),
                entry.kind
            )));
        }
    }
    Ok(())
}

fn check_retained_comment_text(
    service_file: &Path,
    kernel_file: &Path,
    service_manifest_path: &Path,
    kernel_manifest_path: &Path,
    entry: &TrimManifestEntry,
) -> CheckResult<()> {
    if matches!(
        entry.kind.as_str(),
        "entry-trim" | "provider-substitution" | "unsupported-feature-trim" | "test-only-or-doc"
    ) {
        return Ok(());
    }

    let service_comments = retained_comment_lines(&fs::read_to_string(service_file)?);
    let kernel_comments = retained_comment_lines(&fs::read_to_string(kernel_file)?);
    if service_comments != kernel_comments {
        return Err(CheckError::new(format!(
            "retained source `{}` changes comments from `{}` under `{}` manifest entry",
            service_manifest_path.display(),
            kernel_manifest_path.display(),
            entry.kind
        )));
    }
    Ok(())
}

fn retained_comment_lines(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
                Some(trimmed.trim_end().to_string())
            } else {
                None
            }
        })
        .collect()
}

fn item_shapes(file: &Path) -> CheckResult<BTreeMap<String, ItemShape>> {
    let parsed = parse_rust_file(file)?;
    let mut shapes = BTreeMap::new();
    for item in parsed.items {
        collect_item_shape(&mut shapes, item);
    }
    Ok(shapes)
}

fn collect_item_shape(shapes: &mut BTreeMap<String, ItemShape>, item: Item) {
    match item {
        Item::Const(item) => insert_shape(
            shapes,
            format!("const {}", item.ident),
            "const",
            &item.vis,
            &item.ty,
        ),
        Item::Enum(item) => {
            let shape = format!(
                "{} {} {}",
                normalize_visibility(&item.vis),
                normalize_tokens(&item.generics),
                normalize_tokens(&item.variants)
            );
            shapes.insert(
                format!("enum {}", item.ident),
                ItemShape {
                    kind: "enum",
                    shape,
                },
            );
        }
        Item::Fn(item) => {
            shapes.insert(
                format!("fn {}", item.sig.ident),
                ItemShape {
                    kind: "fn",
                    shape: format!(
                        "{} {}",
                        normalize_visibility(&item.vis),
                        normalize_function_signature(&item)
                    ),
                },
            );
        }
        Item::Impl(item) => {
            let self_ty = normalize_tokens(&item.self_ty);
            let trait_path = item
                .trait_
                .as_ref()
                .map(|(_, path, _)| normalize_tokens(path))
                .unwrap_or_else(|| "inherent".to_string());
            shapes.insert(
                format!("impl {trait_path} for {self_ty}"),
                ItemShape {
                    kind: "impl",
                    shape: normalize_tokens(&item.generics),
                },
            );
            for impl_item in item.items {
                if let ImplItem::Fn(method) = impl_item {
                    shapes.insert(
                        format!("impl {trait_path} for {self_ty}::{}", method.sig.ident),
                        ItemShape {
                            kind: "method",
                            shape: format!(
                                "{} {}",
                                normalize_visibility(&method.vis),
                                normalize_tokens(&method.sig)
                            ),
                        },
                    );
                }
            }
        }
        Item::Mod(item) => insert_shape(
            shapes,
            format!("mod {}", item.ident),
            "mod",
            &item.vis,
            &item.ident,
        ),
        Item::Static(item) => insert_shape(
            shapes,
            format!("static {}", item.ident),
            "static",
            &item.vis,
            &item.ty,
        ),
        Item::Struct(item) => {
            let shape = format!(
                "{} {} {}",
                normalize_visibility(&item.vis),
                normalize_tokens(&item.generics),
                normalize_tokens(&item.fields)
            );
            shapes.insert(
                format!("struct {}", item.ident),
                ItemShape {
                    kind: "struct",
                    shape,
                },
            );
        }
        Item::Trait(item) => {
            let items = item
                .items
                .iter()
                .map(normalize_tokens)
                .collect::<Vec<_>>()
                .join("; ");
            shapes.insert(
                format!("trait {}", item.ident),
                ItemShape {
                    kind: "trait",
                    shape: format!(
                        "{} {} {}",
                        normalize_visibility(&item.vis),
                        normalize_tokens(&item.generics),
                        items
                    ),
                },
            );
        }
        Item::Type(item) => {
            let shape = format!(
                "{} {} {}",
                normalize_visibility(&item.vis),
                normalize_tokens(&item.generics),
                normalize_tokens(&item.ty)
            );
            shapes.insert(
                format!("type {}", item.ident),
                ItemShape {
                    kind: "type",
                    shape,
                },
            );
        }
        _ => {}
    }
}

fn defined_item_name(item: &Item) -> Option<String> {
    match item {
        Item::Const(item) => Some(item.ident.to_string()),
        Item::Enum(item) => Some(item.ident.to_string()),
        Item::Fn(item) => Some(item.sig.ident.to_string()),
        Item::Mod(item) => Some(item.ident.to_string()),
        Item::Static(item) => Some(item.ident.to_string()),
        Item::Struct(item) => Some(item.ident.to_string()),
        Item::Trait(item) => Some(item.ident.to_string()),
        Item::Type(item) => Some(item.ident.to_string()),
        _ => None,
    }
}

fn insert_shape(
    shapes: &mut BTreeMap<String, ItemShape>,
    name: String,
    kind: &'static str,
    visibility: &Visibility,
    tokens: &impl ToTokens,
) {
    shapes.insert(
        name,
        ItemShape {
            kind,
            shape: format!(
                "{} {}",
                normalize_visibility(visibility),
                normalize_tokens(tokens)
            ),
        },
    );
}

fn normalize_function_signature(item: &ItemFn) -> String {
    format!(
        "{}({}) -> {}",
        normalize_tokens(&item.sig.generics),
        item.sig
            .inputs
            .iter()
            .map(normalize_tokens)
            .collect::<Vec<_>>()
            .join(", "),
        match &item.sig.output {
            ReturnType::Default => "()".to_string(),
            ReturnType::Type(_, ty) => normalize_type(ty),
        }
    )
}

fn normalize_visibility(visibility: &Visibility) -> String {
    match visibility {
        Visibility::Inherited => String::new(),
        _ => normalize_tokens(visibility),
    }
}

fn normalized_source_for_diff(path: &Path) -> CheckResult<String> {
    let source = fs::read_to_string(path)?;
    if path.extension().is_some_and(|extension| extension == "rs")
        && let Ok(parsed) = syn::parse_file(&source)
    {
        return Ok(normalize_tokens(&parsed));
    }
    Ok(source
        .replace("\r\n", "\n")
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n"))
}

fn retained_source_differs(left: &Path, right: &Path) -> CheckResult<bool> {
    if normalized_source_for_diff(left)? != normalized_source_for_diff(right)? {
        return Ok(true);
    }

    if left.extension().is_some_and(|extension| extension == "rs")
        && right.extension().is_some_and(|extension| extension == "rs")
    {
        let left_comments = retained_comment_lines(&fs::read_to_string(left)?);
        let right_comments = retained_comment_lines(&fs::read_to_string(right)?);
        return Ok(left_comments != right_comments);
    }

    Ok(false)
}

fn check_forbidden_service_subtrees(
    repo_root: &Path,
    config: &Config,
    files: &[PathBuf],
) -> CheckResult<()> {
    if !config.source_trim_enforcement.is_final() {
        return Ok(());
    }

    let service_root = repo_root.join(&config.service_path);
    for file in files {
        let service_relative = file.strip_prefix(&service_root).map_err(|_| {
            CheckError::new(format!("{} is not under service root", file.display()))
        })?;
        if config
            .forbidden_service_subtrees
            .iter()
            .any(|subtree| service_relative.starts_with(subtree))
        {
            return Err(CheckError::new(format!(
                "final FrameVM source trim forbids service-local source `{}`",
                file.display()
            )));
        }
    }
    Ok(())
}

fn check_final_source_layout(
    repo_root: &Path,
    config: &Config,
    service_files: &[PathBuf],
) -> CheckResult<()> {
    if !config.source_trim_enforcement.is_final() {
        return Ok(());
    }

    let service_root = repo_root.join(&config.service_path);
    let lib_path = service_root.join("src/lib.rs");
    let parsed = parse_rust_file(&lib_path)?;
    for item in parsed.items {
        let Item::Mod(item_mod) = item else {
            continue;
        };
        let name = item_mod.ident.to_string();
        if module_path_attr(&item_mod.attrs).is_some() {
            return Err(CheckError::new(format!(
                "{} declares retained module `{name}` through a `#[path = ...]` alias",
                lib_path.display()
            )));
        }
        if config.service_local_module_aliases.contains(&name) {
            return Err(CheckError::new(format!(
                "{} declares service-local retained module alias `{name}`",
                lib_path.display()
            )));
        }
    }

    check_retained_path_attrs(repo_root, config, service_files)?;
    Ok(())
}

fn check_final_superseded_implementation_paths(
    repo_root: &Path,
    config: &Config,
) -> CheckResult<()> {
    if !config.source_trim_enforcement.is_final() {
        return Ok(());
    }

    let service_src = repo_root.join(&config.service_path).join("src");
    for scheduler_path in [
        service_src.join("scheduler.rs"),
        service_src.join("scheduler").join("mod.rs"),
    ] {
        if scheduler_path.exists() {
            return Err(CheckError::new(format!(
                "{} is a service-local scheduler path; the completed scheduler trim must live under `services/aster-framevm/src/sched/**` and map to `kernel/src/sched/**`",
                scheduler_path.display()
            )));
        }
    }

    for alias in &config.service_local_module_aliases {
        for path in [
            service_src.join(format!("{alias}.rs")),
            service_src.join(alias).join("mod.rs"),
        ] {
            if path.exists() {
                return Err(CheckError::new(format!(
                    "{} is a superseded FrameVM implementation path; move retained behavior to kernel-shaped source and delete forwarding wrappers or compatibility aliases",
                    path.display()
                )));
            }
        }
    }

    Ok(())
}

fn check_final_facade_boundary(
    repo_root: &Path,
    config: &Config,
    service_files: &[PathBuf],
) -> CheckResult<()> {
    if !config.source_trim_enforcement.is_final() {
        return Ok(());
    }

    let facade_lib = repo_root.join(&config.facade_path).join("src/lib.rs");
    let parsed = parse_rust_file(&facade_lib)?;
    for item in parsed.items {
        if let Item::Mod(item_mod) = item {
            let name = item_mod.ident.to_string();
            if is_public(&item_mod.vis) && LEGACY_HIGH_LEVEL_FRAMEV_MODULES.contains(&name.as_str())
            {
                return Err(CheckError::new(format!(
                    "{} exposes forbidden high-level FrameV facade module `{name}`",
                    facade_lib.display()
                )));
            }
        }
    }

    for file in service_files {
        let source = fs::read_to_string(file)?;
        for module in LEGACY_HIGH_LEVEL_FRAMEV_MODULES {
            let pattern = format!("ostd::{module}");
            if let Some(line) = source.lines().position(|line| line.contains(&pattern)) {
                return Err(CheckError::new(format!(
                    "{}:{} imports forbidden high-level FrameV facade path `{pattern}`",
                    file.display(),
                    line + 1
                )));
            }
        }
    }
    Ok(())
}

fn check_retained_path_attrs(
    repo_root: &Path,
    config: &Config,
    service_files: &[PathBuf],
) -> CheckResult<()> {
    let service_root = repo_root.join(&config.service_path);
    let kernel_src = repo_root.join(&config.kernel_src_path);
    for file in service_files {
        let service_relative = file.strip_prefix(&service_root).map_err(|_| {
            CheckError::new(format!("{} is not under service root", file.display()))
        })?;
        if config.entry_trim_files.contains(service_relative)
            || config
                .forbidden_service_subtrees
                .iter()
                .any(|subtree| service_relative.starts_with(subtree))
        {
            continue;
        }

        let Ok(retained_relative) = service_relative.strip_prefix("src") else {
            continue;
        };
        let kernel_file = kernel_src.join(retained_relative);
        let service_path_attrs = module_path_attrs(file)?;
        if service_path_attrs.is_empty() {
            continue;
        }
        let kernel_path_attrs = module_path_attrs(&kernel_file)?;
        for (module, service_attr) in service_path_attrs {
            if kernel_path_attrs.get(&module) != Some(&service_attr) {
                return Err(CheckError::new(format!(
                    "{} declares module `{module}` with `#[path = \"{service_attr}\"]`, but `{}` does not declare the same path",
                    file.display(),
                    kernel_file.display()
                )));
            }
        }
    }
    Ok(())
}

fn module_path_attrs(file: &Path) -> CheckResult<BTreeMap<String, String>> {
    let parsed = parse_rust_file(file)?;
    let mut attrs = BTreeMap::new();
    for item in parsed.items {
        if let Item::Mod(item_mod) = item
            && let Some(path) = module_path_attr(&item_mod.attrs)
        {
            attrs.insert(
                item_mod.ident.to_string(),
                path.to_string_lossy().into_owned(),
            );
        }
    }
    Ok(attrs)
}

fn expected_kernel_path_for_manifest_entry(
    config: &Config,
    service_path: &Path,
) -> CheckResult<PathBuf> {
    let service_relative = service_path
        .strip_prefix(&config.service_path)
        .map_err(|_| {
            CheckError::new(format!(
                "trim manifest service_path `{}` is not under configured service_path `{}`",
                service_path.display(),
                config.service_path.display()
            ))
        })?;

    if config.entry_trim_files.contains(service_relative) {
        let file_name = service_relative.file_name().ok_or_else(|| {
            CheckError::new(format!(
                "entry-trim service_path `{}` has no file name",
                service_path.display()
            ))
        })?;
        return Ok(config.kernel_src_path.join(file_name));
    }

    if let Ok(retained_relative) = service_relative.strip_prefix("src") {
        return Ok(config.kernel_src_path.join(retained_relative));
    }

    if let Ok(comp_relative) = service_relative.strip_prefix("comps") {
        let mut components = comp_relative.components();
        let Some(std::path::Component::Normal(comp_name)) = components.next() else {
            return Err(CheckError::new(format!(
                "trim manifest comp service_path `{}` has no comp name",
                service_path.display()
            )));
        };
        let comp_name = PathBuf::from(comp_name);
        let remaining = components.as_path();
        let source_relative = remaining.strip_prefix("src").map_err(|_| {
            CheckError::new(format!(
                "trim manifest comp service_path `{}` must point under comp src",
                service_path.display()
            ))
        })?;
        return Ok(Path::new("kernel/comps")
            .join(comp_name)
            .join("src")
            .join(source_relative));
    }

    Err(CheckError::new(format!(
        "trim manifest service_path `{}` is not a retained source path",
        service_path.display()
    )))
}

fn collect_used_ostd(file: &Path, used: &mut UsedOstd) -> CheckResult<()> {
    let parsed = parse_rust_file(file)?;
    let mut visitor = OstdUseVisitor { used };
    visitor.visit_file(&parsed);
    Ok(())
}

struct OstdUseVisitor<'a> {
    used: &'a mut UsedOstd,
}

impl<'ast> Visit<'ast> for OstdUseVisitor<'_> {
    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        collect_use_tree(&item.tree, Vec::new(), self.used);
        visit::visit_item_use(self, item);
    }

    fn visit_path(&mut self, path: &'ast SynPath) {
        let segments = path_segments(path);
        self.record_segments(&segments);
        visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        let segments = path_segments(&item.path);
        self.record_segments(&segments);
        visit::visit_macro(self, item);
    }
}

impl OstdUseVisitor<'_> {
    fn record_segments(&mut self, segments: &[String]) {
        let Some(first) = segments.first() else {
            return;
        };
        if first == "ostd" {
            record_ostd_path(&segments[1..], self.used);
            return;
        }
        if let Some(prefix) = self.used.aliases.get(first).cloned() {
            let mut path = prefix;
            path.extend_from_slice(&segments[1..]);
            record_ostd_path(&path, self.used);
        }
    }
}

fn collect_use_tree(tree: &UseTree, prefix: Vec<String>, used: &mut UsedOstd) {
    match tree {
        UseTree::Path(path) => {
            let mut next = prefix;
            next.push(path.ident.to_string());
            collect_use_tree(&path.tree, next, used);
        }
        UseTree::Name(name) => {
            let mut full = prefix;
            full.push(name.ident.to_string());
            record_import_path(&full, name.ident.to_string(), used);
        }
        UseTree::Rename(rename) => {
            let mut full = prefix;
            full.push(rename.ident.to_string());
            record_import_path(&full, rename.rename.to_string(), used);
        }
        UseTree::Glob(_) => {
            if prefix == ["ostd", "prelude"] {
                used.prelude_glob = true;
            } else if prefix.first().is_some_and(|segment| segment == "ostd") {
                record_ostd_path(&prefix[1..], used);
            }
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_tree(item, prefix.clone(), used);
            }
        }
    }
}

fn record_import_path(full: &[String], local_name: String, used: &mut UsedOstd) {
    if full.first().is_none_or(|segment| segment != "ostd") || full.len() < 2 {
        return;
    }
    let ostd_path = full[1..].to_vec();
    record_ostd_path(&ostd_path, used);
    used.aliases.insert(local_name, ostd_path);
}

fn record_ostd_path(path: &[String], used: &mut UsedOstd) {
    if path.is_empty() {
        return;
    }
    used.paths.insert(path.join("::"));
}

fn collect_used_prelude_items(
    repo_root: &Path,
    config: &Config,
    service_files: &[PathBuf],
    used: &mut UsedOstd,
) -> CheckResult<()> {
    let prelude_path = prelude_source_path(repo_root, config).ok_or_else(|| {
        CheckError::new("service uses `ostd::prelude::*`, but no facade prelude source was found")
    })?;
    let parsed = parse_rust_file(&prelude_path)?;
    let mut candidates = BTreeMap::<String, Option<String>>::new();
    for item in parsed.items {
        if let Item::Use(item_use) = item {
            collect_prelude_exports(&item_use.tree, Vec::new(), &mut candidates);
        }
    }
    if candidates.is_empty() {
        return Err(CheckError::new(format!(
            "{} exposes no parseable prelude re-exports",
            prelude_path.display()
        )));
    }

    let mut source = String::new();
    for file in service_files {
        source.push_str(&fs::read_to_string(file)?);
        source.push('\n');
    }
    for (name, path) in candidates {
        if contains_ident(&source, &name) {
            let Some(path) = path else {
                return Err(CheckError::new(format!(
                    "ambiguous prelude re-export `{name}`; use an explicit import or path"
                )));
            };
            used.paths.insert(format!("prelude::{path}"));
        }
    }
    Ok(())
}

fn prelude_source_path(repo_root: &Path, config: &Config) -> Option<PathBuf> {
    let facade_prelude = repo_root.join(&config.facade_path).join("src/prelude.rs");
    if facade_prelude.exists() {
        return Some(facade_prelude);
    }

    let provider_prelude = repo_root.join("kernel/comps/framevisor/src/prelude.rs");
    provider_prelude.exists().then_some(provider_prelude)
}

fn collect_prelude_exports(
    tree: &UseTree,
    prefix: Vec<String>,
    exports: &mut BTreeMap<String, Option<String>>,
) {
    match tree {
        UseTree::Path(path) => {
            let mut next = prefix;
            let segment = path.ident.to_string();
            if segment != "self" && segment != "super" && segment != "crate" {
                next.push(segment);
            }
            collect_prelude_exports(&path.tree, next, exports);
        }
        UseTree::Name(name) => {
            let mut full = prefix;
            full.push(name.ident.to_string());
            insert_prelude_export(exports, name.ident.to_string(), full.join("::"));
        }
        UseTree::Rename(rename) => {
            let mut full = prefix;
            full.push(rename.ident.to_string());
            insert_prelude_export(exports, rename.rename.to_string(), full.join("::"));
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_prelude_exports(item, prefix.clone(), exports);
            }
        }
        UseTree::Glob(_) => {}
    }
}

fn insert_prelude_export(
    exports: &mut BTreeMap<String, Option<String>>,
    name: String,
    path: String,
) {
    match exports.get_mut(&name) {
        Some(existing) => *existing = None,
        None => {
            exports.insert(name, Some(path));
        }
    }
}

fn check_used_ostd_shape(
    used: &UsedOstd,
    facade_api: &PublicApi,
    host_api: &PublicApi,
    config: &Config,
) -> CheckResult<()> {
    for path in &used.paths {
        if is_excluded(path, &config.excluded_path_prefixes) {
            continue;
        }
        if !facade_api.contains_public_path(path) {
            return Err(CheckError::new(format!(
                "used OSTD facade path `{path}` is not visible from the facade public surface"
            )));
        }
        if is_allowed_provider_facade_path(path, &config.allowed_provider_facade_paths) {
            continue;
        }
        if !host_api.contains_public_path(path) {
            return Err(CheckError::new(format!(
                "used non-FrameV facade path `{path}` has no Host OSTD public counterpart"
            )));
        }
        if let (Some(facade_shape), Some(host_shape)) =
            (facade_api.exact.get(path), host_api.exact.get(path))
        {
            if !shapes_are_compatible(facade_shape, host_shape) {
                return Err(CheckError::new(format!(
                    "facade public API shape mismatch at `{path}`: facade={facade_shape:?}, host={host_shape:?}"
                )));
            }
        }
    }
    Ok(())
}

fn shapes_are_compatible(facade_shape: &Shape, host_shape: &Shape) -> bool {
    matches!(facade_shape, Shape::Item { kind: "reexport" })
        || matches!(host_shape, Shape::Item { kind: "reexport" })
        || facade_shape == host_shape
}

fn is_allowed_provider_facade_path(path: &str, allowed_paths: &BTreeSet<String>) -> bool {
    allowed_paths
        .iter()
        .any(|allowed| path == allowed || path.starts_with(&format!("{allowed}::")))
}

fn collect_public_api(src_root: &Path) -> CheckResult<PublicApi> {
    let mut api = PublicApi::default();
    collect_module_api(src_root, &src_root.join("lib.rs"), &[], &mut api)?;
    collect_exported_macros(src_root, &mut api)?;
    Ok(api)
}

fn collect_exported_macros(src_root: &Path, api: &mut PublicApi) -> CheckResult<()> {
    for file in rust_files(src_root)? {
        let parsed = parse_rust_file(&file)?;
        for item in parsed.items {
            if let Item::Macro(item) = item
                && is_exported_macro(&item)
                && let Some(ident) = item.ident
            {
                api.insert_item(&[ident.to_string()], Shape::Item { kind: "macro" });
            }
        }
    }
    Ok(())
}

fn collect_module_api(
    src_root: &Path,
    file: &Path,
    module_path: &[String],
    api: &mut PublicApi,
) -> CheckResult<()> {
    let parsed = parse_rust_file(file)?;
    for item in parsed.items {
        match item {
            Item::Mod(item_mod) if is_public(&item_mod.vis) => {
                collect_public_mod(src_root, file, module_path, item_mod, api)?;
            }
            Item::Mod(item_mod) => {
                collect_module_macro_exports(src_root, file, module_path, item_mod, api)?;
            }
            Item::Fn(item_fn) if is_public(&item_fn.vis) => {
                let mut path = module_path.to_vec();
                path.push(item_fn.sig.ident.to_string());
                api.insert_item(&path, Shape::Function(function_shape(&item_fn)));
            }
            Item::Struct(item) if is_public(&item.vis) => {
                insert_named_item(api, module_path, &item.ident.to_string(), "struct");
            }
            Item::Enum(item) if is_public(&item.vis) => {
                insert_named_item(api, module_path, &item.ident.to_string(), "enum");
            }
            Item::Trait(item) if is_public(&item.vis) => {
                insert_named_item(api, module_path, &item.ident.to_string(), "trait");
            }
            Item::Type(item) if is_public(&item.vis) => {
                insert_named_item(api, module_path, &item.ident.to_string(), "type");
            }
            Item::Const(item) if is_public(&item.vis) => {
                insert_named_item(api, module_path, &item.ident.to_string(), "const");
            }
            Item::Static(item) if is_public(&item.vis) => {
                insert_named_item(api, module_path, &item.ident.to_string(), "static");
            }
            Item::Macro(item) if is_exported_macro(&item) => {
                if let Some(ident) = item.ident {
                    api.insert_item(&[ident.to_string()], Shape::Item { kind: "macro" });
                }
            }
            Item::Use(item_use) if is_public(&item_use.vis) => {
                collect_public_use(&item_use.tree, module_path.to_vec(), api);
            }
            Item::Macro(item_macro) if has_macro_export(&item_macro.attrs) => {
                if let Some(ident) = item_macro.ident {
                    insert_named_item(api, &[], &ident.to_string(), "macro");
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn collect_public_mod(
    src_root: &Path,
    current_file: &Path,
    module_path: &[String],
    item_mod: ItemMod,
    api: &mut PublicApi,
) -> CheckResult<()> {
    let mut child_path = module_path.to_vec();
    child_path.push(item_mod.ident.to_string());
    api.insert_module(&child_path);
    if let Some((_, items)) = item_mod.content {
        for item in items {
            collect_inline_item(src_root, current_file, &child_path, item, api)?;
        }
        return Ok(());
    }

    let Some(module_file) = module_file_path(src_root, current_file, &item_mod, module_path) else {
        return Ok(());
    };
    if module_file.exists() {
        collect_module_api(src_root, &module_file, &child_path, api)?;
    }
    Ok(())
}

fn collect_inline_item(
    src_root: &Path,
    current_file: &Path,
    module_path: &[String],
    item: Item,
    api: &mut PublicApi,
) -> CheckResult<()> {
    match item {
        Item::Mod(item_mod) if is_public(&item_mod.vis) => {
            collect_public_mod(src_root, current_file, module_path, item_mod, api)?;
        }
        Item::Mod(item_mod) => {
            collect_module_macro_exports(src_root, current_file, module_path, item_mod, api)?;
        }
        Item::Fn(item_fn) if is_public(&item_fn.vis) => {
            let mut path = module_path.to_vec();
            path.push(item_fn.sig.ident.to_string());
            api.insert_item(&path, Shape::Function(function_shape(&item_fn)));
        }
        Item::Struct(item) if is_public(&item.vis) => {
            insert_named_item(api, module_path, &item.ident.to_string(), "struct");
        }
        Item::Enum(item) if is_public(&item.vis) => {
            insert_named_item(api, module_path, &item.ident.to_string(), "enum");
        }
        Item::Trait(item) if is_public(&item.vis) => {
            insert_named_item(api, module_path, &item.ident.to_string(), "trait");
        }
        Item::Type(item) if is_public(&item.vis) => {
            insert_named_item(api, module_path, &item.ident.to_string(), "type");
        }
        Item::Const(item) if is_public(&item.vis) => {
            insert_named_item(api, module_path, &item.ident.to_string(), "const");
        }
        Item::Static(item) if is_public(&item.vis) => {
            insert_named_item(api, module_path, &item.ident.to_string(), "static");
        }
        Item::Macro(item) if is_exported_macro(&item) => {
            if let Some(ident) = item.ident {
                api.insert_item(&[ident.to_string()], Shape::Item { kind: "macro" });
            }
        }
        Item::Use(item_use) if is_public(&item_use.vis) => {
            collect_public_use(&item_use.tree, module_path.to_vec(), api);
        }
        Item::Macro(item_macro) if has_macro_export(&item_macro.attrs) => {
            if let Some(ident) = item_macro.ident {
                insert_named_item(api, &[], &ident.to_string(), "macro");
            }
        }
        _ => {}
    }
    Ok(())
}

fn collect_module_macro_exports(
    src_root: &Path,
    current_file: &Path,
    module_path: &[String],
    item_mod: ItemMod,
    api: &mut PublicApi,
) -> CheckResult<()> {
    let mut child_path = module_path.to_vec();
    child_path.push(item_mod.ident.to_string());
    if let Some((_, items)) = item_mod.content {
        for item in items {
            collect_macro_export_from_item(src_root, current_file, &child_path, item, api)?;
        }
        return Ok(());
    }

    let Some(module_file) = module_file_path(src_root, current_file, &item_mod, module_path) else {
        return Ok(());
    };
    if module_file.exists() {
        let parsed = parse_rust_file(&module_file)?;
        for item in parsed.items {
            collect_macro_export_from_item(src_root, &module_file, &child_path, item, api)?;
        }
    }
    Ok(())
}

fn collect_macro_export_from_item(
    src_root: &Path,
    current_file: &Path,
    module_path: &[String],
    item: Item,
    api: &mut PublicApi,
) -> CheckResult<()> {
    match item {
        Item::Macro(item_macro) if has_macro_export(&item_macro.attrs) => {
            if let Some(ident) = item_macro.ident {
                insert_named_item(api, &[], &ident.to_string(), "macro");
            }
        }
        Item::Mod(item_mod) => {
            collect_module_macro_exports(src_root, current_file, module_path, item_mod, api)?;
        }
        _ => {}
    }
    Ok(())
}

fn collect_public_use(tree: &UseTree, module_path: Vec<String>, api: &mut PublicApi) {
    match tree {
        UseTree::Path(path) => {
            collect_public_use(&path.tree, module_path, api);
        }
        UseTree::Name(name) => {
            let mut path = module_path;
            path.push(name.ident.to_string());
            if is_likely_module_reexport(&path) {
                api.insert_module(&path);
            }
            api.insert_item(&path, Shape::Item { kind: "reexport" });
        }
        UseTree::Rename(rename) => {
            let mut path = module_path;
            path.push(rename.rename.to_string());
            api.insert_item(&path, Shape::Item { kind: "reexport" });
        }
        UseTree::Glob(_) => {
            api.insert_module(&module_path);
        }
        UseTree::Group(group) => {
            for item in &group.items {
                collect_public_use(item, module_path.clone(), api);
            }
        }
    }
}

fn insert_named_item(api: &mut PublicApi, module_path: &[String], name: &str, kind: &'static str) {
    let mut path = module_path.to_vec();
    path.push(name.to_string());
    api.insert_item(&path, Shape::Item { kind });
}

fn function_shape(item: &ItemFn) -> FunctionShape {
    FunctionShape {
        generics: normalize_generics(&item.sig.generics),
        inputs: item
            .sig
            .inputs
            .iter()
            .map(|input| normalize_tokens(input))
            .collect(),
        output: match &item.sig.output {
            ReturnType::Default => None,
            ReturnType::Type(_, ty) => Some(normalize_type(ty)),
        },
    }
}

fn normalize_generics(generics: &Generics) -> Vec<String> {
    generics
        .params
        .iter()
        .map(|param| match param {
            GenericParam::Type(item) => normalize_tokens(item),
            GenericParam::Lifetime(item) => normalize_tokens(item),
            GenericParam::Const(item) => normalize_tokens(item),
        })
        .collect()
}

fn normalize_type(ty: &Type) -> String {
    normalize_tokens(ty)
}

fn normalize_tokens(tokens: &impl ToTokens) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn module_file_path(
    src_root: &Path,
    current_file: &Path,
    item_mod: &ItemMod,
    module_path: &[String],
) -> Option<PathBuf> {
    if let Some(path_attr) = module_path_attr(&item_mod.attrs) {
        return Some(current_file.parent()?.join(path_attr));
    }

    let name = item_mod.ident.to_string();
    if current_file.file_name()? == "mod.rs" || current_file == src_root.join("lib.rs") {
        let mut dir = src_root.to_path_buf();
        for segment in module_path {
            dir.push(segment);
        }
        let direct = dir.join(format!("{name}.rs"));
        if direct.exists() {
            return Some(direct);
        }
        return Some(dir.join(name).join("mod.rs"));
    }

    let dir = current_file.with_extension("");
    let direct = dir.join(format!("{name}.rs"));
    if direct.exists() {
        return Some(direct);
    }
    Some(dir.join(name).join("mod.rs"))
}

fn module_path_attr(attrs: &[Attribute]) -> Option<PathBuf> {
    for attr in attrs {
        if !attr.path().is_ident("path") {
            continue;
        }
        if let Ok(lit) = attr.parse_args::<syn::LitStr>() {
            return Some(PathBuf::from(lit.value()));
        }
        if let syn::Meta::NameValue(name_value) = &attr.meta
            && let syn::Expr::Lit(expr_lit) = &name_value.value
            && let syn::Lit::Str(lit) = &expr_lit.lit
        {
            return Some(PathBuf::from(lit.value()));
        }
    }
    None
}

fn parse_rust_file(path: &Path) -> CheckResult<File> {
    let source = fs::read_to_string(path)?;
    syn::parse_file(&source)
        .map_err(|error| CheckError::new(format!("failed to parse {}: {error}", path.display())))
}

fn rust_files(root: &Path) -> CheckResult<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_rust_files(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn rust_and_toml_files(root: &Path) -> CheckResult<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_files_with_extensions(root, &["rs", "toml"], &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_rust_files(root: &Path, files: &mut Vec<PathBuf>) -> CheckResult<()> {
    collect_files_with_extensions(root, &["rs"], files)
}

fn collect_files_with_extensions(
    root: &Path,
    extensions: &[&str],
    files: &mut Vec<PathBuf>,
) -> CheckResult<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_files_with_extensions(&path, extensions, files)?;
        } else if path.extension().is_some_and(|ext| {
            extensions
                .iter()
                .any(|expected| ext == std::ffi::OsStr::new(expected))
        }) {
            files.push(path);
        }
    }
    Ok(())
}

fn read_toml(path: &Path) -> CheckResult<toml::Value> {
    fs::read_to_string(path)?
        .parse::<toml::Value>()
        .map_err(|error| CheckError::new(format!("failed to parse {}: {error}", path.display())))
}

fn required_string(value: &toml::Value, key: &str) -> CheckResult<String> {
    value
        .get(key)
        .and_then(toml::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| CheckError::new(format!("missing string config key `{key}`")))
}

fn required_array(value: &toml::Value, key: &str) -> CheckResult<Vec<String>> {
    value
        .get(key)
        .and_then(toml::Value::as_array)
        .ok_or_else(|| CheckError::new(format!("missing array config key `{key}`")))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| CheckError::new(format!("config key `{key}` must contain strings")))
        })
        .collect()
}

fn required_string_set(value: &toml::Value, key: &str) -> CheckResult<BTreeSet<String>> {
    Ok(required_array(value, key)?.into_iter().collect())
}

fn required_path_array(value: &toml::Value, key: &str) -> CheckResult<Vec<PathBuf>> {
    required_array(value, key).map(|items| items.into_iter().map(PathBuf::from).collect())
}

fn required_path_set(value: &toml::Value, key: &str) -> CheckResult<BTreeSet<PathBuf>> {
    required_path_array(value, key).map(|items| items.into_iter().collect())
}

fn required_trimmed_comp_configs(value: &toml::Value) -> CheckResult<Vec<TrimmedCompConfig>> {
    let entries = value
        .get("service_side_trimmed_comps")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            CheckError::new("missing array-of-tables config key `service_side_trimmed_comps`")
        })?;
    entries
        .iter()
        .map(|entry| {
            let table = entry.as_table().ok_or_else(|| {
                CheckError::new("`service_side_trimmed_comps` entries must be tables")
            })?;
            Ok(TrimmedCompConfig {
                name: table_string(table, "name")?,
                service_path: table_string(table, "service_path")?.into(),
                kernel_path: table_string(table, "kernel_path")?.into(),
                package: table_string(table, "package")?,
                dependency_key: table_string(table, "dependency_key")?,
            })
        })
        .collect()
}

fn required_frontend_crate_configs(value: &toml::Value) -> CheckResult<Vec<FrontendCrateConfig>> {
    let entries = value
        .get("framev_frontend_crates")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            CheckError::new("missing array-of-tables config key `framev_frontend_crates`")
        })?;
    entries
        .iter()
        .map(|entry| {
            let table = entry.as_table().ok_or_else(|| {
                CheckError::new("`framev_frontend_crates` entries must be tables")
            })?;
            let allowed_service_dependencies = table
                .get("allowed_service_dependencies")
                .and_then(toml::Value::as_array)
                .ok_or_else(|| {
                    CheckError::new(
                        "`framev_frontend_crates` entries must contain `allowed_service_dependencies`",
                    )
                })?
                .iter()
                .map(|value| {
                    value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                        CheckError::new(
                            "`allowed_service_dependencies` entries must be strings",
                        )
                    })
                })
                .collect::<CheckResult<BTreeSet<_>>>()?;
            Ok(FrontendCrateConfig {
                name: table_string(table, "name")?,
                path: table_string(table, "path")?.into(),
                package: table_string(table, "package")?,
                common_package: table_string(table, "common_package")?,
                allowed_service_dependencies,
            })
        })
        .collect()
}

fn table_string(table: &toml::map::Map<String, toml::Value>, key: &str) -> CheckResult<String> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| CheckError::new(format!("config table missing string `{key}`")))
}

fn path_segments(path: &SynPath) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect()
}

fn is_public(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

fn is_exported_macro(item: &syn::ItemMacro) -> bool {
    item.attrs
        .iter()
        .any(|attr| attr.path().is_ident("macro_export"))
}

fn has_macro_export(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .any(|attr| attr.path().is_ident("macro_export"))
}

fn ancestors(path: &str) -> Vec<String> {
    let mut parts = path.split("::").collect::<Vec<_>>();
    let mut out = Vec::new();
    while parts.len() > 1 {
        parts.pop();
        out.push(parts.join("::"));
    }
    out
}

fn is_excluded(path: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|prefix| path.starts_with(prefix))
}

fn is_likely_module_reexport(path: &[String]) -> bool {
    path.last()
        .and_then(|name| name.chars().next())
        .is_some_and(|first| first.is_ascii_lowercase())
}

fn contains_ident(source: &str, ident: &str) -> bool {
    let bytes = source.as_bytes();
    let needle = ident.as_bytes();
    if needle.is_empty() || bytes.len() < needle.len() {
        return false;
    }
    for index in 0..=bytes.len() - needle.len() {
        if &bytes[index..index + needle.len()] != needle {
            continue;
        }
        let before = index.checked_sub(1).map(|i| bytes[i]);
        let after = bytes.get(index + needle.len()).copied();
        if before.is_none_or(|ch| !is_ident_byte(ch)) && after.is_none_or(|ch| !is_ident_byte(ch)) {
            return true;
        }
    }
    false
}

fn is_ident_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn normalize_path(path: &str) -> String {
    path.trim_end_matches('/').replace('\\', "/")
}

fn normalize_relative_path(path: &Path) -> PathBuf {
    let mut output = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                output.pop();
            }
            std::path::Component::CurDir => {}
            std::path::Component::Normal(value) => output.push(value.to_os_string()),
            _ => {}
        }
    }
    output.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use std::{
        process,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    struct TempRepo {
        path: PathBuf,
    }

    impl TempRepo {
        fn new(name: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time must be after Unix epoch")
                .as_nanos();
            let path = env::temp_dir().join(format!(
                "framevm-service-check-{name}-{}-{nanos}",
                process::id()
            ));
            fs::create_dir_all(&path).expect("failed to create temporary repo");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempRepo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn test_config() -> Config {
        Config {
            service_path: PathBuf::from("services/aster-framevm"),
            kernel_src_path: PathBuf::from("kernel/src"),
            facade_path: PathBuf::from("kernel/comps/framevisor-ostd"),
            host_ostd_path: PathBuf::from("ostd"),
            framevisor_backend_device_root: PathBuf::from("kernel/comps/framevisor/src/device"),
            trim_manifest_path: PathBuf::from("tools/framevm-service-check/trim-manifest.toml"),
            component_metadata_path: PathBuf::from("Components.toml"),
            kernel_component_profile: "kernel".to_owned(),
            framevm_component_profile: "framevm".to_owned(),
            source_trim_enforcement: SourceTrimEnforcement::Migration,
            entry_trim_files: BTreeSet::new(),
            forbidden_service_subtrees: Vec::new(),
            service_local_module_aliases: BTreeSet::new(),
            host_only_component_packages: BTreeSet::from(["aster-virtio".to_owned()]),
            framev_common_crate_roots: Vec::new(),
            framev_frontend_crates: Vec::new(),
            service_side_trimmed_comps: Vec::from([TrimmedCompConfig {
                name: "block".to_owned(),
                service_path: PathBuf::from("services/aster-framevm/comps/block"),
                kernel_path: PathBuf::from("kernel/comps/block"),
                package: "aster-framevm-block".to_owned(),
                dependency_key: "aster-block".to_owned(),
            }]),
            excluded_path_prefixes: Vec::new(),
            allowed_provider_facade_paths: BTreeSet::new(),
        }
    }

    fn final_config() -> Config {
        let mut config = test_config();
        config.source_trim_enforcement = SourceTrimEnforcement::Final;
        config.service_local_module_aliases = BTreeSet::from([
            "fd_table".to_owned(),
            "fs_context".to_owned(),
            "rootfs".to_owned(),
            "scheduler".to_owned(),
        ]);
        config
    }

    fn write_retained_pair(
        repo: &TempRepo,
        relative: &str,
        service_source: &str,
        kernel_source: &str,
    ) -> (PathBuf, PathBuf) {
        let service_file = repo
            .path()
            .join("services/aster-framevm/src")
            .join(relative);
        let kernel_file = repo.path().join("kernel/src").join(relative);
        fs::create_dir_all(service_file.parent().unwrap())
            .expect("failed to create service retained fixture directory");
        fs::create_dir_all(kernel_file.parent().unwrap())
            .expect("failed to create kernel retained fixture directory");
        fs::write(&service_file, service_source).expect("failed to write service retained fixture");
        fs::write(&kernel_file, kernel_source).expect("failed to write kernel retained fixture");
        (service_file, kernel_file)
    }

    fn write_trim_manifest(repo: &TempRepo, contents: &str) {
        let manifest_path = repo
            .path()
            .join("tools/framevm-service-check/trim-manifest.toml");
        fs::create_dir_all(manifest_path.parent().unwrap())
            .expect("failed to create trim manifest fixture directory");
        fs::write(manifest_path, contents).expect("failed to write trim manifest fixture");
    }

    fn source_trim_manifest_entry(relative: &str, kind: &str) -> String {
        format!(
            r#"
[[entries]]
service_path = "services/aster-framevm/src/{relative}"
kernel_path = "kernel/src/{relative}"
kind = "{kind}"
reason = "fixture difference"
"#
        )
    }

    fn assert_profile_error(metadata: &str, expected: &str) {
        let repo = TempRepo::new("component-profile");
        fs::write(repo.path().join("Components.toml"), metadata)
            .expect("failed to write metadata fixture");
        let error = validate_component_profiles(repo.path(), &test_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains(expected),
            "expected error containing `{expected}`, got `{}`",
            error.message
        );
    }

    fn write_service_manifest_fixture(repo: &TempRepo, dependencies: &str) {
        let service_dir = repo.path().join("services/aster-framevm");
        fs::create_dir_all(&service_dir).expect("failed to create service manifest directory");
        fs::write(
            service_dir.join("Cargo.toml"),
            format!(
                r#"
[package]
name = "aster-framevm"
version = "0.1.0"
edition = "2024"

[dependencies]
ostd = {{ path = "../../kernel/comps/framevisor-ostd", package = "aster-framevisor-ostd" }}
{dependencies}
"#
            ),
        )
        .expect("failed to write service manifest fixture");
    }

    fn write_cpu_local_boundary_fixture(
        repo: &TempRepo,
        service_source: &str,
        facade_source: &str,
    ) -> PathBuf {
        let service_file = repo.path().join("services/aster-framevm/src/lib.rs");
        fs::create_dir_all(service_file.parent().unwrap())
            .expect("failed to create service source fixture directory");
        fs::write(&service_file, service_source).expect("failed to write service source fixture");

        let comp_file = repo
            .path()
            .join("services/aster-framevm/comps/block/src/lib.rs");
        fs::create_dir_all(comp_file.parent().unwrap())
            .expect("failed to create comp source fixture directory");
        fs::write(comp_file, "").expect("failed to write comp source fixture");

        let facade_file = repo.path().join("kernel/comps/framevisor-ostd/src/lib.rs");
        fs::create_dir_all(facade_file.parent().unwrap())
            .expect("failed to create facade source fixture directory");
        fs::write(facade_file, facade_source).expect("failed to write facade source fixture");

        let cpu_local_file = repo.path().join("kernel/comps/framevisor/src/cpu/local.rs");
        fs::create_dir_all(cpu_local_file.parent().unwrap())
            .expect("failed to create cpu-local source fixture directory");
        fs::write(
            cpu_local_file,
            r#"
impl<T> StaticCpuLocal<T>
where
    T: Send + Sync + 'static,
{}
pub struct CpuLocalGuard<'a, T: Send + Sync + 'static>(&'a T);
impl<T: Send + Sync + 'static> Deref for CpuLocalGuard<'_, T> {}
pub struct CpuLocalRemoteGuard<T: Send + Sync + 'static>(T);
impl<T: Send + Sync + 'static> Deref for CpuLocalRemoteGuard<T> {}
"#,
        )
        .expect("failed to write cpu-local source fixture");

        service_file
    }

    fn common_crate_config() -> Config {
        let mut config = test_config();
        config.framev_common_crate_roots = Vec::from([PathBuf::from("kernel/comps/framev-test")]);
        config
    }

    fn write_common_crate_fixture(repo: &TempRepo, default_members: &[&str], crate_manifest: &str) {
        let root_manifest = format!(
            r#"
[workspace]
members = ["kernel/comps/framev-test"]
default-members = [{}]
"#,
            default_members
                .iter()
                .map(|member| format!("\"{member}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        fs::write(repo.path().join("Cargo.toml"), root_manifest)
            .expect("failed to write root manifest fixture");
        fs::write(
            repo.path().join("Components.toml"),
            r#"
[components]
block = { name = "aster-framevm-block" }
"#,
        )
        .expect("failed to write component metadata fixture");

        let crate_dir = repo.path().join("kernel/comps/framev-test");
        fs::create_dir_all(&crate_dir).expect("failed to create common crate fixture directory");
        fs::write(crate_dir.join("Cargo.toml"), crate_manifest)
            .expect("failed to write common crate manifest fixture");
    }

    fn frontend_crate_config(package: &str, common_package: &str) -> Config {
        let mut config = test_config();
        config.framev_frontend_crates = Vec::from([FrontendCrateConfig {
            name: "test".to_owned(),
            path: PathBuf::from("services/aster-framevm/comps/framev-test"),
            package: package.to_owned(),
            common_package: common_package.to_owned(),
            allowed_service_dependencies: BTreeSet::new(),
        }]);
        config
    }

    fn write_frontend_crate_fixture(repo: &TempRepo, crate_manifest: &str) {
        fs::write(
            repo.path().join("Cargo.toml"),
            r#"
[workspace]
members = ["services/aster-framevm/comps/framev-test"]
default-members = ["services/aster-framevm/comps/framev-test"]
"#,
        )
        .expect("failed to write root manifest fixture");

        let crate_dir = repo.path().join("services/aster-framevm/comps/framev-test");
        fs::create_dir_all(&crate_dir).expect("failed to create frontend crate fixture directory");
        fs::write(crate_dir.join("Cargo.toml"), crate_manifest)
            .expect("failed to write frontend crate manifest fixture");
    }

    fn write_frontend_source_fixture(repo: &TempRepo, source: &str) {
        let src_dir = repo
            .path()
            .join("services/aster-framevm/comps/framev-test/src");
        fs::create_dir_all(&src_dir).expect("failed to create frontend source fixture directory");
        fs::write(src_dir.join("lib.rs"), source).expect("failed to write frontend source fixture");
    }

    fn write_iht_discipline_fixture(repo: &TempRepo, frame_group_comment: &str) {
        let frame_group = repo
            .path()
            .join("kernel/comps/framevisor/src/vm/frame_group.rs");
        fs::create_dir_all(frame_group.parent().unwrap())
            .expect("failed to create frame group fixture directory");
        fs::write(
            &frame_group,
            format!(
                r#"
impl FrameSchedGroup {{
    /// {frame_group_comment}
    pub fn try_pick_inner(&self) -> InnerPick {{
        if self.iht_context.has_deliverable_work() {{
            return InnerPick::Iht(task);
        }}
        if let Some(task) = self.try_pick_service() {{
            return InnerPick::Service(task);
        }}
        InnerPick::NoWork
    }}
}}
"#
            ),
        )
        .expect("failed to write frame group fixture");

        let iht = repo.path().join("kernel/comps/framevisor/src/iht/mod.rs");
        fs::create_dir_all(iht.parent().unwrap()).expect("failed to create IHT fixture directory");
        fs::write(
            &iht,
            r#"
fn drain_device_event(&self) {
    // IHT owns notification/control delivery only. FrameV protocol and device
    // data-path work must become service-owned work after this handoff.
    crate::irq::dispatch_framev_irq_line(vm_id, irq_line, self.id.vcpu_index());

    // Callbacks queued to IHT must be notification-only, bounded control work.
    // Normal FrameV device data paths belong to FrameVM service runtime.
    callback.call();
}
"#,
        )
        .expect("failed to write IHT fixture");

        let irq = repo.path().join("kernel/comps/framevisor/src/irq/mod.rs");
        fs::create_dir_all(irq.parent().unwrap()).expect("failed to create IRQ fixture directory");
        fs::write(
            &irq,
            r#"
fn dispatch_framev_irq_line() {
    // This dispatch is the IHT-side notification/control handoff. Device-class
    // protocol work must be scheduled into the FrameVM service runtime unless
    // a future change adds a bounded fast path.
    let Some(vm) = vm::get_vm_by_id(vm_id) else {
        return;
    };
}
"#,
        )
        .expect("failed to write IRQ fixture");
    }

    fn write_vsock_rx_callback_fixture(repo: &TempRepo, init_source: &str, stream_source: &str) {
        let vsock_dir = repo
            .path()
            .join("services/aster-framevm/src/net/socket/vsock");
        let stream_dir = vsock_dir.join("stream");
        fs::create_dir_all(&stream_dir).expect("failed to create vsock fixture directories");
        fs::write(vsock_dir.join("mod.rs"), init_source)
            .expect("failed to write vsock init fixture");
        fs::write(stream_dir.join("mod.rs"), stream_source)
            .expect("failed to write vsock stream fixture");
    }

    fn write_framevisor_scheduler_layout_fixture(repo: &TempRepo, keep_legacy_file: bool) {
        let task_root = repo.path().join("kernel/comps/framevisor/src/task");
        let scheduler_root = task_root.join("scheduler");
        fs::create_dir_all(&scheduler_root).expect("failed to create scheduler fixture");
        if keep_legacy_file {
            fs::write(task_root.join("scheduler.rs"), "").expect("failed to write legacy file");
        }
        for module in [
            "cpu_scope.rs",
            "info.rs",
            "interrupt.rs",
            "queue.rs",
            "registry.rs",
            "timer.rs",
            "types.rs",
        ] {
            fs::write(scheduler_root.join(module), "").expect("failed to write scheduler module");
        }
        fs::write(
            scheduler_root.join("mod.rs"),
            r#"
mod cpu_scope;
pub mod info;
mod interrupt;
mod queue;
mod registry;
mod timer;
mod types;

pub use registry::inject_scheduler;
pub use timer::enable_preemption_on_cpu;
pub use types::{EnqueueFlags, LocalRunQueue, Scheduler, UpdateFlags};
"#,
        )
        .expect("failed to write scheduler mod fixture");
    }

    fn write_framevisor_ostd_layout_fixture(repo: &TempRepo) {
        let framevisor_src = repo.path().join("kernel/comps/framevisor/src");
        fs::create_dir_all(&framevisor_src).expect("failed to create framevisor fixture");
        for module in [
            "arch", "boot", "console", "irq", "log", "panic", "power", "prelude", "timer", "user",
        ] {
            fs::write(framevisor_src.join(format!("{module}.rs")), "")
                .expect("failed to write OSTD-shaped framevisor file module");
        }
        for module in [
            "cpu", "device", "iht", "mm", "sync", "task", "util", "vm", "vsock",
        ] {
            let module_dir = framevisor_src.join(module);
            fs::create_dir_all(&module_dir)
                .expect("failed to create OSTD-shaped framevisor tree module");
            fs::write(module_dir.join("mod.rs"), "")
                .expect("failed to write OSTD-shaped framevisor tree module");
        }
    }

    #[test]
    fn rejects_host_only_package_in_framevm_profile() {
        assert_profile_error(
            r#"
[components]
block = { name = "aster-framevm-block" }
virtio = { name = "aster-virtio" }

[profiles]
kernel = ["aster-virtio"]
framevm = ["aster-framevm-block", "aster-virtio"]
"#,
            "must not include host-only package `aster-virtio`",
        );
    }

    #[test]
    fn rejects_dependency_alias_in_framevm_profile() {
        assert_profile_error(
            r#"
[components]
block = { name = "aster-framevm-block" }

[profiles]
kernel = ["aster-framevm-block"]
framevm = ["aster-block"]
"#,
            "unknown package `aster-block`",
        );
    }

    #[test]
    fn rejects_missing_frontend_package_in_framevm_profile() {
        let repo = TempRepo::new("missing-frontend-profile-entry");
        fs::write(
            repo.path().join("Components.toml"),
            r#"
[components]
block = { name = "aster-framevm-block" }
bus = { name = "framev-bus" }

[profiles]
kernel = ["aster-framevm-block"]
framevm = ["aster-framevm-block"]
"#,
        )
        .expect("failed to write metadata fixture");

        let mut config = test_config();
        config.framev_frontend_crates = Vec::from([FrontendCrateConfig {
            name: "bus".to_owned(),
            path: PathBuf::from("services/aster-framevm/comps/framev-bus"),
            package: "framev-bus".to_owned(),
            common_package: "framev-device".to_owned(),
            allowed_service_dependencies: BTreeSet::new(),
        }]);

        let error = validate_component_profiles(repo.path(), &config).expect_err("fixture fails");
        assert!(
            error.message.contains("missing FrameV frontend package"),
            "expected missing frontend profile diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_unknown_empty_and_duplicate_framevm_profile_entries() {
        assert_profile_error(
            r#"
[components]
block = { name = "aster-framevm-block" }

[profiles]
kernel = ["aster-framevm-block"]
"#,
            "missing component profile `framevm`",
        );
        assert_profile_error(
            r#"
[components]
block = { name = "aster-framevm-block" }

[profiles]
kernel = ["aster-framevm-block"]
framevm = ["aster-framevm-block", "missing-package"]
"#,
            "unknown package `missing-package`",
        );
        assert_profile_error(
            r#"
[components]
block = { name = "aster-framevm-block" }

[profiles]
kernel = ["aster-framevm-block"]
framevm = []
"#,
            "must not be empty",
        );
        assert_profile_error(
            r#"
[components]
block = { name = "aster-framevm-block" }

[profiles]
kernel = ["aster-framevm-block"]
framevm = ["aster-framevm-block", "aster-framevm-block"]
"#,
            "duplicate package `aster-framevm-block`",
        );
    }

    #[test]
    fn rejects_common_crate_missing_default_member_entry() {
        let repo = TempRepo::new("common-default-member");
        write_common_crate_fixture(
            &repo,
            &[],
            r#"
[package]
name = "framev-test-common"
version = "0.1.0"
edition = "2024"

[dependencies]
framev-device = { workspace = true }

[lints]
workspace = true
"#,
        );

        let error = validate_framev_common_crates(repo.path(), &common_crate_config())
            .expect_err("fixture must fail");
        assert!(
            error
                .message
                .contains("must be in workspace default-members"),
            "expected missing default-member diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_framev_common_redefining_device_model_semantics() {
        let repo = TempRepo::new("common-redefines-device-model");
        write_common_crate_fixture(
            &repo,
            &["kernel/comps/framev-test"],
            r#"
[package]
name = "framev-test-common"
version = "0.1.0"
edition = "2024"

[dependencies]
framev-device = { workspace = true }

[lints]
workspace = true
"#,
        );
        let src_dir = repo.path().join("kernel/comps/framev-test/src");
        fs::create_dir_all(&src_dir).expect("failed to create common source fixture");
        fs::write(
            src_dir.join("lib.rs"),
            r#"
pub struct FrameVDeviceDescriptor;
"#,
        )
        .expect("failed to write common source fixture");

        let error = validate_framev_common_crates(repo.path(), &common_crate_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("consume it from `framev-device`"),
            "expected common model redefinition diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_service_source_importing_host_authority() {
        let repo = TempRepo::new("host-source-import");
        let source_path = repo.path().join("services/aster-framevm/src/escape.rs");
        fs::create_dir_all(source_path.parent().unwrap())
            .expect("failed to create service source fixture directory");
        fs::write(
            &source_path,
            r#"
fn escape() {
    let _ = aster_framevisor::vm::list_vms();
    let _ = host_ostd::task::Task::current();
}
"#,
        )
        .expect("failed to write service source fixture");

        let error = check_banned_service_refs(&[source_path]).expect_err("fixture must fail");
        assert!(
            error.message.contains("forbidden service reference"),
            "expected forbidden service reference diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_retained_file_without_kernel_counterpart() {
        let repo = TempRepo::new("missing-kernel-counterpart");
        let source_path = repo.path().join("services/aster-framevm/src/fs/missing.rs");
        fs::create_dir_all(source_path.parent().unwrap())
            .expect("failed to create retained source fixture directory");
        fs::write(&source_path, "fn retained() {}\n").expect("failed to write retained fixture");

        let error = check_retained_layout(repo.path(), &final_config(), &[source_path])
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("no corresponding kernel source"),
            "expected missing kernel counterpart diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_undeclared_retained_diff() {
        let repo = TempRepo::new("undeclared-retained-diff");
        let (service_file, _) = write_retained_pair(
            &repo,
            "fs/file.rs",
            "fn retained() {}\n",
            "fn retained2() {}\n",
        );

        let error = check_retained_differences(
            repo.path(),
            &final_config(),
            &[service_file],
            &TrimManifest::default(),
        )
        .expect_err("fixture must fail");
        assert!(
            error.message.contains("without a trim manifest entry"),
            "expected undeclared diff diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_stale_trim_manifest_entry() {
        let repo = TempRepo::new("stale-trim-manifest");
        write_retained_pair(
            &repo,
            "fs/file.rs",
            "fn retained() {}\n",
            "fn retained() {}\n",
        );
        write_trim_manifest(
            &repo,
            &source_trim_manifest_entry("fs/file.rs", "mechanical-adaptation"),
        );

        let error =
            validate_trim_manifest(repo.path(), &test_config()).expect_err("fixture must fail");
        assert!(
            error.message.contains("stale"),
            "expected stale manifest diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_invalid_trim_manifest_kind() {
        let repo = TempRepo::new("invalid-trim-kind");
        write_retained_pair(
            &repo,
            "fs/file.rs",
            "fn retained() {}\n",
            "fn retained2() {}\n",
        );
        write_trim_manifest(&repo, &source_trim_manifest_entry("fs/file.rs", "rewrite"));

        let error =
            validate_trim_manifest(repo.path(), &test_config()).expect_err("fixture must fail");
        assert!(
            error.message.contains("not allowed"),
            "expected invalid manifest kind diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_retained_structural_shape_change() {
        let repo = TempRepo::new("retained-shape-change");
        let (service_file, _) = write_retained_pair(
            &repo,
            "fs/file.rs",
            "fn retained(value: usize) -> usize { value }\n",
            "fn retained() -> usize { 0 }\n",
        );
        write_trim_manifest(
            &repo,
            &source_trim_manifest_entry("fs/file.rs", "mechanical-adaptation"),
        );
        let manifest =
            validate_trim_manifest(repo.path(), &test_config()).expect("manifest should parse");

        let error =
            check_retained_differences(repo.path(), &final_config(), &[service_file], &manifest)
                .expect_err("fixture must fail");
        assert!(
            error.message.contains("changes shape"),
            "expected structural shape diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn accepts_provider_substitution_structural_shape_change() {
        let repo = TempRepo::new("provider-substitution-shape-change");
        let (service_file, _) = write_retained_pair(
            &repo,
            "net/socket/vsock/transport/mod.rs",
            "//! provider docs\nfn framev_transport() {}\n",
            "//! kernel docs\nfn virtio_transport() {}\n",
        );
        write_trim_manifest(
            &repo,
            &source_trim_manifest_entry(
                "net/socket/vsock/transport/mod.rs",
                "provider-substitution",
            ),
        );
        let manifest =
            validate_trim_manifest(repo.path(), &test_config()).expect("manifest should parse");

        check_retained_differences(repo.path(), &test_config(), &[service_file], &manifest)
            .expect("provider substitution should allow structural source differences");
    }

    #[test]
    fn rejects_retained_comment_text_change() {
        let repo = TempRepo::new("retained-comment-change");
        let (service_file, _) = write_retained_pair(
            &repo,
            "fs/file.rs",
            "/// Service-local wording.\nfn retained() -> usize { 0 }\n",
            "/// Kernel wording.\nfn retained() -> usize { 0 }\n",
        );
        write_trim_manifest(
            &repo,
            &source_trim_manifest_entry("fs/file.rs", "mechanical-adaptation"),
        );
        let manifest =
            validate_trim_manifest(repo.path(), &test_config()).expect("manifest should parse");

        let error =
            check_retained_differences(repo.path(), &final_config(), &[service_file], &manifest)
                .expect_err("fixture must fail");
        assert!(
            error.message.contains("changes comments"),
            "expected retained comment diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_forbidden_retained_module_path_alias() {
        let repo = TempRepo::new("retained-path-alias");
        let lib_path = repo.path().join("services/aster-framevm/src/lib.rs");
        fs::create_dir_all(lib_path.parent().unwrap())
            .expect("failed to create lib fixture directory");
        fs::write(
            &lib_path,
            r#"
#[path = "service/rootfs.rs"]
mod fs;
"#,
        )
        .expect("failed to write lib fixture");

        let error = check_final_source_layout(repo.path(), &final_config(), &[lib_path])
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("`#[path = ...]` alias"),
            "expected retained path alias diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_service_local_retained_module_alias() {
        let repo = TempRepo::new("service-local-module-alias");
        let lib_path = repo.path().join("services/aster-framevm/src/lib.rs");
        fs::create_dir_all(lib_path.parent().unwrap())
            .expect("failed to create lib fixture directory");
        fs::write(&lib_path, "mod fd_table;\n").expect("failed to write lib fixture");

        let mut config = final_config();
        config
            .service_local_module_aliases
            .insert("fd_table".to_owned());
        let error = check_final_source_layout(repo.path(), &config, &[lib_path])
            .expect_err("fixture must fail");
        assert!(
            error
                .message
                .contains("service-local retained module alias"),
            "expected retained module alias diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_guest_visible_raw_console_file() {
        let repo = TempRepo::new("raw-console-file");
        let service_file = repo
            .path()
            .join("services/aster-framevm/src/device/tty/mod.rs");
        fs::create_dir_all(service_file.parent().unwrap())
            .expect("failed to create service tty fixture directory");
        fs::write(&service_file, "struct ConsoleFile;\n")
            .expect("failed to write raw console fixture");

        let error = check_final_framevm_interactive_shell_policy(
            repo.path(),
            &final_config(),
            &[service_file],
        )
        .expect_err("fixture must fail");
        assert!(
            error.message.contains("raw guest-visible console"),
            "expected raw console diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_rootfs_init_stdin_sniffing() {
        let repo = TempRepo::new("rootfs-stdin-sniffing");
        let rootfs_image_path = repo
            .path()
            .join("test/initramfs/nix/framevm-rootfs-image.nix");
        fs::create_dir_all(rootfs_image_path.parent().unwrap())
            .expect("failed to create rootfs fixture directory");
        fs::write(
            &rootfs_image_path,
            "static int run_initial_script_from_stdin(void) { return 0; }\n",
        )
        .expect("failed to write rootfs fixture");

        let error = check_final_framevm_interactive_shell_policy(repo.path(), &final_config(), &[])
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("must not sniff stdin"),
            "expected stdin sniffing diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_framevm_host_test_console_stdin_selection() {
        let repo = TempRepo::new("host-test-stdin-selection");
        let script = repo.path().join("test/initramfs/src/framevm/boot.sh");
        fs::create_dir_all(script.parent().unwrap())
            .expect("failed to create FrameVM script fixture directory");
        fs::write(
            &script,
            "printf 'exit\\n' | framevmctl run --drive file=/framevm/rootfs.ext2\n",
        )
        .expect("failed to write FrameVM script fixture");

        let error = check_final_framevm_interactive_shell_policy(repo.path(), &final_config(), &[])
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("through framevmctl --append"),
            "expected host stdin selection diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_host_only_procfs_surface() {
        let repo = TempRepo::new("host-only-procfs");
        let procfs_file = repo
            .path()
            .join("services/aster-framevm/src/fs/fs_impls/procfs/pid/mod.rs");
        fs::create_dir_all(procfs_file.parent().unwrap())
            .expect("failed to create procfs fixture directory");
        fs::write(&procfs_file, "mod cgroup;\n").expect("failed to write procfs fixture");

        let error = check_final_framevm_interactive_shell_policy(
            repo.path(),
            &final_config(),
            &[procfs_file],
        )
        .expect_err("fixture must fail");
        assert!(
            error.message.contains("guest process inspection"),
            "expected procfs surface diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_retained_syscall_parent_path_escape() {
        let repo = TempRepo::new("syscall-path-escape");
        let (service_file, _) = write_retained_pair(
            &repo,
            "syscall/mod.rs",
            r#"
#[path = "../service/syscall/getrlimit.rs"]
mod getrlimit;
"#,
            "mod getrlimit;\n",
        );

        let error = check_retained_path_attrs(repo.path(), &final_config(), &[service_file])
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("does not declare the same path"),
            "expected retained syscall path escape diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_service_manifest_direct_host_dependencies() {
        let repo = TempRepo::new("service-host-dependencies");
        write_service_manifest_fixture(&repo, "host-ostd = { workspace = true }");
        let error =
            validate_service_manifest(repo.path(), &test_config()).expect_err("fixture must fail");
        assert!(
            error.message.contains("host-ostd"),
            "expected host-ostd dependency diagnostic, got `{}`",
            error.message
        );

        let repo = TempRepo::new("service-framevisor-dependency");
        write_service_manifest_fixture(&repo, "aster-framevisor = { workspace = true }");
        let error =
            validate_service_manifest(repo.path(), &test_config()).expect_err("fixture must fail");
        assert!(
            error.message.contains("aster-framevisor"),
            "expected aster-framevisor dependency diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_framevm_loaded_dynamic_cpu_local_allocator_api() {
        let repo = TempRepo::new("dynamic-cpu-local-api");
        let service_file = write_cpu_local_boundary_fixture(
            &repo,
            "fn uses_forbidden_api() { let _ = CpuLocalBox::new; }",
            "pub mod cpu { pub mod local {} }",
        );

        let error = check_framevm_cpu_local_boundary(repo.path(), &test_config(), &[service_file])
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("CPU-local allocation APIs"),
            "expected CPU-local boundary diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_framevisor_ostd_host_cpu_local_reexport() {
        let repo = TempRepo::new("host-cpu-local-reexport");
        let service_file =
            write_cpu_local_boundary_fixture(&repo, "", "pub use host_ostd::cpu::local::*;");

        let error = check_framevm_cpu_local_boundary(repo.path(), &test_config(), &[service_file])
            .expect_err("fixture must fail");
        assert!(
            error
                .message
                .contains("must provide FrameVM CPU-local storage"),
            "expected facade CPU-local diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_static_cpu_local_unlocked_reference_without_sync_bound() {
        let repo = TempRepo::new("static-cpu-local-sync-bound");
        let service_file =
            write_cpu_local_boundary_fixture(&repo, "", "pub mod cpu { pub mod local {} }");
        let cpu_local_file = repo.path().join("kernel/comps/framevisor/src/cpu/local.rs");
        fs::write(
            cpu_local_file,
            r#"
impl<T> StaticCpuLocal<T>
where
    T: Send + 'static,
{}
pub struct CpuLocalGuard<'a, T: Send + 'static>(&'a T);
impl<T: Send + 'static> Deref for CpuLocalGuard<'_, T> {}
pub struct CpuLocalRemoteGuard<T: Send + 'static>(T);
impl<T: Send + 'static> Deref for CpuLocalRemoteGuard<T> {}
"#,
        )
        .expect("failed to write invalid cpu-local source fixture");

        let error = check_framevm_cpu_local_boundary(repo.path(), &test_config(), &[service_file])
            .expect_err("fixture must fail");
        assert!(
            error
                .message
                .contains("static CPU-local references must be exposed only for `Sync`"),
            "expected CPU-local Sync-bound diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_service_manifest_direct_host_kernel_comp_dependency() {
        let repo = TempRepo::new("service-host-kernel-comp");
        write_service_manifest_fixture(&repo, "aster-virtio = { workspace = true }");

        let error =
            validate_service_manifest(repo.path(), &test_config()).expect_err("fixture fails");
        assert!(
            error
                .message
                .contains("host-only kernel comp `aster-virtio`"),
            "expected host kernel comp dependency diagnostic, got `{}`",
            error.message
        );

        let repo = TempRepo::new("service-host-kernel-comp-by-aster-prefix");
        write_service_manifest_fixture(&repo, "aster-pci = { workspace = true }");

        let error =
            validate_service_manifest(repo.path(), &test_config()).expect_err("fixture fails");
        assert!(
            error.message.contains("host-only kernel comp `aster-pci`"),
            "expected direct aster comp dependency diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_legacy_framev_package_dependency() {
        let repo = TempRepo::new("legacy-framev-package");
        fs::write(
            repo.path().join("Cargo.toml"),
            r#"
[workspace]
members = ["services/aster-framevm/comps/framev-test"]
default-members = ["services/aster-framevm/comps/framev-test"]
"#,
        )
        .expect("failed to write root manifest fixture");

        let manifest_path = repo
            .path()
            .join("services/aster-framevm/comps/framev-test/Cargo.toml");
        fs::create_dir_all(manifest_path.parent().unwrap())
            .expect("failed to create legacy package fixture directory");
        fs::write(
            &manifest_path,
            r#"
[package]
name = "framev-test-frontend"
version = "0.1.0"
edition = "2024"

[dependencies]
aster-framevsock = { workspace = true }
"#,
        )
        .expect("failed to write legacy package manifest fixture");

        let error =
            validate_legacy_framev_package_absence(repo.path()).expect_err("fixture must fail");
        assert!(
            error.message.contains("removed legacy FrameV package"),
            "expected legacy package diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_legacy_framev_marker_in_service_check_config() {
        let repo = TempRepo::new("legacy-service-check-config");
        let config_path = repo.path().join("tools/framevm-service-check/config.toml");
        fs::create_dir_all(config_path.parent().unwrap())
            .expect("failed to create config fixture directory");
        fs::write(
            &config_path,
            r#"
forbidden_high_level_framev_modules = ["framev_sock"]
"#,
        )
        .expect("failed to write config fixture");

        let error = read_config(
            repo.path(),
            Path::new("tools/framevm-service-check/config.toml"),
        )
        .expect_err("fixture must fail");
        assert!(
            error.message.contains("removed legacy FrameV marker"),
            "expected legacy service-check config marker diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_service_check_config_mixing_legacy_and_canonical_framev_names() {
        let repo = TempRepo::new("mixed-framev-config");
        let config_path = repo.path().join("tools/framevm-service-check/config.toml");
        fs::create_dir_all(config_path.parent().unwrap())
            .expect("failed to create config fixture directory");
        fs::write(
            &config_path,
            r#"
excluded_path_prefixes = ["framev_sock", "framev-sock-common"]
"#,
        )
        .expect("failed to write config fixture");

        let error = read_config(
            repo.path(),
            Path::new("tools/framevm-service-check/config.toml"),
        )
        .expect_err("fixture must fail");
        assert!(
            error.message.contains("removed legacy FrameV marker"),
            "expected mixed legacy/canonical config diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_trimmed_comp_dependency_on_host_only_kernel_comp() {
        let repo = TempRepo::new("trimmed-comp-host-only");
        fs::write(
            repo.path().join("Cargo.toml"),
            r#"
[workspace]
members = ["services/aster-framevm/comps/block"]
default-members = ["services/aster-framevm/comps/block"]
"#,
        )
        .expect("failed to write root manifest fixture");
        write_service_manifest_fixture(
            &repo,
            r#"aster-block = { path = "comps/block", package = "aster-framevm-block" }"#,
        );
        fs::create_dir_all(repo.path().join("kernel/comps/block/src"))
            .expect("failed to create kernel comp fixture");
        fs::write(repo.path().join("kernel/comps/block/src/lib.rs"), "")
            .expect("failed to write kernel comp fixture");
        let comp_dir = repo.path().join("services/aster-framevm/comps/block");
        fs::create_dir_all(comp_dir.join("src")).expect("failed to create comp fixture");
        fs::write(comp_dir.join("src/lib.rs"), "").expect("failed to write comp source fixture");
        fs::write(
            comp_dir.join("Cargo.toml"),
            r#"
[package]
name = "aster-framevm-block"
version = "0.1.0"
edition = "2024"

[dependencies]
ostd = { package = "aster-framevisor-ostd", workspace = true }
aster-virtio = { workspace = true }

[lints]
workspace = true
"#,
        )
        .expect("failed to write comp manifest fixture");

        let error = validate_trimmed_comp_manifests(repo.path(), &test_config())
            .expect_err("fixture fails");
        assert!(
            error.message.contains("aster-virtio"),
            "expected host-only comp dependency diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_common_crate_dependency_on_ostd_or_component() {
        let repo = TempRepo::new("common-forbidden-dependency");
        write_common_crate_fixture(
            &repo,
            &["kernel/comps/framev-test"],
            r#"
[package]
name = "framev-test-common"
version = "0.1.0"
edition = "2024"

[dependencies]
framev-device = { workspace = true }
ostd = { workspace = true }

[lints]
workspace = true
"#,
        );

        let error = validate_framev_common_crates(repo.path(), &common_crate_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("forbidden package `ostd`"),
            "expected forbidden dependency diagnostic, got `{}`",
            error.message
        );

        let repo = TempRepo::new("common-forbidden-component");
        write_common_crate_fixture(
            &repo,
            &["kernel/comps/framev-test"],
            r#"
[package]
name = "framev-test-common"
version = "0.1.0"
edition = "2024"

[dependencies]
component = { workspace = true }
framev-device = { workspace = true }

[lints]
workspace = true
"#,
        );

        let error = validate_framev_common_crates(repo.path(), &common_crate_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("forbidden package `component`"),
            "expected forbidden dependency diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn accepts_frontend_crate_dependency_shape() {
        let repo = TempRepo::new("frontend-dependencies-ok");
        write_frontend_crate_fixture(
            &repo,
            r#"
[package]
name = "framev-test-frontend"
version = "0.1.0"
edition = "2024"

[dependencies]
component = { workspace = true }
framev-bus = { workspace = true }
framev-test-common = { workspace = true }

[lints]
workspace = true
"#,
        );

        validate_framev_frontend_crates(
            repo.path(),
            &frontend_crate_config("framev-test-frontend", "framev-test-common"),
        )
        .expect("valid frontend dependency shape should pass");
    }

    #[test]
    fn rejects_concrete_frontend_direct_ostd_facade_dependency() {
        let repo = TempRepo::new("frontend-direct-ostd");
        write_frontend_crate_fixture(
            &repo,
            r#"
[package]
name = "framev-test-frontend"
version = "0.1.0"
edition = "2024"

[dependencies]
framev-bus = { workspace = true }
framev-test-common = { workspace = true }
ostd = { package = "aster-framevisor-ostd", workspace = true }

[lints]
workspace = true
"#,
        );

        let error = validate_framev_frontend_crates(
            repo.path(),
            &frontend_crate_config("framev-test-frontend", "framev-test-common"),
        )
        .expect_err("fixture must fail");
        assert!(
            error.message.contains("not directly on the OSTD facade"),
            "expected direct OSTD facade diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_frontend_to_frontend_dependency() {
        let repo = TempRepo::new("frontend-to-frontend");
        write_frontend_crate_fixture(
            &repo,
            r#"
[package]
name = "framev-test-frontend"
version = "0.1.0"
edition = "2024"

[dependencies]
framev-bus = { workspace = true }
framev-other-frontend = { workspace = true }
framev-test-common = { workspace = true }

[lints]
workspace = true
"#,
        );

        let error = validate_framev_frontend_crates(
            repo.path(),
            &frontend_crate_config("framev-test-frontend", "framev-test-common"),
        )
        .expect_err("fixture must fail");
        assert!(
            error
                .message
                .contains("must not depend on another frontend"),
            "expected frontend-to-frontend diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_unallowlisted_frontend_service_dependency() {
        let repo = TempRepo::new("frontend-service-dependency");
        write_frontend_crate_fixture(
            &repo,
            r#"
[package]
name = "framev-test-frontend"
version = "0.1.0"
edition = "2024"

[dependencies]
aster-block = { package = "aster-framevm-block", workspace = true }
framev-bus = { workspace = true }
framev-test-common = { workspace = true }

[lints]
workspace = true
"#,
        );

        let error = validate_framev_frontend_crates(
            repo.path(),
            &frontend_crate_config("framev-test-frontend", "framev-test-common"),
        )
        .expect_err("fixture must fail");
        assert!(
            error.message.contains("not allowlisted"),
            "expected frontend allowlist diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_frontend_dependency_on_backend_package() {
        let repo = TempRepo::new("frontend-backend-dependency");
        write_frontend_crate_fixture(
            &repo,
            r#"
[package]
name = "framev-test-frontend"
version = "0.1.0"
edition = "2024"

[dependencies]
framev-bus = { workspace = true }
framev-test-backend = { workspace = true }
framev-test-common = { workspace = true }

[lints]
workspace = true
"#,
        );

        let error = validate_framev_frontend_crates(
            repo.path(),
            &frontend_crate_config("framev-test-frontend", "framev-test-common"),
        )
        .expect_err("fixture must fail");
        assert!(
            error.message.contains("forbidden backend package"),
            "expected backend dependency diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_concrete_frontend_descriptor_parsing() {
        let repo = TempRepo::new("frontend-descriptor-parsing");
        write_frontend_source_fixture(
            &repo,
            r#"
use framev_device::FrameVDeviceDescriptor;

fn init(value: &str) {
    let _ = FrameVDeviceDescriptor::decode_boot_arg(value);
}
"#,
        );

        let error = validate_framev_frontend_source_boundaries(
            repo.path(),
            &frontend_crate_config("framev-test-frontend", "framev-test-common"),
        )
        .expect_err("fixture must fail");
        assert!(
            error.message.contains("device handles from framev-bus"),
            "expected descriptor boundary diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_frontend_iht_callback_dependency() {
        let repo = TempRepo::new("frontend-iht-callback");
        write_frontend_source_fixture(
            &repo,
            r#"
fn init() {
    framev_sock::install_rx_callback(|| {});
}
"#,
        );

        let error = validate_framev_frontend_source_boundaries(
            repo.path(),
            &frontend_crate_config("framev-test-frontend", "framev-test-common"),
        )
        .expect_err("fixture must fail");
        assert!(
            error
                .message
                .contains("legacy high-level OSTD FrameV facades"),
            "expected IHT callback boundary diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_frontend_iht_internal_dependency() {
        let repo = TempRepo::new("frontend-iht-internal");
        write_frontend_source_fixture(
            &repo,
            r#"
fn init(ctx: IhtContext) {
    let _ = ctx;
}
"#,
        );

        let error = validate_framev_frontend_source_boundaries(
            repo.path(),
            &frontend_crate_config("framev-test-frontend", "framev-test-common"),
        )
        .expect_err("fixture must fail");
        assert!(
            error.message.contains("must not depend on IHT"),
            "expected IHT internal boundary diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_framev_bus_iht_or_legacy_facade_dependency() {
        let repo = TempRepo::new("bus-iht-boundary");
        let src_dir = repo
            .path()
            .join("services/aster-framevm/comps/framev-test/src");
        fs::create_dir_all(&src_dir).expect("failed to create bus source fixture directory");
        fs::write(
            src_dir.join("lib.rs"),
            r#"
fn init(ctx: IhtContext) {
    let _ = ctx;
}
"#,
        )
        .expect("failed to write bus source fixture");

        let error = validate_framev_bus_source_boundary(
            repo.path(),
            &frontend_crate_config("framev-bus", "framev-device"),
        )
        .expect_err("fixture must fail");
        assert!(
            error.message.contains("transport discovery/binding layer"),
            "expected framev-bus boundary diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_framev_backend_workspace_package() {
        let repo = TempRepo::new("backend-package");
        fs::write(
            repo.path().join("Cargo.toml"),
            r#"
[workspace]
members = ["kernel/comps/framev-test-backend"]
default-members = ["kernel/comps/framev-test-backend"]
"#,
        )
        .expect("failed to write root manifest fixture");
        fs::write(
            repo.path().join("Components.toml"),
            r#"
[components]
bus = { name = "framev-bus" }
"#,
        )
        .expect("failed to write component metadata fixture");
        let backend_dir = repo.path().join("kernel/comps/framev-test-backend");
        fs::create_dir_all(&backend_dir).expect("failed to create backend package fixture");
        fs::write(
            backend_dir.join("Cargo.toml"),
            r#"
[package]
name = "framev-test-backend"
version = "0.1.0"
edition = "2024"
"#,
        )
        .expect("failed to write backend package manifest fixture");
        fs::create_dir_all(repo.path().join("kernel/comps/framevisor/src/device"))
            .expect("failed to create backend device root fixture");
        fs::write(
            repo.path()
                .join("kernel/comps/framevisor/src/device/mod.rs"),
            "",
        )
        .expect("failed to write backend device mod fixture");

        let error = validate_framevisor_backend_placement(repo.path(), &test_config())
            .expect_err("fixture must fail");
        assert!(
            error
                .message
                .contains("forbidden FrameVM-loaded backend package"),
            "expected backend package diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_service_first_frame_sched_group_pick() {
        let repo = TempRepo::new("frame-sched-group");
        let file = repo
            .path()
            .join("kernel/comps/framevisor/src/vm/frame_group.rs");
        fs::create_dir_all(file.parent().unwrap()).expect("failed to create frame group fixture");
        fs::write(
            &file,
            r#"
impl FrameSchedGroup {
    /// IHT-first is part of the FrameSchedGroup contract. Do not reverse it.
    pub fn try_pick_inner(&self) -> InnerPick {
        if let Some(task) = self.try_pick_service() {
            return InnerPick::Service(task);
        }
        if self.iht_context.has_deliverable_work() {
            return InnerPick::Iht(task);
        }
        InnerPick::NoWork
    }
}
"#,
        )
        .expect("failed to write frame group fixture");

        let error =
            validate_frame_sched_group_contract(repo.path()).expect_err("fixture must fail");
        assert!(
            error.message.contains("must remain IHT-first"),
            "expected IHT-first diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_missing_iht_callback_discipline_comment() {
        let repo = TempRepo::new("iht-discipline-comment");
        write_iht_discipline_fixture(
            &repo,
            "IHT-first is part of the FrameSchedGroup contract. Do not reverse it.",
        );

        let error =
            validate_iht_callback_discipline_comments(repo.path()).expect_err("fixture must fail");
        assert!(
            error.message.contains("notification/control"),
            "expected callback-discipline comment diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_iht_direct_device_data_path_handler() {
        let repo = TempRepo::new("iht-direct-data-path");
        let iht_path = repo.path().join("kernel/comps/framevisor/src/iht/mod.rs");
        fs::create_dir_all(iht_path.parent().unwrap())
            .expect("failed to create IHT fixture directory");
        fs::write(
            &iht_path,
            r#"
fn drain_device_event() {
    handle_block_request();
}
"#,
        )
        .expect("failed to write IHT fixture");

        let error =
            validate_iht_has_no_direct_device_data_path(repo.path()).expect_err("fixture fails");
        assert!(
            error
                .message
                .contains("must not run FrameV device data-path"),
            "expected direct IHT data-path diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_legacy_framev_sock_direct_rx_callback() {
        let repo = TempRepo::new("legacy-vsock-rx-callback");
        write_vsock_rx_callback_fixture(
            &repo,
            r#"
fn init() {
    ostd::framev_sock::install_rx_callback(stream::handle_rx_notification).unwrap();
}
"#,
            r#"
fn handle_rx_notification() {
    listen::drain_inbound_requests();
}
"#,
        );

        let error = check_framev_sock_rx_callback_boundary(repo.path(), &test_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("direct FrameV-sock RX data-path"),
            "expected direct RX callback diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_parallel_service_local_softirq_framework() {
        let repo = TempRepo::new("parallel-softirq-framework");
        let source_path = repo.path().join("services/aster-framevm/src/softirq.rs");
        fs::create_dir_all(source_path.parent().unwrap())
            .expect("failed to create service source fixture directory");
        fs::write(
            &source_path,
            r#"
struct Taskless;
"#,
        )
        .expect("failed to write service source fixture");

        let error =
            check_no_parallel_softirq_framework(repo.path(), &test_config(), &[source_path])
                .expect_err("fixture must fail");
        assert!(
            error
                .message
                .contains("service-local softirq/taskless framework"),
            "expected parallel softirq framework diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_framevisor_scheduler_legacy_single_file_layout() {
        let repo = TempRepo::new("legacy-scheduler-layout");
        write_framevisor_scheduler_layout_fixture(&repo, true);

        let error =
            validate_framevisor_task_scheduler_layout(repo.path()).expect_err("fixture must fail");
        assert!(
            error.message.contains("responsibility-focused submodules"),
            "expected scheduler layout diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_framevisor_kernel_upper_half_module() {
        let repo = TempRepo::new("framevisor-upper-half-module");
        write_framevisor_ostd_layout_fixture(&repo);
        fs::create_dir_all(repo.path().join("kernel/comps/framevisor/src/fs"))
            .expect("failed to create forbidden upper-half fixture");
        fs::write(
            repo.path().join("kernel/comps/framevisor/src/fs/mod.rs"),
            "",
        )
        .expect("failed to write forbidden upper-half fixture");

        let error = validate_framevisor_ostd_style_module_boundaries(repo.path())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("kernel upper-half module `fs`"),
            "expected upper-half module diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_framevisor_top_level_device_backend_file() {
        let repo = TempRepo::new("framevisor-top-level-device");
        write_framevisor_ostd_layout_fixture(&repo);
        fs::write(repo.path().join("kernel/comps/framevisor/src/block.rs"), "")
            .expect("failed to write forbidden top-level backend fixture");

        let error = validate_framevisor_ostd_style_module_boundaries(repo.path())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("src/device/**"),
            "expected device module diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_host_management_facade_export() {
        let repo = TempRepo::new("host-management-facade-export");
        let facade_lib = repo.path().join("kernel/comps/framevisor-ostd/src/lib.rs");
        fs::create_dir_all(facade_lib.parent().unwrap())
            .expect("failed to create facade fixture directory");
        fs::write(
            &facade_lib,
            r#"
pub mod vm {
    pub use aster_framevisor::vm::list_framevms;
}
"#,
        )
        .expect("failed to write facade fixture");

        let error = validate_framevisor_ostd_host_management_absence(repo.path(), &test_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("host VM-management"),
            "expected host-management facade diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_service_direct_low_level_framev_primitive_use() {
        let repo = TempRepo::new("direct-ostd-framev");
        let source_path = repo
            .path()
            .join("services/aster-framevm/src/framev_escape.rs");
        fs::create_dir_all(source_path.parent().unwrap())
            .expect("failed to create service source fixture directory");
        fs::write(
            &source_path,
            r#"
fn escape() {
    let _ = ostd::framev::devices_boot_arg();
}
"#,
        )
        .expect("failed to write service source fixture");

        let error =
            check_low_level_framev_usage_boundary(repo.path(), &test_config(), &[source_path])
                .expect_err("fixture must fail");
        assert!(
            error.message.contains("only `framev-bus`"),
            "expected low-level FrameV boundary diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_non_framev_facade_shape_mismatch() {
        let mut used = UsedOstd::default();
        used.paths.insert("task::spawn".to_owned());

        let mut facade_api = PublicApi::default();
        facade_api.exact.insert(
            "task::spawn".to_owned(),
            Shape::Function(FunctionShape {
                generics: Vec::new(),
                inputs: Vec::from(["fn()".to_owned()]),
                output: Some("()".to_owned()),
            }),
        );

        let mut host_api = PublicApi::default();
        host_api.exact.insert(
            "task::spawn".to_owned(),
            Shape::Function(FunctionShape {
                generics: Vec::new(),
                inputs: Vec::from(["fn() -> usize".to_owned()]),
                output: Some("usize".to_owned()),
            }),
        );

        let error = check_used_ostd_shape(&used, &facade_api, &host_api, &test_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("shape mismatch"),
            "expected OSTD facade shape diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_legacy_high_level_framev_facade_module() {
        let repo = TempRepo::new("legacy-framev-facade");
        let facade_lib = repo.path().join("kernel/comps/framevisor-ostd/src/lib.rs");
        fs::create_dir_all(facade_lib.parent().unwrap())
            .expect("failed to create facade fixture directory");
        fs::write(
            &facade_lib,
            r#"
pub mod framev_sock {
    pub fn activate() {}
}
"#,
        )
        .expect("failed to write facade fixture");

        let error = check_high_level_framev_facade_absence(repo.path(), &test_config(), &[])
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("forbidden high-level FrameV facade"),
            "expected high-level facade diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_legacy_framev_marker_in_osdk_policy() {
        let repo = TempRepo::new("legacy-osdk-policy-marker");
        let policy_path = repo.path().join("osdk/src/framevm/policy.toml");
        fs::create_dir_all(policy_path.parent().unwrap())
            .expect("failed to create policy fixture directory");
        fs::write(
            &policy_path,
            r#"
allowed_imports = ["framev_sock"]
"#,
        )
        .expect("failed to write policy fixture");

        let error =
            check_legacy_framev_policy_marker_absence(repo.path()).expect_err("fixture must fail");
        assert!(
            error
                .message
                .contains("canonical FrameV package-role names"),
            "expected legacy OSDK policy marker diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_service_importing_high_level_framev_facade() {
        let repo = TempRepo::new("service-high-level-framev");
        let facade_lib = repo.path().join("kernel/comps/framevisor-ostd/src/lib.rs");
        fs::create_dir_all(facade_lib.parent().unwrap())
            .expect("failed to create facade fixture directory");
        fs::write(&facade_lib, "pub mod framev {}").expect("failed to write facade fixture");
        let service_file = repo
            .path()
            .join("services/aster-framevm/src/net/socket/vsock/mod.rs");
        fs::create_dir_all(service_file.parent().unwrap())
            .expect("failed to create service fixture directory");
        fs::write(
            &service_file,
            r#"
fn init() {
    ostd::framev_sock::activate().unwrap();
}
"#,
        )
        .expect("failed to write service fixture");

        let error =
            check_high_level_framev_facade_absence(repo.path(), &test_config(), &[service_file])
                .expect_err("fixture must fail");
        assert!(
            error.message.contains("ostd::framev_sock"),
            "expected service high-level facade diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_vfs_ext2_framev_blk_protocol_import() {
        let repo = TempRepo::new("fs-framev-protocol");
        let source_path = repo
            .path()
            .join("services/aster-framevm/src/fs/fs_impls/ext2/mod.rs");
        fs::create_dir_all(source_path.parent().unwrap())
            .expect("failed to create ext2 fixture directory");
        fs::write(
            &source_path,
            r#"
use framev_blk_common::FrameVBlkStatus;

fn leak_protocol(status: FrameVBlkStatus) {
    let _ = status;
}
"#,
        )
        .expect("failed to write ext2 fixture");

        let error = check_vfs_ext2_framev_protocol_boundary(repo.path(), &test_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("issue I/O through aster-block"),
            "expected fs/FrameV-blk boundary diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_legacy_framevm_packaged_test_script() {
        let repo = TempRepo::new("legacy-packaged-framevm-script");
        let initramfs_path = repo.path().join("test/initramfs/nix/initramfs.nix");
        fs::create_dir_all(initramfs_path.parent().unwrap())
            .expect("failed to create initramfs fixture directory");
        fs::write(
            &initramfs_path,
            r#"
install -Dm755 ${framevmLoad} $out/test/framevm_load.sh
"#,
        )
        .expect("failed to write initramfs fixture");

        let error =
            check_legacy_framevm_test_entrypoint_absence(repo.path()).expect_err("fixture fails");
        assert!(
            error.message.contains("/test/framevm/**"),
            "expected legacy FrameVM test script diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_legacy_framev_vsock_make_target() {
        let repo = TempRepo::new("legacy-framev-vsock-make-target");
        fs::write(
            repo.path().join("Makefile"),
            r#"
framev_vsock_test:
	$(MAKE) run_framevm AUTO_TEST=device
"#,
        )
        .expect("failed to write Makefile fixture");

        let error =
            check_legacy_framevm_test_entrypoint_absence(repo.path()).expect_err("fixture fails");
        assert!(
            error.message.contains("AUTO_TEST=device"),
            "expected legacy Make target diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_legacy_osdk_framevm_default_script_path() {
        let repo = TempRepo::new("legacy-osdk-default-script");
        let osdk_path = repo.path().join("osdk/src/framevm/mod.rs");
        fs::create_dir_all(osdk_path.parent().unwrap())
            .expect("failed to create OSDK fixture directory");
        fs::write(
            &osdk_path,
            r#"
const DEFAULT_INIT: &str = "/test/framev_vsock_test.sh";
"#,
        )
        .expect("failed to write OSDK fixture");

        let error =
            check_legacy_framevm_test_entrypoint_absence(repo.path()).expect_err("fixture fails");
        assert!(
            error.message.contains("unified `/test/framevm/**` runner"),
            "expected legacy OSDK default path diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_final_packaged_cpio_rootfs() {
        let repo = TempRepo::new("packaged-cpio-rootfs");
        let initramfs_path = repo.path().join("test/initramfs/nix/initramfs.nix");
        fs::create_dir_all(initramfs_path.parent().unwrap())
            .expect("failed to create initramfs fixture directory");
        fs::write(
            &initramfs_path,
            r#"
install -Dm644 ${framevmRootfs} $out/framevm/rootfs.cpio.gz
"#,
        )
        .expect("failed to write initramfs fixture");

        let error = check_final_rootfs_artifact_policy(repo.path(), &final_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("rootfs.ext2"),
            "expected rootfs artifact diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_final_cpio_decoder_policy_allowance() {
        let repo = TempRepo::new("cpio-policy");
        let policy_path = repo.path().join("osdk/src/framevm/policy.toml");
        fs::create_dir_all(policy_path.parent().unwrap())
            .expect("failed to create policy fixture directory");
        fs::write(
            &policy_path,
            r#"
allowed_imports = ["cpio_decoder"]
"#,
        )
        .expect("failed to write policy fixture");

        let error = check_final_rootfs_artifact_policy(repo.path(), &final_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("CPIO decoder"),
            "expected cpio decoder policy diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_final_cpio_rootfs_loader_fallback() {
        let repo = TempRepo::new("cpio-loader");
        let loader_path = repo.path().join("kernel/src/vmm/mod.rs");
        fs::create_dir_all(loader_path.parent().unwrap())
            .expect("failed to create loader fixture directory");
        fs::write(
            &loader_path,
            r#"
fn read_framevm_rootfs() {
    let _ = "/framevm/rootfs.cpio.gz";
}
"#,
        )
        .expect("failed to write loader fixture");

        let error = check_final_rootfs_artifact_policy(repo.path(), &final_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("CPIO rootfs fallback"),
            "expected CPIO fallback diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_final_service_local_rootfs_adapter_objects() {
        let repo = TempRepo::new("rootfs-adapter");
        let source_path = repo
            .path()
            .join("services/aster-framevm/src/fs/file/rootfs_file.rs");
        fs::create_dir_all(source_path.parent().unwrap())
            .expect("failed to create rootfs adapter fixture directory");
        fs::write(
            &source_path,
            r#"
struct RootRegularFile;
"#,
        )
        .expect("failed to write rootfs adapter fixture");

        let error = check_final_service_local_rootfs_adapters(&final_config(), &[source_path])
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("kernel VFS/file/pipe abstractions"),
            "expected service-local rootfs adapter diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_final_superseded_forwarding_wrapper_path() {
        let repo = TempRepo::new("superseded-wrapper");
        let wrapper_path = repo.path().join("services/aster-framevm/src/fd_table.rs");
        fs::create_dir_all(wrapper_path.parent().unwrap())
            .expect("failed to create superseded wrapper fixture directory");
        fs::write(
            &wrapper_path,
            r#"
pub use crate::fs::file::file_table::*;
"#,
        )
        .expect("failed to write superseded wrapper fixture");

        let error = check_final_superseded_implementation_paths(repo.path(), &final_config())
            .expect_err("fixture must fail");
        assert!(
            error
                .message
                .contains("superseded FrameVM implementation path"),
            "expected superseded wrapper diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_final_service_local_scheduler_path() {
        let repo = TempRepo::new("service-local-scheduler-path");
        let scheduler_path = repo
            .path()
            .join("services/aster-framevm/src/scheduler/mod.rs");
        fs::create_dir_all(scheduler_path.parent().unwrap())
            .expect("failed to create scheduler fixture directory");
        fs::write(
            &scheduler_path,
            r#"
pub fn init() {}
"#,
        )
        .expect("failed to write scheduler fixture");

        let error = check_final_superseded_implementation_paths(repo.path(), &final_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("service-local scheduler path"),
            "expected service-local scheduler diagnostic, got `{}`",
            error.message
        );
    }

    fn write_final_entry_fixture(repo: &TempRepo, init_source: &str) {
        let service_dir = repo.path().join("services/aster-framevm");
        let init_dir = service_dir.join("src");
        fs::create_dir_all(&init_dir).expect("failed to create init fixture directory");
        fs::write(init_dir.join("init.rs"), init_source).expect("failed to write init fixture");
        fs::write(
            service_dir.join("Cargo.toml"),
            r#"
[package]
name = "aster-framevm"
version = "0.1.0"
edition = "2024"

[dependencies]
aster-cmdline = { package = "aster-framevm-cmdline", workspace = true }
logo-ascii-art = { workspace = true }
"#,
        )
        .expect("failed to write service manifest fixture");
    }

    fn valid_final_entry_source() -> &'static str {
        r#"
use component::InitStage;

aster_cmdline::define_kv_param!("init", INIT_PATH);

fn main() {
    init_framevm_components(InitStage::Bootstrap);
    print_banner();
    init_framevm_components(InitStage::Kthread);
    run_init(aster_cmdline::INIT_PATH.get());
    init_framevm_components(InitStage::Process);
}

fn print_banner() {
    let _ = logo_ascii_art::get_gradient_color_version();
    let _ = "FrameVM";
}
"#
    }

    #[test]
    fn rejects_final_init_path_without_cmdline_provider() {
        let repo = TempRepo::new("hardcoded-init");
        write_final_entry_fixture(
            &repo,
            r#"
use component::InitStage;

fn main() {
    init_framevm_components(InitStage::Bootstrap);
    init_framevm_components(InitStage::Kthread);
    let init_program = "/init";
    init_framevm_components(InitStage::Process);
    let _ = logo_ascii_art::get_gradient_color_version();
    let _ = "FrameVM";
}
"#,
        );

        let error = check_final_entry_init_policy(repo.path(), &final_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("aster-cmdline"),
            "expected cmdline provider diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_final_banner_without_shared_logo_path() {
        let repo = TempRepo::new("missing-logo-banner");
        write_final_entry_fixture(
            &repo,
            r#"
use component::InitStage;

aster_cmdline::define_kv_param!("init", INIT_PATH);

fn main() {
    init_framevm_components(InitStage::Bootstrap);
    init_framevm_components(InitStage::Kthread);
    init_framevm_components(InitStage::Process);
    let _ = "FrameVM";
}
"#,
        );

        let error = check_final_entry_init_policy(repo.path(), &final_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("shared `logo-ascii-art` mechanism"),
            "expected shared banner diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_final_manual_frontend_initialization() {
        let repo = TempRepo::new("manual-frontend-init");
        let source = valid_final_entry_source().replace(
            "print_banner();",
            "print_banner();\n    framev::init_devices().unwrap();",
        );
        write_final_entry_fixture(&repo, &source);

        let error = check_final_entry_init_policy(repo.path(), &final_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("component profiles"),
            "expected manual frontend init diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_lib_entry_without_non_returning_init_delegation() {
        let repo = TempRepo::new("lib-entry-no-delegation");
        let lib_path = repo.path().join("services/aster-framevm/src/lib.rs");
        fs::create_dir_all(lib_path.parent().unwrap())
            .expect("failed to create lib fixture directory");
        fs::write(
            &lib_path,
            r#"
pub extern "Rust" fn __ostd_main() -> ! {
    run_user_program();
    ostd::power::poweroff(ostd::power::ExitCode::Success);
}
"#,
        )
        .expect("failed to write lib fixture");

        let error =
            check_lib_entry_policy(repo.path(), &test_config()).expect_err("fixture must fail");
        assert!(
            error.message.contains("non-returning kernel-shaped entry"),
            "expected lib delegation diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_loader_returning_lib_entry() {
        let repo = TempRepo::new("lib-entry-dynamic");
        let lib_path = repo.path().join("services/aster-framevm/src/lib.rs");
        fs::create_dir_all(lib_path.parent().unwrap())
            .expect("failed to create lib fixture directory");
        fs::write(
            &lib_path,
            r#"
pub extern "Rust" fn __ostd_dynamic_main() {
    init::main();
}

pub extern "Rust" fn __ostd_main() -> ! {
    init::main();
    ostd::power::poweroff(ostd::power::ExitCode::Success);
}
"#,
        )
        .expect("failed to write lib fixture");

        let error =
            check_lib_entry_policy(repo.path(), &test_config()).expect_err("fixture must fail");
        assert!(
            error.message.contains("must not return"),
            "expected loader-returning entry diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_lib_entry_manual_frontend_initialization() {
        let repo = TempRepo::new("lib-entry-manual-init");
        let lib_path = repo.path().join("services/aster-framevm/src/lib.rs");
        fs::create_dir_all(lib_path.parent().unwrap())
            .expect("failed to create lib fixture directory");
        fs::write(
            &lib_path,
            r#"
pub extern "Rust" fn __ostd_main() -> ! {
    framev_bus::init_devices().unwrap();
    init::main();
    ostd::power::poweroff(ostd::power::ExitCode::Success);
}
"#,
        )
        .expect("failed to write lib fixture");

        let error =
            check_lib_entry_policy(repo.path(), &test_config()).expect_err("fixture must fail");
        assert!(
            error.message.contains("must not manually initialize"),
            "expected lib manual init diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_missing_framevm_profile_stage_usage() {
        let repo = TempRepo::new("init-profile");
        let init_dir = repo.path().join("services/aster-framevm/src");
        fs::create_dir_all(&init_dir).expect("failed to create init fixture directory");
        fs::write(
            init_dir.join("init.rs"),
            r#"
use component::InitStage;

fn main() {
    init_framevm_components(InitStage::Bootstrap);
    init_framevm_components(InitStage::Kthread);
}

fn init_framevm_components(stage: InitStage) {
    init_framevm_component_profile(stage);
}

fn init_framevm_component_profile(stage: InitStage) {
    match stage {
        InitStage::Bootstrap => {}
        InitStage::Kthread => {}
        InitStage::Process => {}
    }
}
"#,
        )
        .expect("failed to write init fixture");

        let error = validate_framevm_component_profile_usage(repo.path(), &test_config())
            .expect_err("fixture must fail");
        assert!(
            error.message.contains("InitStage::Process"),
            "expected missing process-stage diagnostic, got `{}`",
            error.message
        );
    }

    #[test]
    fn rejects_framevm_entry_using_global_component_metadata_parser() {
        let repo = TempRepo::new("init-global-parser");
        let init_dir = repo.path().join("services/aster-framevm/src");
        fs::create_dir_all(&init_dir).expect("failed to create init fixture directory");
        fs::write(
            init_dir.join("init.rs"),
            r#"
use component::InitStage;

fn main() {
    init_framevm_components(InitStage::Bootstrap);
    init_framevm_components(InitStage::Kthread);
    init_framevm_components(InitStage::Process);
}

fn init_framevm_components(stage: InitStage) {
    component::init_all(stage, component::parse_metadata!("framevm")).unwrap();
}
"#,
        )
        .expect("failed to write init fixture");

        let error = validate_framevm_component_profile_usage(repo.path(), &test_config())
            .expect_err("fixture must fail");
        assert!(
            error
                .message
                .contains("service-local FrameVM component profile"),
            "expected service-local dispatcher diagnostic, got `{}`",
            error.message
        );
    }
}
