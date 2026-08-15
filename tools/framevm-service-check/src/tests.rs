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
        shared_source_comps: Vec::new(),
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
    let error =
        validate_component_profiles(repo.path(), &test_config()).expect_err("fixture must fail");
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

fn write_irq_discipline_fixture(repo: &TempRepo, frame_group_comment: &str) {
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
    pub fn pick_task(&self) -> Option<Arc<HostTask>> {{
        if self.interrupt_handler.has_deliverable_work() {{
            return Some(task);
        }}
        if let Some(task) = self.try_pick_service() {{
            return Some(task);
        }}
        None
    }}
}}
"#
        ),
    )
    .expect("failed to write frame group fixture");

    let handler = repo
        .path()
        .join("kernel/comps/framevisor/src/irq/handler.rs");
    fs::create_dir_all(handler.parent().unwrap())
        .expect("failed to create IRQ handler fixture directory");
    fs::write(
        &handler,
        r#"
//! interrupt_log owns bounded notification/control work.
//! Device protocol work remains in the service scheduler.
"#,
    )
    .expect("failed to write IRQ handler fixture");

    let irq = repo.path().join("kernel/comps/framevisor/src/irq/mod.rs");
    fs::create_dir_all(irq.parent().unwrap()).expect("failed to create IRQ fixture directory");
    fs::write(
        &irq,
        r#"
fn dispatch_framev_irq_line() {
        // This dispatch is the IRQ-side notification/control handoff. Device-class
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
    fs::write(vsock_dir.join("mod.rs"), init_source).expect("failed to write vsock init fixture");
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
    for module in ["info.rs", "queue.rs", "share.rs", "timer.rs", "types.rs"] {
        fs::write(scheduler_root.join(module), "").expect("failed to write scheduler module");
    }
    fs::write(
        scheduler_root.join("mod.rs"),
        r#"
pub mod info;
mod queue;
mod share;
mod timer;
mod types;

pub fn inject_scheduler() {}
pub use timer::enable_preemption_on_cpu;
pub use types::{EnqueueFlags, LocalRunQueue, Scheduler, UpdateFlags};
"#,
    )
    .expect("failed to write scheduler mod fixture");
}

fn write_host_fair_boundary_fixture(repo: &TempRepo, body: &str) {
    let path = repo.path().join("kernel/src/sched/sched_class/fair.rs");
    fs::create_dir_all(path.parent().unwrap()).expect("failed to create fair scheduler fixture");
    fs::write(
        path,
        format!(
            "impl FairClassRq {{\n    pub(super) fn update_current_frame_group(\n        &mut self,\n        state: &frame_group::FrameSchedEntityState,\n        flags: UpdateFlags,\n    ) -> bool {{\n        {body}\n        true\n    }}\n}}\n"
        ),
    )
    .expect("failed to write fair scheduler fixture");
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
    for module in ["cpu", "device", "mm", "sync", "task", "util", "vm", "vsock"] {
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
bus = { name = "framev-pci" }

[profiles]
kernel = ["aster-framevm-block"]
framevm = ["aster-framevm-block"]
"#,
    )
    .expect("failed to write metadata fixture");

    let mut config = test_config();
    config.framev_frontend_crates = Vec::from([FrontendCrateConfig {
        name: "pci".to_owned(),
        path: PathBuf::from("services/aster-framevm/comps/framev-pci"),
        package: "framev-pci".to_owned(),
        common_package: "framev-pci-common".to_owned(),
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

fn write_shared_source_fixture(repo: &TempRepo, host_module: &str) -> Config {
    let host_src = repo.path().join("host/pci/src");
    let service_src = repo.path().join("service/pci/src");
    fs::create_dir_all(&host_src).expect("failed to create host source fixture");
    fs::create_dir_all(&service_src).expect("failed to create service source fixture");
    fs::write(host_src.join("bus.rs"), host_module).expect("failed to write host module fixture");
    fs::write(service_src.join("bus.rs"), host_module)
        .expect("failed to write copied service module fixture");
    fs::write(service_src.join("lib.rs"), "pub mod bus;\nmod platform;\n")
        .expect("failed to write service root fixture");
    fs::write(service_src.join("platform.rs"), "").expect("failed to write provider fixture");

    let mut config = test_config();
    config.shared_source_comps = Vec::from([SharedSourceCompConfig {
        name: "pci".to_owned(),
        host_source_path: PathBuf::from("host/pci/src"),
        service_source_path: PathBuf::from("service/pci/src"),
        service_path_prefix: PathBuf::from("../../../host/pci/src"),
        shared_modules: BTreeSet::from([PathBuf::from("bus.rs")]),
    }]);
    config
}

#[test]
fn accepts_identical_copied_shared_source_module() {
    let repo = TempRepo::new("shared-source-positive");
    let config = write_shared_source_fixture(&repo, "pub struct PciBus;\n");

    validate_shared_source_comps(repo.path(), &config).expect("fixture must pass");
}

#[test]
fn rejects_divergent_copied_shared_source_module() {
    let repo = TempRepo::new("shared-source-copy");
    let config = write_shared_source_fixture(&repo, "pub struct PciBus;\n");
    fs::write(
        repo.path().join("service/pci/src/bus.rs"),
        "pub struct CopiedPciBus;\n",
    )
    .expect("failed to write copied source fixture");

    let error = validate_shared_source_comps(repo.path(), &config).expect_err("fixture must fail");
    assert!(error.message.contains("[shared-source]"));
    assert!(error.message.contains("differs from Host module"));
    assert!(error.message.contains("service/pci/src/bus.rs"));
}

#[test]
fn rejects_feature_selected_provider_in_shared_source() {
    let repo = TempRepo::new("shared-source-feature-provider");
    let config =
        write_shared_source_fixture(&repo, "#[cfg(feature = \"framevm\")]\npub struct PciBus;\n");

    let error = validate_shared_source_comps(repo.path(), &config).expect_err("fixture must fail");
    assert!(error.message.contains("[shared-source]"));
    assert!(error.message.contains("Cargo features"));
    assert!(error.message.contains("host/pci/src/bus.rs"));
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

[lints]
workspace = true
"#,
    );
    let src_dir = repo.path().join("kernel/comps/framev-test/src");
    fs::create_dir_all(&src_dir).expect("failed to create common source fixture");
    fs::write(
        src_dir.join("lib.rs"),
        r#"
pub struct OwnedResource;
"#,
    )
    .expect("failed to write common source fixture");

    let error = validate_framev_common_crates(repo.path(), &common_crate_config())
        .expect_err("fixture must fail");
    assert!(
        error
            .message
            .contains("forbidden generic FrameV model item"),
        "expected common model redefinition diagnostic, got `{}`",
        error.message
    );
}

#[test]
fn accepts_common_crate_without_common_device_semantics() {
    let repo = TempRepo::new("independent-common-protocol");
    write_common_crate_fixture(
        &repo,
        &["kernel/comps/framev-test"],
        r#"
[package]
name = "framev-test-common"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
"#,
    );
    let src_dir = repo.path().join("kernel/comps/framev-test/src");
    fs::create_dir_all(&src_dir).expect("failed to create common source fixture");
    fs::write(
        src_dir.join("lib.rs"),
        "pub const MAX_DIRECT_BYTES: usize = 4096;\n",
    )
    .expect("failed to write common source fixture");

    validate_framev_common_crates(repo.path(), &common_crate_config())
        .expect("a protocol-only common crate has no generic transport dependency");
}

#[test]
fn rejects_common_crate_simulated_dma_transport() {
    let repo = TempRepo::new("common-simulated-dma");
    write_common_crate_fixture(
        &repo,
        &["kernel/comps/framev-test"],
        r#"
[package]
name = "framev-test-common"
version = "0.1.0"
edition = "2024"

[lints]
workspace = true
"#,
    );
    let src_dir = repo.path().join("kernel/comps/framev-test/src");
    fs::create_dir_all(&src_dir).expect("failed to create common source fixture");
    fs::write(src_dir.join("lib.rs"), "pub struct DmaArena;\n")
        .expect("failed to write common source fixture");

    let error = validate_framev_common_crates(repo.path(), &common_crate_config())
        .expect_err("fixture must fail");
    assert!(error.message.contains("simulated DMA transport"));
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

    let error = validate_trim_manifest(repo.path(), &test_config()).expect_err("fixture must fail");
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

    let error = validate_trim_manifest(repo.path(), &test_config()).expect_err("fixture must fail");
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
        &source_trim_manifest_entry("net/socket/vsock/transport/mod.rs", "provider-substitution"),
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
    fs::create_dir_all(lib_path.parent().unwrap()).expect("failed to create lib fixture directory");
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
    fs::create_dir_all(lib_path.parent().unwrap()).expect("failed to create lib fixture directory");
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
    fs::write(&service_file, "struct ConsoleFile;\n").expect("failed to write raw console fixture");

    let error =
        check_final_framevm_interactive_shell_policy(repo.path(), &final_config(), &[service_file])
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
        "printf 'exit\\n' | framevmm -append init=/bin/sh\n",
    )
    .expect("failed to write FrameVM script fixture");

    let error = check_final_framevm_interactive_shell_policy(repo.path(), &final_config(), &[])
        .expect_err("fixture must fail");
    assert!(
        error.message.contains("through framevmm -append"),
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

    let error =
        check_final_framevm_interactive_shell_policy(repo.path(), &final_config(), &[procfs_file])
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

    let repo = TempRepo::new("service-host-aster-util");
    write_service_manifest_fixture(&repo, "aster-util = { workspace = true }");
    let error =
        validate_service_manifest(repo.path(), &test_config()).expect_err("fixture must fail");
    assert!(
        error.message.contains("host kernel comp `aster-util`"),
        "expected host aster-util dependency diagnostic, got `{}`",
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

    let error = validate_service_manifest(repo.path(), &test_config()).expect_err("fixture fails");
    assert!(
        error
            .message
            .contains("host-only kernel comp `aster-virtio`"),
        "expected host kernel comp dependency diagnostic, got `{}`",
        error.message
    );

    let repo = TempRepo::new("service-host-kernel-comp-by-aster-prefix");
    write_service_manifest_fixture(&repo, "aster-pci = { workspace = true }");

    let error = validate_service_manifest(repo.path(), &test_config()).expect_err("fixture fails");
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

    let error = validate_legacy_framev_package_absence(repo.path()).expect_err("fixture must fail");
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

    let error =
        validate_trimmed_comp_manifests(repo.path(), &test_config()).expect_err("fixture fails");
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
framev-pci = { workspace = true }
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
framev-pci = { workspace = true }
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
framev-pci = { workspace = true }
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
framev-pci = { workspace = true }
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
framev-pci = { workspace = true }
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
        error.message.contains("device handles from framev-pci"),
        "expected descriptor boundary diagnostic, got `{}`",
        error.message
    );
}

#[test]
fn rejects_frontend_simulated_dma_transport() {
    let repo = TempRepo::new("frontend-simulated-dma");
    write_frontend_source_fixture(&repo, "fn submit(stream: DmaStream) { let _ = stream; }\n");

    let error = validate_framev_frontend_source_boundaries(
        repo.path(),
        &frontend_crate_config("framev-test-frontend", "framev-test-common"),
    )
    .expect_err("fixture must fail");
    assert!(error.message.contains("simulated DMA transport"));
}

#[test]
fn rejects_block_frontend_payload_staging() {
    let repo = TempRepo::new("block-payload-staging");
    write_frontend_source_fixture(
        &repo,
        "fn stage(bytes: &[u8]) { let _copy = bytes.to_vec(); }\n",
    );

    let error = validate_framev_frontend_source_boundaries(
        repo.path(),
        &frontend_crate_config("framev-blk-frontend", "framev-blk-common"),
    )
    .expect_err("fixture must fail");
    assert!(error.message.contains("must not stage payload bytes"));
}

#[test]
fn rejects_nvme_post_bio_payload_staging() {
    let repo = TempRepo::new("nvme-post-bio-payload-staging");
    let path = repo
        .path()
        .join("kernel/comps/nvme/src/device/block_device.rs");
    fs::create_dir_all(path.parent().unwrap()).expect("failed to create NVMe fixture directory");
    fs::write(
        &path,
        r#"
fn io_rw_request(&self, request: BioRequest, io_op: IoOp) {
    let dma_slice = segment.inner_dma_slice();
    let ptr0 = dma_slice.daddr();
    nvme_cmd::io_read(nsid, lba, 0, ptr0, 0);
    nvme_cmd::io_write(nsid, lba, 0, ptr0, 0);
    staging.copy_from_slice(payload);
}

    fn read(&self, request: BioRequest) {}
"#,
    )
    .expect("failed to write NVMe fixture");

    let error = validate_nvme_direct_bio_contract(repo.path()).expect_err("fixture must fail");
    assert!(error.message.contains("post-BIO payload staging buffer"));
}

#[test]
fn rejects_frontend_interrupt_callback_dependency() {
    let repo = TempRepo::new("frontend-interrupt-callback");
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
        "expected interrupt callback boundary diagnostic, got `{}`",
        error.message
    );
}

#[test]
fn rejects_frontend_interrupt_internal_dependency() {
    let repo = TempRepo::new("frontend-interrupt-internal");
    write_frontend_source_fixture(
        &repo,
        r#"
fn init(ctx: InterruptHandler) {
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
        error
            .message
            .contains("must not depend on interrupt-handler"),
        "expected interrupt-handler boundary diagnostic, got `{}`",
        error.message
    );
}

#[test]
fn rejects_framev_pci_interrupt_or_legacy_facade_dependency() {
    let repo = TempRepo::new("bus-interrupt-boundary");
    let src_dir = repo
        .path()
        .join("services/aster-framevm/comps/framev-test/src");
    fs::create_dir_all(&src_dir).expect("failed to create bus source fixture directory");
    fs::write(
        src_dir.join("lib.rs"),
        r#"
fn init(ctx: InterruptHandler) {
    let _ = ctx;
}
"#,
    )
    .expect("failed to write bus source fixture");

    let error = validate_framev_pci_source_boundary(
        repo.path(),
        &frontend_crate_config("framev-pci", "framev-pci-common"),
    )
    .expect_err("fixture must fail");
    assert!(
        error.message.contains("transport discovery/binding layer"),
        "expected framev-pci boundary diagnostic, got `{}`",
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
bus = { name = "framev-pci" }
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
    /// Interrupt-first is part of the FrameSchedGroup contract. Do not reverse it.
    pub fn pick_task(&self) -> Option<Arc<HostTask>> {
        if let Some(task) = self.try_pick_service() {
            return Some(task);
        }
        if self.interrupt_handler.has_deliverable_work() {
            return Some(task);
        }
        None
    }
}
"#,
    )
    .expect("failed to write frame group fixture");

    let error = validate_frame_sched_group_contract(repo.path()).expect_err("fixture must fail");
    assert!(
        error.message.contains("must remain interrupt-first"),
        "expected interrupt-first diagnostic, got `{}`",
        error.message
    );
}

#[test]
fn rejects_missing_irq_discipline_comment() {
    let repo = TempRepo::new("irq-discipline-comment");
    write_irq_discipline_fixture(
        &repo,
        "Interrupt-first is part of the FrameSchedGroup contract. Do not reverse it.",
    );

    let error = check_irq_control_boundary(repo.path()).expect_err("fixture must fail");
    assert!(
        error.message.contains("notification/control"),
        "expected callback-discipline comment diagnostic, got `{}`",
        error.message
    );
}

#[test]
fn rejects_irq_direct_device_data_path_handler() {
    let repo = TempRepo::new("irq-direct-data-path");
    let irq_path = repo
        .path()
        .join("kernel/comps/framevisor/src/irq/handler.rs");
    fs::create_dir_all(irq_path.parent().unwrap())
        .expect("failed to create IRQ handler fixture directory");
    fs::write(
        &irq_path,
        r#"
fn drain_device_event() {
    handle_block_request();
}
"#,
    )
    .expect("failed to write IRQ handler fixture");

    let error =
        validate_irq_has_no_direct_device_data_path(repo.path()).expect_err("fixture fails");
    assert!(
        error
            .message
            .contains("must not run FrameV device data-path"),
        "expected direct IRQ data-path diagnostic, got `{}`",
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

    let error = check_no_parallel_softirq_framework(repo.path(), &test_config(), &[source_path])
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
fn accepts_host_fair_cgroup_accounting_boundary() {
    let repo = TempRepo::new("host-fair-cgroup-boundary");
    write_host_fair_boundary_fixture(
        &repo,
        "if matches!(flags, UpdateFlags::Tick) {\n            state.task_group().account_system_tick(self.cpu);\n        }",
    );

    validate_host_scheduler_cgroup_boundary(repo.path()).expect("fixture must pass");
}

#[test]
fn rejects_host_fair_timer_requeue_in_accounting_boundary() {
    let repo = TempRepo::new("host-fair-timer-requeue");
    write_host_fair_boundary_fixture(
        &repo,
        "if matches!(flags, UpdateFlags::Tick) {\n            state.task_group().account_system_tick(self.cpu);\n            group.record_timer_tick();\n        }",
    );

    let error = validate_host_scheduler_cgroup_boundary(repo.path()).expect_err("fixture fails");
    assert!(error.message.contains("feed a drained FrameVM timer tick"));
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

    let error = check_low_level_framev_usage_boundary(repo.path(), &test_config(), &[source_path])
        .expect_err("fixture must fail");
    assert!(
        error.message.contains("only `framev-pci`"),
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
fn public_module_does_not_make_unknown_descendants_public() {
    let mut api = PublicApi::default();
    api.module_prefixes.insert("task".to_owned());
    api.exact
        .insert("task::spawn".to_owned(), Shape::Item { kind: "function" });

    assert!(api.contains_public_path("task"));
    assert!(api.contains_public_path("task::spawn"));
    assert!(!api.contains_public_path("task::not_an_api"));
}

#[test]
fn self_import_records_the_enclosing_ostd_module() {
    let use_tree = syn::parse_str::<UseTree>("ostd::timer::{self, TIMER_FREQ}").unwrap();
    let mut used = UsedOstd::default();

    collect_use_tree(&use_tree, Vec::new(), &mut used);

    assert!(used.paths.contains("timer"));
    assert!(used.paths.contains("timer::TIMER_FREQ"));
    assert!(!used.paths.contains("timer::self"));
    assert_eq!(used.aliases.get("timer"), Some(&vec!["timer".to_string()]));
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

    let error =
        check_final_entry_init_policy(repo.path(), &final_config()).expect_err("fixture must fail");
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

    let error =
        check_final_entry_init_policy(repo.path(), &final_config()).expect_err("fixture must fail");
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

    let error =
        check_final_entry_init_policy(repo.path(), &final_config()).expect_err("fixture must fail");
    assert!(
        error.message.contains("component profiles"),
        "expected manual frontend init diagnostic, got `{}`",
        error.message
    );
}

#[test]
fn rejects_lib_entry_without_returning_init_delegation() {
    let repo = TempRepo::new("lib-entry-no-delegation");
    let lib_path = repo.path().join("services/aster-framevm/src/lib.rs");
    fs::create_dir_all(lib_path.parent().unwrap()).expect("failed to create lib fixture directory");
    fs::write(
        &lib_path,
        r#"
pub extern "Rust" fn __ostd_dynamic_main() {
    run_user_program();
}
"#,
    )
    .expect("failed to write lib fixture");

    let error = check_lib_entry_policy(repo.path(), &test_config()).expect_err("fixture must fail");
    assert!(
        error.message.contains("returning FrameVM bootstrap entry"),
        "expected lib delegation diagnostic, got `{}`",
        error.message
    );
}

#[test]
fn rejects_non_returning_ostd_lib_entry() {
    let repo = TempRepo::new("lib-entry-dynamic");
    let lib_path = repo.path().join("services/aster-framevm/src/lib.rs");
    fs::create_dir_all(lib_path.parent().unwrap()).expect("failed to create lib fixture directory");
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

    let error = check_lib_entry_policy(repo.path(), &test_config()).expect_err("fixture must fail");
    assert!(
        error
            .message
            .contains("must not use a non-returning OSTD entry"),
        "expected non-returning entry diagnostic, got `{}`",
        error.message
    );
}

#[test]
fn rejects_lib_entry_manual_frontend_initialization() {
    let repo = TempRepo::new("lib-entry-manual-init");
    let lib_path = repo.path().join("services/aster-framevm/src/lib.rs");
    fs::create_dir_all(lib_path.parent().unwrap()).expect("failed to create lib fixture directory");
    fs::write(
        &lib_path,
        r#"
pub extern "Rust" fn __ostd_dynamic_main() {
    framev_pci::init_devices().unwrap();
    init::main();
}
"#,
    )
    .expect("failed to write lib fixture");

    let error = check_lib_entry_policy(repo.path(), &test_config()).expect_err("fixture must fail");
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
