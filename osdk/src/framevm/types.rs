// SPDX-License-Identifier: MPL-2.0

use std::{
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::config::Config;

pub const DEFAULT_LOAD_SUCCESS_MARKER: &str = "FRAMEVM_LOAD_OK";
pub const DEFAULT_LOAD_INIT_PATH: &str = "/test/framevm/shell.sh";
pub const LOAD_TEST_INIT_PATH: &str = "/test/framevm/load.sh";
pub const BOOT_LOAD_INIT_PATH: &str = "/test/framevm/boot.sh";
pub const REGRESSION_LOAD_INIT_PATH: &str = "/test/framevm/regression.sh";
pub const DEVICE_LOAD_INIT_PATH: &str = "/test/framevm/device.sh";
pub const ROOTFS_LOAD_INIT_PATH: &str = "/test/framevm/rootfs.sh";
pub const LIFECYCLE_LOAD_INIT_PATH: &str = "/test/framevm/lifecycle.sh";
pub const NET_LOAD_INIT_PATH: &str = "/test/framevm/net.sh";
pub const APPLICATION_LOAD_INIT_PATH: &str = "/test/framevm/application.sh";
pub const NVME_LOAD_INIT_PATH: &str = "/test/framevm/nvme_passthrough.sh";
pub const MEMORY_LOAD_INIT_PATH: &str = "/test/framevm/memory.sh";
pub const ALLOCATOR_LOAD_INIT_PATH: &str = "/test/framevm/allocator.sh";
pub const PLACEMENT_LOAD_INIT_PATH: &str = "/test/framevm/placement.sh";
pub const SMP_LOAD_INIT_PATH: &str = "/test/framevm/smp.sh";
pub const FAIRNESS_LOAD_INIT_PATH: &str = "/test/framevm/fairness.sh";
pub const SHELL_LOAD_INIT_PATH: &str = "/test/framevm/shell_test.sh";
pub const ALL_LOAD_INIT_PATH: &str = "/test/framevm/all.sh";
pub const BOOT_SUCCESS_MARKER: &str = "FRAMEVM_BOOT_OK";
pub const REGRESSION_SUCCESS_MARKER: &str = "FRAMEVM_REGRESSION_OK";
pub const DEVICE_SUCCESS_MARKER: &str = "FRAMEVM_DEVICE_OK";
pub const ROOTFS_SUCCESS_MARKER: &str = "FRAMEVM_ROOTFS_OK";
pub const LIFECYCLE_SUCCESS_MARKER: &str = "FRAMEVM_LIFECYCLE_OK";
pub const NET_SUCCESS_MARKER: &str = "FRAMEV_NET_OK";
pub const APPLICATION_SUCCESS_MARKER: &str = "FRAMEVM_APPLICATION_OK";
pub const NVME_SUCCESS_MARKER: &str = "FRAMEVM_NVME_PASSTHROUGH_OK";
pub const MEMORY_SUCCESS_MARKER: &str = "FRAMEVM_MEMORY_OK";
pub const ALLOCATOR_SUCCESS_MARKER: &str = "FRAMEVM_ALLOCATOR_OK";
pub const PLACEMENT_SUCCESS_MARKER: &str = "FRAMEVM_PLACEMENT_OK";
pub const SMP_SUCCESS_MARKER: &str = "FRAMEVM_SMP_OK";
pub const FAIRNESS_SUCCESS_MARKER: &str = "FRAMEVM_FAIRNESS_OK";
pub const SHELL_SUCCESS_MARKER: &str = "FRAMEVM_SHELL_OK";

#[derive(Clone, Debug)]
pub struct FrameVmBuildConfig {
    pub osdk_config: Config,
    pub target: String,
    pub object_output: Option<PathBuf>,
    pub install_path: PathBuf,
    pub features: Vec<String>,
    pub no_default_features: bool,
    pub skip_service_check: bool,
    pub load_action: FrameVmLoadAction,
    /// Optional inner FrameVM memory limit exported by the host init.
    ///
    /// This is a runtime argument. It is deliberately not part of the
    /// FrameVM object identity; changing it may refresh only the boot carrier
    /// and must not rebuild the service object.
    pub memory_limit: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FrameVmRunConfig {
    pub build: FrameVmBuildConfig,
    pub no_build: bool,
}

#[derive(Clone, Debug)]
pub enum FrameVmLoadAction {
    Default,
    Script(PathBuf),
}

impl FrameVmLoadAction {
    pub(super) fn init_args_with_memory_limit(&self, memory_limit: Option<&str>) -> Vec<String> {
        let script = match self {
            Self::Default => Path::new(DEFAULT_LOAD_INIT_PATH),
            Self::Script(path) => path.as_path(),
        };

        let mut args = vec!["--no-script".to_string()];
        if let Some(memory_limit) = memory_limit {
            args.push("/bin/env".to_string());
            args.push(format!("FRAMEVM_MEMORY_LIMIT={memory_limit}"));
        }
        args.push(script.to_string_lossy().into_owned());
        args
    }

    pub(super) fn success_markers(&self) -> &'static [&'static str] {
        match self.init_path() {
            path if path == Path::new(DEFAULT_LOAD_INIT_PATH) => &[],
            path if path == Path::new(LOAD_TEST_INIT_PATH) => &[DEFAULT_LOAD_SUCCESS_MARKER],
            path if path == Path::new(BOOT_LOAD_INIT_PATH) => &[BOOT_SUCCESS_MARKER],
            path if path == Path::new(REGRESSION_LOAD_INIT_PATH) => &[REGRESSION_SUCCESS_MARKER],
            path if path == Path::new(DEVICE_LOAD_INIT_PATH) => &[DEVICE_SUCCESS_MARKER],
            path if path == Path::new(ROOTFS_LOAD_INIT_PATH) => &[ROOTFS_SUCCESS_MARKER],
            path if path == Path::new(LIFECYCLE_LOAD_INIT_PATH) => &[LIFECYCLE_SUCCESS_MARKER],
            path if path == Path::new(NET_LOAD_INIT_PATH) => &[NET_SUCCESS_MARKER],
            path if path == Path::new(APPLICATION_LOAD_INIT_PATH) => &[APPLICATION_SUCCESS_MARKER],
            path if path == Path::new(NVME_LOAD_INIT_PATH) => &[NVME_SUCCESS_MARKER],
            path if path == Path::new(MEMORY_LOAD_INIT_PATH) => &[MEMORY_SUCCESS_MARKER],
            path if path == Path::new(ALLOCATOR_LOAD_INIT_PATH) => &[ALLOCATOR_SUCCESS_MARKER],
            path if path == Path::new(PLACEMENT_LOAD_INIT_PATH) => &[PLACEMENT_SUCCESS_MARKER],
            path if path == Path::new(SMP_LOAD_INIT_PATH) => &[SMP_SUCCESS_MARKER],
            path if path == Path::new(FAIRNESS_LOAD_INIT_PATH) => &[FAIRNESS_SUCCESS_MARKER],
            path if path == Path::new(SHELL_LOAD_INIT_PATH) => &[SHELL_SUCCESS_MARKER],
            path if path == Path::new(ALL_LOAD_INIT_PATH) => &[
                BOOT_SUCCESS_MARKER,
                REGRESSION_SUCCESS_MARKER,
                DEVICE_SUCCESS_MARKER,
                ROOTFS_SUCCESS_MARKER,
                LIFECYCLE_SUCCESS_MARKER,
                NET_SUCCESS_MARKER,
                PLACEMENT_SUCCESS_MARKER,
                FAIRNESS_SUCCESS_MARKER,
                SHELL_SUCCESS_MARKER,
            ],
            _ => &[DEFAULT_LOAD_SUCCESS_MARKER],
        }
    }

    pub(super) fn case_name(&self) -> Option<&'static str> {
        match self.init_path() {
            path if path == Path::new(DEFAULT_LOAD_INIT_PATH) => None,
            path if path == Path::new(LOAD_TEST_INIT_PATH) => Some("load"),
            path if path == Path::new(BOOT_LOAD_INIT_PATH) => Some("boot"),
            path if path == Path::new(REGRESSION_LOAD_INIT_PATH) => Some("regression"),
            path if path == Path::new(DEVICE_LOAD_INIT_PATH) => Some("device"),
            path if path == Path::new(NVME_LOAD_INIT_PATH) => Some("nvme-passthrough"),
            path if path == Path::new(ROOTFS_LOAD_INIT_PATH) => Some("rootfs"),
            path if path == Path::new(LIFECYCLE_LOAD_INIT_PATH) => Some("lifecycle"),
            path if path == Path::new(NET_LOAD_INIT_PATH) => Some("net"),
            path if path == Path::new(APPLICATION_LOAD_INIT_PATH) => Some("application"),
            path if path == Path::new(MEMORY_LOAD_INIT_PATH) => Some("memory"),
            path if path == Path::new(ALLOCATOR_LOAD_INIT_PATH) => Some("allocator"),
            path if path == Path::new(PLACEMENT_LOAD_INIT_PATH) => Some("placement"),
            path if path == Path::new(SMP_LOAD_INIT_PATH) => Some("smp"),
            path if path == Path::new(FAIRNESS_LOAD_INIT_PATH) => Some("fairness"),
            path if path == Path::new(SHELL_LOAD_INIT_PATH) => Some("shell"),
            path if path == Path::new(ALL_LOAD_INIT_PATH) => Some("all"),
            _ => None,
        }
    }

    pub(super) fn success_timeout(&self) -> Duration {
        match self.init_path() {
            path if path == Path::new(DEFAULT_LOAD_INIT_PATH) => Duration::from_secs(180),
            path if path == Path::new(APPLICATION_LOAD_INIT_PATH) => Duration::from_secs(1_500),
            _ => Duration::from_secs(600),
        }
    }

    pub(super) fn is_interactive(&self) -> bool {
        self.init_path() == Path::new(DEFAULT_LOAD_INIT_PATH)
    }

    fn init_path(&self) -> &Path {
        match self {
            Self::Default => Path::new(DEFAULT_LOAD_INIT_PATH),
            Self::Script(path) => path.as_path(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FrameVmBuildOutcome {
    pub object: PathBuf,
    pub symbols: PathBuf,
    pub initramfs: PathBuf,
    pub bundle: PathBuf,
}

#[derive(Clone, Debug)]
pub struct FrameVmRunOutcome {
    pub success_markers: &'static [&'static str],
}

#[derive(Debug)]
pub enum FrameVmStageError {
    Workspace(String),
    ServiceCheck(String),
    ObjectBuild(String),
    ObjectLink(String),
    ImportValidation(String),
    Package(String),
    Run(String),
}

impl fmt::Display for FrameVmStageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Workspace(message) => write!(formatter, "framevm workspace error: {message}"),
            Self::ServiceCheck(message) => {
                write!(formatter, "framevm service check failed: {message}")
            }
            Self::ObjectBuild(message) => {
                write!(formatter, "framevm object build failed: {message}")
            }
            Self::ObjectLink(message) => write!(formatter, "framevm object link failed: {message}"),
            Self::ImportValidation(message) => {
                write!(formatter, "framevm import validation failed: {message}")
            }
            Self::Package(message) => write!(formatter, "framevm packaging failed: {message}"),
            Self::Run(message) => write!(formatter, "framevm run failed: {message}"),
        }
    }
}

impl std::error::Error for FrameVmStageError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_actions_select_case_success_markers() {
        assert_eq!(FrameVmLoadAction::Default.success_markers(), &[] as &[&str]);
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(LOAD_TEST_INIT_PATH)).success_markers(),
            &[DEFAULT_LOAD_SUCCESS_MARKER]
        );
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(BOOT_LOAD_INIT_PATH)).success_markers(),
            &[BOOT_SUCCESS_MARKER]
        );
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(ROOTFS_LOAD_INIT_PATH)).success_markers(),
            &[ROOTFS_SUCCESS_MARKER]
        );
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(NET_LOAD_INIT_PATH)).success_markers(),
            &[NET_SUCCESS_MARKER]
        );
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(APPLICATION_LOAD_INIT_PATH)).success_markers(),
            &[APPLICATION_SUCCESS_MARKER]
        );
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(NVME_LOAD_INIT_PATH)).success_markers(),
            &[NVME_SUCCESS_MARKER]
        );
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(MEMORY_LOAD_INIT_PATH)).success_markers(),
            &[MEMORY_SUCCESS_MARKER]
        );
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(ALLOCATOR_LOAD_INIT_PATH)).success_markers(),
            &[ALLOCATOR_SUCCESS_MARKER]
        );
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(PLACEMENT_LOAD_INIT_PATH)).success_markers(),
            &[PLACEMENT_SUCCESS_MARKER]
        );
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(SMP_LOAD_INIT_PATH)).success_markers(),
            &[SMP_SUCCESS_MARKER]
        );
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(FAIRNESS_LOAD_INIT_PATH)).success_markers(),
            &[FAIRNESS_SUCCESS_MARKER]
        );
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(SHELL_LOAD_INIT_PATH)).success_markers(),
            &[SHELL_SUCCESS_MARKER]
        );
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(ALL_LOAD_INIT_PATH)).success_markers(),
            &[
                BOOT_SUCCESS_MARKER,
                REGRESSION_SUCCESS_MARKER,
                DEVICE_SUCCESS_MARKER,
                ROOTFS_SUCCESS_MARKER,
                LIFECYCLE_SUCCESS_MARKER,
                NET_SUCCESS_MARKER,
                PLACEMENT_SUCCESS_MARKER,
                FAIRNESS_SUCCESS_MARKER,
                SHELL_SUCCESS_MARKER
            ]
        );
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from("/custom/framevm.sh")).success_markers(),
            &[DEFAULT_LOAD_SUCCESS_MARKER]
        );
    }

    #[test]
    fn application_load_action_has_workload_sized_timeout() {
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(APPLICATION_LOAD_INIT_PATH)).success_timeout(),
            Duration::from_secs(1_500)
        );
    }

    #[test]
    fn runtime_memory_limit_is_exported_before_load_script() {
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(BOOT_LOAD_INIT_PATH))
                .init_args_with_memory_limit(Some("64M")),
            vec![
                "--no-script",
                "/bin/env",
                "FRAMEVM_MEMORY_LIMIT=64M",
                BOOT_LOAD_INIT_PATH,
            ]
        );
    }

    #[test]
    fn load_actions_have_stable_case_names() {
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from(NVME_LOAD_INIT_PATH)).case_name(),
            Some("nvme-passthrough")
        );
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from("/custom/framevm.sh")).case_name(),
            None
        );
    }
}
