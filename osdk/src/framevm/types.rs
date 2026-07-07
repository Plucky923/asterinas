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
pub const ALL_LOAD_INIT_PATH: &str = "/test/framevm/all.sh";
pub const BOOT_SUCCESS_MARKER: &str = "FRAMEVM_BOOT_OK";
pub const REGRESSION_SUCCESS_MARKER: &str = "FRAMEVM_REGRESSION_OK";
pub const DEVICE_SUCCESS_MARKER: &str = "FRAMEVM_DEVICE_OK";
pub const ROOTFS_SUCCESS_MARKER: &str = "FRAMEVM_ROOTFS_OK";
pub const LIFECYCLE_SUCCESS_MARKER: &str = "FRAMEVM_LIFECYCLE_OK";

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
    pub(super) fn init_args(&self) -> Vec<String> {
        let script = match self {
            Self::Default => Path::new(DEFAULT_LOAD_INIT_PATH),
            Self::Script(path) => path.as_path(),
        };

        vec![
            "--no-script".to_string(),
            script.to_string_lossy().into_owned(),
        ]
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
            path if path == Path::new(ALL_LOAD_INIT_PATH) => &[
                BOOT_SUCCESS_MARKER,
                REGRESSION_SUCCESS_MARKER,
                DEVICE_SUCCESS_MARKER,
                ROOTFS_SUCCESS_MARKER,
            ],
            _ => &[DEFAULT_LOAD_SUCCESS_MARKER],
        }
    }

    pub(super) fn success_timeout(&self) -> Duration {
        match self {
            Self::Default => Duration::from_secs(180),
            Self::Script(_) => Duration::from_secs(600),
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
            FrameVmLoadAction::Script(PathBuf::from(ALL_LOAD_INIT_PATH)).success_markers(),
            &[
                BOOT_SUCCESS_MARKER,
                REGRESSION_SUCCESS_MARKER,
                DEVICE_SUCCESS_MARKER,
                ROOTFS_SUCCESS_MARKER
            ]
        );
        assert_eq!(
            FrameVmLoadAction::Script(PathBuf::from("/custom/framevm.sh")).success_markers(),
            &[DEFAULT_LOAD_SUCCESS_MARKER]
        );
    }
}
