// SPDX-License-Identifier: MPL-2.0

//! FrameVM service-carrier packaging.

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::config::Config;

use super::{
    object::FrameVmObjectArtifact,
    process,
    types::{FrameVmBuildConfig, FrameVmStageError},
};

#[derive(Clone, Debug)]
pub(super) struct InitramfsArtifact {
    pub(super) path: PathBuf,
}

pub(super) fn package_initramfs(
    workspace_root: &Path,
    config: &Config,
    build_config: &FrameVmBuildConfig,
    object: &FrameVmObjectArtifact,
) -> Result<InitramfsArtifact, FrameVmStageError> {
    if std::env::var_os("VDSO_LIBRARY_DIR").is_none() {
        return Err(FrameVmStageError::Package(
            "`VDSO_LIBRARY_DIR` must be set before building the initramfs".to_string(),
        ));
    }

    let initramfs_path = framevm_initramfs_path(workspace_root);
    let mut command = process::command("make");
    command
        .arg("--no-print-directory")
        .arg("-C")
        .arg(workspace_root.join("test/initramfs"))
        .arg(format!("TARGET_ARCH={}", config.target_arch))
        .arg(format!("FRAMEVM_OBJ_PATH={}", object.path.display()))
        .arg(format!(
            "FRAMEVM_INSTALL_PATH={}",
            build_config.install_path.display()
        ));

    process::run_status(
        command,
        "building framevm initramfs carrier",
        FrameVmStageError::Package,
    )?;

    if !initramfs_path.exists() {
        return Err(FrameVmStageError::Package(format!(
            "initramfs was not produced at {}",
            initramfs_path.display()
        )));
    }

    fs::metadata(&initramfs_path).map_err(|error| {
        FrameVmStageError::Package(format!(
            "failed to inspect initramfs {}: {error}",
            initramfs_path.display()
        ))
    })?;

    Ok(InitramfsArtifact {
        path: initramfs_path,
    })
}

pub(super) fn framevm_initramfs_path(workspace_root: &Path) -> PathBuf {
    workspace_root.join("test/initramfs/build/initramfs.cpio.gz")
}
