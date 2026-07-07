// SPDX-License-Identifier: MPL-2.0

//! Process execution helpers for FrameVM build stages.

use std::{
    ffi::OsStr,
    path::Path,
    process::{Command, Stdio},
};

use crate::util::new_command_checked_exists;

use super::types::FrameVmStageError;

pub(super) fn command(program: impl AsRef<Path>) -> Command {
    new_command_checked_exists(program)
}

pub(super) fn run_status(
    mut command: Command,
    purpose: &'static str,
    error_fn: fn(String) -> FrameVmStageError,
) -> Result<(), FrameVmStageError> {
    command.stdout(Stdio::inherit()).stderr(Stdio::piped());
    let output = command
        .output()
        .map_err(|error| error_fn(format!("failed to start {purpose}: {error}")))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(error_fn(format!(
        "{purpose} exited with status {:?}: {}",
        output.status.code(),
        stderr.trim()
    )))
}

pub(super) fn capture_stdout<I, S>(
    program: &str,
    args: I,
    purpose: &'static str,
    error_fn: fn(String) -> FrameVmStageError,
) -> Result<String, FrameVmStageError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = command(program)
        .args(args)
        .output()
        .map_err(|error| error_fn(format!("failed to start {purpose}: {error}")))?;

    if !output.status.success() {
        return Err(error_fn(format!(
            "{purpose} exited with status {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
