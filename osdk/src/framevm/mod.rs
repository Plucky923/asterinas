// SPDX-License-Identifier: MPL-2.0

//! OSDK-owned FrameVM artifact build and run transactions.

mod host;
mod identity;
mod imports;
mod metadata;
mod object;
mod package;
mod policy;
mod process;
mod report;
mod retention;
mod rustflags;
mod symbols;
mod transaction;
mod types;

pub use self::types::{
    DEFAULT_LOAD_INIT_PATH, FrameVmBuildConfig, FrameVmBuildOutcome, FrameVmLoadAction,
    FrameVmRunConfig, FrameVmRunOutcome, FrameVmStageError,
};

pub fn build(config: FrameVmBuildConfig) -> Result<FrameVmBuildOutcome, FrameVmStageError> {
    transaction::FrameVmTransaction::new(config)?.build_artifact_set()
}

pub fn run(config: FrameVmRunConfig) -> Result<FrameVmRunOutcome, FrameVmStageError> {
    transaction::FrameVmTransaction::new(config.build)?.run_artifact_set(config.no_build)
}
