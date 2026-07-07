// SPDX-License-Identifier: MPL-2.0

//! Command dispatch for the OSDK FrameVM workflow.

use std::{path::Path, process};

use crate::{
    cli::{FrameVmArgs, FrameVmBuildArgs, FrameVmCommand, FrameVmRunArgs},
    config::Config,
    error::Errno,
    error_msg,
    framevm::{
        self, DEFAULT_LOAD_INIT_PATH, FrameVmBuildConfig, FrameVmLoadAction, FrameVmRunConfig,
    },
};

pub fn execute_framevm_command(config: &Config, args: &FrameVmArgs) {
    let result = match &args.command {
        FrameVmCommand::Build(args) => framevm::build(build_config(config, args)).map(|outcome| {
            info!(
                "framevm artifacts ready: object={}, symbols={}, initramfs={}, bundle={}",
                outcome.object.display(),
                outcome.symbols.display(),
                outcome.initramfs.display(),
                outcome.bundle.display()
            );
        }),
        FrameVmCommand::Run(args) => framevm::run(run_config(config, args)).map(|outcome| {
            if outcome.success_markers.is_empty() {
                info!("framevm interactive run completed");
            } else {
                info!(
                    "framevm load success markers observed: {}",
                    outcome.success_markers.join(", ")
                );
            }
        }),
    };

    if let Err(error) = result {
        error_msg!("{}", error);
        process::exit(Errno::ExecuteCommand as _);
    }
}

fn build_config(config: &Config, args: &FrameVmBuildArgs) -> FrameVmBuildConfig {
    FrameVmBuildConfig {
        osdk_config: config.clone(),
        target: args.framevm.target.clone(),
        object_output: args.framevm.object_output.clone(),
        install_path: args.framevm.install_path.clone(),
        features: args.framevm.features.clone(),
        no_default_features: args.framevm.no_default_features,
        skip_service_check: args.framevm.skip_service_check,
        load_action: FrameVmLoadAction::Default,
    }
}

fn run_config(config: &Config, args: &FrameVmRunArgs) -> FrameVmRunConfig {
    let load_action = if args.load_init.as_path() == Path::new(DEFAULT_LOAD_INIT_PATH) {
        FrameVmLoadAction::Default
    } else {
        FrameVmLoadAction::Script(args.load_init.clone())
    };

    FrameVmRunConfig {
        build: FrameVmBuildConfig {
            osdk_config: config.clone(),
            target: args.framevm.target.clone(),
            object_output: args.framevm.object_output.clone(),
            install_path: args.framevm.install_path.clone(),
            features: args.framevm.features.clone(),
            no_default_features: args.framevm.no_default_features,
            skip_service_check: args.framevm.skip_service_check,
            load_action,
        },
        no_build: args.no_build,
    }
}
