//! QEMU-compatible command-line entry point for FrameVM management.

mod framevm_api;
mod qemu_compat;
mod runtime;

use std::process::ExitCode;

fn main() -> ExitCode {
    match qemu_compat::parse(std::env::args_os()) {
        Ok(configuration) => match runtime::run(configuration) {
            Ok(exit_code) => exit_code,
            Err(error) => {
                eprintln!("framevmm: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("framevmm: {error}");
            ExitCode::from(2)
        }
    }
}
