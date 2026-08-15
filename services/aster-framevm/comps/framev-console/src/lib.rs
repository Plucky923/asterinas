// SPDX-License-Identifier: MPL-2.0

//! FrameV console frontend provider for the FrameVM service.

#![no_std]
#![deny(unsafe_code)]

use component::{ComponentInitError, init_component};
use framev_pci::FrameVPciError;

#[init_component(kthread)]
fn init() -> Result<(), ComponentInitError> {
    init_for_framevm_component_profile()
}

/// Initializes the FrameV console frontend in the FrameVM component profile.
pub fn init_for_framevm_component_profile() -> Result<(), ComponentInitError> {
    Ok(())
}

/// Writes bytes through the default `framev-console` provider.
pub fn write(input: &[u8]) -> Result<usize, FrameVPciError> {
    framev_pci::console()?.write(input)
}

/// Registers the input callback for the default `framev-console` provider.
pub fn register_input_callback(callback: fn(&[u8])) -> Result<(), FrameVPciError> {
    framev_pci::console()?.register_input_callback(callback)
}
