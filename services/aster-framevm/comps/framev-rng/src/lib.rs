// SPDX-License-Identifier: MPL-2.0

//! FrameV RNG frontend provider for the FrameVM service.

#![no_std]
#![deny(unsafe_code)]

use component::{ComponentInitError, init_component};
use framev_bus::FrameVBusError;

#[init_component(kthread)]
fn init() -> Result<(), ComponentInitError> {
    init_for_framevm_component_profile()
}

/// Initializes the FrameV RNG frontend in the FrameVM component profile.
pub fn init_for_framevm_component_profile() -> Result<(), ComponentInitError> {
    Ok(())
}

/// Fills `dst` through the default `framev-rng` provider.
pub fn fill_bytes(dst: &mut [u8]) -> Result<(), FrameVBusError> {
    framev_bus::rng()?.fill_bytes(dst)
}
