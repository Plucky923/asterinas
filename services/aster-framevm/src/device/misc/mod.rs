// SPDX-License-Identifier: MPL-2.0

//! Misc devices.

mod hwrng;

pub(crate) use hwrng::{getrandom, getrandom_bytes, geturandom};

/// Initializes misc device providers used by copied kernel code.
pub(crate) fn init() -> crate::error::Result<()> {
    hwrng::init()
}
