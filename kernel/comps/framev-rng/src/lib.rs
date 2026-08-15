// SPDX-License-Identifier: MPL-2.0

//! FrameV RNG protocol constants shared by the frontend and backend.

#![no_std]
#![deny(unsafe_code)]

/// Maximum number of bytes filled by one direct frontend call.
pub const MAX_FILL_BYTES: usize = 4096;

#[cfg(test)]
mod tests;
