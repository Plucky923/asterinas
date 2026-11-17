// SPDX-License-Identifier: MPL-2.0

//! Runs kernelet guest images on a Linux Host.
//!
//! With the `kernelet` feature, `entry` initializes the image and calls Host
//! services instead of owning physical hardware. Both halves use [`abi`] for
//! entry tables, services, and shared per-vCPU records.

pub mod abi;
#[cfg(any(feature = "kernelet", ktest))]
pub(crate) mod dma;

#[cfg(any(feature = "kernelet", ktest))]
pub(crate) mod clock;

#[cfg(feature = "kernelet")]
pub mod entry;

#[cfg(feature = "kernelet")]
pub(crate) mod image_grant;
#[cfg(any(feature = "kernelet", ktest))]
mod initial_grant;
