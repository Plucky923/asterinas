// SPDX-License-Identifier: MPL-2.0

//! Common FrameV block-device protocol types.
//!
//! FrameV-blk models the virtio-blk operation and status meanings needed by
//! the first raw-root-disk target. Transport ownership remains private to the
//! concrete frontend and backend.

#![no_std]
#![deny(unsafe_code)]

mod config;
mod status;

pub use config::{FrameVBlkConfig, FrameVBlkConfigError, FrameVBlkConfigFlags};
pub use status::FrameVBlkStatus;

/// The FrameV block sector size in bytes.
pub const FRAMEV_BLK_SECTOR_SIZE: u64 = 512;

/// Maximum number of non-empty scatter/gather extents in one block operation.
pub const FRAMEV_BLK_MAX_EXTENTS: usize = 32;

#[cfg(test)]
mod tests;
