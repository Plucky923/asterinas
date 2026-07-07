// SPDX-License-Identifier: MPL-2.0

//! Common FrameV block-device protocol types.
//!
//! FrameV-blk models the virtio-blk operation and status meanings needed by
//! the first raw-root-disk target while keeping transport ownership in the
//! common FrameV device model.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

mod completion;
mod config;
mod metadata;
mod request;

pub use completion::{
    FrameVBlkBioStatusIntent, FrameVBlkCompletion, FrameVBlkDeviceError, FrameVBlkStatus,
    data_completion, flush_completion,
};
pub use config::{FrameVBlkConfig, FrameVBlkConfigError, FrameVBlkConfigFlags};
pub use metadata::{
    DEFAULT_DEVICE_ID, DEFAULT_IRQ_LINE, FRAMEV_BLK_QUEUE_COUNT, FRAMEV_BLK_SECTOR_SIZE,
    FrameVBlkDeviceMetadata, default_device_info,
};
pub use request::{
    FrameVBlkOp, FrameVBlkRequestError, FrameVBlkRequestHeader, FrameVBlkResourceShape,
};

#[cfg(test)]
mod tests;
