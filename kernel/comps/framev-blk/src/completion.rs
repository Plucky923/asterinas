// SPDX-License-Identifier: MPL-2.0

//! FrameV-blk completion status and resource-result mapping.

use alloc::vec;

use framev_device::{CompletionInfo, OperationError, OperationResult, ResourceResult};

/// Virtio-blk-style FrameV-blk operation status.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVBlkStatus {
    /// Operation completed successfully.
    Ok = 0,
    /// Operation failed due to I/O, validation, readonly, or malformed input.
    IoErr = 1,
    /// Operation is unsupported in v1.
    Unsupported = 2,
}

impl FrameVBlkStatus {
    /// Returns the raw ABI value.
    pub const fn raw(self) -> u8 {
        self as u8
    }

    /// Converts this block status to the common operation result.
    pub const fn operation_result(self) -> OperationResult<FrameVBlkDeviceError> {
        match self {
            Self::Ok => OperationResult::Ok,
            Self::IoErr => OperationResult::Error(OperationError::Device(FrameVBlkDeviceError::Io)),
            Self::Unsupported => {
                OperationResult::Error(OperationError::Device(FrameVBlkDeviceError::Unsupported))
            }
        }
    }
}

/// FrameV-blk device-class operation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVBlkDeviceError {
    Io,
    Unsupported,
}

/// Side-neutral BIO completion mapping intent for FrameV-blk frontends.
///
/// The common crate cannot depend on service-side `aster-block`, so this enum
/// records the intended upper-block status without importing `BioStatus`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVBlkBioStatusIntent {
    Complete,
    IoError,
    NotSupported,
}

impl FrameVBlkStatus {
    /// Returns the service-side block-layer status intent for this completion.
    pub const fn bio_status_intent(self) -> FrameVBlkBioStatusIntent {
        match self {
            Self::Ok => FrameVBlkBioStatusIntent::Complete,
            Self::IoErr => FrameVBlkBioStatusIntent::IoError,
            Self::Unsupported => FrameVBlkBioStatusIntent::NotSupported,
        }
    }
}

/// FrameV-blk completion information.
pub type FrameVBlkCompletion = CompletionInfo<FrameVBlkStatus, FrameVBlkDeviceError>;

/// Creates a read or write completion.
pub fn data_completion(status: FrameVBlkStatus) -> FrameVBlkCompletion {
    CompletionInfo::new(
        status.operation_result(),
        vec![ResourceResult::Returned],
        status,
    )
}

/// Creates a flush completion.
pub fn flush_completion(status: FrameVBlkStatus) -> FrameVBlkCompletion {
    CompletionInfo::new(status.operation_result(), vec![], status)
}
