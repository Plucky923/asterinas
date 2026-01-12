// SPDX-License-Identifier: MPL-2.0

//! Error types for FrameVisor operations.

use crate::mm::page_table::PageTableError;

/// Error types for FrameVisor operations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// Invalid arguments provided.
    InvalidArgs,
    /// Insufficient memory available.
    NoMemory,
    /// Page fault occurred.
    PageFault,
    /// Access to a resource is denied.
    AccessDenied,
    /// Input/output error.
    IoError,
    /// Insufficient system resources.
    NotEnoughResources,
    /// Arithmetic Overflow occurred.
    Overflow,
}

impl From<PageTableError> for Error {
    fn from(_err: PageTableError) -> Error {
        Error::AccessDenied
    }
}

impl From<ostd::Error> for Error {
    fn from(err: ostd::Error) -> Error {
        match err {
            ostd::Error::InvalidArgs => Error::InvalidArgs,
            ostd::Error::NoMemory => Error::NoMemory,
            ostd::Error::PageFault => Error::PageFault,
            ostd::Error::AccessDenied => Error::AccessDenied,
            ostd::Error::IoError => Error::IoError,
            ostd::Error::NotEnoughResources => Error::NotEnoughResources,
            ostd::Error::Overflow => Error::Overflow,
        }
    }
}

/// Initialize error module (no-op, kept for API compatibility).
pub fn init_error() {
    // Error types are statically defined, no runtime initialization needed.
}
