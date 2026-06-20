// SPDX-License-Identifier: MPL-2.0

//! Error types.

use crate::mm::page_table::PageTableError;

/// Error types for kernel operations.
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

impl From<host_ostd::Error> for Error {
    fn from(err: host_ostd::Error) -> Error {
        match err {
            host_ostd::Error::InvalidArgs => Error::InvalidArgs,
            host_ostd::Error::NoMemory => Error::NoMemory,
            host_ostd::Error::PageFault => Error::PageFault,
            host_ostd::Error::AccessDenied => Error::AccessDenied,
            host_ostd::Error::IoError => Error::IoError,
            host_ostd::Error::NotEnoughResources => Error::NotEnoughResources,
            host_ostd::Error::Overflow => Error::Overflow,
        }
    }
}

/// Initialize error module (no-op, kept for API compatibility).
pub(crate) fn init_error() {
    // Error types are statically defined, no runtime initialization needed.
}
