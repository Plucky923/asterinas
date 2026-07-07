//! FrameV console byte-buffer resources.
//!
//! This module defines the non-empty byte buffer transferred by console input
//! and output requests.

extern crate alloc;

use alloc::vec::Vec;

use crate::request::ConsoleError;

/// A concrete FrameV console byte-buffer resource.
#[derive(Debug, Eq, PartialEq)]
pub struct ConsoleByteBuffer {
    bytes: Vec<u8>,
}

impl ConsoleByteBuffer {
    /// Creates a non-empty console byte-buffer resource.
    pub fn new(bytes: Vec<u8>) -> Result<Self, ConsoleError> {
        if bytes.is_empty() {
            return Err(ConsoleError::EmptyBuffer);
        }
        Ok(Self { bytes })
    }

    /// Returns the transported bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the resource and returns the transported bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
