//! FrameV RNG output-buffer resources.
//!
//! This module defines the write-only output buffer transferred by RNG fill
//! requests.

extern crate alloc;

use alloc::vec::Vec;

use crate::request::RngError;

/// A concrete FrameV RNG output-buffer resource.
#[derive(Debug, Eq, PartialEq)]
pub struct RngOutputBuffer {
    bytes: Vec<u8>,
}

impl RngOutputBuffer {
    /// Creates an output buffer with nonzero capacity.
    pub fn new(capacity: usize) -> Result<Self, RngError> {
        if capacity == 0 {
            return Err(RngError::EmptyBuffer);
        }

        Ok(Self {
            bytes: alloc::vec![0; capacity],
        })
    }

    /// Returns the buffer capacity.
    pub fn capacity(&self) -> usize {
        self.bytes.len()
    }

    /// Writes random bytes into the output buffer without reading previous contents.
    pub fn write_prefix(&mut self, random_bytes: &[u8]) -> Result<usize, RngError> {
        if random_bytes.is_empty() || random_bytes.len() > self.capacity() {
            return Err(RngError::InvalidCompletion);
        }

        Ok(self.write_valid_prefix(random_bytes))
    }

    pub(crate) fn write_valid_prefix(&mut self, random_bytes: &[u8]) -> usize {
        debug_assert!(!random_bytes.is_empty());
        debug_assert!(random_bytes.len() <= self.capacity());
        self.bytes[..random_bytes.len()].copy_from_slice(random_bytes);
        random_bytes.len()
    }

    /// Consumes the output buffer and returns all backing bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
