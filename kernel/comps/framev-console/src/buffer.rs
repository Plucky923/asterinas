//! Owned FrameV console input.

extern crate alloc;

use alloc::vec::Vec;

use crate::MAX_INPUT_CHUNK_BYTES;

/// Owned input published by the Host and taken by the FrameVM frontend.
#[derive(Debug, Eq, PartialEq)]
pub struct ConsoleInput {
    bytes: Vec<u8>,
}

impl ConsoleInput {
    /// Creates non-empty owned console input within one input chunk.
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > MAX_INPUT_CHUNK_BYTES {
            return None;
        }
        Some(Self { bytes })
    }

    /// Returns the input bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the input and returns its byte allocation.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
