// SPDX-License-Identifier: MPL-2.0

//! Owned input value shared by the FrameV console frontend and backend.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

mod buffer;

pub use buffer::ConsoleInput;

/// Maximum number of bytes transferred in one Host-to-FrameVM input value.
pub const MAX_INPUT_CHUNK_BYTES: usize = 4096;

/// Maximum number of unread console input bytes retained by FrameVisor.
pub const QUEUED_INPUT_CAPACITY_BYTES: usize = 4096;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
