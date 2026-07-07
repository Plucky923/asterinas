// SPDX-License-Identifier: MPL-2.0

//! FrameV console device model contract.
//!
//! This crate defines the FrameV console protocol metadata, byte-buffer
//! resource, requests, completions, ring behavior, and class-local cleanup
//! helpers. FrameVisor-owned host console policy remains outside this crate.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

mod buffer;
mod cleanup;
mod completion;
mod metadata;
mod request;
mod ring;

pub use buffer::ConsoleByteBuffer;
pub use cleanup::{discard_completed_console_for_stop, resolve_submitted_console_reset};
pub use completion::{ConsoleCompletedSlot, ConsoleCompletion, ConsoleSubmittedSlot};
pub use metadata::{
    DEFAULT_DEVICE_ID, DEFAULT_IRQ_LINE, DEFAULT_NOTIFICATION_TARGET, RING_COUNT,
    default_device_info,
};
pub use request::{ConsoleDirection, ConsoleError, ConsoleRequest, ConsoleSubmittedRequest};
pub use ring::{ConsoleRing, ConsoleRingDirection, ConsoleRuntime, ConsoleSubmitError};

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
