// SPDX-License-Identifier: MPL-2.0

//! FrameV RNG device model contract.
//!
//! This crate defines the FrameV RNG protocol metadata, output-buffer resource,
//! fill requests, completions, ring behavior, and class-local cleanup helpers.
//! FrameVisor-owned host RNG batching and retry policy remain outside this crate.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

mod buffer;
mod cleanup;
mod completion;
mod metadata;
mod request;
mod ring;

pub use buffer::RngOutputBuffer;
pub use cleanup::{discard_completed_rng_for_stop, resolve_submitted_rng_reset};
pub use completion::{
    RngCompletedFill, RngCompletedSlot, RngCompletion, RngCompletionPayload, RngSubmitOutcome,
    RngSubmittedSlot,
};
pub use metadata::{
    DEFAULT_DEVICE_ID, DEFAULT_IRQ_LINE, DEFAULT_NOTIFICATION_TARGET, MIN_RING_DEPTH, RING_COUNT,
    default_device_info,
};
pub use request::{RngError, RngFillRequest, RngSubmittedFill};
pub use ring::{RngRing, RngRuntime, RngSubmitError};

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
