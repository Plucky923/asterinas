//! FrameV RNG completion types.
//!
//! This module maps RNG fill completion payloads and slot state onto common
//! FrameV completion and submit-outcome types.

use framev_device::{CompletionInfo, OwnedResource, RingSlot, SubmitOutcome};

use crate::{
    buffer::RngOutputBuffer,
    request::{RngError, RngSubmittedFill},
};

/// A successful RNG fill payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RngCompletionPayload {
    bytes_written: usize,
}

impl RngCompletionPayload {
    /// Creates an RNG completion payload.
    pub fn new(bytes_written: usize) -> Self {
        Self { bytes_written }
    }

    /// Returns the number of valid bytes written into the output buffer.
    pub const fn bytes_written(self) -> usize {
        self.bytes_written
    }
}
/// RNG completion info.
pub type RngCompletion = CompletionInfo<RngCompletionPayload, RngError>;

/// A submitted RNG slot.
pub type RngSubmittedSlot = RingSlot<framev_device::Submitted, RngSubmittedFill>;

/// A completed RNG slot.
pub type RngCompletedSlot = RingSlot<framev_device::Completed, RngSubmittedFill, RngCompletion>;
/// A synchronously completed RNG fill.
#[derive(Debug, Eq, PartialEq)]
pub struct RngCompletedFill {
    completion: RngCompletion,
    output: OwnedResource<RngOutputBuffer>,
}

impl RngCompletedFill {
    /// Creates a synchronously completed RNG fill.
    pub fn new(completion: RngCompletion, output: OwnedResource<RngOutputBuffer>) -> Self {
        Self { completion, output }
    }

    /// Returns completion info.
    pub const fn completion(&self) -> &RngCompletion {
        &self.completion
    }

    /// Consumes this completion and returns completion plus output buffer.
    pub fn into_parts(self) -> (RngCompletion, OwnedResource<RngOutputBuffer>) {
        (self.completion, self.output)
    }
}

/// RNG submit success outcome.
pub type RngSubmitOutcome = SubmitOutcome<RngSubmittedSlot, RngCompletedFill>;
