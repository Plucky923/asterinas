//! FrameV RNG fill request types.
//!
//! This module defines RNG request validation, errors, and submitted fill
//! ownership behavior.

extern crate alloc;

use alloc::vec::Vec;

use framev_device::{
    CompletionInfo, OperationError, OperationResult, OwnedResource, ResourceResult,
    SubmittedResource, WriteOnly,
};

use crate::{
    buffer::RngOutputBuffer,
    completion::{RngCompletion, RngCompletionPayload},
};

/// A FrameV RNG device-class error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RngError {
    InvalidRequest,
    EmptyBuffer,
    InvalidCompletion,
    InvalidRingDepth,
}
/// A validated RNG fill request carrying exactly one output-buffer resource.
#[derive(Debug, Eq, PartialEq)]
pub struct RngFillRequest {
    output: OwnedResource<RngOutputBuffer>,
}

impl RngFillRequest {
    /// Creates an RNG fill request with exactly one output-buffer resource.
    pub fn new(mut outputs: Vec<OwnedResource<RngOutputBuffer>>) -> Result<Self, RngError> {
        if outputs.len() != 1 {
            return Err(RngError::InvalidRequest);
        }

        Ok(Self {
            output: outputs.remove(0),
        })
    }

    /// Returns the output-buffer capacity.
    pub fn capacity(&self) -> usize {
        self.output.value().capacity()
    }

    pub(crate) fn into_output(self) -> OwnedResource<RngOutputBuffer> {
        self.output
    }

    /// Transfers the output buffer to the backend as a write-only resource.
    pub fn submit(self) -> RngSubmittedFill {
        RngSubmittedFill {
            output: self.output.submit::<WriteOnly>(),
        }
    }
}

/// A backend-owned submitted RNG fill request.
#[derive(Debug, Eq, PartialEq)]
pub struct RngSubmittedFill {
    output: SubmittedResource<RngOutputBuffer, WriteOnly>,
}

impl RngSubmittedFill {
    /// Returns the output-buffer capacity.
    pub fn capacity(&mut self) -> usize {
        self.output.get_mut().capacity()
    }

    /// Fills the output buffer and returns completion state with the returned buffer.
    pub fn complete_success(
        mut self,
        random_bytes: &[u8],
    ) -> Result<(RngCompletion, OwnedResource<RngOutputBuffer>), RngError> {
        let bytes_written = self.output.get_mut().write_prefix(random_bytes)?;
        let returned = self.output.return_to_owner().reclaim();
        Ok((
            CompletionInfo::new(
                OperationResult::Ok,
                alloc::vec![ResourceResult::Returned],
                RngCompletionPayload::new(bytes_written),
            ),
            returned,
        ))
    }

    /// Fails the fill request and returns the output buffer by default.
    pub fn complete_error(
        self,
        error: OperationError<RngError>,
    ) -> (RngCompletion, OwnedResource<RngOutputBuffer>) {
        let returned = self.output.return_to_owner().reclaim();
        (
            CompletionInfo::new(
                OperationResult::Error(error),
                alloc::vec![ResourceResult::Returned],
                RngCompletionPayload::new(0),
            ),
            returned,
        )
    }
}
