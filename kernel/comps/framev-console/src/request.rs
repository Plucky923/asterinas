//! FrameV console request types.
//!
//! This module defines console request direction, validation errors, and
//! submitted request ownership behavior.

extern crate alloc;

use alloc::vec::Vec;

use framev_device::{
    CompletionInfo, OperationError, OperationResult, OwnedResource, ReadOnly, ResourceResult,
    SubmittedResource,
};

use crate::{buffer::ConsoleByteBuffer, completion::ConsoleCompletion};

/// A FrameV console request direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleDirection {
    Output,
    Input,
}

/// A FrameV console device-class error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleError {
    InvalidRequest,
    EmptyBuffer,
    WrongDirection,
}
/// A validated console request carrying exactly one byte-buffer resource.
#[derive(Debug, Eq, PartialEq)]
pub struct ConsoleRequest {
    direction: ConsoleDirection,
    buffer: OwnedResource<ConsoleByteBuffer>,
}

impl ConsoleRequest {
    /// Creates a console request with exactly one byte-buffer resource.
    pub fn new(
        direction: ConsoleDirection,
        mut buffers: Vec<OwnedResource<ConsoleByteBuffer>>,
    ) -> Result<Self, ConsoleError> {
        if buffers.len() != 1 {
            return Err(ConsoleError::InvalidRequest);
        }

        let buffer = buffers.remove(0);
        Ok(Self { direction, buffer })
    }

    /// Returns the request direction.
    pub const fn direction(&self) -> ConsoleDirection {
        self.direction
    }

    /// Transfers the request buffer to the receiver as read-only consume-style data.
    pub fn submit(self) -> ConsoleSubmittedRequest {
        ConsoleSubmittedRequest {
            direction: self.direction,
            buffer: self.buffer.submit::<ReadOnly>(),
        }
    }
}

/// A submitted console request owned by the receiver.
#[derive(Debug, Eq, PartialEq)]
pub struct ConsoleSubmittedRequest {
    direction: ConsoleDirection,
    buffer: SubmittedResource<ConsoleByteBuffer, ReadOnly>,
}

impl ConsoleSubmittedRequest {
    /// Returns the request direction.
    pub const fn direction(&self) -> ConsoleDirection {
        self.direction
    }

    /// Returns read-only access to the submitted bytes.
    pub fn bytes(&self) -> &[u8] {
        self.buffer.get().bytes()
    }

    /// Completes the request successfully and consumes the byte buffer.
    pub fn complete_success(self) -> ConsoleCompletion {
        let _consumed = self.buffer.consume();
        CompletionInfo::new(
            OperationResult::Ok,
            alloc::vec![ResourceResult::Consumed],
            (),
        )
    }

    /// Fails the request and returns the byte buffer to the submitter.
    pub fn complete_error(
        self,
        error: OperationError<ConsoleError>,
    ) -> (ConsoleCompletion, OwnedResource<ConsoleByteBuffer>) {
        let returned = self.buffer.return_to_owner().reclaim();
        (
            CompletionInfo::new(
                OperationResult::Error(error),
                alloc::vec![ResourceResult::Returned],
                (),
            ),
            returned,
        )
    }
}
