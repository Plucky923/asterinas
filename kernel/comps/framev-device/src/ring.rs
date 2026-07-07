//! FrameV ring slot typestates.
//!
//! This module defines common free, submitted, completed, reclaim, poll, and
//! cleanup transitions for ring-style device-class data paths.

use core::marker::PhantomData;

use crate::error::{FrameVDeviceError, Result};

/// A free ring slot marker.
#[derive(Debug, Eq, PartialEq)]
pub struct Free;

/// A submitted ring slot marker.
#[derive(Debug, Eq, PartialEq)]
pub struct Submitted;

/// A completed ring slot marker.
#[derive(Debug, Eq, PartialEq)]
pub struct Completed;

/// A common typestate wrapper for a FrameV ring slot.
#[derive(Debug, Eq, PartialEq)]
pub struct RingSlot<State, Request = (), Completion = ()> {
    index: usize,
    request: Option<Request>,
    completion: Option<Completion>,
    state: PhantomData<State>,
}

impl RingSlot<Free> {
    /// Creates a free ring slot.
    pub const fn new(index: usize) -> Self {
        Self {
            index,
            request: None,
            completion: None,
            state: PhantomData,
        }
    }

    /// Returns the ring slot index.
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Writes request state into a free slot.
    pub fn prepare<Request>(self, request: Request) -> RingSlot<Free, Request> {
        RingSlot {
            index: self.index,
            request: Some(request),
            completion: None,
            state: PhantomData,
        }
    }
}

impl<Request> RingSlot<Free, Request> {
    /// Publishes a free slot to the receiver.
    pub fn submit(self) -> RingSlot<Submitted, Request> {
        RingSlot {
            index: self.index,
            request: self.request,
            completion: None,
            state: PhantomData,
        }
    }
}

impl<Request, Completion> RingSlot<Submitted, Request, Completion> {
    /// Returns the ring slot index.
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Borrows the submitted request.
    pub fn request(&self) -> Result<&Request> {
        self.request
            .as_ref()
            .ok_or(FrameVDeviceError::InvalidLifecycleTransition)
    }

    /// Completes a submitted slot.
    pub fn complete<NewCompletion>(
        self,
        completion: NewCompletion,
    ) -> RingSlot<Completed, Request, NewCompletion> {
        RingSlot {
            index: self.index,
            request: self.request,
            completion: Some(completion),
            state: PhantomData,
        }
    }
}

impl<Request, Completion> RingSlot<Completed, Request, Completion> {
    /// Returns the ring slot index.
    pub const fn index(&self) -> usize {
        self.index
    }

    /// Borrows the completion.
    pub fn completion(&self) -> Result<&Completion> {
        self.completion
            .as_ref()
            .ok_or(FrameVDeviceError::InvalidLifecycleTransition)
    }

    /// Reclaims the completed slot and consumes the completion state.
    pub fn reclaim(self) -> Result<ReclaimOutcome<Request, Completion>> {
        let Some(request) = self.request else {
            return Err(FrameVDeviceError::InvalidLifecycleTransition);
        };
        let Some(completion) = self.completion else {
            return Err(FrameVDeviceError::InvalidLifecycleTransition);
        };

        Ok(ReclaimOutcome {
            free_slot: RingSlot::new(self.index),
            request,
            completion,
        })
    }
}

/// The result of reclaiming a completed ring slot.
#[derive(Debug, Eq, PartialEq)]
pub struct ReclaimOutcome<Request, Completion> {
    free_slot: RingSlot<Free>,
    request: Request,
    completion: Completion,
}

impl<Request, Completion> ReclaimOutcome<Request, Completion> {
    /// Returns the reclaimed free slot.
    pub fn free_slot(self) -> RingSlot<Free> {
        self.free_slot
    }

    /// Splits the reclaim outcome into its parts.
    pub fn into_parts(self) -> (RingSlot<Free>, Request, Completion) {
        (self.free_slot, self.request, self.completion)
    }
}

/// A submit success outcome.
#[derive(Debug, Eq, PartialEq)]
pub enum SubmitOutcome<SubmittedState, CompletedState> {
    Submitted(SubmittedState),
    Completed(CompletedState),
}

/// A poll outcome for handle-based completion observation.
#[derive(Debug, Eq, PartialEq)]
pub enum PollOutcome<SubmittedState, CompletedState> {
    Pending(SubmittedState),
    Completed(CompletedState),
}

/// A reclaim outcome for reset or stop cleanup.
#[derive(Debug, Eq, PartialEq)]
pub struct CleanupOutcome<State, Request, Completion = ()> {
    free_slot: RingSlot<Free>,
    state: State,
    request: Request,
    completion: Option<Completion>,
}

impl<State, Request, Completion> CleanupOutcome<State, Request, Completion> {
    /// Splits the cleanup outcome into its parts.
    pub fn into_parts(self) -> (RingSlot<Free>, State, Request, Option<Completion>) {
        (self.free_slot, self.state, self.request, self.completion)
    }
}

/// Reset cleanup state for an in-flight slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupState {
    Submitted,
    Completed,
}

impl<Request, Completion> RingSlot<Submitted, Request, Completion> {
    /// Observes a submitted slot without completing it.
    pub fn poll_pending(self) -> PollOutcome<Self, RingSlot<Completed, Request, Completion>> {
        PollOutcome::Pending(self)
    }

    /// Drains a submitted slot during reset or stop cleanup.
    pub fn cleanup(self) -> Result<CleanupOutcome<CleanupState, Request, Completion>> {
        let Some(request) = self.request else {
            return Err(FrameVDeviceError::InvalidLifecycleTransition);
        };

        Ok(CleanupOutcome {
            free_slot: RingSlot::new(self.index),
            state: CleanupState::Submitted,
            request,
            completion: None,
        })
    }
}

impl<Request, Completion> RingSlot<Completed, Request, Completion> {
    /// Drains a completed slot during reset or stop cleanup.
    pub fn cleanup(self) -> Result<CleanupOutcome<CleanupState, Request, Completion>> {
        let Some(request) = self.request else {
            return Err(FrameVDeviceError::InvalidLifecycleTransition);
        };
        let Some(completion) = self.completion else {
            return Err(FrameVDeviceError::InvalidLifecycleTransition);
        };

        Ok(CleanupOutcome {
            free_slot: RingSlot::new(self.index),
            state: CleanupState::Completed,
            request,
            completion: Some(completion),
        })
    }
}
