//! FrameV RNG ring and lifecycle-light runtime wrappers.
//!
//! This module defines nonblocking RNG ring submission, bounded synchronous fill
//! completion, notification helpers, and a small lifecycle-backed RNG wrapper
//! that remains independent of FrameVisor host RNG policy.

extern crate alloc;

use alloc::vec::Vec;

use framev_device::{
    CommonError, CompletionInfo, ControlPathAuthority, DeviceGeneration, DeviceState, DeviceStatus,
    FrameVDeviceError, IrqAccepted, IrqDelivery, OperationError, OperationResult, OwnedResource,
    ResourceResult, RingSlot, SubmitOutcome,
};

use crate::{
    RngCompletionPayload,
    completion::{RngCompletedFill, RngSubmitOutcome, RngSubmittedSlot},
    metadata::{DEFAULT_IRQ_LINE, DEFAULT_NOTIFICATION_TARGET, MIN_RING_DEPTH},
    request::{RngError, RngFillRequest},
};

/// An RNG submit failure that preserves request ownership.
#[derive(Debug, Eq, PartialEq)]
pub struct RngSubmitError {
    error: OperationError<RngError>,
    request: RngFillRequest,
}

impl RngSubmitError {
    /// Returns the submit error.
    pub const fn error(&self) -> &OperationError<RngError> {
        &self.error
    }

    /// Returns the unsubmitted request to the caller.
    pub fn into_request(self) -> RngFillRequest {
        self.request
    }
}

/// A small nonblocking RNG request ring model for the device-class protocol.
#[derive(Debug, Eq, PartialEq)]
pub struct RngRing {
    depth: usize,
    free_slots: Vec<RingSlot<framev_device::Free>>,
}

impl RngRing {
    /// Creates an RNG request ring with a fixed ready-time depth.
    pub fn new(depth: usize) -> Result<Self, RngError> {
        if depth < MIN_RING_DEPTH {
            return Err(RngError::InvalidRingDepth);
        }

        let mut free_slots = Vec::new();
        for index in 0..depth {
            free_slots.push(RingSlot::new(index));
        }

        Ok(Self { depth, free_slots })
    }

    /// Returns the stable ring depth.
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// Returns the number of currently free slots.
    pub fn free_len(&self) -> usize {
        self.free_slots.len()
    }

    /// Submits an RNG fill request without blocking.
    pub fn submit(&mut self, request: RngFillRequest) -> Result<RngSubmittedSlot, RngSubmitError> {
        let Some(free_slot) = self.free_slots.pop() else {
            return Err(RngSubmitError {
                error: OperationError::Common(CommonError::Full),
                request,
            });
        };

        Ok(free_slot.prepare(request.submit()).submit())
    }

    /// Returns a submitted-later outcome for an accepted request.
    pub fn submit_outcome(
        &mut self,
        request: RngFillRequest,
    ) -> Result<RngSubmitOutcome, RngSubmitError> {
        self.submit(request).map(SubmitOutcome::Submitted)
    }

    /// Submits an RNG fill and completes synchronously when valid bytes are immediately available.
    pub fn submit_with_immediate_fill(
        &mut self,
        request: RngFillRequest,
        immediate_random_bytes: Option<&[u8]>,
    ) -> Result<RngSubmitOutcome, RngSubmitError> {
        if let Some(random_bytes) = immediate_random_bytes
            && !random_bytes.is_empty()
            && random_bytes.len() <= request.capacity()
        {
            let Some(free_slot) = self.free_slots.pop() else {
                return Err(RngSubmitError {
                    error: OperationError::Common(CommonError::Full),
                    request,
                });
            };
            let mut output = request.into_output().into_inner();
            let bytes_written = output.write_valid_prefix(random_bytes);
            let completion = CompletionInfo::new(
                OperationResult::Ok,
                alloc::vec![ResourceResult::Returned],
                RngCompletionPayload::new(bytes_written),
            );
            self.free_slots.push(free_slot);
            return Ok(SubmitOutcome::Completed(RngCompletedFill::new(
                completion,
                OwnedResource::new(output),
            )));
        }

        self.submit(request).map(SubmitOutcome::Submitted)
    }

    /// Notifies the frontend after one or more async completions are visible.
    pub fn notify_completion<N: IrqDelivery<Error = CommonError>>(
        &self,
        notifier: &N,
    ) -> Result<IrqAccepted, CommonError> {
        notifier.notify_irq(DEFAULT_IRQ_LINE, DEFAULT_NOTIFICATION_TARGET)
    }
}

/// A ready FrameV RNG runtime backed by common lifecycle state.
#[derive(Debug, Eq, PartialEq)]
pub struct RngRuntime {
    control: DeviceState,
    ring: RngRing,
}

impl RngRuntime {
    /// Creates a ready RNG runtime with fixed ready-time topology.
    pub fn new(depth: usize) -> framev_device::Result<Self> {
        let ring =
            RngRing::new(depth).map_err(|_| FrameVDeviceError::InvalidLifecycleTransition)?;
        let mut control = DeviceState::new();
        control.set_status(DeviceStatus::Ready)?;
        Ok(Self { control, ring })
    }

    /// Returns the stable request-ring depth.
    pub const fn depth(&self) -> usize {
        self.ring.depth()
    }

    /// Submits an RNG fill after common lifecycle validation.
    pub fn submit(&mut self, request: RngFillRequest) -> Result<RngSubmittedSlot, RngSubmitError> {
        self.ensure_data_path_ready(request)
            .and_then(|request| self.ring.submit(request))
    }

    /// Submits an RNG fill and allows bounded synchronous completion.
    pub fn submit_with_immediate_fill(
        &mut self,
        request: RngFillRequest,
        immediate_random_bytes: Option<&[u8]>,
    ) -> Result<RngSubmitOutcome, RngSubmitError> {
        self.ensure_data_path_ready(request).and_then(|request| {
            self.ring
                .submit_with_immediate_fill(request, immediate_random_bytes)
        })
    }

    /// Starts a reset barrier.
    pub fn begin_reset(
        &mut self,
    ) -> framev_device::Result<(DeviceGeneration, ControlPathAuthority)> {
        self.control.begin_reset()
    }

    /// Finishes reset cleanup.
    pub fn finish_reset(
        &mut self,
        generation: DeviceGeneration,
        authority: ControlPathAuthority,
    ) -> framev_device::Result<()> {
        self.control.finish_reset(generation, authority)
    }

    /// Stops the runtime.
    pub fn stop(&mut self) {
        self.control.stop();
    }

    fn ensure_data_path_ready(
        &self,
        request: RngFillRequest,
    ) -> Result<RngFillRequest, RngSubmitError> {
        match self.control.ensure_ready() {
            Ok(()) => Ok(request),
            Err(error) => Err(RngSubmitError {
                error: OperationError::Common(error),
                request,
            }),
        }
    }
}
