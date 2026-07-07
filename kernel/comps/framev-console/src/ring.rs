//! FrameV console ring and lifecycle-light runtime wrappers.
//!
//! This module defines console ring direction, nonblocking ring submission,
//! completion notification helpers, and a small lifecycle-backed console wrapper
//! that remains independent of FrameVisor host integration policy.

extern crate alloc;

use alloc::vec::Vec;

use framev_device::{
    CommonError, CompletionInfo, ControlPathAuthority, DeviceGeneration, DeviceState, DeviceStatus,
    IrqAccepted, IrqDelivery, OperationError, OperationResult, PollOutcome, ResourceResult,
    RingSlot,
};

use crate::{
    completion::{ConsoleCompletedSlot, ConsoleSubmittedSlot},
    metadata::{DEFAULT_IRQ_LINE, DEFAULT_NOTIFICATION_TARGET},
    request::{ConsoleDirection, ConsoleError, ConsoleRequest},
};

/// A FrameV console ring direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleRingDirection {
    FrontendToBackendOutput,
    BackendToFrontendInput,
}

impl ConsoleRingDirection {
    /// Returns the request direction carried by this ring.
    pub const fn request_direction(self) -> ConsoleDirection {
        match self {
            Self::FrontendToBackendOutput => ConsoleDirection::Output,
            Self::BackendToFrontendInput => ConsoleDirection::Input,
        }
    }
}
/// A console submit failure that preserves request ownership.
#[derive(Debug, Eq, PartialEq)]
pub struct ConsoleSubmitError {
    error: OperationError<ConsoleError>,
    request: ConsoleRequest,
}

impl ConsoleSubmitError {
    /// Returns the submit error.
    pub const fn error(&self) -> &OperationError<ConsoleError> {
        &self.error
    }

    /// Returns the unsubmitted request to the caller.
    pub fn into_request(self) -> ConsoleRequest {
        self.request
    }
}

/// A small nonblocking console ring model for the device-class protocol.
#[derive(Debug, Eq, PartialEq)]
pub struct ConsoleRing {
    direction: ConsoleRingDirection,
    depth: usize,
    free_slots: Vec<RingSlot<framev_device::Free>>,
}

impl ConsoleRing {
    /// Creates a console ring with a fixed ready-time depth.
    pub fn new(direction: ConsoleRingDirection, depth: usize) -> Self {
        let mut free_slots = Vec::new();
        for index in 0..depth {
            free_slots.push(RingSlot::new(index));
        }
        Self {
            direction,
            depth,
            free_slots,
        }
    }

    /// Returns the stable ring direction.
    pub const fn direction(&self) -> ConsoleRingDirection {
        self.direction
    }

    /// Returns the stable ready-time ring depth.
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// Returns the number of currently free slots.
    pub fn free_len(&self) -> usize {
        self.free_slots.len()
    }

    /// Submits a console request without blocking.
    pub fn submit(
        &mut self,
        request: ConsoleRequest,
    ) -> Result<ConsoleSubmittedSlot, ConsoleSubmitError> {
        if request.direction() != self.direction.request_direction() {
            return Err(ConsoleSubmitError {
                error: OperationError::Device(ConsoleError::WrongDirection),
                request,
            });
        }

        let Some(free_slot) = self.free_slots.pop() else {
            return Err(ConsoleSubmitError {
                error: OperationError::Common(CommonError::Full),
                request,
            });
        };

        Ok(free_slot.prepare(request.submit()).submit())
    }

    /// Completes a submitted slot successfully.
    pub fn complete_success(&mut self, slot: ConsoleSubmittedSlot) -> ConsoleCompletedSlot {
        let completion = CompletionInfo::new(
            OperationResult::Ok,
            alloc::vec![ResourceResult::Consumed],
            (),
        );
        slot.complete(completion)
    }

    /// Completes the slot only when the receiver can accept the full buffer.
    pub fn complete_when_accepted(
        &mut self,
        slot: ConsoleSubmittedSlot,
        receiver_accepts_full_buffer: bool,
    ) -> PollOutcome<ConsoleSubmittedSlot, ConsoleCompletedSlot> {
        if !receiver_accepts_full_buffer {
            return PollOutcome::Pending(slot);
        }

        PollOutcome::Completed(self.complete_success(slot))
    }

    /// Submits backend input and notifies the frontend after publication.
    pub fn submit_input_and_notify<N: IrqDelivery<Error = CommonError>>(
        &mut self,
        request: ConsoleRequest,
        notifier: &N,
    ) -> Result<(ConsoleSubmittedSlot, Result<IrqAccepted, CommonError>), ConsoleSubmitError> {
        let slot = self.submit(request)?;
        let notification = notifier.notify_irq(DEFAULT_IRQ_LINE, DEFAULT_NOTIFICATION_TARGET);
        Ok((slot, notification))
    }

    /// Notifies the submitter after completion state is visible.
    pub fn notify_completion<N: IrqDelivery<Error = CommonError>>(
        &self,
        notifier: &N,
    ) -> Result<IrqAccepted, CommonError> {
        notifier.notify_irq(DEFAULT_IRQ_LINE, DEFAULT_NOTIFICATION_TARGET)
    }
}

/// A ready FrameV console runtime backed by common lifecycle state.
#[derive(Debug, Eq, PartialEq)]
pub struct ConsoleRuntime {
    control: DeviceState,
    output_ring: ConsoleRing,
    input_ring: ConsoleRing,
}

impl ConsoleRuntime {
    /// Creates a ready console runtime with fixed ready-time topology.
    pub fn new(output_depth: usize, input_depth: usize) -> framev_device::Result<Self> {
        let mut control = DeviceState::new();
        control.set_status(DeviceStatus::Ready)?;
        Ok(Self {
            control,
            output_ring: ConsoleRing::new(
                ConsoleRingDirection::FrontendToBackendOutput,
                output_depth,
            ),
            input_ring: ConsoleRing::new(ConsoleRingDirection::BackendToFrontendInput, input_depth),
        })
    }

    /// Returns the stable output-ring depth.
    pub const fn output_depth(&self) -> usize {
        self.output_ring.depth()
    }

    /// Returns the stable input-ring depth.
    pub const fn input_depth(&self) -> usize {
        self.input_ring.depth()
    }

    /// Submits console output after common lifecycle validation.
    pub fn submit_output(
        &mut self,
        request: ConsoleRequest,
    ) -> Result<ConsoleSubmittedSlot, ConsoleSubmitError> {
        self.ensure_data_path_ready(request)
            .and_then(|request| self.output_ring.submit(request))
    }

    /// Submits console input and notifies after common lifecycle validation.
    pub fn submit_input_and_notify<N: IrqDelivery<Error = CommonError>>(
        &mut self,
        request: ConsoleRequest,
        notifier: &N,
    ) -> Result<(ConsoleSubmittedSlot, Result<IrqAccepted, CommonError>), ConsoleSubmitError> {
        self.ensure_data_path_ready(request)
            .and_then(|request| self.input_ring.submit_input_and_notify(request, notifier))
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
        request: ConsoleRequest,
    ) -> Result<ConsoleRequest, ConsoleSubmitError> {
        match self.control.ensure_ready() {
            Ok(()) => Ok(request),
            Err(error) => Err(ConsoleSubmitError {
                error: OperationError::Common(error),
                request,
            }),
        }
    }
}
