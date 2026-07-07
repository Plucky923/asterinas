//! FrameV console reset and stop cleanup helpers.
//!
//! This module contains console-local cleanup behavior for submitted and
//! completed console slots.

use framev_device::{CommonError, OperationError, OwnedResource, RingSlot};

use crate::{
    buffer::ConsoleByteBuffer,
    completion::{ConsoleCompletedSlot, ConsoleCompletion, ConsoleSubmittedSlot},
};

/// Resolves a submitted console slot through reset cleanup.
pub fn resolve_submitted_console_reset(
    slot: ConsoleSubmittedSlot,
) -> framev_device::Result<(
    RingSlot<framev_device::Free>,
    ConsoleCompletion,
    OwnedResource<ConsoleByteBuffer>,
)> {
    let (free_slot, _state, request, _completion) = slot.cleanup()?.into_parts();
    let (completion, returned) = request.complete_error(OperationError::Common(CommonError::Reset));
    Ok((free_slot, completion, returned))
}

/// Discards a completed console slot through stop or teardown cleanup.
pub fn discard_completed_console_for_stop(
    slot: ConsoleCompletedSlot,
) -> framev_device::Result<RingSlot<framev_device::Free>> {
    let (free_slot, _state, _request, _completion) = slot.cleanup()?.into_parts();
    Ok(free_slot)
}
