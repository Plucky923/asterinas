//! FrameV RNG reset and stop cleanup helpers.
//!
//! This module contains RNG-local cleanup behavior for submitted and completed
//! RNG slots.

use framev_device::{CommonError, OperationError, OwnedResource, RingSlot};

use crate::{
    buffer::RngOutputBuffer,
    completion::{RngCompletedSlot, RngCompletion, RngSubmittedSlot},
};

/// Resolves a submitted RNG fill through reset cleanup.
pub fn resolve_submitted_rng_reset(
    slot: RngSubmittedSlot,
) -> framev_device::Result<(
    RingSlot<framev_device::Free>,
    RngCompletion,
    OwnedResource<RngOutputBuffer>,
)> {
    let (free_slot, _state, request, _completion) = slot.cleanup()?.into_parts();
    let (completion, returned) = request.complete_error(OperationError::Common(CommonError::Reset));
    Ok((free_slot, completion, returned))
}

/// Discards a completed RNG slot through stop or teardown cleanup.
pub fn discard_completed_rng_for_stop(
    slot: RngCompletedSlot,
) -> framev_device::Result<RingSlot<framev_device::Free>> {
    let (free_slot, _state, _request, _completion) = slot.cleanup()?.into_parts();
    Ok(free_slot)
}
