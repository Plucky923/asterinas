//! FrameV console completion aliases.
//!
//! This module maps console request and completion state onto the common FrameV
//! completion and ring-slot typestates.

use framev_device::{CompletionInfo, RingSlot};

use crate::request::{ConsoleError, ConsoleSubmittedRequest};

/// Console completion info.
pub type ConsoleCompletion = CompletionInfo<(), ConsoleError>;

/// A submitted console slot.
pub type ConsoleSubmittedSlot = RingSlot<framev_device::Submitted, ConsoleSubmittedRequest>;

/// A completed console slot.
pub type ConsoleCompletedSlot =
    RingSlot<framev_device::Completed, ConsoleSubmittedRequest, ConsoleCompletion>;
