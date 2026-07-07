// SPDX-License-Identifier: MPL-2.0

//! Common FrameV device model types.
//!
//! This crate provides common FrameV descriptor metadata, lifecycle state,
//! ownership-transfer typestates, ring-slot typestates, notification primitives,
//! endpoint authorities, and extension traits. Device-class crates own concrete
//! protocol requests, resources, completions, ring layouts, and runtime policy.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

mod authority;
mod descriptor;
mod dispatch;
mod error;
mod lifecycle;
mod notification;
mod resource;
mod ring;
mod traits;

pub use authority::{ControlPathAuthority, ReceiverEndpoint, RingAuthorities, SubmitterEndpoint};
pub use descriptor::{
    FrameVDeviceDescriptor, FrameVDeviceId, FrameVDeviceInfo, FrameVDeviceType, InvalidIrqLine,
    IrqLine, well_known,
};
pub use dispatch::{DispatchEnter, SynchronousDispatchGuard, SynchronousDispatchState};
pub use error::{
    CommonError, CompletionInfo, FrameVDeviceError, OperationError, OperationResult,
    ResourceResult, Result,
};
pub use lifecycle::{DeviceGeneration, DeviceState, DeviceStatus};
pub use notification::{IrqAccepted, IrqDelivery, IrqTarget};
pub use resource::{
    Consume, ConsumedResource, OwnedResource, ReadOnly, ReadWrite, ResourceAccessMode,
    ReturnedResource, SubmittedResource, WriteOnly,
};
pub use ring::{
    CleanupOutcome, CleanupState, Completed, Free, PollOutcome, ReclaimOutcome, RingSlot,
    SubmitOutcome, Submitted,
};
pub use traits::{
    BatchCompletionObserver, FrameVDevice, FrameVRequest, FrameVResource, FrameVRingLayout,
};

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
