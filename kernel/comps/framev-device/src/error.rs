//! Common FrameV error and completion result types.
//!
//! This module defines the shared error envelopes and completion metadata used
//! by FrameV device-class protocols.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use crate::descriptor::{FrameVDeviceId, FrameVDeviceInfo, FrameVDeviceType, IrqLine};

/// A result returned by the FrameV device model.
pub type Result<T> = core::result::Result<T, FrameVDeviceError>;

/// An error returned by the FrameV device model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVDeviceError {
    DuplicateDeviceId(FrameVDeviceId),
    DuplicateIrqLine(IrqLine),
    DuplicateRequiredDevice(FrameVDeviceType),
    InvalidDescriptorEncoding,
    InvalidDeviceType,
    InvalidLifecycleTransition,
    MissingRequiredDevice(FrameVDeviceType),
    ReservedIrqLine,
    RequiredDeviceMismatch {
        expected: FrameVDeviceInfo,
        actual: FrameVDeviceInfo,
    },
    Stopped,
    UnexpectedDeviceCount {
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for FrameVDeviceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateDeviceId(id) => {
                write!(formatter, "duplicate FrameV device id {}", id.raw())
            }
            Self::DuplicateIrqLine(line) => {
                write!(formatter, "duplicate FrameV IRQ line {}", line.raw())
            }
            Self::DuplicateRequiredDevice(device_type) => {
                write!(
                    formatter,
                    "duplicate required FrameV {} device",
                    device_type.boot_name()
                )
            }
            Self::InvalidDescriptorEncoding => {
                formatter.write_str("invalid FrameV descriptor encoding")
            }
            Self::InvalidDeviceType => formatter.write_str("invalid FrameV device type"),
            Self::InvalidLifecycleTransition => {
                formatter.write_str("invalid FrameV lifecycle transition")
            }
            Self::MissingRequiredDevice(device_type) => {
                write!(
                    formatter,
                    "missing required FrameV {} device",
                    device_type.boot_name()
                )
            }
            Self::ReservedIrqLine => write!(
                formatter,
                "reserved FrameV IRQ line {}",
                IrqLine::RESERVED_RAW
            ),
            Self::RequiredDeviceMismatch { expected, actual } => {
                write!(
                    formatter,
                    "required FrameV {} device mismatch: expected id={}, irq={}; actual id={}, type={}, irq={}",
                    expected.device_type.boot_name(),
                    expected.id.raw(),
                    expected.irq_line.raw(),
                    actual.id.raw(),
                    actual.device_type.boot_name(),
                    actual.irq_line.raw()
                )
            }
            Self::Stopped => formatter.write_str("FrameV device runtime is stopped"),
            Self::UnexpectedDeviceCount { expected, actual } => {
                write!(
                    formatter,
                    "unexpected FrameV device count: expected {}, actual {}",
                    expected, actual
                )
            }
        }
    }
}
/// A common FrameV data-path error cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommonError {
    NotReady,
    Full,
    InvalidSlot,
    InvalidResource,
    Reset,
    Stopped,
}

/// A common or device-class-specific operation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationError<DeviceError> {
    Common(CommonError),
    Device(DeviceError),
}

/// A common operation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationResult<DeviceError> {
    Ok,
    Error(OperationError<DeviceError>),
}

/// The final ownership result for one transferred resource.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceResult {
    Returned,
    Consumed,
}

/// Completion information common to FrameV device classes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionInfo<Payload, DeviceError> {
    operation: OperationResult<DeviceError>,
    resources: Vec<ResourceResult>,
    payload: Payload,
}

impl<Payload, DeviceError> CompletionInfo<Payload, DeviceError> {
    /// Creates completion information.
    pub fn new(
        operation: OperationResult<DeviceError>,
        resources: Vec<ResourceResult>,
        payload: Payload,
    ) -> Self {
        Self {
            operation,
            resources,
            payload,
        }
    }

    /// Returns the common operation result.
    pub const fn operation(&self) -> &OperationResult<DeviceError> {
        &self.operation
    }

    /// Returns the resource ownership results.
    pub fn resource_results(&self) -> &[ResourceResult] {
        &self.resources
    }

    /// Returns the device-class completion payload.
    pub const fn payload(&self) -> &Payload {
        &self.payload
    }

    /// Consumes the completion info and returns the device-class payload.
    pub fn into_payload(self) -> Payload {
        self.payload
    }
}
