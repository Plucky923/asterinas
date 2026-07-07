//! FrameV device lifecycle state.
//!
//! This module defines the common init/ready/stopped lifecycle, reset barrier,
//! and generation tracking. Ready-time topology, IRQ delivery, and pending
//! notification state belong to the owning backend aggregate.

use crate::{
    authority::ControlPathAuthority,
    error::{CommonError, FrameVDeviceError, Result},
};

/// The backend-authoritative FrameV device lifecycle status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceStatus {
    Init,
    Ready,
    Stopped,
}

/// A generation for one backend device runtime.
pub type DeviceGeneration = u64;

/// Common FrameV device lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceState {
    status: DeviceStatus,
    reset_barrier: bool,
    generation: DeviceGeneration,
}

impl DeviceState {
    /// Creates FrameV device lifecycle state.
    pub const fn new() -> Self {
        Self {
            status: DeviceStatus::Init,
            reset_barrier: false,
            generation: 0,
        }
    }

    /// Returns the current device status.
    pub const fn status(self) -> DeviceStatus {
        self.status
    }

    /// Returns the current control-path generation.
    pub const fn generation(self) -> DeviceGeneration {
        self.generation
    }

    /// Sets the lifecycle status.
    pub fn set_status(&mut self, status: DeviceStatus) -> Result<()> {
        if self.status == DeviceStatus::Stopped && status != DeviceStatus::Stopped {
            return Err(FrameVDeviceError::Stopped);
        }
        if status == DeviceStatus::Ready && self.reset_barrier {
            return Err(FrameVDeviceError::InvalidLifecycleTransition);
        }
        if status == DeviceStatus::Stopped {
            self.stop();
            return Ok(());
        }
        if status == DeviceStatus::Ready {
            self.reset_barrier = false;
        }
        self.status = status;
        Ok(())
    }

    /// Returns whether normal data-path operations may be accepted.
    pub const fn common_data_path_error(self) -> Option<CommonError> {
        if self.reset_barrier {
            return Some(CommonError::Reset);
        }
        match self.status {
            DeviceStatus::Init => Some(CommonError::NotReady),
            DeviceStatus::Ready => None,
            DeviceStatus::Stopped => Some(CommonError::Stopped),
        }
    }

    /// Checks that the device is ready for normal data-path operations.
    pub fn ensure_ready(self) -> core::result::Result<(), CommonError> {
        self.common_data_path_error().map_or(Ok(()), Err)
    }

    /// Starts a serialized reset barrier.
    pub fn begin_reset(&mut self) -> Result<(DeviceGeneration, ControlPathAuthority)> {
        if self.status == DeviceStatus::Stopped {
            return Err(FrameVDeviceError::Stopped);
        }
        if self.reset_barrier {
            return Err(FrameVDeviceError::InvalidLifecycleTransition);
        }
        self.reset_barrier = true;
        Ok((self.generation, ControlPathAuthority::new()))
    }

    /// Finishes reset cleanup and returns the device to init.
    pub fn finish_reset(
        &mut self,
        generation: DeviceGeneration,
        _authority: ControlPathAuthority,
    ) -> Result<()> {
        if self.status == DeviceStatus::Stopped {
            return Err(FrameVDeviceError::Stopped);
        }
        if !self.reset_barrier {
            return Err(FrameVDeviceError::InvalidLifecycleTransition);
        }
        if self.generation != generation {
            return Err(FrameVDeviceError::InvalidLifecycleTransition);
        }
        self.status = DeviceStatus::Init;
        self.reset_barrier = false;
        self.generation = self.generation.saturating_add(1);
        Ok(())
    }

    /// Resets transient state and returns the device to init.
    pub fn reset(&mut self) {
        if let Ok((generation, authority)) = self.begin_reset() {
            let _ = self.finish_reset(generation, authority);
        }
    }

    /// Stops the runtime and cleans common transient state.
    pub fn stop(&mut self) {
        self.status = DeviceStatus::Stopped;
        self.reset_barrier = false;
        self.generation = self.generation.saturating_add(1);
    }
}
