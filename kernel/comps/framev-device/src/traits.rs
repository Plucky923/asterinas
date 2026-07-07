//! FrameV common extension traits.
//!
//! This module defines protocol extension traits and the backend-authoritative
//! device control-plane trait shared by FrameV device classes.

extern crate alloc;

use alloc::vec::Vec;

use crate::{
    descriptor::FrameVDeviceInfo,
    error::{CommonError, Result},
    lifecycle::{DeviceGeneration, DeviceStatus},
    notification::{IrqAccepted, IrqDelivery, IrqTarget},
};

/// Extension point for device-class request types.
pub trait FrameVRequest {}

/// Extension point for device-class resource representations.
pub trait FrameVResource {}

/// Extension point for device-class ring layouts.
pub trait FrameVRingLayout {
    /// Returns the number of rings in the layout.
    fn ring_count(&self) -> usize;
}

/// Extension point for batch completion observation.
pub trait BatchCompletionObserver<CompletedState> {
    /// Drains typed completed states that are currently observable.
    fn observe_batch(&mut self, completed: &mut Vec<CompletedState>);
}

/// A backend-authoritative FrameV device control-plane object.
pub trait FrameVDevice {
    /// Returns stable device metadata.
    fn info(&self) -> FrameVDeviceInfo;

    /// Returns the current backend-authoritative device status.
    fn status(&self) -> DeviceStatus;

    /// Returns the current backend-authoritative device generation.
    fn generation(&self) -> DeviceGeneration;

    /// Checks that the device accepts normal data-path operations.
    fn ensure_ready(&self) -> core::result::Result<DeviceGeneration, CommonError>;

    /// Marks the backend-authoritative device runtime ready.
    fn mark_ready(&self) -> Result<()>;

    /// Stops the backend-authoritative device runtime.
    fn stop(&self);

    /// Begins the ordered reset protocol.
    fn begin_reset(&self) -> Result<DeviceGeneration>;

    /// Resets backend-owned device state.
    fn reset_backend(&self);

    /// Finishes the ordered reset protocol.
    fn finish_reset(&self, generation: DeviceGeneration) -> Result<()>;

    /// Notifies the frontend through the owning aggregate's IRQ delivery.
    fn notify<D: IrqDelivery>(
        &self,
        delivery: &D,
        target: IrqTarget,
    ) -> core::result::Result<IrqAccepted, D::Error> {
        delivery.notify_irq(self.info().irq_line, target)
    }
}
