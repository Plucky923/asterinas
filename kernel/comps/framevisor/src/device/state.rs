// SPDX-License-Identifier: MPL-2.0

use framev_device::{
    ControlPathAuthority, DeviceGeneration, DeviceState, DeviceStatus, FrameVDeviceError,
    FrameVDeviceInfo,
};

use crate::sync::SpinLock;

pub(super) struct CommonDevice {
    info: FrameVDeviceInfo,
    state: SpinLock<DeviceState>,
    reset_authority: SpinLock<Option<ControlPathAuthority>>,
}

impl CommonDevice {
    pub(super) fn new(info: FrameVDeviceInfo) -> Self {
        Self {
            info,
            state: SpinLock::new(DeviceState::new()),
            reset_authority: SpinLock::new(None),
        }
    }

    pub(super) fn info(&self) -> FrameVDeviceInfo {
        self.info
    }

    pub(super) fn status(&self) -> DeviceStatus {
        self.state.lock().status()
    }

    pub(super) fn generation(&self) -> DeviceGeneration {
        self.state.lock().generation()
    }

    pub(super) fn ensure_ready(&self) -> Result<DeviceGeneration, framev_device::CommonError> {
        let state = *self.state.lock();
        state.ensure_ready()?;
        Ok(state.generation())
    }

    pub(super) fn mark_ready(&self) -> framev_device::Result<()> {
        self.state.lock().set_status(DeviceStatus::Ready)
    }

    pub(super) fn stop(&self) {
        *self.reset_authority.lock() = None;
        self.state.lock().stop();
    }

    pub(super) fn begin_reset(&self) -> framev_device::Result<DeviceGeneration> {
        let (generation, authority) = self.state.lock().begin_reset()?;
        *self.reset_authority.lock() = Some(authority);
        Ok(generation)
    }

    pub(super) fn finish_reset(&self, generation: DeviceGeneration) -> framev_device::Result<()> {
        let authority = self
            .reset_authority
            .lock()
            .take()
            .ok_or(FrameVDeviceError::InvalidLifecycleTransition)?;
        let mut state = self.state.lock();
        state.finish_reset(generation, authority)
    }

    pub(super) fn reset(&self) {
        *self.reset_authority.lock() = None;
        self.state.lock().reset();
    }
}
