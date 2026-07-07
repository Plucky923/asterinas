// SPDX-License-Identifier: MPL-2.0

use framev_device::{CommonError, DeviceGeneration, DeviceStatus, FrameVDevice, FrameVDeviceInfo};

use super::{Devices, state::CommonDevice};
use crate::{Error, Result, irq_routing::VcpuIrqLoad, rng::FrameVRngDevice, vm::VmId};

/// Typed host handle for one VM's FrameV RNG backend.
pub struct Rng {
    common: CommonDevice,
    backend: FrameVRngDevice,
}

impl Rng {
    pub(super) fn new(info: FrameVDeviceInfo) -> Self {
        Self {
            common: CommonDevice::new(info),
            backend: FrameVRngDevice::new(),
        }
    }

    /// Completes entropy requests for `dst`.
    pub fn fill_bytes<F>(
        &self,
        dst: &mut [u8],
        vm_id: VmId,
        vm_running: bool,
        devices: &Devices,
        load_of: F,
    ) -> Result<()>
    where
        F: Fn(usize) -> Option<VcpuIrqLoad> + Copy,
    {
        self.ensure_ready().map_err(|_| Error::InvalidArgs)?;
        self.backend.fill_bytes(dst, || {
            devices.notify_rng(vm_id, vm_running, load_of).map(|_| ())
        })
    }

    pub(super) fn reset(&self) {
        self.common.reset();
        self.backend.reset();
    }
}

impl FrameVDevice for Rng {
    fn info(&self) -> FrameVDeviceInfo {
        self.common.info()
    }

    fn status(&self) -> DeviceStatus {
        self.common.status()
    }

    fn generation(&self) -> DeviceGeneration {
        self.common.generation()
    }

    fn ensure_ready(&self) -> Result<DeviceGeneration, CommonError> {
        self.common.ensure_ready()
    }

    fn mark_ready(&self) -> framev_device::Result<()> {
        self.common.mark_ready()
    }

    fn stop(&self) {
        self.common.stop();
        self.backend.stop();
    }

    fn begin_reset(&self) -> framev_device::Result<DeviceGeneration> {
        self.common.begin_reset()
    }

    fn reset_backend(&self) {
        self.backend.reset();
    }

    fn finish_reset(&self, generation: DeviceGeneration) -> framev_device::Result<()> {
        self.common.finish_reset(generation)
    }
}
