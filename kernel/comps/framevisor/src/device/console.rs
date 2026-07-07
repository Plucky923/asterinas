// SPDX-License-Identifier: MPL-2.0

use framev_device::{CommonError, DeviceGeneration, DeviceStatus, FrameVDevice, FrameVDeviceInfo};

use super::state::CommonDevice;
use crate::{
    Result,
    console::{ConsoleInputCallback, ConsoleOutputRead, FrameVConsoleDevice},
    task,
    vm::{FrameVcpuId, VmId},
};

/// Typed host handle for one VM's FrameV console backend.
pub struct Console {
    common: CommonDevice,
    backend: FrameVConsoleDevice,
    vm_id: VmId,
    vcpu_count: usize,
}

impl Console {
    pub(super) fn new(info: FrameVDeviceInfo, vm_id: VmId, vcpu_count: usize) -> Self {
        Self {
            common: CommonDevice::new(info),
            backend: FrameVConsoleDevice::new(),
            vm_id,
            vcpu_count,
        }
    }

    /// Writes guest output to this console backend.
    pub fn write(&self, bytes: &[u8]) -> Result<usize> {
        self.backend.write(bytes)
    }

    /// Reads input queued for this console backend.
    pub fn read(&self, output: &mut [u8]) -> Result<usize> {
        self.backend.read(output)
    }

    /// Queues host-provided input without dropping unread bytes.
    pub fn inject_input(&self, bytes: &[u8]) -> Result<usize> {
        let accepted = self.backend.inject_input(bytes)?;
        self.wake_service_after_input(accepted);
        Ok(accepted)
    }

    /// Queues host-provided input, blocking until at least one byte fits.
    pub fn inject_input_blocking(&self, bytes: &[u8]) -> Result<usize> {
        let accepted = self.backend.inject_input_blocking(bytes)?;
        self.wake_service_after_input(accepted);
        Ok(accepted)
    }

    /// Registers a frontend input callback.
    pub fn register_input_callback(&self, callback: ConsoleInputCallback) {
        let accepted = self.backend.register_input_callback(callback);
        self.wake_service_after_input(accepted);
    }

    /// Clears queued input.
    pub fn clear_input(&self) {
        self.backend.clear_input();
    }

    /// Clears frontend input callbacks.
    pub fn clear_input_callbacks(&self) {
        self.backend.clear_input_callbacks();
    }

    /// Clears captured output.
    pub fn clear_output_log(&self) {
        self.backend.clear_output_log();
    }

    /// Reads captured output from a caller-owned cursor offset.
    pub fn read_output_from(&self, offset: u64, max_len: usize) -> ConsoleOutputRead {
        self.backend.read_output_from(offset, max_len)
    }

    /// Returns the current output tail offset.
    pub fn output_tail_offset(&self) -> u64 {
        self.backend.output_tail_offset()
    }

    /// Blocks until captured output or lost-byte accounting is available.
    pub fn wait_output_from(&self, offset: u64, max_len: usize) -> Result<ConsoleOutputRead> {
        self.backend.wait_output_from(offset, max_len)
    }

    /// Returns captured output.
    pub fn output_log_snapshot(&self) -> alloc::string::String {
        self.backend.output_log_snapshot()
    }

    pub(crate) fn has_input(&self) -> bool {
        self.backend.has_input()
    }

    pub(super) fn reset(&self) {
        self.common.reset();
        self.backend.reset();
    }

    fn wake_service_after_input(&self, accepted_len: usize) {
        if accepted_len == 0 {
            return;
        }

        // Console input is a device event that can make service-side file,
        // poll, or shell work runnable. The backend only performs the
        // notification handoff here; the console data path remains owned by
        // FrameVM service tasks.
        for vcpu_index in 0..self.vcpu_count {
            task::wake_service_tasks_in_frame_vcpu(FrameVcpuId::new(self.vm_id, vcpu_index));
        }
    }
}

impl FrameVDevice for Console {
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
