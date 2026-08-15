// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;

use framev_pci_common::FrameVFunctionFamily;

use super::state::FunctionRuntime;
use crate::{
    Result,
    console::{ConsoleOutputRead, FrameVConsoleDevice},
    pci::VirtualPciBus,
};

/// Typed host handle for one VM's FrameV console backend.
pub struct Console {
    runtime: Arc<FunctionRuntime>,
    backend: FrameVConsoleDevice,
    pci: Arc<VirtualPciBus>,
}

impl Console {
    pub(super) fn new(runtime: Arc<FunctionRuntime>, pci: Arc<VirtualPciBus>) -> Self {
        Self {
            runtime,
            backend: FrameVConsoleDevice::new(),
            pci,
        }
    }

    pub(crate) fn runtime(&self) -> &FunctionRuntime {
        &self.runtime
    }

    /// Writes guest output to this console backend.
    pub fn write(&self, bytes: &[u8]) -> Result<usize> {
        self.backend.write(bytes)
    }

    /// Reads input queued for this console backend.
    pub fn read(&self, output: &mut [u8]) -> Result<usize> {
        self.backend.read(output)
    }

    /// Takes one queued input chunk without waiting.
    pub fn take_input(&self) -> Result<Option<framev_console_common::ConsoleInput>> {
        self.backend.take_input()
    }

    /// Queues host-provided input without dropping unread bytes.
    pub fn inject_input(&self, bytes: &[u8]) -> Result<usize> {
        self.backend.inject_input(bytes)
    }

    /// Queues host-provided input, blocking until at least one byte fits.
    pub fn inject_input_blocking(&self, bytes: &[u8]) -> Result<usize> {
        self.backend.inject_input_blocking(bytes)
    }

    pub(crate) fn inject_host_input(&self, bytes: &[u8]) -> Result<usize> {
        let _call = self.runtime.enter_host()?;
        let accepted = self.backend.inject_input(bytes)?;
        self.notify_input(accepted)
    }

    pub(crate) fn inject_host_input_blocking(&self, bytes: &[u8]) -> Result<usize> {
        let _call = self.runtime.enter_host()?;
        let accepted = self.backend.inject_input_blocking(bytes)?;
        self.notify_input(accepted)
    }

    /// Clears queued input.
    pub fn clear_input(&self) {
        self.backend.clear_input();
    }

    /// Clears captured output.
    pub fn clear_output_log(&self) {
        self.backend.clear_output_log();
    }

    /// Registers a callback for newly captured guest output.
    pub fn register_output_callback(&self, callback: crate::console::ConsoleOutputCallback) {
        self.backend.register_output_callback(callback);
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
        self.backend.reset();
    }

    pub(super) fn stop(&self) {
        self.backend.stop();
    }

    fn notify_input(&self, accepted: usize) -> Result<usize> {
        if accepted == 0 {
            return Ok(0);
        }

        let generation = self.runtime.generation();
        self.pci
            .raise(FrameVFunctionFamily::Console, 0, generation)
            .map(|_| accepted)
    }
}
