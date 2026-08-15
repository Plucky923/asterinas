// SPDX-License-Identifier: MPL-2.0

//! Console output.

use alloc::{collections::VecDeque, string::String, sync::Arc, vec::Vec};
use core::fmt::Arguments;

use framev_console_common::{ConsoleInput, MAX_INPUT_CHUNK_BYTES, QUEUED_INPUT_CAPACITY_BYTES};
use framev_pci_common::FrameVFunctionFamily;
use host_ostd::sync::{SpinLock, WaitQueue};

use crate::{Error, Result, vm};

const HELPER_CHUNK_BYTES: usize = 4096;
const OUTPUT_LOG_LIMIT: usize = 64 * 1024;

pub type ConsoleOutputCallback = Arc<dyn Fn() + Send + Sync>;

#[derive(Clone, Copy)]
enum InputMode {
    Nonblocking,
    Blocking,
}

/// Bytes read from one FrameV console output ring.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsoleOutputRead {
    bytes: Vec<u8>,
    next_offset: u64,
    lost_bytes: u64,
}

impl ConsoleOutputRead {
    fn new(bytes: Vec<u8>, next_offset: u64, lost_bytes: u64) -> Self {
        Self {
            bytes,
            next_offset,
            lost_bytes,
        }
    }

    /// Returns the bytes copied from the output ring.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the read result and returns the copied bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns the cursor offset for the next read.
    pub const fn next_offset(&self) -> u64 {
        self.next_offset
    }

    /// Returns how many bytes were already overwritten before this read.
    pub const fn lost_bytes(&self) -> u64 {
        self.lost_bytes
    }
}

struct ConsoleOutputRing {
    bytes: VecDeque<u8>,
    base_offset: u64,
    next_offset: u64,
    stopped: bool,
    generation: u64,
}

impl ConsoleOutputRing {
    fn new() -> Self {
        Self {
            bytes: VecDeque::with_capacity(OUTPUT_LOG_LIMIT),
            base_offset: 0,
            next_offset: 0,
            stopped: false,
            generation: 0,
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        for byte in bytes {
            if self.bytes.len() == OUTPUT_LOG_LIMIT {
                let _ = self.bytes.pop_front();
                self.base_offset = self.base_offset.saturating_add(1);
            }
            self.bytes.push_back(*byte);
            self.next_offset = self.next_offset.saturating_add(1);
        }
    }

    fn read_from(&self, offset: u64, max_len: usize) -> ConsoleOutputRead {
        let (start_offset, lost_bytes) = if offset < self.base_offset {
            (self.base_offset, self.base_offset.saturating_sub(offset))
        } else {
            (offset.min(self.next_offset), 0)
        };

        let start_index = start_offset.saturating_sub(self.base_offset) as usize;
        let available = self.bytes.len().saturating_sub(start_index);
        let read_len = available.min(max_len);
        let bytes = self
            .bytes
            .iter()
            .skip(start_index)
            .take(read_len)
            .copied()
            .collect::<Vec<_>>();
        let next_offset = start_offset.saturating_add(read_len as u64);

        ConsoleOutputRead::new(bytes, next_offset, lost_bytes)
    }

    fn clear(&mut self) {
        self.bytes.clear();
        self.base_offset = self.next_offset;
    }

    fn tail_offset(&self) -> u64 {
        self.next_offset
    }

    fn reset(&mut self) {
        self.clear();
        self.stopped = false;
        self.generation = self.generation.saturating_add(1);
    }

    fn stop(&mut self) {
        self.clear();
        self.stopped = true;
        self.generation = self.generation.saturating_add(1);
    }
}

struct ConsoleInputState {
    chunks: VecDeque<ConsoleInput>,
    queued_bytes: usize,
    stopped: bool,
    generation: u64,
}

impl ConsoleInputState {
    fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            queued_bytes: 0,
            stopped: false,
            generation: 0,
        }
    }

    fn clear(&mut self) {
        self.chunks.clear();
        self.queued_bytes = 0;
    }

    fn reset(&mut self) {
        self.clear();
        self.stopped = false;
        self.generation = self.generation.saturating_add(1);
    }

    fn stop(&mut self) {
        self.clear();
        self.stopped = true;
        self.generation = self.generation.saturating_add(1);
    }
}

/// Host backend state for one required `framev-console` device.
pub(crate) struct FrameVConsoleDevice {
    input: SpinLock<ConsoleInputState>,
    input_wait: WaitQueue,
    input_space_wait: WaitQueue,
    output_log: SpinLock<ConsoleOutputRing>,
    output_wait: WaitQueue,
    output_callbacks: SpinLock<Vec<ConsoleOutputCallback>>,
}

impl Default for FrameVConsoleDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameVConsoleDevice {
    /// Creates an empty console backend.
    pub(crate) fn new() -> Self {
        Self {
            input: SpinLock::new(ConsoleInputState::new()),
            input_wait: WaitQueue::new(),
            input_space_wait: WaitQueue::new(),
            output_log: SpinLock::new(ConsoleOutputRing::new()),
            output_wait: WaitQueue::new(),
            output_callbacks: SpinLock::new(Vec::new()),
        }
    }

    /// Writes guest output to this console backend.
    pub(crate) fn write(&self, bytes: &[u8]) -> Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }

        let mut written = 0usize;
        for chunk in bytes.chunks(HELPER_CHUNK_BYTES) {
            self.append_output(chunk)?;
            written = written.saturating_add(chunk.len());
        }

        Ok(written)
    }

    /// Reads input queued for this console backend.
    pub(crate) fn read(&self, output: &mut [u8]) -> Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }

        let mut bytes = self.wait_for_input()?.into_bytes();
        let read_len = output.len().min(bytes.len());
        output[..read_len].copy_from_slice(&bytes[..read_len]);
        if read_len != bytes.len() {
            bytes.drain(..read_len);
            let Some(remainder) = ConsoleInput::new(bytes) else {
                return Err(Error::InvalidArgs);
            };
            let mut input = self.input.lock();
            input.queued_bytes = input
                .queued_bytes
                .checked_add(remainder.bytes().len())
                .ok_or(Error::Overflow)?;
            input.chunks.push_front(remainder);
        }

        self.input_space_wait.wake_all();
        Ok(read_len)
    }

    /// Takes one pending input chunk without waiting.
    pub(crate) fn take_input(&self) -> Result<Option<ConsoleInput>> {
        let mut input = self.input.lock();
        if input.stopped {
            return Err(Error::IoError);
        }
        let Some(chunk) = input.chunks.pop_front() else {
            return Ok(None);
        };
        input.queued_bytes = input.queued_bytes.saturating_sub(chunk.bytes().len());
        drop(input);
        self.input_space_wait.wake_all();
        Ok(Some(chunk))
    }

    /// Queues host-provided input without dropping unread bytes.
    pub(crate) fn inject_input(&self, bytes: &[u8]) -> Result<usize> {
        self.inject_input_with_mode(bytes, InputMode::Nonblocking)
    }

    /// Queues host-provided input, blocking until at least one byte fits.
    pub(crate) fn inject_input_blocking(&self, bytes: &[u8]) -> Result<usize> {
        self.inject_input_with_mode(bytes, InputMode::Blocking)
    }

    fn inject_input_with_mode(&self, bytes: &[u8], mode: InputMode) -> Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }

        loop {
            let accepted_len = self.queue_input(bytes)?;
            if accepted_len != 0 {
                self.input_wait.wake_all();
                return Ok(accepted_len);
            }
            if matches!(mode, InputMode::Nonblocking) {
                return Ok(0);
            }
            self.wait_for_input_space();
        }
    }

    /// Returns whether queued input is available.
    pub(crate) fn has_input(&self) -> bool {
        !self.input.lock().chunks.is_empty()
    }

    /// Clears queued input for stop/reset handling.
    pub(crate) fn clear_input(&self) {
        self.input.lock().clear();
        self.input_wait.wake_all();
        self.input_space_wait.wake_all();
    }

    /// Clears captured output.
    pub(crate) fn clear_output_log(&self) {
        self.output_log.lock().clear();
        self.output_wait.wake_all();
    }

    /// Registers a callback that is invoked whenever output readiness changes.
    pub(crate) fn register_output_callback(&self, callback: ConsoleOutputCallback) {
        self.output_callbacks.lock().push(callback);
    }

    /// Reads captured output from a caller-owned cursor offset.
    pub(crate) fn read_output_from(&self, offset: u64, max_len: usize) -> ConsoleOutputRead {
        self.output_log.lock().read_from(offset, max_len)
    }

    pub(crate) fn output_tail_offset(&self) -> u64 {
        self.output_log.lock().tail_offset()
    }

    /// Blocks until captured output or lost-byte accounting is available.
    pub(crate) fn wait_output_from(
        &self,
        offset: u64,
        max_len: usize,
    ) -> Result<ConsoleOutputRead> {
        if max_len == 0 {
            return Ok(self.read_output_from(offset, max_len));
        }

        let generation = self.output_generation();
        self.output_wait.wait_until(|| {
            let output_log = self.output_log.lock();
            if output_log.generation != generation || output_log.stopped {
                return Some(Err(Error::IoError));
            }
            let read = output_log.read_from(offset, max_len);
            (!read.bytes().is_empty() || read.lost_bytes() != 0).then_some(Ok(read))
        })
    }

    /// Returns captured output.
    pub(crate) fn output_log_snapshot(&self) -> String {
        let read = self.read_output_from(0, OUTPUT_LOG_LIMIT);
        String::from_utf8(read.into_bytes())
            .unwrap_or_else(|error| ascii_fallback(error.into_bytes()))
    }

    /// Stops this console backend and wakes blocked waiters.
    pub(crate) fn stop(&self) {
        self.input.lock().stop();
        self.output_log.lock().stop();
        self.input_wait.wake_all();
        self.input_space_wait.wake_all();
        self.output_wait.wake_all();
        self.notify_output_callbacks();
    }

    /// Resets this console backend for a new lifecycle.
    pub(crate) fn reset(&self) {
        self.input.lock().reset();
        self.output_log.lock().reset();
        self.input_wait.wake_all();
        self.input_space_wait.wake_all();
        self.output_wait.wake_all();
        self.notify_output_callbacks();
    }

    fn append_output(&self, bytes: &[u8]) -> Result<()> {
        let mut output_log = self.output_log.lock();
        if output_log.stopped {
            return Err(Error::IoError);
        }
        output_log.append(bytes);
        drop(output_log);
        self.output_wait.wake_all();
        self.notify_output_callbacks();
        Ok(())
    }

    fn notify_output_callbacks(&self) {
        let callbacks = self.output_callbacks.lock().clone();
        for callback in callbacks {
            callback();
        }
    }

    fn output_generation(&self) -> u64 {
        self.output_log.lock().generation
    }

    fn queue_input(&self, bytes: &[u8]) -> Result<usize> {
        let mut input = self.input.lock();
        if input.stopped {
            return Err(Error::IoError);
        }

        let available = QUEUED_INPUT_CAPACITY_BYTES.saturating_sub(input.queued_bytes);
        if available == 0 {
            return Ok(0);
        }

        let accepted_len = available.min(bytes.len()).min(MAX_INPUT_CHUNK_BYTES);
        let bytes = bytes[..accepted_len]
            .iter()
            .map(|byte| if *byte == b'\r' { b'\n' } else { *byte })
            .collect::<Vec<_>>();
        let chunk = ConsoleInput::new(bytes).ok_or(Error::InvalidArgs)?;
        input.queued_bytes = input
            .queued_bytes
            .checked_add(chunk.bytes().len())
            .ok_or(Error::Overflow)?;
        input.chunks.push_back(chunk);
        Ok(accepted_len)
    }

    fn wait_for_input(&self) -> Result<ConsoleInput> {
        let generation = self.input.lock().generation;
        self.input_wait.wait_until(|| {
            let mut input = self.input.lock();
            if input.generation != generation || input.stopped {
                return Some(Err(Error::IoError));
            }
            let chunk = input.chunks.pop_front()?;
            input.queued_bytes = input.queued_bytes.saturating_sub(chunk.bytes().len());
            Some(Ok(chunk))
        })
    }

    fn wait_for_input_space(&self) {
        self.input_space_wait.wait_until(|| {
            let input = self.input.lock();
            (input.stopped || input.queued_bytes < QUEUED_INPUT_CAPACITY_BYTES).then_some(())
        });
    }
}

fn ascii_fallback(bytes: Vec<u8>) -> String {
    let mut output = String::new();
    for byte in bytes {
        if byte.is_ascii() {
            output.push(char::from(byte));
        } else {
            output.push_str("<binary>");
        }
    }
    output
}

fn with_current_console<T>(f: impl FnOnce(&crate::device::Console) -> Result<T>) -> Result<T> {
    let frame_vcpu_id = crate::task::current_frame_vcpu_id().ok_or(Error::InvalidArgs)?;
    let vm = vm::get_vm_by_id(frame_vcpu_id.vm_id()).ok_or(Error::InvalidArgs)?;
    f(vm.devices().console())
}

pub fn write(bytes: &[u8]) -> Result<usize> {
    with_current_console(|console| {
        let _call = console.runtime().enter_host()?;
        console.write(bytes)
    })
}

/// Writes through one claimed console PCI function.
pub fn write_claimed(claim: &crate::device::FunctionClaim, bytes: &[u8]) -> Result<usize> {
    let _call = claim.enter(FrameVFunctionFamily::Console)?;
    with_current_console(|console| console.write(bytes))
}

/// Prints formatted arguments to the early console log.
pub fn early_print(args: Arguments<'_>) {
    // Early service diagnostics must not depend on FrameV console resource
    // transfer. The normal console data path starts after the frontend binds.
    host_ostd::console::early_print(args);
}

pub fn read(output: &mut [u8]) -> Result<usize> {
    with_current_console(|console| console.read(output))
}

/// Takes one pending console input allocation without copying it.
pub fn take_input() -> Result<Option<ConsoleInput>> {
    with_current_console(|console| {
        let _call = console.runtime().enter_host()?;
        console.take_input()
    })
}

/// Copies one input chunk into caller-owned storage through a claimed console
/// PCI function.
///
/// The buffer belongs to the FrameVM service. Returning the Host queue's
/// `ConsoleInput` allocation directly would cross the Host/service allocator
/// boundary and could run the wrong deallocation glue when the value drops.
pub fn take_claimed_input(
    claim: &crate::device::FunctionClaim,
    output: &mut [u8],
) -> Result<Option<usize>> {
    if output.len() < MAX_INPUT_CHUNK_BYTES {
        return Err(Error::InvalidArgs);
    }
    let _call = claim.enter(FrameVFunctionFamily::Console)?;
    with_current_console(|console| {
        let Some(input) = console.take_input()? else {
            return Ok(None);
        };
        let bytes = input.bytes();
        output[..bytes.len()].copy_from_slice(bytes);
        Ok(Some(bytes.len()))
    })
}

pub fn is_active() -> bool {
    crate::task::current_frame_vcpu_id()
        .and_then(|frame_vcpu_id| vm::get_vm_by_id(frame_vcpu_id.vm_id()))
        .is_some()
}

pub fn has_input() -> bool {
    with_current_console(|console| Ok(console.has_input())).unwrap_or(false)
}

pub fn clear_input() -> Result<()> {
    with_current_console(|console| {
        console.clear_input();
        Ok(())
    })
}

/// Prints to the console.
#[macro_export]
macro_rules! early_print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::early_print(format_args!($fmt $(, $($arg)+)?))
    };
}

/// Prints to the console with a newline.
#[macro_export]
macro_rules! early_println {
    () => { $crate::early_print!("\n") };
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::console::early_print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?))
    };
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn output_ring_reports_lost_bytes_for_stale_cursor() {
        let mut ring = ConsoleOutputRing::new();
        ring.append(&alloc::vec![b'a'; OUTPUT_LOG_LIMIT + 3]);

        let read = ring.read_from(0, 8);

        assert_eq!(read.lost_bytes(), 3);
        assert_eq!(read.next_offset(), 11);
        assert_eq!(read.bytes(), &[b'a'; 8]);
    }

    #[ktest]
    fn input_backpressure_preserves_unread_bytes() {
        let console = FrameVConsoleDevice::new();
        let first = alloc::vec![b'a'; QUEUED_INPUT_CAPACITY_BYTES];
        let second = alloc::vec![b'b'; 1];

        assert_eq!(
            console.inject_input(&first).unwrap(),
            QUEUED_INPUT_CAPACITY_BYTES
        );
        assert_eq!(console.inject_input(&second).unwrap(), 0);

        let mut output = alloc::vec![0; QUEUED_INPUT_CAPACITY_BYTES];
        assert_eq!(
            console.read(&mut output).unwrap(),
            QUEUED_INPUT_CAPACITY_BYTES
        );
        assert!(output.iter().all(|byte| *byte == b'a'));
    }

    #[ktest]
    fn service_shims_fail_or_noop_without_current_vm_context() {
        let mut output = [0u8; 8];

        assert_eq!(write(b"x"), Err(Error::InvalidArgs));
        assert_eq!(read(&mut output), Err(Error::InvalidArgs));
        assert_eq!(take_input(), Err(Error::InvalidArgs));
        assert_eq!(clear_input(), Err(Error::InvalidArgs));
        assert!(!is_active());
        assert!(!has_input());
    }
}
