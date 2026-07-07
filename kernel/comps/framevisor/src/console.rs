// SPDX-License-Identifier: MPL-2.0

//! Console output.

use alloc::{collections::VecDeque, string::String, vec::Vec};
use core::fmt::Arguments;

use framev_console_common::{ConsoleByteBuffer, ConsoleDirection, ConsoleRequest};
use framev_device::{CommonError, OperationError, OwnedResource};
use host_ostd::sync::{SpinLock, WaitQueue};

use crate::{Error, Result, vm};

const INPUT_CAPACITY: usize = 4096;
const HELPER_CHUNK_BYTES: usize = 4096;
const OUTPUT_LOG_LIMIT: usize = 64 * 1024;

pub(crate) type ConsoleInputCallback = fn(&[u8]);

enum ConsoleInputDelivery {
    Dispatch {
        callbacks: Vec<ConsoleInputCallback>,
        bytes: Vec<u8>,
    },
    Queued(usize),
    Full,
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
    bytes: VecDeque<u8>,
    stopped: bool,
    generation: u64,
}

impl ConsoleInputState {
    fn new() -> Self {
        Self {
            bytes: VecDeque::with_capacity(INPUT_CAPACITY),
            stopped: false,
            generation: 0,
        }
    }

    fn clear(&mut self) {
        self.bytes.clear();
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
pub struct FrameVConsoleDevice {
    input: SpinLock<ConsoleInputState>,
    input_wait: WaitQueue,
    input_space_wait: WaitQueue,
    output_log: SpinLock<ConsoleOutputRing>,
    output_wait: WaitQueue,
    input_callbacks: SpinLock<Vec<ConsoleInputCallback>>,
}

impl FrameVConsoleDevice {
    /// Creates an empty console backend.
    pub fn new() -> Self {
        Self {
            input: SpinLock::new(ConsoleInputState::new()),
            input_wait: WaitQueue::new(),
            input_space_wait: WaitQueue::new(),
            output_log: SpinLock::new(ConsoleOutputRing::new()),
            output_wait: WaitQueue::new(),
            input_callbacks: SpinLock::new(Vec::new()),
        }
    }

    /// Writes guest output to this console backend.
    pub fn write(&self, bytes: &[u8]) -> Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }

        let mut written = 0usize;
        for chunk in bytes.chunks(HELPER_CHUNK_BYTES) {
            let output_bytes = self.deliver_output_chunk(chunk)?;
            written = written.saturating_add(output_bytes.len());
        }

        Ok(written)
    }

    fn deliver_output_chunk(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let request = console_request(ConsoleDirection::Output, bytes)?;
        let submitted = request.submit();
        let output_bytes = submitted.bytes().to_vec();
        if let Err(error) = self.append_output(&output_bytes) {
            let _returned = submitted.complete_error(OperationError::Common(CommonError::Stopped));
            return Err(error);
        }
        let _completion = submitted.complete_success();

        Ok(output_bytes)
    }

    /// Reads input queued for this console backend.
    pub fn read(&self, output: &mut [u8]) -> Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }

        let generation = self.input_generation();
        let read_len = self.input_wait.wait_until(|| {
            let mut input = self.input.lock();
            if input.generation != generation || input.stopped {
                return Some(Err(Error::IoError));
            }
            if input.bytes.is_empty() {
                return None;
            }

            let mut read_len = 0;
            for slot in &mut *output {
                let Some(byte) = input.bytes.pop_front() else {
                    break;
                };
                *slot = byte;
                read_len += 1;
            }
            Some(Ok(read_len))
        })?;

        self.input_space_wait.wake_all();
        Ok(read_len)
    }

    /// Queues host-provided input without dropping unread bytes.
    pub fn inject_input(&self, bytes: &[u8]) -> Result<usize> {
        self.inject_input_with_mode(bytes, false)
    }

    /// Queues host-provided input, blocking until at least one byte fits.
    pub fn inject_input_blocking(&self, bytes: &[u8]) -> Result<usize> {
        self.inject_input_with_mode(bytes, true)
    }

    fn inject_input_with_mode(&self, bytes: &[u8], blocking: bool) -> Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }

        loop {
            match self.prepare_input_delivery(bytes)? {
                ConsoleInputDelivery::Dispatch { callbacks, bytes } => {
                    let accepted_len = bytes.len();
                    for callback in callbacks {
                        callback(&bytes);
                    }
                    return Ok(accepted_len);
                }
                ConsoleInputDelivery::Queued(accepted_len) => {
                    self.input_wait.wake_all();
                    return Ok(accepted_len);
                }
                ConsoleInputDelivery::Full if !blocking => return Ok(0),
                ConsoleInputDelivery::Full => {
                    self.wait_for_input_space_or_callback();
                }
            }
        }
    }

    /// Registers a frontend input callback.
    pub fn register_input_callback(&self, callback: ConsoleInputCallback) -> usize {
        let pending = {
            let mut callbacks = self.input_callbacks.lock();
            callbacks.push(callback);
            let mut input = self.input.lock();
            input.bytes.drain(..).collect::<Vec<_>>()
        };
        self.input_space_wait.wake_all();
        if !pending.is_empty() {
            callback(&pending);
        }
        pending.len()
    }

    /// Returns whether queued input is available.
    pub(crate) fn has_input(&self) -> bool {
        !self.input.lock().bytes.is_empty()
    }

    /// Clears queued input for stop/reset handling.
    pub fn clear_input(&self) {
        self.input.lock().clear();
        self.input_wait.wake_all();
        self.input_space_wait.wake_all();
    }

    /// Clears frontend input callbacks.
    pub fn clear_input_callbacks(&self) {
        self.input_callbacks.lock().clear();
    }

    /// Clears captured output.
    pub fn clear_output_log(&self) {
        self.output_log.lock().clear();
        self.output_wait.wake_all();
    }

    /// Reads captured output from a caller-owned cursor offset.
    pub fn read_output_from(&self, offset: u64, max_len: usize) -> ConsoleOutputRead {
        self.output_log.lock().read_from(offset, max_len)
    }

    pub fn output_tail_offset(&self) -> u64 {
        self.output_log.lock().tail_offset()
    }

    /// Blocks until captured output or lost-byte accounting is available.
    pub fn wait_output_from(&self, offset: u64, max_len: usize) -> Result<ConsoleOutputRead> {
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
    pub fn output_log_snapshot(&self) -> String {
        let read = self.read_output_from(0, OUTPUT_LOG_LIMIT);
        String::from_utf8(read.into_bytes())
            .unwrap_or_else(|error| ascii_fallback(error.into_bytes()))
    }

    /// Stops this console backend and wakes blocked waiters.
    pub fn stop(&self) {
        self.input.lock().stop();
        self.output_log.lock().stop();
        self.clear_input_callbacks();
        self.input_wait.wake_all();
        self.input_space_wait.wake_all();
        self.output_wait.wake_all();
    }

    /// Resets this console backend for a new lifecycle.
    pub fn reset(&self) {
        self.input.lock().reset();
        self.output_log.lock().reset();
        self.clear_input_callbacks();
        self.input_wait.wake_all();
        self.input_space_wait.wake_all();
        self.output_wait.wake_all();
    }

    fn append_output(&self, bytes: &[u8]) -> Result<()> {
        let mut output_log = self.output_log.lock();
        if output_log.stopped {
            return Err(Error::IoError);
        }
        output_log.append(bytes);
        drop(output_log);
        self.output_wait.wake_all();
        Ok(())
    }

    fn prepare_input_delivery(&self, bytes: &[u8]) -> Result<ConsoleInputDelivery> {
        let callbacks = self.input_callbacks.lock();
        if callbacks.is_empty() {
            return self.queue_input_with_callbacks_locked(bytes);
        }

        Ok(ConsoleInputDelivery::Dispatch {
            callbacks: callbacks.clone(),
            bytes: bytes.iter().map(normalize_input_byte).collect(),
        })
    }

    fn input_generation(&self) -> u64 {
        self.input.lock().generation
    }

    fn output_generation(&self) -> u64 {
        self.output_log.lock().generation
    }

    fn queue_input_with_callbacks_locked(&self, bytes: &[u8]) -> Result<ConsoleInputDelivery> {
        let mut input = self.input.lock();
        if input.stopped {
            return Err(Error::IoError);
        }

        let available = INPUT_CAPACITY.saturating_sub(input.bytes.len());
        if available == 0 {
            return Ok(ConsoleInputDelivery::Full);
        }

        let mut accepted_len = 0;
        for byte in bytes.iter().take(available) {
            let byte = if *byte == b'\r' { b'\n' } else { *byte };
            input.bytes.push_back(byte);
            accepted_len += 1;
        }
        Ok(ConsoleInputDelivery::Queued(accepted_len))
    }

    fn wait_for_input_space_or_callback(&self) {
        self.input_space_wait.wait_until(|| {
            if !self.input_callbacks.lock().is_empty() {
                return Some(());
            }

            let input = self.input.lock();
            (input.stopped || input.bytes.len() < INPUT_CAPACITY).then_some(())
        });
    }
}

fn normalize_input_byte(byte: &u8) -> u8 {
    if *byte == b'\r' { b'\n' } else { *byte }
}

fn console_request(direction: ConsoleDirection, bytes: &[u8]) -> Result<ConsoleRequest> {
    let buffer = ConsoleByteBuffer::new(bytes.to_vec()).map_err(|_| Error::InvalidArgs)?;
    ConsoleRequest::new(direction, alloc::vec![OwnedResource::new(buffer)])
        .map_err(|_| Error::InvalidArgs)
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

fn with_console_for_vm<T>(
    vm_id: vm::VmId,
    f: impl FnOnce(&crate::device::Console) -> Result<T>,
) -> Result<T> {
    let vm = vm::get_vm_by_id(vm_id).ok_or(Error::InvalidArgs)?;
    f(vm.devices().console())
}

fn with_current_console<T>(f: impl FnOnce(&crate::device::Console) -> Result<T>) -> Result<T> {
    let frame_vcpu_id = crate::task::current_frame_vcpu_id().ok_or(Error::InvalidArgs)?;
    with_console_for_vm(frame_vcpu_id.vm_id(), f)
}

pub fn write(bytes: &[u8]) -> Result<usize> {
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

pub fn register_input_callback(callback: ConsoleInputCallback) -> Result<()> {
    with_current_console(|console| {
        console.register_input_callback(callback);
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
        let first = alloc::vec![b'a'; INPUT_CAPACITY];
        let second = alloc::vec![b'b'; 1];

        assert_eq!(console.inject_input(&first).unwrap(), INPUT_CAPACITY);
        assert_eq!(console.inject_input(&second).unwrap(), 0);

        let mut output = alloc::vec![0; INPUT_CAPACITY];
        assert_eq!(console.read(&mut output).unwrap(), INPUT_CAPACITY);
        assert!(output.iter().all(|byte| *byte == b'a'));
    }

    #[ktest]
    fn service_shims_fail_or_noop_without_current_vm_context() {
        let mut output = [0u8; 8];

        assert_eq!(write(b"x"), Err(Error::InvalidArgs));
        assert_eq!(read(&mut output), Err(Error::InvalidArgs));
        assert_eq!(clear_input(), Err(Error::InvalidArgs));
        assert_eq!(register_input_callback(|_| {}), Err(Error::InvalidArgs));
        assert!(!is_active());
        assert!(!has_input());
    }
}
