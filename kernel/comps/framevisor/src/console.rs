// SPDX-License-Identifier: MPL-2.0

//! Console output.

use alloc::string::String;
#[cfg(feature = "host-api")]
use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec::Vec};
use core::fmt::{Arguments, Write};

#[cfg(feature = "host-api")]
use aster_console::{AnyConsoleDevice, ConsoleCallback, InputOwner};
#[cfg(not(feature = "host-api"))]
use aster_console_transport as console_transport;
#[cfg(feature = "host-api")]
use aster_console_transport::{
    self as console_transport, Backend, ConsoleInputCallback, Error as ConsoleTransportError,
};
use host_ostd::sync::SpinLock;
#[cfg(feature = "host-api")]
use host_ostd::{
    mm::{VmReader as OstdVmReader, VmWriter},
    sync::WaitQueue,
};

#[cfg(feature = "host-api")]
use crate::mm::Infallible;
use crate::{Error, Result, sync::Once};

#[cfg(feature = "host-api")]
const INPUT_CAPACITY: usize = 4096;
const OUTPUT_LOG_LIMIT: usize = 64 * 1024;
#[cfg(feature = "host-api")]
const PREFERRED_CONSOLE_NAMES: &[&str] = &["Uart-Console", "Virtio-Console"];

#[cfg(feature = "host-api")]
static CONSOLE_ENDPOINT: Once<Option<Arc<ConsoleEndpoint>>> = Once::new();
#[cfg(feature = "host-api")]
static CONSOLE_INPUT_OWNER: Once<InputOwner> = Once::new();
static OUTPUT_LOG: Once<SpinLock<String>> = Once::new();
#[cfg(feature = "host-api")]
static TRANSPORT_INPUT_CALLBACKS: Once<SpinLock<Vec<TransportInputCallback>>> = Once::new();
#[cfg(feature = "host-api")]
static INJECTED_INPUT: Once<SpinLock<VecDeque<u8>>> = Once::new();

#[cfg(feature = "host-api")]
pub(crate) type TransportInputCallback = fn(&[u8]);

fn output_log() -> &'static SpinLock<String> {
    OUTPUT_LOG.call_once(|| SpinLock::new(String::new()))
}

fn append_output_str(text: &str) {
    let mut output = output_log().lock();
    output.push_str(text);
    if output.len() > OUTPUT_LOG_LIMIT {
        let overflow = output.len() - OUTPUT_LOG_LIMIT;
        output.drain(..overflow);
    }
}

#[cfg(feature = "host-api")]
fn transport_input_callbacks() -> &'static SpinLock<Vec<TransportInputCallback>> {
    TRANSPORT_INPUT_CALLBACKS.call_once(|| SpinLock::new(Vec::new()))
}

#[cfg(feature = "host-api")]
fn dispatch_transport_input(bytes: &[u8]) {
    let callbacks = transport_input_callbacks().lock().clone();
    for callback in callbacks {
        callback(bytes);
    }
}

#[cfg(feature = "host-api")]
fn injected_input() -> &'static SpinLock<VecDeque<u8>> {
    INJECTED_INPUT.call_once(|| SpinLock::new(VecDeque::with_capacity(INPUT_CAPACITY)))
}

#[cfg(feature = "host-api")]
fn queue_injected_input(bytes: &[u8]) {
    let mut input = injected_input().lock();
    for byte in bytes {
        let byte = if *byte == b'\r' { b'\n' } else { *byte };
        if input.len() == INPUT_CAPACITY {
            input.pop_front();
        }
        input.push_back(byte);
    }
}

#[cfg(feature = "host-api")]
fn dispatch_injected_input() {
    if transport_input_callbacks().lock().is_empty() {
        return;
    }

    let mut input = injected_input().lock();
    if input.is_empty() {
        return;
    }

    let bytes = input.drain(..).collect::<Vec<_>>();
    drop(input);
    dispatch_transport_input(&bytes);
}

#[cfg(feature = "host-api")]
struct ConsoleEndpoint {
    device: Arc<dyn AnyConsoleDevice>,
    input: SpinLock<VecDeque<u8>>,
    input_wait: WaitQueue,
}

#[cfg(feature = "host-api")]
impl ConsoleEndpoint {
    fn new(device: Arc<dyn AnyConsoleDevice>) -> Arc<Self> {
        Arc::new(Self {
            device,
            input: SpinLock::new(VecDeque::with_capacity(INPUT_CAPACITY)),
            input_wait: WaitQueue::new(),
        })
    }

    fn push_input(&self, bytes: &[u8]) {
        if !self.is_active() {
            return;
        }

        let mut input = self.input.lock();
        for byte in bytes {
            let byte = if *byte == b'\r' { b'\n' } else { *byte };
            if input.len() == INPUT_CAPACITY {
                input.pop_front();
            }
            input.push_back(byte);
        }
        drop(input);
        self.input_wait.wake_all();
    }

    fn read(&self, output: &mut [u8]) -> usize {
        if output.is_empty() {
            return 0;
        }

        self.input_wait.wait_until(|| {
            if !self.is_active() {
                return Some(0);
            }

            let mut input = self.input.lock();
            if input.is_empty() {
                return None;
            }

            let mut read_len = 0;
            for slot in &mut *output {
                let Some(byte) = input.pop_front() else {
                    break;
                };
                *slot = byte;
                read_len += 1;
            }
            Some(read_len)
        })
    }

    fn clear_input(&self) {
        self.input.lock().clear();
    }

    fn has_input(&self) -> bool {
        self.is_active() && !self.input.lock().is_empty()
    }

    fn enter(&self) {
        self.clear_input();
        aster_console::acquire_input(input_owner());
        self.input_wait.wake_all();
    }

    fn leave(&self) {
        aster_console::release_input(input_owner());
        self.clear_input();
        self.input_wait.wake_all();
    }

    fn is_active(&self) -> bool {
        aster_console::input_is_owned_by(input_owner())
    }
}

#[cfg(feature = "host-api")]
fn input_owner() -> InputOwner {
    *CONSOLE_INPUT_OWNER.call_once(aster_console::alloc_input_owner)
}

#[cfg(feature = "host-api")]
fn endpoint() -> Result<Arc<ConsoleEndpoint>> {
    let endpoint = CONSOLE_ENDPOINT.call_once(|| {
        let devices = aster_console::all_devices();
        let device = PREFERRED_CONSOLE_NAMES
            .iter()
            .find_map(|preferred| {
                devices
                    .iter()
                    .find(|(name, _)| name.as_str() == *preferred)
                    .map(|(_, device)| device.clone())
            })
            .or_else(|| devices.first().map(|(_, device)| device.clone()))?;

        let endpoint = ConsoleEndpoint::new(device.clone());
        let input_endpoint = endpoint.clone();
        device.register_callback(Box::leak(
            Box::new(move |mut reader: OstdVmReader<Infallible>| {
                if !input_endpoint.is_active() {
                    return;
                }

                let mut buffer = [0u8; 64];
                while reader.remain() > 0 {
                    let read_len = reader.remain().min(buffer.len());
                    let mut limited_reader = reader.clone();
                    limited_reader.limit(read_len);
                    limited_reader.read(&mut VmWriter::from(&mut buffer[..read_len]));
                    reader.skip(read_len);
                    input_endpoint.push_input(&buffer[..read_len]);
                    dispatch_transport_input(&buffer[..read_len]);
                }
            }) as Box<ConsoleCallback>,
        ));

        Some(endpoint)
    });

    endpoint.clone().ok_or(Error::NotEnoughResources)
}

#[cfg(feature = "host-api")]
pub(crate) fn write(bytes: &[u8]) -> Result<usize> {
    append_output_str(core::str::from_utf8(bytes).unwrap_or("<binary>"));
    endpoint()?.device.send(bytes);
    Ok(bytes.len())
}

#[cfg(not(feature = "host-api"))]
pub(crate) fn write(bytes: &[u8]) -> Result<usize> {
    append_output_str(core::str::from_utf8(bytes).unwrap_or("<binary>"));
    map_service_transport_result(console_transport::write(bytes))
}

/// Prints formatted arguments to the early console log.
pub fn early_print(args: Arguments<'_>) {
    let mut output = String::new();
    let _ = output.write_fmt(args);
    append_output_str(&output);

    #[cfg(feature = "host-api")]
    if let Ok(endpoint) = endpoint() {
        endpoint.device.send(output.as_bytes());
    }

    #[cfg(not(feature = "host-api"))]
    {
        let _ = console_transport::write(output.as_bytes());
    }
}

#[cfg(feature = "host-api")]
pub(crate) fn read(output: &mut [u8]) -> Result<usize> {
    Ok(endpoint()?.read(output))
}

#[cfg(not(feature = "host-api"))]
pub(crate) fn read(output: &mut [u8]) -> Result<usize> {
    map_service_transport_result(console_transport::read(output))
}

#[cfg(feature = "host-api")]
pub(crate) fn acquire_input() -> Result<()> {
    endpoint()?.enter();
    Ok(())
}

#[cfg(not(feature = "host-api"))]
pub(crate) fn acquire_input() -> Result<()> {
    map_service_transport_result(console_transport::acquire_input())
}

#[cfg(feature = "host-api")]
pub(crate) fn release_input() -> Result<()> {
    endpoint()?.leave();
    Ok(())
}

#[cfg(not(feature = "host-api"))]
pub(crate) fn release_input() -> Result<()> {
    map_service_transport_result(console_transport::release_input())
}

#[cfg(feature = "host-api")]
pub(crate) fn is_active() -> bool {
    match CONSOLE_ENDPOINT.get() {
        Some(Some(endpoint)) => endpoint.is_active(),
        _ => false,
    }
}

#[cfg(not(feature = "host-api"))]
pub(crate) fn is_active() -> bool {
    false
}

#[cfg(feature = "host-api")]
pub(crate) fn has_input() -> bool {
    match CONSOLE_ENDPOINT.get() {
        Some(Some(endpoint)) => endpoint.has_input(),
        _ => false,
    }
}

#[cfg(not(feature = "host-api"))]
pub(crate) fn has_input() -> bool {
    false
}

#[cfg(feature = "host-api")]
pub(crate) fn clear_input() -> Result<()> {
    endpoint()?.clear_input();
    Ok(())
}

#[cfg(not(feature = "host-api"))]
pub(crate) fn clear_input() -> Result<()> {
    Ok(())
}

#[cfg(feature = "host-api")]
pub(crate) fn register_transport_input_callback(callback: TransportInputCallback) -> Result<()> {
    let _ = endpoint()?;
    transport_input_callbacks().lock().push(callback);
    Ok(())
}

#[cfg(feature = "host-api")]
pub(crate) fn clear_transport_input_callbacks() {
    transport_input_callbacks().lock().clear();
}

#[cfg(not(feature = "host-api"))]
fn map_service_transport_result<T>(result: console_transport::Result<T>) -> Result<T> {
    result.map_err(|_| Error::IoError)
}

#[cfg(feature = "host-api")]
pub(crate) fn install_transport_backend() {
    console_transport::install_backend(Backend::new(
        transport_write,
        transport_read,
        transport_acquire_input,
        transport_release_input,
        transport_register_input_callback,
    ));
    console_transport::preserve_symbols();
}

#[cfg(feature = "host-api")]
fn map_transport_result<T>(result: Result<T>) -> console_transport::Result<T> {
    result.map_err(|_| ConsoleTransportError::Unavailable)
}

#[cfg(feature = "host-api")]
fn transport_write(bytes: &[u8]) -> console_transport::Result<usize> {
    map_transport_result(write(bytes))
}

#[cfg(feature = "host-api")]
fn transport_read(output: &mut [u8]) -> console_transport::Result<usize> {
    map_transport_result(read(output))
}

#[cfg(feature = "host-api")]
pub(crate) fn inject_input(bytes: &[u8]) -> Result<usize> {
    let endpoint = endpoint()?;
    queue_injected_input(bytes);
    if endpoint.is_active() {
        dispatch_injected_input();
    }
    Ok(bytes.len())
}

#[cfg(feature = "host-api")]
fn transport_acquire_input() -> console_transport::Result<()> {
    let result = map_transport_result(acquire_input());
    if result.is_ok() {
        dispatch_injected_input();
    }
    result
}

#[cfg(feature = "host-api")]
fn transport_release_input() -> console_transport::Result<()> {
    map_transport_result(release_input())
}

#[cfg(feature = "host-api")]
fn transport_register_input_callback(
    callback: ConsoleInputCallback,
) -> console_transport::Result<()> {
    map_transport_result(register_transport_input_callback(callback))
}

/// Clears captured service console output.
#[cfg(feature = "host-api")]
pub fn clear_output_log() {
    output_log().lock().clear();
}

/// Returns captured service console output.
#[cfg(feature = "host-api")]
pub fn output_log_snapshot() -> String {
    output_log().lock().clone()
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
