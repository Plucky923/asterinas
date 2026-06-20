// SPDX-License-Identifier: MPL-2.0

//! Console endpoint used by the kernel image.

use alloc::{boxed::Box, collections::VecDeque, sync::Arc};

use aster_console::{AnyConsoleDevice, ConsoleCallback, InputOwner};
use ostd::{
    mm::{Infallible, VmReader, VmWriter},
    sync::{Once, SpinLock, WaitQueue},
};

use crate::{
    error::{Errno, Error, Result},
    events::IoEvents,
    pollee::{PollHandle, Pollee},
};

const INPUT_CAPACITY: usize = 4096;
const PREFERRED_CONSOLE_NAMES: &[&str] = &["Uart-Console", "Virtio-Console"];

static CONSOLE_ENDPOINT: Once<Option<Arc<ConsoleEndpoint>>> = Once::new();
static CONSOLE_INPUT_OWNER: Once<InputOwner> = Once::new();

struct ConsoleEndpoint {
    device: Arc<dyn AnyConsoleDevice>,
    input: SpinLock<VecDeque<u8>>,
    input_wait: WaitQueue,
    pollee: Pollee,
}

impl ConsoleEndpoint {
    fn new(device: Arc<dyn AnyConsoleDevice>) -> Arc<Self> {
        Arc::new(Self {
            device,
            input: SpinLock::new(VecDeque::with_capacity(INPUT_CAPACITY)),
            input_wait: WaitQueue::new(),
            pollee: Pollee::new(),
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
        self.pollee.notify(IoEvents::IN | IoEvents::RDNORM);
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
            if input.is_empty() {
                self.pollee.invalidate();
            }
            Some(read_len)
        })
    }

    fn clear_input(&self) {
        self.input.lock().clear();
        self.pollee.invalidate();
    }

    fn has_input(&self) -> bool {
        self.is_active() && !self.input.lock().is_empty()
    }

    fn input_len(&self) -> usize {
        if self.is_active() {
            self.input.lock().len()
        } else {
            0
        }
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

    fn check_io_events(&self) -> IoEvents {
        let mut events = IoEvents::OUT;
        if self.has_input() {
            events |= IoEvents::IN | IoEvents::RDNORM;
        }
        events
    }

    fn poll_revents(&self, events: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(events, poller, || self.check_io_events())
    }
}

fn input_owner() -> InputOwner {
    *CONSOLE_INPUT_OWNER.call_once(aster_console::alloc_input_owner)
}

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
            Box::new(move |mut reader: VmReader<Infallible>| {
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
                }
            }) as Box<ConsoleCallback>,
        ));

        Some(endpoint)
    });

    endpoint
        .clone()
        .ok_or_else(|| Error::with_message(Errno::EIO, "console device is unavailable"))
}

pub fn acquire_input() -> Result<()> {
    endpoint()?.enter();
    Ok(())
}

pub fn release_input() -> Result<()> {
    endpoint()?.leave();
    Ok(())
}

pub fn read(output: &mut [u8]) -> Result<usize> {
    Ok(endpoint()?.read(output))
}

pub fn write(input: &[u8]) -> Result<usize> {
    endpoint()?.device.send(input);
    Ok(input.len())
}

pub fn has_input() -> bool {
    CONSOLE_ENDPOINT
        .get()
        .and_then(|endpoint| endpoint.as_ref())
        .is_some_and(|endpoint| endpoint.has_input())
}

pub fn input_len() -> Result<usize> {
    Ok(endpoint()?.input_len())
}

pub fn poll_revents(events: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
    match CONSOLE_ENDPOINT
        .get()
        .and_then(|endpoint| endpoint.as_ref())
    {
        Some(endpoint) => endpoint.poll_revents(events, poller),
        None => events & IoEvents::OUT,
    }
}
