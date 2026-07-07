// SPDX-License-Identifier: MPL-2.0

//! Console endpoint used by the kernel image.

use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec};

use device_id::{DeviceId, MajorId, MinorId};
use ostd::{
    mm::{FallibleVmRead, FallibleVmWrite, VmReader, VmWriter},
    sync::{Once, SpinLock, WaitQueue},
};

use crate::{
    device::{Device, DeviceType, DevtmpfsInodeMeta, registry::char},
    error::{Errno, Error, Result},
    events::IoEvents,
    fs::{
        file::{PerOpenFileOps, StatusFlags},
        vfs::inode::FileOps,
    },
    pollee::{PollHandle, Pollee},
};

const INPUT_CAPACITY: usize = 4096;
static INSTALLING_CONSOLE_ENDPOINT: Once<SpinLock<Option<Arc<ConsoleEndpoint>>>> = Once::new();
static CONSOLE_ENDPOINT: Once<Option<Arc<ConsoleEndpoint>>> = Once::new();

struct ConsoleEndpoint {
    input: SpinLock<VecDeque<u8>>,
    input_wait: WaitQueue,
    pollee: Pollee,
}

impl ConsoleEndpoint {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            input: SpinLock::new(VecDeque::with_capacity(INPUT_CAPACITY)),
            input_wait: WaitQueue::new(),
            pollee: Pollee::new(),
        })
    }

    fn push_input(&self, bytes: &[u8]) {
        let mut input = self.input.lock();
        let mut accepted_len = 0;
        for byte in bytes {
            if input.len() == INPUT_CAPACITY {
                break;
            }

            let byte = if *byte == b'\r' { b'\n' } else { *byte };
            input.push_back(byte);
            accepted_len += 1;
        }
        drop(input);

        if accepted_len != 0 {
            self.input_wait.wake_all();
            self.pollee.notify(IoEvents::IN | IoEvents::RDNORM);
        }
    }

    fn read(&self, output: &mut [u8], nonblocking: bool) -> Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }

        if nonblocking {
            let mut input = self.input.lock();
            if input.is_empty() {
                return Err(Error::new(Errno::EAGAIN));
            }
            let read_len = self.drain_input(&mut input, output);
            return Ok(read_len);
        }

        let read_len = self.input_wait.wait_until(|| {
            let mut input = self.input.lock();
            if input.is_empty() {
                return None;
            }

            let read_len = self.drain_input(&mut input, output);
            Some(read_len)
        });
        Ok(read_len)
    }

    fn drain_input(&self, input: &mut VecDeque<u8>, output: &mut [u8]) -> usize {
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
        read_len
    }

    fn has_input(&self) -> bool {
        !self.input.lock().is_empty()
    }

    fn input_len(&self) -> usize {
        self.input.lock().len()
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

fn endpoint() -> Result<Arc<ConsoleEndpoint>> {
    let endpoint = CONSOLE_ENDPOINT.call_once(|| {
        let endpoint = ConsoleEndpoint::new();
        *installing_endpoint().lock() = Some(endpoint.clone());
        if framev_console_frontend::register_input_callback(dispatch_console_input).is_err() {
            *installing_endpoint().lock() = None;
            return None;
        }

        Some(endpoint)
    });

    endpoint
        .clone()
        .ok_or_else(|| Error::with_message(Errno::EIO, "console device is unavailable"))
}

fn dispatch_console_input(bytes: &[u8]) {
    if let Some(endpoint) = current_or_installing_endpoint() {
        endpoint.push_input(bytes);
    }
}

fn current_or_installing_endpoint() -> Option<Arc<ConsoleEndpoint>> {
    CONSOLE_ENDPOINT
        .get()
        .and_then(|endpoint| endpoint.as_ref())
        .cloned()
        .or_else(|| installing_endpoint().lock().clone())
}

fn installing_endpoint() -> &'static SpinLock<Option<Arc<ConsoleEndpoint>>> {
    INSTALLING_CONSOLE_ENDPOINT.call_once(|| SpinLock::new(None))
}

/// Initializes the default `framev-console` frontend.
pub fn init() -> Result<()> {
    let console =
        framev_bus::console().map_err(|err| Error::with_message(Errno::EINVAL, err.message()))?;
    endpoint()?;
    ostd::early_println!("use console provided by FrameV device {:?}", console.id());
    Ok(())
}

pub(super) fn init_in_first_process() -> Result<()> {
    char::register(SystemConsole::singleton().clone())?;
    Ok(())
}

pub fn read(output: &mut [u8], nonblocking: bool) -> Result<usize> {
    endpoint()?.read(output, nonblocking)
}

pub fn write(input: &[u8]) -> Result<usize> {
    endpoint()?;
    framev_console_frontend::write(input)
        .map_err(|err| Error::with_message(Errno::EIO, err.message()))
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

struct SystemConsole;

impl SystemConsole {
    fn singleton() -> &'static Arc<SystemConsole> {
        static INSTANCE: Once<Arc<SystemConsole>> = Once::new();
        INSTANCE.call_once(|| Arc::new(Self))
    }
}

impl Device for SystemConsole {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        DeviceId::new(MajorId::new(5), MinorId::new(1))
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsInodeMeta<'_>> {
        Some(DevtmpfsInodeMeta::new("console"))
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        endpoint()?;
        Ok(Box::new(ConsoleFile))
    }
}

struct ConsoleFile;

impl FileOps for ConsoleFile {
    fn read_at(
        &self,
        _offset: usize,
        writer: &mut VmWriter,
        status_flags: StatusFlags,
    ) -> Result<usize> {
        let mut buffer = vec![0; writer.avail().min(INPUT_CAPACITY)];
        let read_len = read(&mut buffer, status_flags.contains(StatusFlags::O_NONBLOCK))?;
        let mut reader = VmReader::from(&buffer[..read_len]);
        writer
            .write_fallible(&mut reader)
            .map(|len| len)
            .map_err(|(err, _)| err.into())
    }

    fn write_at(
        &self,
        _offset: usize,
        reader: &mut VmReader,
        _status_flags: StatusFlags,
    ) -> Result<usize> {
        let mut total = 0;
        let mut buffer = vec![0; reader.remain().min(INPUT_CAPACITY)];
        while reader.has_remain() {
            let read_len = reader.remain().min(INPUT_CAPACITY);
            let mut writer = VmWriter::from(&mut buffer[..read_len]);
            let copied = reader
                .read_fallible(&mut writer)
                .map_err(|(err, _)| Error::from(err))?;
            if copied == 0 {
                break;
            }
            write(&buffer[..copied])?;
            total += copied;
        }
        Ok(total)
    }
}

impl crate::process::signal::Pollable for ConsoleFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        poll_revents(mask, poller)
    }
}

impl PerOpenFileOps for ConsoleFile {
    fn check_seekable(&self) -> Result<()> {
        Err(Error::with_message(
            Errno::ESPIPE,
            "console is not seekable",
        ))
    }

    fn is_offset_aware(&self) -> bool {
        false
    }
}
