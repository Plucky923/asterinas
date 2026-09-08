// SPDX-License-Identifier: MPL-2.0

use core::{
    fmt::Display,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    events::IoEvents,
    fs::{
        file::{AccessMode, CreationFlags, FileCommon, FileLike, StatusFlags, file_table::FdFlags},
        pseudofs::AnonInodeFs,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable, Pollee},
    vmm::FrameVmControl,
};

const CONSOLE_IO_CHUNK: usize = 4096;

pub(super) struct FrameVmConsoleFile {
    cursor: Mutex<u64>,
    control: Arc<FrameVmControl>,
    has_seen_vm: AtomicBool,
    output_callback_registered: AtomicBool,
    pollee: Pollee,
    common: FileCommon,
}

impl FrameVmConsoleFile {
    pub(super) fn new(cursor: u64, control: Arc<FrameVmControl>) -> Arc<Self> {
        let pseudo_path = AnonInodeFs::new_path(|_| "anon_inode:[framevm-console]".to_string());
        Arc::new(Self {
            cursor: Mutex::new(cursor),
            control,
            has_seen_vm: AtomicBool::new(false),
            output_callback_registered: AtomicBool::new(false),
            pollee: Pollee::new(),
            common: FileCommon::new(pseudo_path, AccessMode::O_RDWR, StatusFlags::empty()),
        })
    }

    fn console(&self) -> Result<Option<Arc<aster_framevisor::vm::FrameVm>>> {
        if self.control.state().is_terminal() {
            return Ok(None);
        }
        match self.control.vm_id() {
            None => Ok(None),
            Some(vm_id) => {
                let Some(vm) = aster_framevisor::get_framevm(vm_id) else {
                    return Ok(None);
                };
                if !self.output_callback_registered.swap(true, Ordering::AcqRel) {
                    let pollee = self.pollee.clone();
                    vm.devices()
                        .console()
                        .register_output_callback(Arc::new(move || pollee.notify(IoEvents::IN)));
                }
                self.has_seen_vm.store(true, Ordering::Release);
                Ok(Some(vm))
            }
        }
    }

    fn read_available(
        &self,
        writer: &mut VmWriter,
        vm: &aster_framevisor::vm::FrameVm,
    ) -> Result<usize> {
        loop {
            let mut cursor = self.cursor.lock();
            let output = vm
                .devices()
                .console()
                .read_output_from(*cursor, writer.avail());
            if output.bytes().is_empty() && output.lost_bytes() != 0 {
                *cursor = output.next_offset();
                continue;
            }
            let bytes_start = output.next_offset() - output.bytes().len() as u64;
            let bytes = output.into_bytes();
            let mut reader = VmReader::from(bytes.as_slice());
            let initial_avail = writer.avail();
            let result = writer.write_fallible(&mut reader);
            let written = initial_avail - writer.avail();
            *cursor = bytes_start + written as u64;
            result?;
            return Ok(written);
        }
    }

    fn wait_and_read(
        &self,
        writer: &mut VmWriter,
        vm: &aster_framevisor::vm::FrameVm,
    ) -> Result<usize> {
        loop {
            let offset = *self.cursor.lock();
            let output = match vm
                .devices()
                .console()
                .wait_output_from(offset, writer.avail())
            {
                Ok(output) => output,
                Err(_) => return Ok(0),
            };

            let mut cursor = self.cursor.lock();
            if *cursor != offset {
                continue;
            }
            if output.bytes().is_empty() && output.lost_bytes() != 0 {
                *cursor = output.next_offset();
                continue;
            }
            let bytes_start = output.next_offset() - output.bytes().len() as u64;
            let bytes = output.into_bytes();
            let mut reader = VmReader::from(bytes.as_slice());
            let initial_avail = writer.avail();
            let result = writer.write_fallible(&mut reader);
            let written = initial_avail - writer.avail();
            *cursor = bytes_start + written as u64;
            result?;
            return Ok(written);
        }
    }

    fn read_events(&self) -> IoEvents {
        let Some(vm) = self.console().ok().flatten() else {
            if self.has_seen_vm.load(Ordering::Acquire) {
                return IoEvents::IN | IoEvents::HUP;
            }
            return IoEvents::empty();
        };

        let cursor = *self.cursor.lock();
        let output = vm.devices().console().read_output_from(cursor, 1);
        if !output.bytes().is_empty() || output.lost_bytes() != 0 {
            IoEvents::IN
        } else {
            IoEvents::empty()
        }
    }

    fn no_console_read_result(&self) -> Result<usize> {
        if self.console_has_finished() {
            Ok(0)
        } else {
            return_errno_with_message!(Errno::EAGAIN, "FrameVM console is not available")
        }
    }

    fn no_console_write_result(&self) -> Result<usize> {
        if self.console_has_finished() {
            return_errno_with_message!(Errno::EIO, "FrameVM console is stopped")
        } else {
            return_errno_with_message!(Errno::EAGAIN, "FrameVM console is not available")
        }
    }

    fn console_has_finished(&self) -> bool {
        self.has_seen_vm.load(Ordering::Acquire) || self.control.state().is_terminal()
    }
}

impl Pollable for FrameVmConsoleFile {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        let mut events = if let Some(poller) = poller {
            let events = self
                .pollee
                .poll_with(mask, Some(&mut *poller), || self.read_events());
            events | self.control.poll_terminal(mask, Some(poller))
        } else {
            self.read_events() | self.control.poll_terminal(mask, None)
        };
        if self.console().ok().flatten().is_some() {
            events |= IoEvents::OUT;
        }
        events & mask
    }
}

impl FileLike for FrameVmConsoleFile {
    fn read(&self, writer: &mut VmWriter) -> Result<usize> {
        if writer.avail() == 0 {
            return Ok(0);
        }

        let Some(vm) = self.console()? else {
            let mut cursor = self.cursor.lock();
            if let Some(result) = self
                .control
                .read_retained_console_output(&mut cursor, writer)
            {
                return result;
            }
            return self.no_console_read_result();
        };

        if self.common.is_nonblocking() {
            let read_len = self.read_available(writer, &vm)?;
            if read_len == 0 {
                return_errno_with_message!(Errno::EAGAIN, "no FrameVM console output is available");
            }
            return Ok(read_len);
        }

        self.wait_and_read(writer, &vm)
    }

    fn write(&self, reader: &mut VmReader) -> Result<usize> {
        if reader.remain() == 0 {
            return Ok(0);
        }

        let Some(vm) = self.console()? else {
            return self.no_console_write_result();
        };

        let write_len = reader.remain().min(CONSOLE_IO_CHUNK);
        let mut bytes = vec![0u8; write_len];
        let copied_len = reader.read_fallible(&mut bytes.as_mut_slice().into())?;
        bytes.truncate(copied_len);

        let written_len = if self.common.is_nonblocking() {
            vm.devices().inject_console_input(&bytes)?
        } else {
            match vm.devices().inject_console_input_blocking(&bytes) {
                Ok(written_len) => written_len,
                Err(_) => return_errno_with_message!(Errno::EIO, "FrameVM console is stopped"),
            }
        };

        if written_len == 0 {
            return_errno_with_message!(Errno::EAGAIN, "FrameVM console input is full");
        }
        Ok(written_len)
    }

    fn common(&self) -> &FileCommon {
        &self.common
    }

    fn dump_proc_fdinfo(self: Arc<Self>, fd_flags: FdFlags) -> Box<dyn Display> {
        struct FdInfo {
            inner: Arc<FrameVmConsoleFile>,
            fd_flags: FdFlags,
        }

        impl Display for FdInfo {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let mut flags = self.inner.common.access_mode() as u32;
                flags |= u32::from(self.inner.common.status_flags());
                if self.fd_flags.contains(FdFlags::CLOEXEC) {
                    flags |= CreationFlags::O_CLOEXEC.bits();
                }

                let vm_id = self
                    .inner
                    .console()
                    .ok()
                    .flatten()
                    .and_then(|vm| vm.id().guest_id())
                    .unwrap_or(0);
                writeln!(formatter, "pos:\t{}", 0)?;
                writeln!(formatter, "flags:\t0{:o}", flags)?;
                writeln!(formatter, "vm_id:\t{}", vm_id)?;
                writeln!(formatter, "cursor:\t{}", *self.inner.cursor.lock())
            }
        }

        Box::new(FdInfo {
            inner: self,
            fd_flags,
        })
    }
}
