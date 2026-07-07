// SPDX-License-Identifier: MPL-2.0

use core::{
    fmt::Display,
    sync::atomic::{AtomicBool, Ordering},
};

use crate::{
    events::IoEvents,
    fs::{
        file::{
            AccessMode, AtomicStatusFlags, CreationFlags, FileLike, StatusFlags,
            file_table::FdFlags,
        },
        pseudofs::AnonInodeFs,
        vfs::path::Path,
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
};

const CONSOLE_IO_CHUNK: usize = 4096;

pub(super) struct FrameVmConsoleFile {
    cursor: Mutex<u64>,
    has_seen_vm: AtomicBool,
    status_flags: AtomicStatusFlags,
    pseudo_path: Path,
}

impl FrameVmConsoleFile {
    pub(super) fn new(cursor: u64) -> Arc<Self> {
        Arc::new(Self {
            cursor: Mutex::new(cursor),
            has_seen_vm: AtomicBool::new(false),
            status_flags: AtomicStatusFlags::new(StatusFlags::empty()),
            pseudo_path: AnonInodeFs::new_path(|_| "anon_inode:[framevm-console]".to_string()),
        })
    }

    fn console(&self) -> Result<Option<Arc<aster_framevisor::vm::FrameVm>>> {
        let framevms = aster_framevisor::list_framevms();
        match framevms.as_slice() {
            [] => Ok(None),
            [vm_id] => {
                let vm = aster_framevisor::get_framevm(*vm_id)
                    .ok_or_else(|| Error::with_message(Errno::EINVAL, "FrameVM does not exist"))?;
                self.has_seen_vm.store(true, Ordering::Release);
                Ok(Some(vm))
            }
            _ => return_errno_with_message!(Errno::EBUSY, "multiple FrameVM consoles exist"),
        }
    }

    fn read_available(
        &self,
        writer: &mut VmWriter,
        vm: &aster_framevisor::vm::FrameVm,
    ) -> Result<usize> {
        loop {
            let bytes = {
                let mut cursor = self.cursor.lock();
                let output = vm
                    .devices()
                    .console()
                    .read_output_from(*cursor, writer.avail());
                *cursor = output.next_offset();
                if output.bytes().is_empty() && output.lost_bytes() != 0 {
                    None
                } else {
                    Some(output.into_bytes())
                }
            };

            let Some(bytes) = bytes else {
                continue;
            };
            let mut reader = VmReader::from(bytes.as_slice());
            return Ok(writer.write_fallible(&mut reader)?);
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

            let bytes = {
                let mut cursor = self.cursor.lock();
                if *cursor != offset {
                    None
                } else {
                    *cursor = output.next_offset();
                    if output.bytes().is_empty() && output.lost_bytes() != 0 {
                        None
                    } else {
                        Some(output.into_bytes())
                    }
                }
            };

            let Some(bytes) = bytes else {
                continue;
            };
            let mut reader = VmReader::from(bytes.as_slice());
            return Ok(writer.write_fallible(&mut reader)?);
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
        if self.has_seen_vm.load(Ordering::Acquire) {
            Ok(0)
        } else {
            return_errno_with_message!(Errno::EAGAIN, "FrameVM console is not available")
        }
    }

    fn no_console_write_result(&self) -> Result<usize> {
        if self.has_seen_vm.load(Ordering::Acquire) {
            return_errno_with_message!(Errno::EIO, "FrameVM console is stopped")
        } else {
            return_errno_with_message!(Errno::EAGAIN, "FrameVM console is not available")
        }
    }
}

impl Pollable for FrameVmConsoleFile {
    fn poll(&self, mask: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        let mut events = self.read_events();
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
            return self.no_console_read_result();
        };

        if self.status_flags().contains(StatusFlags::O_NONBLOCK) {
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

        let written_len = if self.status_flags().contains(StatusFlags::O_NONBLOCK) {
            vm.devices().console().inject_input(&bytes)?
        } else {
            match vm.devices().console().inject_input_blocking(&bytes) {
                Ok(written_len) => written_len,
                Err(_) => return_errno_with_message!(Errno::EIO, "FrameVM console is stopped"),
            }
        };

        if written_len == 0 {
            return_errno_with_message!(Errno::EAGAIN, "FrameVM console input is full");
        }
        Ok(written_len)
    }

    fn access_mode(&self) -> AccessMode {
        AccessMode::O_RDWR
    }

    fn path(&self) -> &Path {
        &self.pseudo_path
    }

    fn status_flags(&self) -> StatusFlags {
        self.status_flags.load(Ordering::Relaxed)
    }

    fn set_status_flags(&self, new_flags: StatusFlags) -> Result<()> {
        self.status_flags.store(
            new_flags & (StatusFlags::O_NONBLOCK | StatusFlags::O_ASYNC),
            Ordering::Relaxed,
        );
        Ok(())
    }

    fn dump_proc_fdinfo(self: Arc<Self>, fd_flags: FdFlags) -> Box<dyn Display> {
        struct FdInfo {
            inner: Arc<FrameVmConsoleFile>,
            fd_flags: FdFlags,
        }

        impl Display for FdInfo {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let mut flags = self.inner.access_mode() as u32;
                flags |= u32::from(self.inner.status_flags());
                if self.fd_flags.contains(FdFlags::CLOEXEC) {
                    flags |= CreationFlags::O_CLOEXEC.bits();
                }

                let vm_id = self.inner.console().ok().flatten().map_or(0, |vm| vm.id());
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
