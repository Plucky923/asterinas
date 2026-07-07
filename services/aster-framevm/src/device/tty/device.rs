// SPDX-License-Identifier: MPL-2.0

//! TTY devices.
//!
//! This module implements TTY devices such as `/dev/tty` and `/dev/console`.
//!
//! Reference: <https://www.kernel.org/doc/html/latest/admin-guide/devices.html>

use device_id::{DeviceId, MajorId, MinorId};
use spin::Once;

use crate::{
    device::{registry::char, tty::framev_console_device, Device, DeviceType, DevtmpfsInodeMeta},
    fs::file::{mkmod, PerOpenFileOps},
    prelude::*,
};

/// Corresponds to `/dev/tty` in the file system. This device represents the controlling terminal
/// of the session of the current process.
pub struct TtyDevice;

impl Device for TtyDevice {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        DeviceId::new(MajorId::new(5), MinorId::new(0))
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsInodeMeta<'_>> {
        // Reference: <https://elixir.bootlin.com/linux/v6.18/source/drivers/tty/tty_io.c#L3511>.
        Some(DevtmpfsInodeMeta::with_mode("tty", mkmod!(a+rw)))
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        let Some(terminal) = current!().terminal() else {
            return_errno_with_message!(
                Errno::ENOTTY,
                "the process does not have a controlling terminal"
            );
        };

        terminal.open()
    }
}

/// Corresponds to `/dev/console` in the file system. This device represents a console to which
/// system messages will be sent.
pub struct SystemConsole {
    inner: Arc<dyn Device>,
}

impl SystemConsole {
    /// Returns the singleton instance of the console device.
    pub fn singleton() -> Result<&'static Arc<SystemConsole>> {
        static INSTANCE: Once<Arc<SystemConsole>> = Once::new();

        let inner = framev_console_device()?;
        Ok(INSTANCE.call_once(|| Arc::new(Self { inner })))
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
        self.inner.open()
    }
}

pub(super) fn init_in_first_process() -> Result<()> {
    char::register(Arc::new(TtyDevice))?;
    char::register(SystemConsole::singleton()?.clone())?;

    Ok(())
}
