// SPDX-License-Identifier: MPL-2.0

//! `/dev/framevm` control device.

use device_id::{DeviceId, MinorId};

use crate::{
    device::{Device, DeviceType, DevtmpfsInodeMeta, registry::char},
    fs::file::{PerOpenFileOps, mkmod},
    prelude::*,
};

mod console_file;
mod controller;
mod ioctl_defs;
mod vm_file;

const FRAMEVM_MINOR: u32 = 0x7c;

/// The `/dev/framevm` controller device.
#[derive(Debug)]
struct FrameVmDevice {
    id: DeviceId,
}

impl FrameVmDevice {
    fn new() -> Arc<Self> {
        let major = super::MISC_MAJOR.get().unwrap().get();
        let minor = MinorId::new(FRAMEVM_MINOR);

        let id = DeviceId::new(major, minor);
        Arc::new(Self { id })
    }
}

impl Device for FrameVmDevice {
    fn type_(&self) -> DeviceType {
        DeviceType::Char
    }

    fn id(&self) -> DeviceId {
        self.id
    }

    fn devtmpfs_meta(&self) -> Option<DevtmpfsInodeMeta<'_>> {
        Some(DevtmpfsInodeMeta::with_mode("framevm", mkmod!(u+rw)))
    }

    fn open(&self) -> Result<Box<dyn PerOpenFileOps>> {
        // TODO: Reject non-`O_RDWR` opens with `EINVAL` once device `open`
        // callbacks receive the requested access mode.
        Ok(Box::new(controller::FrameVmControllerFile))
    }
}

pub(super) fn init_in_first_kthread() {
    char::register(FrameVmDevice::new()).unwrap();
}
