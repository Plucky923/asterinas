// SPDX-License-Identifier: MPL-2.0

use device_id::DeviceId;

use crate::{device::Device, fs::vfs::path::PathResolver, prelude::*};

pub(super) fn init_in_first_kthread() {}

pub(super) fn init_in_first_process(_path_resolver: &PathResolver) -> Result<()> {
    Ok(())
}

pub(super) fn lookup(_id: DeviceId) -> Option<Arc<dyn Device>> {
    None
}
