// SPDX-License-Identifier: MPL-2.0

//! FrameVM rootfs support.

use alloc::sync::Arc;

use crate::{
    error::{Errno, Error, Result},
    fs::{
        fs_impls::ext2::Ext2,
        vfs::{file_system::FileSystem, path::MountNamespace},
    },
};

/// Mounts the FrameVM root filesystem from the whole `framevblk0` device.
pub fn mount_ext2_root_from_block_device() -> Result<()> {
    let block = aster_block::collect_all()
        .into_iter()
        .find(|device| device.name() == "framevblk0")
        .ok_or_else(|| {
            log_block_devices_for_rootfs();
            Error::with_message(Errno::ENOENT, "missing framevblk0")
        })?;
    let rootfs = Ext2::open(block, None).map(|fs| fs as Arc<dyn FileSystem>)?;
    MountNamespace::init_singleton_with_root(rootfs)
}

fn log_block_devices_for_rootfs() {
    ostd::early_println!("FrameVM rootfs requires a FrameV-blk device named framevblk0");
    for device in aster_block::collect_all() {
        ostd::early_println!("available block device: {}", device.name());
    }
}
