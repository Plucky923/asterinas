// SPDX-License-Identifier: MPL-2.0

//! Concrete file system implementations.
//!
//! This module contains all the specific file system implementations supported by the kernel.

pub mod ext2;
pub mod procfs;
pub mod pseudofs;
pub mod ramfs;
pub mod sysfs;
pub mod tmpfs;

pub(super) fn init() {
    sysfs::init();
    procfs::init();
    ramfs::init();
    tmpfs::init();
    pseudofs::init();
    ext2::init();
}
