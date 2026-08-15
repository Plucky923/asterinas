// SPDX-License-Identifier: MPL-2.0

//! FrameV block completion status.

/// Virtio-blk-style FrameV block operation status.
///
/// The numeric values intentionally match the `VIRTIO_BLK_S_*` status values
/// from the Linux virtio-blk UAPI definition:
/// <https://github.com/torvalds/linux/blob/master/include/uapi/linux/virtio_blk.h>.
/// FrameV-blk keeps only the success, generic I/O error, and unsupported
/// outcomes needed by its revision-1 frontend/backend contract.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVBlkStatus {
    /// Operation completed successfully.
    Ok = 0,
    /// Operation failed due to I/O, validation, readonly, or malformed input.
    IoErr = 1,
    /// Operation is unsupported.
    Unsupported = 2,
}
