// SPDX-License-Identifier: MPL-2.0

//! Typed device interface for explicit shared-buffer block attachments.

use super::{PendingIo, ReadBuffer, ReadWriteBuffer};
use crate::kernelet::{
    abi::{
        INVALID,
        buffer::{BLOCK_ALIGNMENT, BLOCK_INFO, DEVICE_READ_ONLY},
    },
    shared_buffer::{DeviceAccess, ZeroCopyBlockInfo},
};

/// A Host-authorized zero-copy block attachment, in its own device namespace.
/// It cannot address an ordinary VirtIO MMIO device. Buffer access returns
/// through the owning request's return grant after all backend holds end.
#[derive(Clone, Copy, Debug)]
pub struct ZeroCopyBlock {
    id: u32,
    info: ZeroCopyBlockInfo,
}

impl ZeroCopyBlock {
    /// Discovers the attachment at this index. None marks the end of the list.
    pub fn open(index: u32) -> Result<Option<Self>, i64> {
        let reply = super::call(BLOCK_INFO, 0, [index as u64, 0, 0]);
        if reply.status < 0 {
            return Err(reply.status);
        }
        if reply.value == 0 {
            return Ok(None);
        }
        if reply.status & !DEVICE_READ_ONLY != 0
            || !reply.value.is_multiple_of(BLOCK_ALIGNMENT as u64)
        {
            return Err(-INVALID);
        }
        Ok(Some(Self {
            id: index,
            info: ZeroCopyBlockInfo {
                capacity_bytes: reply.value,
                read_only: reply.status & DEVICE_READ_ONLY != 0,
            },
        }))
    }

    /// Returns immutable Host-validated device properties.
    pub fn info(&self) -> ZeroCopyBlockInfo {
        self.info
    }

    /// Reads a disk range into the owned allocation, or returns it on rejection.
    pub fn read(
        &self,
        buffer: ReadWriteBuffer,
        offset: u64,
        len: usize,
    ) -> Result<PendingIo, (ReadWriteBuffer, i64)> {
        if !self.info.permits(offset, len, DeviceAccess::Write) {
            return Err((buffer, -INVALID));
        }
        buffer.submit(self.id, offset, len, DeviceAccess::Write)
    }

    /// Writes a range from an exclusively owned buffer's useful payload.
    pub fn write(
        &self,
        buffer: ReadWriteBuffer,
        offset: u64,
        len: usize,
    ) -> Result<PendingIo, (ReadWriteBuffer, i64)> {
        if !self.info.permits(offset, len, DeviceAccess::Read) || len > buffer.payload_len() {
            return Err((buffer, -INVALID));
        }
        buffer.submit(self.id, offset, len, DeviceAccess::Read)
    }

    /// Writes a range from a read-only grant; it grants no device write access.
    pub fn write_read_only(
        &self,
        buffer: ReadBuffer,
        offset: u64,
        len: usize,
    ) -> Result<PendingIo, (ReadBuffer, i64)> {
        if !self.info.permits(offset, len, DeviceAccess::Read) {
            return Err((buffer, -INVALID));
        }
        buffer.submit(self.id, offset, len)
    }
}
