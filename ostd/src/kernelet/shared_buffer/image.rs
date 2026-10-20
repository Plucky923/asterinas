// SPDX-License-Identifier: MPL-2.0

//! Image-side owning grants and backend request lifetimes.
//!
//! `Local` redeems a single-use Host token and releases it on drop. The public
//! read-only and read-write wrappers tie byte access to their own borrows.
//! Handoff consumes ownership; submission moves it into `PendingIo` until the
//! Host returns a fresh grant after every backend hold ends. The block and
//! network submodules expose typed device operations over this protocol.

use super::{DeviceAccess, GrantAccess};
use crate::{
    kernelet::{
        abi::{INVALID, MmioResult, buffer::*},
        entry,
    },
    mm::{Infallible, VmReader, VmWriter},
};

mod block;
pub use block::ZeroCopyBlock;
mod net;
pub use net::{ZeroCopyDatagram, ZeroCopyDatagramSocket, ZeroCopyNet};
mod shared_net;
pub use shared_net::SharedNetTransport;

fn call(operation: u32, token: u64, args: [u64; 3]) -> MmioResult {
    (entry::services().buffer)(operation, token, args[0], args[1], args[2])
}

struct Local {
    token: u64,
    address: usize,
    capacity: usize,
    payload: usize,
}

impl Local {
    fn reader(&self) -> VmReader<'_, Infallible> {
        // SAFETY: Single-use redemption retains initialized shared storage.
        // The accessor borrows this owning wrapper, preventing a consuming
        // operation until the accessor ends. Only payload bytes are readable.
        unsafe { VmReader::from_kernel_space(self.address as *const u8, self.payload) }
    }

    fn handoff(&mut self, connection: u64, access: GrantAccess, payload: usize) -> Result<(), i64> {
        if payload > self.capacity {
            return Err(-INVALID);
        }
        let reply = call(
            HANDOFF,
            self.token,
            [connection, access as u64, payload as u64],
        );
        if reply.status < 0 {
            return Err(reply.status);
        }
        self.token = 0;
        Ok(())
    }

    fn submit(
        &mut self,
        device: u32,
        offset: u64,
        len: usize,
        access: DeviceAccess,
    ) -> Result<PendingIo, i64> {
        if len == 0 || len > self.capacity {
            return Err(-INVALID);
        }
        let reply = call(
            SUBMIT,
            self.token,
            [
                device as u64,
                offset,
                len as u64 | ((u64::from(access == DeviceAccess::Write)) << 32),
            ],
        );
        if reply.status < 0 {
            return Err(reply.status);
        }
        self.token = 0;
        Ok(PendingIo {
            token: reply.value,
            returned: None,
        })
    }
}

impl Drop for Local {
    fn drop(&mut self) {
        if self.token != 0 {
            call(RELEASE, self.token, [0; 3]);
        }
    }
}

/// Read-only grant. No writable backing or identifier constructor is exposed.
pub struct ReadBuffer(Local);
/// Exclusive local read/write grant. Writers require a mutable borrow.
pub struct ReadWriteBuffer(Local);

/// Imported or returned buffer, selected by its Host-validated access mode.
pub enum Buffer {
    /// Imported read-only access.
    ReadOnly(ReadBuffer),
    /// Imported exclusive read/write access.
    ReadWrite(ReadWriteBuffer),
}

/// An operation result and a new local grant for the same allocation.
pub struct Received {
    /// Backend status, including errors after acceptance.
    pub status: i64,
    /// The return grant's validated permissions.
    pub buffer: Buffer,
}

fn redeem(token: u64) -> Result<Buffer, i64> {
    let reply = call(REDEEM, token, [0; 3]);
    if reply.status < 0 {
        return Err(reply.status);
    }
    buffer_from_mapping(token, reply.value, reply.status)
}

fn buffer_from_mapping(token: u64, address: u64, mapping: i64) -> Result<Buffer, i64> {
    let (capacity, payload, writable) = mapping_fields(mapping);
    // Host and vOSTD are trusted and built from matching source. These checks
    // catch a broken response before constructing any byte accessor.
    if address == 0
        || capacity == 0
        || capacity > MAX_CAPACITY
        || payload > capacity
        || address.checked_add(capacity as u64).is_none()
    {
        call(RELEASE, token, [0; 3]);
        return Err(-INVALID);
    }
    let local = Local {
        token,
        address: address as usize,
        capacity,
        payload,
    };
    Ok(if writable {
        Buffer::ReadWrite(ReadWriteBuffer(local))
    } else {
        Buffer::ReadOnly(ReadBuffer(local))
    })
}

impl ReadWriteBuffer {
    /// Allocates zeroed storage. Capacity is rounded up to a page.
    pub fn allocate(capacity: usize) -> Result<Self, i64> {
        Self::allocate_with(ALLOCATE, capacity, 0)
    }

    fn allocate_with(operation: u32, capacity: usize, connection: u64) -> Result<Self, i64> {
        let reply = call(operation, 0, [capacity as u64, connection, 0]);
        if reply.status < 0 {
            return Err(reply.status);
        }
        match redeem(reply.value) {
            Ok(Buffer::ReadWrite(buffer)) => Ok(buffer),
            Ok(_) => Err(-INVALID),
            Err(error) => {
                call(DISCARD, reply.value, [0; 3]);
                Err(error)
            }
        }
    }

    /// Returns the full initialized capacity authorized by this grant.
    pub fn capacity(&self) -> usize {
        self.0.capacity
    }
    /// Returns the useful payload length.
    pub fn payload_len(&self) -> usize {
        self.0.payload
    }
    /// Sets useful payload length within the initialized allocation.
    pub fn set_payload_len(&mut self, len: usize) -> Result<(), i64> {
        if len > self.0.capacity {
            return Err(-INVALID);
        }
        self.0.payload = len;
        Ok(())
    }
    /// Borrows the useful payload for reads.
    pub fn reader(&self) -> VmReader<'_, Infallible> {
        self.0.reader()
    }
    /// Exclusively borrows the initialized capacity for writes.
    pub fn writer(&mut self) -> VmWriter<'_, Infallible> {
        // SAFETY: The exclusive local borrow excludes readers, writers and
        // consuming operations. Allocation zeroing initializes full capacity.
        unsafe { VmWriter::from_kernel_space(self.0.address as *mut u8, self.0.capacity) }
    }

    /// Transfers access, returning this wrapper unchanged on rejection.
    pub fn handoff(
        mut self,
        connection: u64,
        access: GrantAccess,
        payload_len: usize,
    ) -> Result<(), (Self, i64)> {
        match self.0.handoff(connection, access, payload_len) {
            Ok(()) => Ok(()),
            Err(error) => Err((self, error)),
        }
    }

    /// Submits owning storage, returning this wrapper on pre-acceptance errors.
    pub fn submit(
        mut self,
        device: u32,
        offset: u64,
        len: usize,
        access: DeviceAccess,
    ) -> Result<PendingIo, (Self, i64)> {
        match self.0.submit(device, offset, len, access) {
            Ok(request) => Ok(request),
            Err(error) => Err((self, error)),
        }
    }
}

impl ReadBuffer {
    /// Returns the initialized capacity; this type exposes only payload reads.
    pub fn capacity(&self) -> usize {
        self.0.capacity
    }
    /// Returns the readable payload length.
    pub fn payload_len(&self) -> usize {
        self.0.payload
    }
    /// Borrows only the authorized useful payload for reads.
    pub fn reader(&self) -> VmReader<'_, Infallible> {
        self.0.reader()
    }

    /// Forwards read-only access, returning this wrapper on rejection.
    pub fn handoff(mut self, connection: u64, payload_len: usize) -> Result<(), (Self, i64)> {
        if payload_len > self.0.payload {
            return Err((self, -INVALID));
        }
        match self
            .0
            .handoff(connection, GrantAccess::ReadOnly, payload_len)
        {
            Ok(()) => Ok(()),
            Err(error) => Err((self, error)),
        }
    }

    /// A read-only holder can submit only device reads (disk writes / TX).
    pub fn submit(
        mut self,
        device: u32,
        offset: u64,
        len: usize,
    ) -> Result<PendingIo, (Self, i64)> {
        if len > self.0.payload {
            return Err((self, -INVALID));
        }
        match self.0.submit(device, offset, len, DeviceAccess::Read) {
            Ok(request) => Ok(request),
            Err(error) => Err((self, error)),
        }
    }
}

impl Buffer {
    /// Enumerates connections authorized by the Host for this instance.
    pub fn connection(index: u32) -> Result<Option<u64>, i64> {
        let reply = call(CONNECTION, 0, [index as u64, 0, 0]);
        if reply.status < 0 {
            return Err(reply.status);
        }
        Ok((reply.value != 0).then_some(reply.value))
    }
    /// Polls a Host-authorized connection. Repeated polling never duplicates a
    /// wrapper: the grant is activated exactly once by redemption.
    pub fn receive(connection: u64) -> Result<Option<Self>, i64> {
        let reply = call(RECEIVE, 0, [connection, 0, 0]);
        if reply.status < 0 {
            return Err(reply.status);
        }
        if reply.value == 0 {
            return Ok(None);
        }
        match redeem(reply.value) {
            Ok(buffer) => Ok(Some(buffer)),
            Err(error) if error == -INVALID => {
                // Another receiver of this connection may have redeemed the
                // observed grant between these two service calls. Reobserve
                // once without consuming a later grant or hiding an invalid
                // token that remains queued.
                let observed = call(RECEIVE, 0, [connection, 0, 0]);
                if observed.status < 0 {
                    Err(observed.status)
                } else if observed.value != reply.value {
                    Ok(None)
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }
}

/// Accepted work. Dropping it requests cancellation and discards its result;
/// storage remains retained until every backend access and callback ends.
pub struct PendingIo {
    token: u64,
    returned: Option<(i64, u64)>,
}

impl PendingIo {
    /// Requests cancellation without returning local buffer access.
    pub fn cancel(&self) -> Result<(), i64> {
        if self.returned.is_some() || self.token == 0 {
            return Ok(());
        }
        let reply = call(CANCEL, self.token, [0; 3]);
        if reply.status < 0 {
            Err(reply.status)
        } else {
            Ok(())
        }
    }

    /// Redeems completed storage once; backend errors accompany the buffer.
    pub fn poll(&mut self) -> Result<Option<Received>, i64> {
        if let Some((status, token)) = self.returned {
            let buffer = redeem(token)?;
            self.returned = None;
            self.token = 0;
            return Ok(Some(Received { status, buffer }));
        }
        let reply = call(POLL, self.token, [0; 3]);
        if reply.value == 0 {
            return if reply.status < 0 {
                Err(reply.status)
            } else {
                Ok(None)
            };
        }
        // Preserve the return token if activation fails; a subsequent poll
        // must retry that grant rather than querying the retired operation.
        self.returned = Some((reply.status, reply.value));
        let buffer = redeem(reply.value)?;
        self.returned = None;
        self.token = 0;
        Ok(Some(Received {
            status: reply.status,
            buffer,
        }))
    }
}

impl Drop for PendingIo {
    fn drop(&mut self) {
        if let Some((_, token)) = self.returned {
            call(DISCARD, token, [0; 3]);
        } else if self.token != 0 {
            call(ABANDON, self.token, [0; 3]);
        }
    }
}
