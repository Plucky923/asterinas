// SPDX-License-Identifier: MPL-2.0

//! A distinct network device that moves access to whole datagram allocations.
//!
//! Each authorized inter-instance datagram connection exposes one bidirectional
//! device. Private Ethernet connections use `SharedNetTransport` discovery.
//! This transport has no Ethernet, IP, or VirtIO framing. A producer writes its
//! protocol bytes directly into shared storage. The consumer imports that same
//! allocation and can parse it through a borrowed reader without copying it.

use super::{Buffer, ReadBuffer, ReadWriteBuffer};
use crate::{
    kernelet::{
        abi::{INVALID, buffer::NET_INFO},
        shared_buffer::{GrantAccess, MAX_DATAGRAM_PAYLOAD, ZeroCopyNetInfo},
    },
    mm::{Infallible, VmReader},
};

/// A separately enumerated, Host-authorized shared-buffer network device.
///
/// Connections appear after the Host creates them. An index is only a discovery
/// position; an opened handle retains its nonreusable connection identity.
#[derive(Clone, Copy, Debug)]
pub struct ZeroCopyNet {
    info: ZeroCopyNetInfo,
}

impl ZeroCopyNet {
    /// Discovers a live link. None marks the end of the current device list.
    pub fn open(index: u32) -> Result<Option<Self>, i64> {
        let reply = super::call(NET_INFO, 0, [index as u64, 0, 0]);
        if reply.status < 0 {
            return Err(reply.status);
        }
        if reply.value == 0 {
            return Ok(None);
        }
        if reply.status == 0 || reply.status as u64 > MAX_DATAGRAM_PAYLOAD as u64 {
            return Err(-INVALID);
        }
        Ok(Some(Self {
            info: ZeroCopyNetInfo {
                connection: reply.value,
                max_payload: reply.status as usize,
            },
        }))
    }

    /// Returns the immutable properties validated when opening this device.
    pub fn info(&self) -> ZeroCopyNetInfo {
        self.info
    }

    /// Creates a nonblocking owning-buffer socket on this bidirectional link.
    pub fn socket(self) -> ZeroCopyDatagramSocket {
        ZeroCopyDatagramSocket { device: self }
    }
}

/// An owned packet suitable for direct import by a socket or protocol layer.
///
/// The packet exposes no writable accessor. Its reader borrows the packet, so
/// sending, releasing, or extracting storage requires every reader to end.
pub struct ZeroCopyDatagram {
    buffer: Buffer,
}

impl ZeroCopyDatagram {
    /// Imports an existing owning grant without copying its payload.
    /// Rejection returns the original wrapper with its permissions intact.
    pub fn import(buffer: Buffer) -> Result<Self, (Buffer, i64)> {
        let payload = match &buffer {
            Buffer::ReadOnly(buffer) => buffer.payload_len(),
            Buffer::ReadWrite(buffer) => buffer.payload_len(),
        };
        if payload > MAX_DATAGRAM_PAYLOAD {
            return Err((buffer, -INVALID));
        }
        Ok(Self { buffer })
    }

    /// Borrows protocol bytes from their original allocation.
    pub fn reader(&self) -> VmReader<'_, Infallible> {
        match &self.buffer {
            Buffer::ReadOnly(buffer) => buffer.reader(),
            Buffer::ReadWrite(buffer) => buffer.reader(),
        }
    }

    /// Returns the exact datagram length; empty datagrams are permitted.
    pub fn payload_len(&self) -> usize {
        match &self.buffer {
            Buffer::ReadOnly(buffer) => buffer.payload_len(),
            Buffer::ReadWrite(buffer) => buffer.payload_len(),
        }
    }

    /// Moves the owning grant into another transport or buffer consumer.
    pub fn into_buffer(self) -> Buffer {
        self.buffer
    }
}

/// A nonblocking datagram socket whose queue entries retain shared storage.
///
/// Successful sends consume the sender's grant and issue a read-only receiver
/// grant. They do not return the buffer to the sender. A full receiver queue
/// rejects the send and returns the original wrapper. Receiving consumes one
/// queued grant; dropping the packet releases it. Leaks remain quota bounded.
///
/// Polling returns None while no packet is queued. This interface neither spins
/// nor parks a task. A caller that needs blocking I/O supplies its own waiting
/// policy. It must not treat acceptance as peer application consumption.
pub struct ZeroCopyDatagramSocket {
    device: ZeroCopyNet,
}

impl ZeroCopyDatagramSocket {
    /// Returns the selected network device's immutable properties.
    pub fn info(&self) -> ZeroCopyNetInfo {
        self.device.info
    }

    /// Allocates initialized storage into which a producer writes directly.
    pub fn allocate(&self, payload_len: usize) -> Result<ReadWriteBuffer, i64> {
        if payload_len > self.device.info.max_payload {
            return Err(-INVALID);
        }
        let mut buffer = ReadWriteBuffer::allocate(payload_len.max(1))?;
        buffer.set_payload_len(payload_len)?;
        Ok(buffer)
    }

    /// Sends a producer's buffer, ending all local access on acceptance.
    pub fn try_send(&self, buffer: ReadWriteBuffer) -> Result<(), (ReadWriteBuffer, i64)> {
        let len = buffer.payload_len();
        if len > self.device.info.max_payload {
            return Err((buffer, -INVALID));
        }
        buffer.handoff(self.device.info.connection, GrantAccess::ReadOnly, len)
    }

    /// Sends an imported read-only grant, preserving its permission on failure.
    pub fn try_send_read_only(&self, buffer: ReadBuffer) -> Result<(), (ReadBuffer, i64)> {
        let len = buffer.payload_len();
        if len > self.device.info.max_payload {
            return Err((buffer, -INVALID));
        }
        buffer.handoff(self.device.info.connection, len)
    }

    /// Forwards an imported packet without allocating or copying payload bytes.
    pub fn try_send_datagram(
        &self,
        packet: ZeroCopyDatagram,
    ) -> Result<(), (ZeroCopyDatagram, i64)> {
        let result = match packet.buffer {
            Buffer::ReadOnly(buffer) => self
                .try_send_read_only(buffer)
                .map_err(|(buffer, error)| (Buffer::ReadOnly(buffer), error)),
            Buffer::ReadWrite(buffer) => self
                .try_send(buffer)
                .map_err(|(buffer, error)| (Buffer::ReadWrite(buffer), error)),
        };
        result.map_err(|(buffer, error)| (ZeroCopyDatagram { buffer }, error))
    }

    /// Receives one owning packet without copying into a posted destination.
    /// Participant teardown makes later operations fail through the Host.
    pub fn try_recv(&self) -> Result<Option<ZeroCopyDatagram>, i64> {
        let Some(buffer) = Buffer::receive(self.device.info.connection)? else {
            return Ok(None);
        };
        let packet = ZeroCopyDatagram::import(buffer).map_err(|(_, error)| error)?;
        if packet.payload_len() > self.device.info.max_payload {
            return Err(-INVALID);
        }
        Ok(Some(packet))
    }
}
