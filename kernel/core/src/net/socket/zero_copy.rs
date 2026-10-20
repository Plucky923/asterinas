// SPDX-License-Identifier: MPL-2.0

//! Owning-buffer datagram sockets for shared-buffer network devices.
//!
//! Kernel protocol producers allocate their packet storage here and write it
//! directly. Consumers retain an imported packet instead of copying it into a
//! `MultiWrite` destination. Ordinary Linux socket entry points keep their
//! existing interfaces, address families, and device selection.

use ostd::kernelet::{
    abi::{INVALID, LIMIT, NOT_OWNED, STATE},
    shared_buffer::{
        Buffer, ReadWriteBuffer, ZeroCopyDatagram, ZeroCopyDatagramSocket, ZeroCopyNet,
        ZeroCopyNetInfo,
    },
};

use crate::prelude::*;

/// A kernel socket with a bidirectional, Host-authorized peer connection.
///
/// All operations are nonblocking. No caller byte accessor can outlive its
/// owning packet. Queue backpressure returns the original owned packet once.
pub(crate) struct DatagramSocket {
    transport: ZeroCopyDatagramSocket,
}

impl DatagramSocket {
    /// Opens a currently enumerated independent shared-buffer network device.
    pub(crate) fn open(index: u32) -> Result<Self> {
        let device = ZeroCopyNet::open(index)
            .map_err(transport_error)?
            .ok_or_else(|| Error::with_message(Errno::ENODEV, "shared network device absent"))?;
        Ok(Self {
            transport: device.socket(),
        })
    }

    /// Returns the connection identity and datagram limit.
    pub(crate) fn info(&self) -> ZeroCopyNetInfo {
        self.transport.info()
    }

    /// Allocates a producer's storage without an intermediate packet buffer.
    pub(crate) fn allocate(&self, payload_len: usize) -> Result<ReadWriteBuffer> {
        self.transport
            .allocate(payload_len)
            .map_err(transport_error)
    }

    /// Sends directly from producer storage. Rejection preserves its grant.
    pub(crate) fn send_buffer(
        &self,
        buffer: ReadWriteBuffer,
    ) -> Result<(), (ReadWriteBuffer, Error)> {
        self.transport
            .try_send(buffer)
            .map_err(|(buffer, error)| (buffer, transport_error(error)))
    }

    /// Imports an existing grant for parsing or forwarding without copying it.
    pub(crate) fn import(buffer: Buffer) -> Result<ZeroCopyDatagram, (Buffer, Error)> {
        ZeroCopyDatagram::import(buffer).map_err(|(buffer, error)| (buffer, transport_error(error)))
    }

    /// Sends an existing protocol packet while preserving storage on rejection.
    pub(crate) fn send(&self, packet: ZeroCopyDatagram) -> Result<(), (ZeroCopyDatagram, Error)> {
        self.transport
            .try_send_datagram(packet)
            .map_err(|(packet, error)| (packet, transport_error(error)))
    }

    /// Receives the original allocation. An empty queue returns EAGAIN.
    pub(crate) fn recv(&self) -> Result<ZeroCopyDatagram> {
        self.transport
            .try_recv()
            .map_err(transport_error)?
            .ok_or_else(|| Error::with_message(Errno::EAGAIN, "shared datagram queue empty"))
    }
}

fn transport_error(status: i64) -> Error {
    let errno = match status {
        value if value == -INVALID => Errno::EINVAL,
        value if value == -LIMIT => Errno::EAGAIN,
        value if value == -STATE || value == -NOT_OWNED => Errno::ENOTCONN,
        _ => Errno::EIO,
    };
    Error::with_message(errno, "shared datagram transport failed")
}
