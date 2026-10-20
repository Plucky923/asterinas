// SPDX-License-Identifier: MPL-2.0

//! Discovery and bounded owning exchanges for the selected Ethernet transport.

use super::{Buffer, ReadWriteBuffer, buffer_from_mapping};
use crate::{
    kernelet::{
        abi::{
            INVALID, LIMIT,
            buffer::{self, SHARED_NET_EXCHANGE, SHARED_NET_INFO, SHARED_NET_KICK},
        },
        shared_buffer::{SharedNetHeader, SharedNetInfo},
    },
    mm::{HasPaddr, PAGE_SIZE, dma::DmaCoherent, io::util::HasVmReaderWriter},
};

/// A startup-authorized NIC connection, separate from user-created datagrams.
pub struct SharedNetTransport {
    index: u32,
    info: SharedNetInfo,
    scratch: DmaCoherent,
    pending: bool,
}

impl SharedNetTransport {
    /// Maximum empty returns and received grants in one exchange.
    pub const BATCH_SIZE: usize = buffer::SHARED_NET_BATCH_SIZE;
    pub const POOL_SIZE: usize = buffer::SHARED_NET_POOL_SIZE;

    /// Discovers a NIC. A zero connection marks the end of the device list.
    pub fn open(index: u32) -> Result<Option<Self>, i64> {
        let query_fn = |kind: u32| {
            let reply = super::call(SHARED_NET_INFO, 0, [index as u64, kind as u64, 0]);
            if reply.status < 0 {
                Err(reply.status)
            } else {
                Ok(reply.value)
            }
        };
        let connection = query_fn(buffer::NET_QUERY_CONNECTION)?;
        if connection == 0 {
            return Ok(None);
        }
        let mac_value = query_fn(buffer::NET_QUERY_MAC)?;
        let max_frame =
            usize::try_from(query_fn(buffer::NET_QUERY_MAX_FRAME)?).map_err(|_| -INVALID)?;
        let irq = u8::try_from(query_fn(buffer::NET_QUERY_IRQ)?).map_err(|_| -INVALID)?;
        if mac_value >> 48 != 0 || !(14..=SharedNetHeader::MAX_FRAME).contains(&max_frame) {
            return Err(-INVALID);
        }
        let mut mac = [0; 6];
        mac.copy_from_slice(&mac_value.to_le_bytes()[..6]);
        Ok(Some(Self {
            index,
            info: SharedNetInfo {
                connection,
                mac,
                max_frame,
                irq,
            },
            scratch: DmaCoherent::alloc(1, true).map_err(|_| -LIMIT)?,
            pending: false,
        }))
    }

    /// Returns immutable properties checked during discovery.
    pub fn info(&self) -> SharedNetInfo {
        self.info
    }

    /// Allocates one page from the selected NIC's independent bounded pool.
    pub fn allocate_buffer(&self) -> Result<ReadWriteBuffer, i64> {
        ReadWriteBuffer::allocate_with(buffer::SHARED_NET_ALLOCATE, PAGE_SIZE, self.info.connection)
    }

    /// Reports queued deliveries observed after the last successful exchange.
    /// Later handoffs are reported through the device's interrupt notification.
    pub fn has_pending(&self) -> bool {
        self.pending
    }

    /// Publishes one owning transmit batch. Rejection leaves every slot intact;
    /// successful publication disarms wrappers before their local destruction.
    pub fn transmit(
        &mut self,
        frames: &mut [Option<(ReadWriteBuffer, usize)>; Self::BATCH_SIZE],
    ) -> Result<usize, i64> {
        let mut descriptors = [buffer::NetTransmitDescriptor::default(); Self::BATCH_SIZE];
        let mut count = 0;
        for (frame, payload) in frames.iter().flatten() {
            if *payload == 0 || *payload > frame.capacity() {
                return Err(-INVALID);
            }
            descriptors[count] = buffer::NetTransmitDescriptor {
                token: frame.0.token,
                payload: *payload as u64,
            };
            count += 1;
        }
        if count == 0 {
            return Ok(0);
        }
        const {
            assert!(size_of::<[buffer::NetTransmitDescriptor; Self::BATCH_SIZE]>() <= PAGE_SIZE);
        }
        let bytes = ostd_pod::IntoBytes::as_bytes(&descriptors[..count]);
        self.scratch
            .writer()
            .write(&mut crate::mm::VmReader::from(bytes));
        let reply = super::call(
            buffer::SHARED_NET_TRANSMIT,
            0,
            [
                self.info.connection,
                self.scratch.paddr() as u64,
                count as u64,
            ],
        );
        if reply.status < 0 {
            return Err(reply.status);
        }
        // The trusted Host accepted all descriptors. Disarm first even if its
        // reply count is malformed, so no accepted token is released twice.
        for slot in frames {
            if let Some((mut frame, _)) = slot.take() {
                frame.0.token = 0;
            }
        }
        if reply.value != count as u64 {
            return Err(-INVALID);
        }
        Ok(count)
    }

    /// Returns empty buffers and receives active grants in one bounded call.
    ///
    /// `received` must contain only `None`. Success clears every `returns` slot
    /// and fills the first returned-count slots in `received`. Host rejection
    /// keeps all input owners. Malformed trusted replies can report an error
    /// after accepted returns have ended access.
    /// No packet allocation or payload copy occurs here.
    pub fn exchange(
        &mut self,
        returns: &mut [Option<ReadWriteBuffer>; Self::BATCH_SIZE],
        received: &mut [Option<Buffer>; Self::BATCH_SIZE],
    ) -> Result<usize, i64> {
        if received.iter().any(Option::is_some) {
            return Err(-INVALID);
        }
        let mut tokens = [0; Self::BATCH_SIZE];
        let mut return_count = 0;
        for buffer in returns.iter().flatten() {
            tokens[return_count] = buffer.0.token;
            return_count += 1;
        }
        const { assert!(buffer::NET_EXCHANGE_BYTES <= PAGE_SIZE) };
        let bytes = ostd_pod::IntoBytes::as_bytes(&tokens[..return_count]);
        self.scratch
            .writer()
            .write(&mut crate::mm::VmReader::from(bytes));
        let reply = super::call(
            SHARED_NET_EXCHANGE,
            0,
            [
                self.info.connection,
                self.scratch.paddr() as u64,
                return_count as u64,
            ],
        );
        if reply.status < 0 {
            return Err(reply.status);
        }
        self.pending = reply.status != 0;
        // Accepted returns no longer authorize local access. Disarm wrappers
        // before dropping them; Drop must not make a per-buffer RELEASE call.
        for slot in returns {
            if let Some(mut buffer) = slot.take() {
                buffer.0.token = 0;
            }
        }
        let count = usize::try_from(reply.value).map_err(|_| -INVALID)?;
        if count > Self::BATCH_SIZE {
            return Err(-INVALID);
        }
        let mut reader = self.scratch.reader();
        reader.skip(buffer::NET_RETURN_BYTES);
        let mut failure = None;
        for slot in &mut received[..count] {
            let descriptor = reader.read_val::<buffer::NetGrantDescriptor>().unwrap();
            match buffer_from_mapping(descriptor.token, descriptor.address, descriptor.mapping) {
                Ok(buffer) => *slot = Some(buffer),
                Err(error) => failure = Some(error),
            }
        }
        if let Some(error) = failure {
            // A broken trusted Host reply must not leak other activated grants.
            for slot in received {
                *slot = None;
            }
            return Err(error);
        }
        Ok(count)
    }

    /// Wakes the Host after a batch of accepted data or empty-buffer handoffs.
    pub fn kick(&self) -> Result<(), i64> {
        let reply = super::call(SHARED_NET_KICK, 0, [self.index as u64, 0, 0]);
        if reply.status < 0 {
            Err(reply.status)
        } else {
            Ok(())
        }
    }
}

impl core::fmt::Debug for SharedNetTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedNetTransport")
            .field("index", &self.index)
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}
