// SPDX-License-Identifier: MPL-2.0

use alloc::{sync::Arc, vec};
use core::marker::PhantomData;

use framev_net_common::OwnedNetworkBuffer;
use ostd::{
    Result,
    mm::{
        Daddr, HasDaddr, HasSize, Infallible, VmReader, VmWriter,
        dma::{FromDevice, ToDevice},
    },
};
use ostd_pod::Pod;

use crate::dma_pool::{DmaPool, DmaSegment};

pub struct TxBuffer {
    segment: DmaSegment<ToDevice>,
    nbytes: usize,
}

impl TxBuffer {
    pub fn new<H: Pod>(header: &H, payload: &[u8], pool: &Arc<DmaPool<ToDevice>>) -> Result<Self> {
        let mut builder = Self::new_builder::<H>(pool)?;

        builder
            .copy_payload(|mut writer| {
                assert!(writer.avail() >= payload.len());
                Ok(writer.write(&mut VmReader::from(payload)))
            })
            .unwrap();

        Ok(builder.build(header))
    }

    pub fn new_builder<H: Pod>(pool: &Arc<DmaPool<ToDevice>>) -> Result<TxBufferBuilder<H>> {
        assert!(size_of::<H>() <= pool.segment_size());

        let segment = pool.alloc_segment()?;

        let builder = TxBufferBuilder {
            segment,
            nbytes: size_of::<H>(),
            _phantom: PhantomData,
        };
        Ok(builder)
    }

    fn sync_to_device(&self) {
        self.segment.sync_to_device(0..self.nbytes).unwrap();
    }
}

impl HasSize for TxBuffer {
    fn size(&self) -> usize {
        self.nbytes
    }
}

impl HasDaddr for TxBuffer {
    fn daddr(&self) -> Daddr {
        self.segment.daddr()
    }
}

pub struct TxBufferBuilder<H> {
    segment: DmaSegment<ToDevice>,
    nbytes: usize,
    _phantom: PhantomData<H>,
}

impl<H: Pod> TxBufferBuilder<H> {
    pub fn copy_payload<F>(&mut self, copy_fn: F) -> Result<usize>
    where
        F: FnOnce(VmWriter<Infallible>) -> Result<usize>,
    {
        let mut writer = self.segment.writer().unwrap();
        writer.skip(self.nbytes);

        let bytes_written = copy_fn(writer)?;
        self.nbytes += bytes_written;
        debug_assert!(self.nbytes <= self.segment.size());

        Ok(bytes_written)
    }

    pub const fn payload_len(&self) -> usize {
        self.nbytes - size_of::<H>()
    }

    pub fn build(self, header: &H) -> TxBuffer {
        self.segment
            .writer()
            .unwrap()
            .write(&mut VmReader::from(header.as_bytes()));

        let tx_buffer = TxBuffer {
            segment: self.segment,
            nbytes: self.nbytes,
        };
        tx_buffer.sync_to_device();
        tx_buffer
    }
}

/// Owns one receive buffer while a physical device may access its DMA storage.
pub struct DmaRxBuffer {
    segment: DmaSegment<FromDevice>,
    header_len: usize,
    payload_len: usize,
}

impl DmaRxBuffer {
    /// Allocates a DMA-backed receive buffer.
    pub fn new(header_len: usize, pool: &Arc<DmaPool<FromDevice>>) -> Result<Self> {
        assert!(header_len <= pool.segment_size());

        let segment = pool.alloc_segment()?;
        Ok(Self {
            segment,
            header_len,
            payload_len: 0,
        })
    }

    pub const fn payload_len(&self) -> usize {
        self.payload_len
    }

    /// Records the byte count written after the driver-specific header.
    pub fn set_payload_len(&mut self, payload_len: usize) {
        assert!(self.header_len.checked_add(payload_len).unwrap() <= self.segment.size());
        self.payload_len = payload_len;
    }

    /// Returns a reader over the received payload.
    pub fn payload(&self) -> VmReader<'_, Infallible> {
        self.segment
            .sync_from_device(self.header_len..self.header_len + self.payload_len)
            .unwrap();

        let mut reader = self.segment.reader().unwrap();
        reader.skip(self.header_len).limit(self.payload_len);
        reader
    }

    /// Returns a reader over the received header and payload.
    pub fn buf(&self) -> VmReader<'_, Infallible> {
        self.segment
            .sync_from_device(0..self.header_len + self.payload_len)
            .unwrap();

        let mut reader = self.segment.reader().unwrap();
        reader.limit(self.header_len + self.payload_len);
        reader
    }

    /// Converts a completed DMA buffer into a transport-neutral receive buffer.
    pub fn into_rx_buffer(self) -> RxBuffer {
        RxBuffer {
            storage: Some(RxBufferStorage::Dma(self.segment)),
            header_len: self.header_len,
            payload_len: self.payload_len,
        }
    }
}

impl HasSize for DmaRxBuffer {
    fn size(&self) -> usize {
        self.segment.size()
    }
}

impl HasDaddr for DmaRxBuffer {
    fn daddr(&self) -> Daddr {
        self.segment.daddr()
    }
}

/// A transport-neutral received packet.
pub struct RxBuffer {
    storage: Option<RxBufferStorage>,
    header_len: usize,
    payload_len: usize,
}

enum RxBufferStorage {
    Dma(DmaSegment<FromDevice>),
    Owned {
        storage: OwnedNetworkBuffer,
        recycler: Option<Arc<dyn OwnedNetworkBufferRecycler>>,
    },
}

/// Receives original owned network storage after its payload has been consumed.
pub trait OwnedNetworkBufferRecycler: Send + Sync {
    /// Recycles one receive buffer without retaining its payload borrow.
    fn recycle(&self, receive_buffer: OwnedNetworkBuffer);
}

impl RxBuffer {
    /// Creates a receive buffer from owned FrameV-compatible storage.
    pub fn from_owned(storage: OwnedNetworkBuffer, header_len: usize, payload_len: usize) -> Self {
        assert!(header_len.checked_add(payload_len).unwrap() <= storage.len());
        Self {
            storage: Some(RxBufferStorage::Owned {
                storage,
                recycler: None,
            }),
            header_len,
            payload_len,
        }
    }

    /// Creates a receive buffer that returns its original storage to `recycler` on drop.
    pub fn from_owned_with_recycler(
        storage: OwnedNetworkBuffer,
        header_len: usize,
        payload_len: usize,
        recycler: Arc<dyn OwnedNetworkBufferRecycler>,
    ) -> Self {
        assert!(header_len.checked_add(payload_len).unwrap() <= storage.len());
        Self {
            storage: Some(RxBufferStorage::Owned {
                storage,
                recycler: Some(recycler),
            }),
            header_len,
            payload_len,
        }
    }

    /// Returns the byte count after the driver-specific header.
    pub const fn payload_len(&self) -> usize {
        self.payload_len
    }

    /// Consumes the buffer and exposes its payload only for the closure call.
    pub fn consume_payload<R>(self, consume_fn: impl FnOnce(&[u8]) -> R) -> R {
        let payload_end = self.header_len.checked_add(self.payload_len).unwrap();
        match self.storage.as_ref().unwrap() {
            RxBufferStorage::Dma(segment) => {
                segment
                    .sync_from_device(self.header_len..payload_end)
                    .unwrap();

                let mut reader = segment.reader().unwrap();
                reader.skip(self.header_len).limit(self.payload_len);
                let mut payload = vec![0; self.payload_len];
                reader.read(&mut VmWriter::from(&mut payload as &mut [u8]));
                consume_fn(&payload)
            }
            RxBufferStorage::Owned { storage, .. } => {
                consume_fn(&storage.as_bytes()[self.header_len..payload_end])
            }
        }
    }
}

impl Drop for RxBuffer {
    fn drop(&mut self) {
        let Some(RxBufferStorage::Owned {
            storage,
            recycler: Some(recycler),
        }) = self.storage.take()
        else {
            return;
        };
        recycler.recycle(storage);
    }
}

impl HasSize for RxBuffer {
    fn size(&self) -> usize {
        match self.storage.as_ref().unwrap() {
            RxBufferStorage::Dma(segment) => segment.size(),
            RxBufferStorage::Owned { storage, .. } => storage.len(),
        }
    }
}

#[cfg(ktest)]
mod tests {
    use alloc::vec;

    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn owned_buffer_consumes_the_original_payload_slice() {
        let storage = OwnedNetworkBuffer::new(vec![0xaa, 1, 2, 3, 0xbb]);
        let expected_pointer = storage.as_bytes()[1..4].as_ptr();
        let buffer = RxBuffer::from_owned(storage, 1, 3);

        let (actual_pointer, payload) =
            buffer.consume_payload(|payload| (payload.as_ptr(), payload.to_vec()));

        assert_eq!(actual_pointer, expected_pointer);
        assert_eq!(payload, [1, 2, 3]);
    }
}
