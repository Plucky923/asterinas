// SPDX-License-Identifier: MPL-2.0

//! Owning shared storage behind the existing packet interfaces.

use core::sync::atomic::{AtomicU64, Ordering};

use ostd::{
    Error,
    kernelet::shared_buffer::{Buffer, ReadWriteBuffer},
};

use super::*;

static SHARED_TX: AtomicU64 = AtomicU64::new(0);
static NATIVE_TO_SHARED: AtomicU64 = AtomicU64::new(0);
static NATIVE_TO_SHARED_BYTES: AtomicU64 = AtomicU64::new(0);
static SHARED_TO_NATIVE: AtomicU64 = AtomicU64::new(0);
static SHARED_TO_NATIVE_BYTES: AtomicU64 = AtomicU64::new(0);

/// Counts packet storage conversions separately from transport completions.
#[derive(Clone, Copy, Debug)]
pub struct SharedPacketStatistics {
    pub shared_tx_packets: u64,
    pub native_to_shared_packets: u64,
    pub native_to_shared_bytes: u64,
    pub shared_to_native_packets: u64,
    pub shared_to_native_bytes: u64,
}

/// Returns counts without changing packet ownership or invoking the Host.
pub fn shared_packet_statistics() -> SharedPacketStatistics {
    SharedPacketStatistics {
        shared_tx_packets: SHARED_TX.load(Ordering::Relaxed),
        native_to_shared_packets: NATIVE_TO_SHARED.load(Ordering::Relaxed),
        native_to_shared_bytes: NATIVE_TO_SHARED_BYTES.load(Ordering::Relaxed),
        shared_to_native_packets: SHARED_TO_NATIVE.load(Ordering::Relaxed),
        shared_to_native_bytes: SHARED_TO_NATIVE_BYTES.load(Ordering::Relaxed),
    }
}

pub(super) struct SharedStorage {
    buffer: Option<Buffer>,
    recycle_fn: Option<fn(ReadWriteBuffer)>,
}

impl SharedStorage {
    fn new(buffer: Buffer, recycle_fn: Option<fn(ReadWriteBuffer)>) -> Self {
        Self {
            buffer: Some(buffer),
            recycle_fn,
        }
    }

    pub(super) fn reader(&self) -> VmReader<'_, Infallible> {
        match self.buffer.as_ref().unwrap() {
            Buffer::ReadOnly(buffer) => buffer.reader(),
            Buffer::ReadWrite(buffer) => buffer.reader(),
        }
    }

    pub(super) fn writer(&mut self) -> VmWriter<'_, Infallible> {
        // TX constructors accept only RW storage. RxPacket exposes no writer.
        let Buffer::ReadWrite(buffer) = self.buffer.as_mut().unwrap() else {
            unreachable!("a TX packet requires exclusive writable storage");
        };
        buffer.writer()
    }

    fn take(mut self) -> ReadWriteBuffer {
        let Some(Buffer::ReadWrite(buffer)) = self.buffer.take() else {
            unreachable!("a TX packet requires exclusive writable storage");
        };
        buffer
    }
}

impl Drop for SharedStorage {
    fn drop(&mut self) {
        if let Some(Buffer::ReadWrite(buffer)) = self.buffer.take()
            && let Some(recycle_fn) = self.recycle_fn
        {
            recycle_fn(buffer);
        }
    }
}

/// An owned shared allocation and its useful link-layer byte range.
/// The copied flag records compatibility conversion from native storage.
pub struct SharedPacket {
    buffer: ReadWriteBuffer,
    range: Range<usize>,
    copied: bool,
}

impl SharedPacket {
    /// Moves the allocation to the transport after all packet borrows end.
    pub fn into_parts(self) -> (ReadWriteBuffer, Range<usize>, bool) {
        (self.buffer, self.range, self.copied)
    }
}

impl<L: Layer> FreshTxPacket<L> {
    /// Creates a fresh packet over initialized, exclusively owned shared storage.
    /// The callback recycles storage only if the packet ends before handoff.
    pub fn from_shared(
        mut buffer: ReadWriteBuffer,
        payload_len: usize,
        recycle_fn: Option<fn(ReadWriteBuffer)>,
    ) -> Result<Self> {
        let total = payload_len
            .checked_add(L::HEAD_ROOM_SIZE)
            .ok_or(Error::Overflow)?;
        if total > buffer.capacity() {
            return Err(Error::InvalidArgs);
        }
        buffer
            .set_payload_len(buffer.capacity())
            .map_err(|_| Error::InvalidArgs)?;
        Ok(Self(
            Box::new(Common {
                storage: Storage::Shared(SharedStorage::new(Buffer::ReadWrite(buffer), recycle_fn)),
                alloc_range: 0..total,
                data_range: L::HEAD_ROOM_SIZE..L::HEAD_ROOM_SIZE,
                dma_buffer: None,
            }),
            PhantomData,
        ))
    }
}

impl TxPacket<LinkLayer> {
    /// Extracts shared storage or performs one measured native compatibility copy.
    /// The allocator must return enough initialized capacity for the full frame.
    pub fn into_shared_frame(
        self,
        allocate_fn: impl FnOnce(usize) -> Result<ReadWriteBuffer>,
    ) -> Result<SharedPacket> {
        if matches!(self.0.storage, Storage::Shared(_)) {
            let Common {
                storage,
                data_range,
                ..
            } = *self.0;
            let Storage::Shared(storage) = storage else {
                unreachable!();
            };
            SHARED_TX.fetch_add(1, Ordering::Relaxed);
            return Ok(SharedPacket {
                buffer: storage.take(),
                range: data_range,
                copied: false,
            });
        }

        let len = self.len();
        let end = LinkLayer::HEAD_ROOM_SIZE
            .checked_add(len)
            .ok_or(Error::Overflow)?;
        let mut buffer = allocate_fn(end)?;
        if buffer.capacity() < end {
            return Err(Error::InvalidArgs);
        }
        buffer
            .set_payload_len(buffer.capacity())
            .map_err(|_| Error::InvalidArgs)?;
        {
            let mut writer = buffer.writer();
            writer.skip(LinkLayer::HEAD_ROOM_SIZE).limit(len);
            writer.write(&mut self.reader());
        }
        NATIVE_TO_SHARED.fetch_add(1, Ordering::Relaxed);
        NATIVE_TO_SHARED_BYTES.fetch_add(len as u64, Ordering::Relaxed);
        Ok(SharedPacket {
            buffer,
            range: LinkLayer::HEAD_ROOM_SIZE..end,
            copied: true,
        })
    }
}

impl<L> TxPacket<L> {
    pub(super) fn ensure_native_storage(&mut self) -> Result<()> {
        if matches!(self.0.storage, Storage::Native(_)) {
            return Ok(());
        }
        let segment: USegment = FrameAllocOptions::new()
            .alloc_segment(self.0.alloc_range.end.div_ceil(PAGE_SIZE))?
            .into();
        let len = self.len();
        {
            let mut writer = segment.writer();
            writer.skip(self.0.data_range.start).limit(len);
            writer.write(&mut self.reader());
        }
        // Replacing storage ends all shared borrows and invokes its recycler.
        self.0.storage = Storage::Native(segment);
        SHARED_TO_NATIVE.fetch_add(1, Ordering::Relaxed);
        SHARED_TO_NATIVE_BYTES.fetch_add(len as u64, Ordering::Relaxed);
        Ok(())
    }
}

impl<L> RxPacket<L> {
    /// Imports a whole owning grant while exposing only a checked packet range.
    /// The wrapper retains storage until all readers and the packet have ended.
    pub fn from_shared(
        buffer: Buffer,
        range: Range<usize>,
        recycle_fn: Option<fn(ReadWriteBuffer)>,
    ) -> Result<Self> {
        let payload = match &buffer {
            Buffer::ReadOnly(buffer) => buffer.payload_len(),
            Buffer::ReadWrite(buffer) => buffer.payload_len(),
        };
        if range.start > range.end || range.end > payload {
            return Err(Error::InvalidArgs);
        }
        Ok(Self(
            Box::new(Common {
                storage: Storage::Shared(SharedStorage::new(buffer, recycle_fn)),
                alloc_range: 0..payload,
                data_range: range,
                dma_buffer: None,
            }),
            PhantomData,
        ))
    }
}
