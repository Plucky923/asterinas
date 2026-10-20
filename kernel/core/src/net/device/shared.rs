// SPDX-License-Identifier: MPL-2.0

//! Ethernet packets over exclusively owned shared allocations.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use aster_bigtcp::{
    device::{AnyNetworkDevice, Checksum, DeviceCapabilities, EthernetAddress, Medium, NetError},
    packet::{ApplicationLayer, FreshTxPacket, Layer, LinkLayer, RxPacket, TxPacket},
};
use aster_softirq::BottomHalfDisabled;
use ostd::{
    irq::IrqLine,
    kernelet::{
        abi::LIMIT,
        shared_buffer::{
            Buffer, GrantAccess, ReadWriteBuffer, SharedNetHeader, SharedNetTransport,
        },
    },
};

use crate::prelude::*;

pub(crate) const DEVICE_NAME: &str = "shared_net";
const POOL_SIZE: usize = 32;
const BATCH_SIZE: usize = SharedNetTransport::BATCH_SIZE;

// Drop callbacks only enqueue local wrappers. Host transitions happen after
// packet readers end, outside these locks, at the end of interface polling.
static TX_FREE: SpinLock<Vec<ReadWriteBuffer>, BottomHalfDisabled> = SpinLock::new(Vec::new());
static RX_RETURN: SpinLock<Vec<ReadWriteBuffer>, BottomHalfDisabled> = SpinLock::new(Vec::new());
// The initial poll also drains deliveries published before IRQ registration.
static IRQ_PENDING: AtomicBool = AtomicBool::new(true);
static TX_PACKETS: AtomicU64 = AtomicU64::new(0);
static RX_PACKETS: AtomicU64 = AtomicU64::new(0);
static REJECTED: AtomicU64 = AtomicU64::new(0);
#[cfg(kernelet_shared_io_test)]
static EXCHANGES: AtomicU64 = AtomicU64::new(0);
#[cfg(kernelet_shared_io_test)]
static EXCHANGE_RECEIVED: AtomicU64 = AtomicU64::new(0);
#[cfg(kernelet_shared_io_test)]
static EXCHANGE_RETURNED: AtomicU64 = AtomicU64::new(0);
#[cfg(kernelet_shared_io_test)]
static EXCHANGE_MAX_RECEIVED: AtomicU64 = AtomicU64::new(0);

/// Accepted NIC traffic, separate from packet-storage compatibility copies.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SharedNetStatistics {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub rejected_packets: u64,
    #[cfg(kernelet_shared_io_test)]
    pub exchanges: u64,
    #[cfg(kernelet_shared_io_test)]
    pub exchange_received: u64,
    #[cfg(kernelet_shared_io_test)]
    pub exchange_returned: u64,
    #[cfg(kernelet_shared_io_test)]
    pub exchange_max_received: u64,
}

pub(crate) fn statistics() -> SharedNetStatistics {
    SharedNetStatistics {
        tx_packets: TX_PACKETS.load(Ordering::Relaxed),
        rx_packets: RX_PACKETS.load(Ordering::Relaxed),
        rejected_packets: REJECTED.load(Ordering::Relaxed),
        #[cfg(kernelet_shared_io_test)]
        exchanges: EXCHANGES.load(Ordering::Relaxed),
        #[cfg(kernelet_shared_io_test)]
        exchange_received: EXCHANGE_RECEIVED.load(Ordering::Relaxed),
        #[cfg(kernelet_shared_io_test)]
        exchange_returned: EXCHANGE_RETURNED.load(Ordering::Relaxed),
        #[cfg(kernelet_shared_io_test)]
        exchange_max_received: EXCHANGE_MAX_RECEIVED.load(Ordering::Relaxed),
    }
}

fn recycle_tx(buffer: ReadWriteBuffer) {
    // A compatible externally allocated packet may use a smaller allocation.
    // Accept its transmission without putting undersized storage in this pool.
    if buffer.capacity() < PAGE_SIZE {
        return;
    }
    let mut pool = TX_FREE.lock();
    if pool.len() < POOL_SIZE {
        pool.push(buffer);
        return;
    }
    // Packets from other allocators remain accepted without growing our pool.
    drop(pool);
    drop(buffer);
}

fn recycle_rx(buffer: ReadWriteBuffer) {
    RX_RETURN.lock().push(buffer);
}

fn take_tx(required: usize) -> ostd::Result<ReadWriteBuffer> {
    if required > PAGE_SIZE {
        return Err(ostd::Error::InvalidArgs);
    }
    TX_FREE.lock().pop().ok_or(ostd::Error::NoMemory)
}

pub(crate) struct SharedNetworkDevice {
    transport: SharedNetTransport,
    caps: DeviceCapabilities,
    ready: VecDeque<RxPacket<LinkLayer>>,
    returns: [Option<ReadWriteBuffer>; BATCH_SIZE],
    received: [Option<Buffer>; BATCH_SIZE],
    alive: bool,
    _irq: IrqLine,
}

impl Debug for SharedNetworkDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedNetworkDevice")
            .field("info", &self.transport.info())
            .field("alive", &self.alive)
            .finish()
    }
}

impl SharedNetworkDevice {
    /// Installs only the NIC selected by the Host before Image startup.
    pub(crate) fn init() -> core::result::Result<bool, i64> {
        let Some(transport) = SharedNetTransport::open(0)? else {
            return Ok(false);
        };
        let info = transport.info();
        let mut irq = IrqLine::alloc_specific(info.irq).map_err(|_| -22_i64)?;
        let mut buffers = Vec::with_capacity(POOL_SIZE);
        for _ in 0..POOL_SIZE {
            buffers.push(ReadWriteBuffer::allocate(PAGE_SIZE)?);
        }
        *TX_FREE.lock() = buffers;
        RX_RETURN.lock().reserve(POOL_SIZE);

        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = info.max_frame;
        caps.checksum.ipv4 = Checksum::Both;
        caps.checksum.tcp = Checksum::Both;
        caps.checksum.udp = Checksum::Both;
        caps.checksum.icmpv4 = Checksum::Both;
        caps.checksum.icmpv6 = Checksum::Both;

        irq.on_active(|_| {
            IRQ_PENDING.store(true, Ordering::Release);
            aster_network::raise_receive_softirq();
            aster_network::raise_send_softirq();
        });
        // The initial Host RX pool may already contain packets before callback registration.
        transport.kick()?;
        let device = Self {
            transport,
            caps,
            ready: VecDeque::with_capacity(POOL_SIZE),
            returns: core::array::from_fn(|_| None),
            received: core::array::from_fn(|_| None),
            alive: true,
            _irq: irq,
        };
        aster_network::register_device(DEVICE_NAME.to_string(), Arc::new(SpinLock::new(device)));
        info!(
            "Shared Ethernet device: mac={:?}, max_frame={}, irq={}",
            info.mac, info.max_frame, info.irq
        );
        Ok(true)
    }

    fn collect(&mut self) {
        if !self.alive {
            return;
        }
        let pending = IRQ_PENDING.swap(false, Ordering::Acquire);
        if !pending && RX_RETURN.lock().is_empty() {
            return;
        }
        for _ in 0..(POOL_SIZE * 2 / BATCH_SIZE) {
            {
                let mut returned = RX_RETURN.lock();
                for slot in &mut self.returns {
                    if slot.is_none() {
                        *slot = returned.pop();
                    }
                }
            }
            #[cfg(kernelet_shared_io_test)]
            let returned = self.returns.iter().filter(|slot| slot.is_some()).count();
            let count = match self
                .transport
                .exchange(&mut self.returns, &mut self.received)
            {
                Ok(count) => count,
                Err(error) if error == -LIMIT => {
                    // A rejected batch retains every owner. Keep the batch
                    // for the next poll when the peer has made room; do not
                    // turn temporary import pressure into device shutdown.
                    IRQ_PENDING.store(true, Ordering::Release);
                    return;
                }
                Err(error) => {
                    warn!("shared Ethernet exchange failed: {}", error);
                    self.alive = false;
                    // A rejected exchange leaves the local owners intact.
                    // Release them outside the return-queue lock.
                    for slot in &mut self.returns {
                        drop(slot.take());
                    }
                    return;
                }
            };
            #[cfg(kernelet_shared_io_test)]
            {
                EXCHANGES.fetch_add(1, Ordering::Relaxed);
                EXCHANGE_RECEIVED.fetch_add(count as u64, Ordering::Relaxed);
                EXCHANGE_RETURNED.fetch_add(returned as u64, Ordering::Relaxed);
                EXCHANGE_MAX_RECEIVED.fetch_max(count as u64, Ordering::Relaxed);
            }
            for index in 0..BATCH_SIZE {
                if let Some(buffer) = self.received[index].take() {
                    self.accept(buffer);
                }
            }
            // Never clear the flag again: a concurrent IRQ after the entry
            // swap must retain its notification for the next poll.
            if !self.transport.has_pending() {
                return;
            }
        }
        // A coalesced IRQ may cover more work than this bounded batch. Schedule
        // another poll without relying on a subsequent Host notification.
        IRQ_PENDING.store(true, Ordering::Release);
        aster_network::raise_receive_softirq();
        aster_network::raise_send_softirq();
    }

    fn accept(&mut self, buffer: Buffer) {
        let Buffer::ReadWrite(buffer) = buffer else {
            REJECTED.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if buffer.payload_len() == 0 {
            recycle_tx(buffer);
            return;
        }
        let header = buffer
            .reader()
            .read_val::<[u8; SharedNetHeader::SIZE]>()
            .ok()
            .and_then(SharedNetHeader::decode);
        let range = header.and_then(|header| {
            let start = header.frame_offset();
            let len = header.frame_len();
            let end = start.checked_add(len)?;
            (len <= self.caps.max_transmission_unit && end <= buffer.payload_len())
                .then_some(start..end)
        });
        let Some(range) = range else {
            REJECTED.fetch_add(1, Ordering::Relaxed);
            recycle_rx(buffer);
            return;
        };
        let packet = RxPacket::from_shared(Buffer::ReadWrite(buffer), range, Some(recycle_rx))
            .expect("validated shared Ethernet frame range");
        RX_PACKETS.fetch_add(1, Ordering::Relaxed);
        self.ready.push_back(packet);
    }
}

impl AnyNetworkDevice for SharedNetworkDevice {
    fn mac_addr(&self) -> EthernetAddress {
        EthernetAddress(self.transport.info().mac)
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }

    fn can_receive(&self) -> bool {
        !self.ready.is_empty()
    }

    fn can_send(&self) -> bool {
        self.alive && !TX_FREE.lock().is_empty()
    }

    fn receive(&mut self) -> core::result::Result<RxPacket<LinkLayer>, NetError> {
        if self.ready.is_empty() {
            self.collect();
        }
        self.ready.pop_front().ok_or(NetError::NotReady)
    }

    fn send(&mut self, packet: TxPacket<LinkLayer>) -> core::result::Result<(), NetError> {
        if !self.alive {
            return Err(NetError::NotReady);
        }
        let shared = packet
            .into_shared_frame(take_tx)
            .map_err(|_| NetError::NoMemory)?;
        let (mut buffer, range, copied) = shared.into_parts();
        let Some(header) = SharedNetHeader::new(range.start, range.len(), copied) else {
            recycle_tx(buffer);
            return Err(NetError::Busy);
        };
        if range.len() > self.caps.max_transmission_unit {
            recycle_tx(buffer);
            return Err(NetError::Busy);
        }
        // Headroom outside the Ethernet frame must not disclose old packet bytes.
        buffer.writer().fill_zeros(range.start);
        buffer.writer().write_val(&header.encode()).unwrap();
        match buffer.handoff(
            self.transport.info().connection,
            GrantAccess::ReadWrite,
            range.end,
        ) {
            Ok(()) => {
                TX_PACKETS.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err((buffer, _)) => {
                recycle_tx(buffer);
                REJECTED.fetch_add(1, Ordering::Relaxed);
                Err(NetError::Busy)
            }
        }
    }

    fn alloc_tx_buffer(payload_len: usize) -> ostd::Result<FreshTxPacket> {
        let required = payload_len
            .checked_add(ApplicationLayer::HEAD_ROOM_SIZE)
            .ok_or(ostd::Error::Overflow)?;
        FreshTxPacket::from_shared(take_tx(required)?, payload_len, Some(recycle_tx))
    }

    fn free_processed_tx_buffers(&mut self) {
        self.collect();
    }

    fn notify_poll_end(&mut self) {
        self.collect();
        if !self.ready.is_empty() {
            // The return exchange can receive another batch after the current
            // ingress poll has finished. Arrange a poll for these packets.
            aster_network::raise_receive_softirq();
        }
        if !self.alive {
            loop {
                let buffer = RX_RETURN.lock().pop();
                match buffer {
                    Some(buffer) => drop(buffer),
                    None => break,
                }
            }
        }
    }
}
