// SPDX-License-Identifier: MPL-2.0

//! Startup-bound shared Ethernet transport for the existing Host NAT worker.
//! Storage moves by exclusive whole-buffer grants; protocol parsing and smoltcp
//! borrow that storage directly. Native socket and TCP-ring copies are unchanged.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ostd::kernelet::{
    abi::{INVALID, MmioResult, STATE, buffer},
    control::{HostByteCharge, Kernelet},
    shared_buffer::{HostLocalEndpoint, HostLocalGrant, HostSendCredit, SharedNetHeader},
};

use super::{
    policy::{Admission, EndpointReservation},
    scheduling::ExecutionThreads,
    virtio_net::{NetEndpoint, NetWorker, Work},
};
use crate::prelude::*;

#[cfg(ktest)]
mod test;

const BUFFERS: usize = buffer::SHARED_NET_POOL_SIZE;
const RETURNS: usize = BUFFERS;
const BATCH: usize = buffer::SHARED_NET_BATCH_SIZE;
type Delivery = (HostLocalGrant, HostSendCredit, usize);
const CAPACITY: usize = ostd::mm::PAGE_SIZE;

/// Actual Ethernet transfers at the Host/Image boundary. Copies inside TCP or
/// native sockets do not contribute to these staging-copy counters.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct SharedNetStats {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub payload_copy_bytes: u64,
    pub native_fallback_packets: u64,
    pub native_fallback_bytes: u64,
    pub allocations: u64,
    pub reuses: u64,
}

#[derive(Default)]
struct Counters {
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    payload_copy_bytes: AtomicU64,
    native_fallback_packets: AtomicU64,
    native_fallback_bytes: AtomicU64,
    allocations: AtomicU64,
    reuses: AtomicU64,
}

/// A distinct backend binding. It reuses the configured endpoint and NAT worker,
/// while its model never reads copying VirtIO descriptor queues.
pub(super) struct SharedNet {
    worker: NetWorker,
    transport: Arc<SharedNetTransport>,
    mac: [u8; 6],
    irq: u8,
    _reservation: EndpointReservation,
    _host: HostByteCharge,
}

impl SharedNet {
    #[cfg(ktest)]
    pub(in crate::endovisor) fn transport_for_test(&self) -> &Arc<SharedNetTransport> {
        &self.transport
    }

    pub(super) fn new(
        admission: &Arc<Admission>,
        kernelet: Arc<Kernelet>,
        endpoint: Arc<NetEndpoint>,
        mac: [u8; 6],
        irq: u8,
    ) -> ostd::Result<Arc<Self>> {
        let bytes = size_of::<Self>()
            + HostLocalEndpoint::reservation_bytes()
            + size_of::<SharedNetTransport>()
            + (BUFFERS + RETURNS + BATCH) * size_of::<HostLocalGrant>()
            + BUFFERS * size_of::<Delivery>();
        let reservation = admission
            .reserve_endpoint_bytes(bytes)
            .map_err(|_| ostd::Error::NotEnoughResources)?;
        let host = kernelet.reserve_host_bytes(bytes)?;
        let local = kernelet.shared_buffer_host_endpoint()?;
        let mut free = Vec::with_capacity(BUFFERS);
        for _ in 0..BUFFERS {
            let charge = admission
                .reserve_shared_buffer(CAPACITY * 2)
                .map_err(|_| ostd::Error::NotEnoughResources)?;
            free.push(local.allocate_net(Box::new(charge))?);
        }
        let transport = Arc::new(SharedNetTransport {
            local,
            endpoint: Arc::downgrade(&endpoint),
            kernelet: Arc::downgrade(&kernelet),
            irq,
            cancelled: AtomicBool::new(false),
            return_import_blocked: AtomicBool::new(false),
            free: Mutex::new(free),
            returned: Mutex::new(VecDeque::with_capacity(RETURNS)),
            received: Mutex::new(VecDeque::with_capacity(BATCH)),
            transmit: Mutex::new(VecDeque::with_capacity(BUFFERS)),
            counters: Counters::default(),
        });
        transport
            .counters
            .allocations
            .store(BUFFERS as u64, Ordering::Relaxed);
        let worker = Arc::downgrade(&transport);
        let image = Arc::downgrade(&transport);
        transport.local.set_notifiers(
            Arc::new(move || {
                if let Some(transport) = worker.upgrade() {
                    transport.wake();
                }
            }),
            Arc::new(move || {
                if let Some(transport) = image.upgrade() {
                    transport.notify_image();
                }
            }),
        )?;
        endpoint.enable_shared_frames();
        let worker = NetWorker::for_shared(kernelet, endpoint, mac, transport.clone());
        Ok(Arc::new(Self {
            worker,
            transport,
            mac,
            irq,
            _reservation: reservation,
            _host: host,
        }))
    }

    pub(super) fn start_worker(self: &Arc<Self>, execution: &ExecutionThreads) {
        let device = self.clone();
        execution.spawn_worker(move || device.worker.run());
    }

    pub(super) fn cancel(&self) {
        self.transport.cancelled.store(true, Ordering::Release);
        self.transport.local.close();
        self.transport.wake();
        // Active Frame wrappers retain their allocation until their final read ends.
        let free = core::mem::take(&mut *self.transport.free.lock());
        let returned = core::mem::take(&mut *self.transport.returned.lock());
        let received = core::mem::take(&mut *self.transport.received.lock());
        let transmit = core::mem::take(&mut *self.transport.transmit.lock());
        drop(free);
        drop(returned);
        drop(received);
        drop(transmit);
    }

    pub(super) fn info(&self, query: u32) -> MmioResult {
        if self.transport.cancelled.load(Ordering::Acquire) {
            return MmioResult {
                status: -STATE,
                value: 0,
            };
        }
        let value = match query {
            buffer::NET_QUERY_CONNECTION => self.transport.local.connection(),
            buffer::NET_QUERY_MAC => u64::from_le_bytes([
                self.mac[0],
                self.mac[1],
                self.mac[2],
                self.mac[3],
                self.mac[4],
                self.mac[5],
                0,
                0,
            ]),
            buffer::NET_QUERY_MAX_FRAME => SharedNetHeader::MAX_FRAME as u64,
            buffer::NET_QUERY_IRQ => u64::from(self.irq),
            _ => {
                return MmioResult {
                    status: -INVALID,
                    value: 0,
                };
            }
        };
        MmioResult { status: 0, value }
    }

    pub(super) fn kick(&self) {
        self.transport.wake();
    }

    pub(super) fn stats(&self) -> SharedNetStats {
        let c = &self.transport.counters;
        SharedNetStats {
            tx_packets: c.tx_packets.load(Ordering::Relaxed),
            tx_bytes: c.tx_bytes.load(Ordering::Relaxed),
            rx_packets: c.rx_packets.load(Ordering::Relaxed),
            rx_bytes: c.rx_bytes.load(Ordering::Relaxed),
            payload_copy_bytes: c.payload_copy_bytes.load(Ordering::Relaxed),
            native_fallback_packets: c.native_fallback_packets.load(Ordering::Relaxed),
            native_fallback_bytes: c.native_fallback_bytes.load(Ordering::Relaxed),
            allocations: c.allocations.load(Ordering::Relaxed),
            reuses: c.reuses.load(Ordering::Relaxed),
        }
    }
}

pub(super) struct SharedNetTransport {
    local: HostLocalEndpoint,
    endpoint: Weak<NetEndpoint>,
    kernelet: Weak<Kernelet>,
    irq: u8,
    cancelled: AtomicBool,
    return_import_blocked: AtomicBool,
    free: Mutex<Vec<HostLocalGrant>>,
    returned: Mutex<VecDeque<HostLocalGrant>>,
    received: Mutex<VecDeque<HostLocalGrant>>,
    transmit: Mutex<VecDeque<Delivery>>,
    counters: Counters,
}

impl SharedNetTransport {
    pub(super) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn wake(&self) {
        if let Some(endpoint) = self.endpoint.upgrade() {
            endpoint.wake_backend();
        }
    }

    fn notify_image(&self) {
        if let Some(kernelet) = self.kernelet.upgrade() {
            let _ = kernelet.raise_irq(self.irq);
        }
    }

    /// Reserves both initialized storage and receiver import credit before the
    /// infallible smoltcp callback is offered.
    /// No allocation occurs per packet.
    pub(super) fn allocate_frame(self: &Arc<Self>) -> Option<SharedTxFrame> {
        if self.cancelled.load(Ordering::Acquire) {
            return None;
        }
        let grant = self.free.lock().pop()?;
        let credit = match self.local.reserve_send(CAPACITY) {
            Ok(credit) => credit,
            Err(_) => {
                self.recycle_host_buffer(grant);
                return None;
            }
        };
        Some(SharedTxFrame::new(
            grant,
            self.clone(),
            credit,
            SharedNetHeader::SIZE,
        ))
    }

    pub(super) fn can_transmit(&self) -> bool {
        !self.cancelled.load(Ordering::Acquire)
            && self.has_free_buffer()
            && self.local.can_send(CAPACITY)
    }

    pub(super) fn has_free_buffer(&self) -> bool {
        !self.free.lock().is_empty()
    }

    #[cfg(kernelet_nat_failure_diag_host)]
    pub(super) fn diagnostic_buffer_counts(&self) -> (usize, usize) {
        let free = self.free.lock().len();
        let returned = self.returned.lock().len();
        (free, returned)
    }

    pub(super) fn take_return_retry(&self) -> bool {
        // The common idle path only reads the flag. Query the queue only
        // after an actual import failure, and consume that attempt's retry.
        self.return_import_blocked.load(Ordering::Relaxed)
            && self.return_import_blocked.swap(false, Ordering::Relaxed)
            && !self.returned.lock().is_empty()
    }

    fn queue_transmit(
        &self,
        grant: HostLocalGrant,
        credit: HostSendCredit,
        payload: usize,
    ) -> bool {
        let mut queue = self.transmit.lock();
        if self.cancelled.load(Ordering::Acquire) || queue.len() == BUFFERS {
            return false;
        }
        queue.push_back((grant, credit, payload));
        let full = queue.len() >= BATCH;
        drop(queue);
        if full {
            self.flush_transmit();
        }
        true
    }

    fn publication_failed(&self, error: ostd::Error) {
        // Reserved credits make publication infallible while the owners are
        // live and their generations can advance. These errors are terminal.
        warn!("shared Ethernet admitted batch failed: {:?}", error);
        self.cancelled.store(true, Ordering::Release);
        self.local.close();
        self.notify_image();
        self.wake();
    }

    /// Publishes bounded batches at the worker poll boundary, including a short
    /// final batch. Never park while a locally accepted packet is unpublished.
    pub(super) fn flush_transmit(&self) -> bool {
        let mut batch: [Option<Delivery>; BATCH] = core::array::from_fn(|_| None);
        {
            let mut queue = self.transmit.lock();
            for slot in &mut batch {
                *slot = queue.pop_front();
            }
        }
        let bytes = batch
            .iter()
            .flatten()
            .map(|(_, _, payload)| payload - SharedNetHeader::SIZE)
            .sum::<usize>();
        match self.local.handoff_batch(&mut batch) {
            Ok(0) => false,
            Ok(count) => {
                self.counters
                    .rx_packets
                    .fetch_add(count as u64, Ordering::Relaxed);
                self.counters
                    .rx_bytes
                    .fetch_add(bytes as u64, Ordering::Relaxed);
                true
            }
            Err(error) => {
                self.publication_failed(error);
                false
            }
        }
    }

    fn flush_returns(&self) -> bool {
        let mut pending: [Option<HostLocalGrant>; BATCH] = core::array::from_fn(|_| None);
        {
            let mut returned = self.returned.lock();
            for slot in &mut pending {
                *slot = returned.pop_front();
            }
        }
        // Quota reservations and grant publication happen outside the queue
        // lock. Only the failure path needs to enqueue unprocessed owners again.
        let mut pending = pending.into_iter().flatten();
        let mut batch: [Option<Delivery>; BATCH] = core::array::from_fn(|_| None);
        for slot in &mut batch {
            let Some(grant) = pending.next() else {
                break;
            };
            match self.local.reserve_send(grant.capacity()) {
                Ok(credit) => *slot = Some((grant, credit, 0)),
                Err(_) => {
                    self.return_import_blocked.store(true, Ordering::Relaxed);
                    self.return_to_image(grant);
                    for grant in pending.by_ref() {
                        self.return_to_image(grant);
                    }
                    break;
                }
            }
        }
        match self.local.handoff_batch(&mut batch) {
            Ok(count) => count != 0,
            Err(error) => {
                self.publication_failed(error);
                false
            }
        }
    }

    fn return_to_image(&self, grant: HostLocalGrant) {
        if self.cancelled.load(Ordering::Acquire) {
            return;
        }
        let mut returned = self.returned.lock();
        if !self.cancelled.load(Ordering::Acquire) && returned.len() < RETURNS {
            returned.push_back(grant);
        }
        // The worker revisits returned buffers through its progress loop.
        // Image handoffs and teardown retain their external wake notifications.
    }

    fn recycle_host_buffer(&self, grant: HostLocalGrant) {
        if self.cancelled.load(Ordering::Acquire) {
            return;
        }
        let mut free = self.free.lock();
        if !self.cancelled.load(Ordering::Acquire) && free.len() < BUFFERS {
            free.push(grant);
        }
    }

    /// Performs one bounded worker step driven by the endpoint poll generation.
    pub(super) fn take_work(self: &Arc<Self>) -> Option<Work> {
        let endpoint = self.endpoint.upgrade()?;
        if self.cancelled.load(Ordering::Acquire) || endpoint.is_revoked() {
            return Some(Work::Cancel);
        }
        if self.flush_returns() {
            return Some(Work::Progress);
        }
        if self.received.lock().is_empty() {
            let mut batch = core::array::from_fn(|_| None);
            let count = self.local.receive_batch(&mut batch).ok()?;
            if count == 0 {
                return None;
            }
            let mut received = self.received.lock();
            if self.cancelled.load(Ordering::Acquire) {
                return Some(Work::Cancel);
            }
            for grant in batch.into_iter().flatten() {
                if grant.payload_len() != 0 {
                    received.push_back(grant);
                    continue;
                }
                if grant.is_writable() && grant.capacity() == CAPACITY {
                    self.counters.reuses.fetch_add(1, Ordering::Relaxed);
                    self.recycle_host_buffer(grant);
                }
            }
            if received.is_empty() {
                return Some(Work::Progress);
            }
        }
        if !endpoint.shared_output_has_space() {
            return None;
        }
        let Some(grant) = self.received.lock().pop_front() else {
            return None;
        };
        let header = grant
            .with_bytes(0..SharedNetHeader::SIZE, |bytes| {
                SharedNetHeader::decode(bytes.try_into().unwrap())
            })
            .ok()
            .flatten();
        let Some(header) = header.filter(|header| {
            grant.is_writable()
                && (header.frame_offset())
                    .checked_add(header.frame_len())
                    .is_some_and(|end| end <= grant.payload_len())
        }) else {
            return Some(Work::Progress);
        };
        let len = header.frame_len();
        self.counters.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.counters
            .tx_bytes
            .fetch_add(len as u64, Ordering::Relaxed);
        if header.copied() {
            self.counters
                .payload_copy_bytes
                .fetch_add(len as u64, Ordering::Relaxed);
            self.counters
                .native_fallback_packets
                .fetch_add(1, Ordering::Relaxed);
            self.counters
                .native_fallback_bytes
                .fetch_add(len as u64, Ordering::Relaxed);
        }
        let frame = SharedFrame::from_image(grant, self.clone(), header.frame_offset(), len);
        let _ = endpoint.push_shared_output(frame);
        Some(Work::Progress)
    }
}

/// An Image packet's owning read view; drop returns its empty allocation.
pub(super) struct SharedFrame {
    grant: Option<HostLocalGrant>,
    transport: Arc<SharedNetTransport>,
    offset: usize,
    len: usize,
}

impl SharedFrame {
    fn from_image(
        grant: HostLocalGrant,
        transport: Arc<SharedNetTransport>,
        offset: usize,
        len: usize,
    ) -> Self {
        Self {
            grant: Some(grant),
            transport,
            offset,
            len,
        }
    }

    pub(super) fn with_bytes<R>(&self, read_fn: impl for<'a> FnOnce(&'a [u8]) -> R) -> R {
        self.grant
            .as_ref()
            .unwrap()
            .with_bytes(self.offset..self.offset + self.len, read_fn)
            .expect("validated shared frame range")
    }
}

impl Drop for SharedFrame {
    fn drop(&mut self) {
        if let Some(grant) = self.grant.take() {
            self.transport.return_to_image(grant);
        }
    }
}

/// Initialized output storage and its reserved Image import capacity.
pub(super) struct SharedTxFrame {
    grant: Option<HostLocalGrant>,
    transport: Arc<SharedNetTransport>,
    credit: Option<HostSendCredit>,
    offset: usize,
}

impl SharedTxFrame {
    fn new(
        grant: HostLocalGrant,
        transport: Arc<SharedNetTransport>,
        credit: HostSendCredit,
        offset: usize,
    ) -> Self {
        Self {
            grant: Some(grant),
            transport,
            credit: Some(credit),
            offset,
        }
    }

    pub(super) fn with_bytes_mut<R>(
        &mut self,
        len: usize,
        write_fn: impl for<'a> FnOnce(&'a mut [u8]) -> R,
    ) -> R {
        self.grant
            .as_mut()
            .unwrap()
            .with_bytes_mut(self.offset..self.offset + len, write_fn)
            .expect("reserved shared frame capacity")
    }

    pub(super) fn deliver(mut self, len: usize) -> bool {
        let Some(header) = SharedNetHeader::new(self.offset, len, false) else {
            return false;
        };
        let grant = self.grant.as_mut().unwrap();
        if grant
            .with_bytes_mut(0..SharedNetHeader::SIZE, |bytes| {
                bytes.copy_from_slice(&header.encode())
            })
            .is_err()
        {
            return false;
        }
        let grant = self.grant.take().unwrap();
        let credit = self.credit.take().unwrap();
        self.transport
            .queue_transmit(grant, credit, self.offset + len)
    }
}

impl Drop for SharedTxFrame {
    fn drop(&mut self) {
        // Release an unused peer credit before publishing this buffer for reuse.
        drop(self.credit.take());
        if let Some(grant) = self.grant.take() {
            self.transport.recycle_host_buffer(grant);
        }
    }
}
