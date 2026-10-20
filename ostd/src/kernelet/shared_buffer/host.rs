// SPDX-License-Identifier: MPL-2.0

//! The pool owns storage independently of images. One registry lock serializes
//! grant transitions, receipt, completion and post-carrier teardown. DMA work,
//! storage allocation, completion synchronization and destruction run outside it.

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use super::{DeviceAccess, GrantAccess};

#[path = "host_local.rs"]
mod host_local;
pub use host_local::{HostLocalEndpoint, HostLocalGrant, HostSendCredit};

#[path = "host_shared_net.rs"]
mod shared_net;
pub(crate) use shared_net::{dispatch_net_exchange, dispatch_net_transmit};

use crate::{
    Error, Result,
    kernelet::{
        abi::{self, MmioResult, buffer::*},
        account::Account,
    },
    mm::{
        HasDaddr, HasSize, Infallible, PAGE_SIZE, VmReader, VmWriter, dma::DmaStream,
        io::util::HasVmReaderWriter,
    },
    sync::{LocalIrqDisabled, SpinLock},
};

// Bounds include leaked active wrappers and unredeemed deliveries. Each
// participant has separate allocation and import quotas; sender charges do
// not migrate with a grant. There are no unbounded completion queues.
const MAX_BUFFERS: usize = 64;
// Private NICs may hold a full data window and a full empty-return window.
// Allocation and ordinary datagram import quotas retain their original bounds.
const PRIVATE_NET_IMPORTS: usize = SHARED_NET_IMPORT_LIMIT;
const MAX_BYTES: usize = 16 * MAX_CAPACITY;
const MAX_CONNECTIONS: usize = 64;
// Reserve metadata independently of useful payload. This covers the record,
// two Arc owners, an operation and the pinned toolchain's BTree node share.
const RECORD_RESERVE: usize = PAGE_SIZE;
static NEXT: AtomicU64 = AtomicU64::new(1);
static POOL: SpinLock<BTreeMap<u32, Record>, LocalIrqDisabled> = SpinLock::new(BTreeMap::new());

fn identity() -> Result<u64> {
    // Never reuse a connection or allocation identity, even after reclamation.
    NEXT.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
        .map_err(|_| Error::Overflow)
}

fn advance(token: u64) -> Result<u64> {
    token.checked_add(1u64 << 32).ok_or(Error::Overflow)
}

#[derive(Default)]
struct Quota {
    count: AtomicUsize,
    bytes: AtomicUsize,
}

struct Reservation {
    quota: Arc<Quota>,
    bytes: usize,
}

impl Reservation {
    fn new(quota: &Arc<Quota>, bytes: usize) -> Result<Self> {
        Self::with_limits(quota, bytes, MAX_BUFFERS, MAX_BYTES)
    }

    fn private_net(quota: &Arc<Quota>, bytes: usize) -> Result<Self> {
        Self::with_limits(quota, bytes, PRIVATE_NET_IMPORTS, MAX_BYTES)
    }

    fn private_data(quota: &Arc<Quota>, bytes: usize) -> Result<Self> {
        Self::with_limits(quota, bytes, SHARED_NET_POOL_SIZE, MAX_BYTES / 2)
    }

    fn with_limits(
        quota: &Arc<Quota>,
        bytes: usize,
        limit: usize,
        byte_limit: usize,
    ) -> Result<Self> {
        quota
            .count
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < limit).then_some(n + 1)
            })
            .map_err(|_| Error::NotEnoughResources)?;
        let mut result = Self {
            quota: quota.clone(),
            bytes: 0,
        };
        quota
            .bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(bytes).filter(|&n| n <= byte_limit)
            })
            .map_err(|_| Error::NotEnoughResources)?;
        result.bytes = bytes;
        Ok(result)
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.quota.bytes.fetch_sub(self.bytes, Ordering::Release);
        self.quota.count.fetch_sub(1, Ordering::Release);
    }
}

struct Charge {
    // Retain only accounting, never the sender image or its RunControl.
    account: Arc<Account>,
    _reservation: Reservation,
    bytes: usize,
    _admission: Box<dyn Send + Sync>,
}

impl Charge {
    fn new(
        owner: &Participant,
        bytes: usize,
        admission: Box<dyn Send + Sync>,
        reservation: Reservation,
    ) -> Result<Self> {
        let bytes = bytes.checked_add(RECORD_RESERVE).ok_or(Error::Overflow)?;
        owner
            .account
            .host_bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                n.checked_add(bytes)
            })
            .map_err(|_| Error::Overflow)?;
        Ok(Self {
            account: owner.account.clone(),
            _reservation: reservation,
            bytes,
            _admission: admission,
        })
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        self.account
            .host_bytes
            .fetch_sub(self.bytes, Ordering::Release);
    }
}

struct Allocation {
    dma: DmaStream,
    _charge: Charge,
}

struct Peer {
    owner: Weak<Participant>,
    // Keep the private NIC namespace even after the endpoint and its notifier
    // retire while an issued delivery remains in the Image inbox.
    host_local: bool,
}

impl Peer {
    fn new(owner: &Arc<Participant>) -> Self {
        Self {
            owner: Arc::downgrade(owner),
            host_local: owner.host_local,
        }
    }

    fn upgrade(&self) -> Option<Arc<Participant>> {
        self.owner.upgrade()
    }
}

pub(crate) struct Participant {
    live: AtomicBool,
    host_local: bool,
    account: Arc<Account>,
    allocations: Arc<Quota>,
    net_allocations: Arc<Quota>,
    imports: Arc<Quota>,
    net_imports: Arc<Quota>,
    // Private Host links retain a complete empty-return window independently
    // of data imports, including externally allocated NIC packets.
    data_imports: Arc<Quota>,
    peers: SpinLock<BTreeMap<u64, Peer>, LocalIrqDisabled>,
    notifiers: SpinLock<BTreeMap<u64, Arc<dyn Fn() + Send + Sync>>, LocalIrqDisabled>,
    // Reserved at participant creation. Import credit guarantees that pushes
    // need no allocation after handoff acceptance. POOL precedes this lock.
    inbox: SpinLock<Vec<(u64, u64)>, LocalIrqDisabled>,
}

impl Participant {
    pub(crate) fn new(account: Arc<Account>) -> Arc<Self> {
        Self::new_inner(account, false)
    }

    fn new_inner(account: Arc<Account>, host_local: bool) -> Arc<Self> {
        Arc::new(Self {
            live: AtomicBool::new(true),
            host_local,
            account,
            allocations: Arc::default(),
            net_allocations: Arc::default(),
            imports: Arc::default(),
            net_imports: Arc::default(),
            data_imports: Arc::default(),
            peers: SpinLock::new(BTreeMap::new()),
            notifiers: SpinLock::new(BTreeMap::new()),
            inbox: SpinLock::new(Vec::with_capacity(MAX_BUFFERS + PRIVATE_NET_IMPORTS)),
        })
    }

    /// Host-authorized connection; image arguments cannot choose a participant.
    pub(crate) fn connect(a: &Arc<Self>, b: &Arc<Self>) -> Result<u64> {
        if Arc::ptr_eq(a, b) {
            return Err(Error::InvalidArgs);
        }
        // All peer-map changes serialize through POOL, including close.
        let _pool = POOL.lock();
        if !a.live.load(Ordering::Acquire) || !b.live.load(Ordering::Acquire) {
            return Err(Error::AccessDenied);
        }
        a.prune_connections();
        b.prune_connections();
        let mut a_peers = a.peers.lock();
        let mut b_peers = b.peers.lock();
        if let Some((&connection, _)) = a_peers
            .iter()
            .find(|(_, peer)| Weak::ptr_eq(&peer.owner, &Arc::downgrade(b)))
        {
            debug_assert!(b_peers.contains_key(&connection));
            return Ok(connection);
        }
        if a_peers.len() >= MAX_CONNECTIONS || b_peers.len() >= MAX_CONNECTIONS {
            return Err(Error::NotEnoughResources);
        }
        let connection = identity()?;
        a_peers.insert(connection, Peer::new(b));
        b_peers.insert(connection, Peer::new(a));
        Ok(connection)
    }

    // Caller holds POOL. A dead peer's accepted deliveries remain recoverable
    // through their original connection until redemption or discard.
    fn prune_connections(&self) {
        let inbox = self.inbox.lock();
        self.peers.lock().retain(|connection, peer| {
            peer.upgrade()
                .is_some_and(|peer| peer.live.load(Ordering::Acquire))
                || inbox.iter().any(|(pending, _)| pending == connection)
        });
    }

    pub(crate) fn mark_dying(&self) {
        self.live.store(false, Ordering::Release);
    }

    /// Image participants close after their carriers and local accessors stop.
    /// Host-local wrappers retain independent allocation holds across close.
    pub(crate) fn close(&self) {
        self.mark_dying();
        // Remove one record at a time so DMA storage drops outside POOL.
        loop {
            let removed = {
                let mut pool = POOL.lock();
                let token = pool.iter().find_map(|(&token, record)| {
                    (core::ptr::eq(&*record.holder, self)
                        && !matches!(record.state, State::Backend))
                    .then_some(token)
                });
                token.and_then(|token| pool.remove(&token))
            };
            if removed.is_none() {
                break;
            }
            drop(removed);
        }
        let notifiers = {
            let _pool = POOL.lock();
            self.peers.lock().clear();
            self.inbox.lock().clear();
            core::mem::take(&mut *self.notifiers.lock())
        };
        drop(notifiers);
    }
}

enum State {
    Issued,
    Active,
    Backend,
    Completed(i64),
}

struct Record {
    token: u64,
    allocation: Arc<Allocation>,
    holder: Arc<Participant>,
    state: State,
    writable: bool,
    payload: usize,
    connection: Option<u64>,
    _credit: Option<Reservation>,
    _local_data_credit: Option<Reservation>,
    backend: Weak<BackendLease>,
    abandoned: bool,
}

/// Fully admitted ownership publication; callers prepare inboxes and notices.
struct Delivery {
    holder: Arc<Participant>,
    token: u64,
    connection: u64,
    access: GrantAccess,
    payload: usize,
    credit: Reservation,
    local_data_credit: Option<Reservation>,
}

impl Record {
    fn publish(&mut self, delivery: Delivery) {
        self.holder = delivery.holder;
        self.token = delivery.token;
        self.state = State::Issued;
        self.writable = delivery.access == GrantAccess::ReadWrite;
        self.payload = delivery.payload;
        self.connection = Some(delivery.connection);
        self._credit = Some(delivery.credit);
        self._local_data_credit = delivery.local_data_credit;
    }
}

/// Copied and validated submission metadata; offsets are bytes.
#[derive(Clone, Copy, Debug)]
pub struct IoRequest {
    /// Index in this instance's separate zero-copy device configuration.
    pub device: u32,
    /// Byte offset in the device.
    pub offset: u64,
    /// Submitted range starts at buffer offset zero and covers this many bytes.
    pub len: usize,
    /// True when the device writes into the buffer.
    pub device_writes: bool,
}

struct BackendLease {
    token: u64,
    allocation: Arc<Allocation>,
    request: IoRequest,
    cancelled: AtomicBool,
    result: SpinLock<Option<(i64, usize)>, LocalIrqDisabled>,
}

/// An accepted operation's storage hold. Every DMA view and callback must
/// retain an `Arc<BackendBuffer>` until its last possible access. The return grant is created
/// only after the last clone drops and DMA synchronization finishes.
pub struct BackendBuffer(Arc<BackendLease>);

impl BackendBuffer {
    /// Returns the validated Host-owned metadata snapshot.
    pub fn request(&self) -> IoRequest {
        self.0.request
    }
    /// Observes cancellation; it does not establish that DMA has stopped.
    pub fn cancel_requested(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }

    /// Records a result once; this does not return access to the submitter.
    pub fn complete(&self, status: i64, transferred: usize) -> Result<()> {
        if status > 0 || transferred > self.0.request.len {
            return Err(Error::InvalidArgs);
        }
        let mut result = self.0.result.lock();
        if result.is_some() {
            return Err(Error::InvalidArgs);
        }
        *result = Some((status, transferred));
        Ok(())
    }

    /// Reads a buffer submitted for device reads, within the submitted length.
    pub fn reader(&self) -> Result<VmReader<'_, Infallible>> {
        if self.0.request.device_writes {
            return Err(Error::AccessDenied);
        }
        let mut reader = self.0.allocation.dma.reader()?;
        reader.limit(self.0.request.len);
        Ok(reader)
    }

    /// Writes a buffer submitted for device writes through an exclusive borrow.
    pub fn writer(&mut self) -> Result<VmWriter<'_, Infallible>> {
        if !self.0.request.device_writes {
            return Err(Error::AccessDenied);
        }
        let mut writer = self.0.allocation.dma.writer()?;
        writer.limit(self.0.request.len);
        Ok(writer)
    }

    /// Synchronizes a bounded DMA view without exposing its backing owner.
    pub fn sync_from_device(&self, range: core::ops::Range<usize>) -> Result<()> {
        if range.start > range.end || range.end > self.size() {
            return Err(Error::InvalidArgs);
        }
        self.0.allocation.dma.sync_from_device(range)
    }

    /// Synchronizes a bounded DMA view before publishing descriptors.
    pub fn sync_to_device(&self, range: core::ops::Range<usize>) -> Result<()> {
        if range.start > range.end || range.end > self.size() {
            return Err(Error::InvalidArgs);
        }
        self.0.allocation.dma.sync_to_device(range)
    }
}

impl core::fmt::Debug for BackendBuffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BackendBuffer")
            .field("request", &self.0.request)
            .finish_non_exhaustive()
    }
}

#[cfg(ktest)]
mod test;

impl HasSize for BackendBuffer {
    fn size(&self) -> usize {
        self.0.request.len
    }
}
impl HasDaddr for BackendBuffer {
    fn daddr(&self) -> crate::mm::Daddr {
        self.0.allocation.dma.daddr()
    }
}

impl Drop for BackendLease {
    fn drop(&mut self) {
        // No backend reference, accessor or DMA view can remain at this point.
        let sync = if self.request.device_writes {
            self.allocation.dma.sync_from_device(0..self.request.len)
        } else {
            Ok(())
        };
        let (mut status, transferred) = self.result.lock().take().unwrap_or((-abi::STATE, 0));
        if sync.is_err() {
            status = -abi::STATE;
        }
        let removed = {
            let mut pool = POOL.lock();
            let Some(record) = pool.get_mut(&(self.token as u32)) else {
                return;
            };
            if record.token != self.token || !matches!(record.state, State::Backend) {
                return;
            }
            if record.holder.live.load(Ordering::Acquire) && !record.abandoned {
                if self.request.device_writes {
                    record.payload = transferred;
                }
                record.state = State::Completed(status);
                None
            } else {
                pool.remove(&(self.token as u32))
            }
        };
        drop(removed);
    }
}

fn owned<'a>(
    pool: &'a mut BTreeMap<u32, Record>,
    holder: &Arc<Participant>,
    token: u64,
) -> Result<&'a mut Record> {
    let record = pool
        .get_mut(&(token as u32))
        .filter(|record| record.token == token)
        .ok_or(Error::InvalidArgs)?;
    if !Arc::ptr_eq(&record.holder, holder) {
        return Err(Error::AccessDenied);
    }
    Ok(record)
}

fn response(status: i64, value: u64) -> MmioResult {
    MmioResult { status, value }
}

/// Dispatches from an authenticated carrier. No reference to an image-owned
/// request or output record crosses a scheduling or asynchronous boundary.
/// Validates the separate device namespace before any owning transition.
pub(crate) fn dispatch_device(
    holder: &Arc<Participant>,
    operation: u32,
    token: u64,
    args: [u64; 3],
    device_info_fn: impl FnOnce(u32) -> Option<super::ZeroCopyBlockInfo>,
    reserve_fn: impl FnOnce(usize) -> Result<Box<dyn Send + Sync>>,
    submit_fn: impl FnOnce(BackendBuffer, IoRequest),
) -> MmioResult {
    if !holder.live.load(Ordering::Acquire) {
        return response(-abi::STATE, 0);
    }
    if operation == NET_INFO {
        if token != 0 || args[1] != 0 || args[2] != 0 {
            return response(-abi::INVALID, 0);
        }
        let Ok(index) = usize::try_from(args[0]) else {
            return response(-abi::INVALID, 0);
        };
        let _pool = POOL.lock();
        if !holder.live.load(Ordering::Acquire) {
            return response(-abi::STATE, 0);
        }
        let inbox = holder.inbox.lock();
        return holder
            .peers
            .lock()
            .iter()
            .filter(|(connection, peer)| {
                if peer.host_local {
                    return false;
                }
                peer.upgrade()
                    .is_some_and(|peer| peer.live.load(Ordering::Acquire))
                    || inbox.iter().any(|(pending, _)| pending == *connection)
            })
            .nth(index)
            .map_or(response(0, 0), |(&connection, _)| {
                response(super::MAX_DATAGRAM_PAYLOAD as i64, connection)
            });
    }
    if operation == BLOCK_INFO {
        if token != 0 || args[1] != 0 || args[2] != 0 {
            return response(-abi::INVALID, 0);
        }
        return u32::try_from(args[0]).ok().and_then(device_info_fn).map_or(
            response(0, 0),
            |info| {
                response(
                    if info.read_only { DEVICE_READ_ONLY } else { 0 },
                    info.capacity_bytes,
                )
            },
        );
    }
    if operation == SUBMIT
        && !u32::try_from(args[0])
            .ok()
            .and_then(device_info_fn)
            .is_some_and(|info| {
                args[2] >> 32 <= DEVICE_WRITE as u64
                    && info.permits(
                        args[1],
                        args[2] as u32 as usize,
                        if args[2] >> 32 == DEVICE_WRITE as u64 {
                            DeviceAccess::Write
                        } else {
                            DeviceAccess::Read
                        },
                    )
            })
    {
        return response(-abi::INVALID, 0);
    }
    dispatch(holder, operation, token, args, reserve_fn, submit_fn)
}

fn dispatch(
    holder: &Arc<Participant>,
    operation: u32,
    token: u64,
    args: [u64; 3],
    reserve_fn: impl FnOnce(usize) -> Result<Box<dyn Send + Sync>>,
    submit_fn: impl FnOnce(BackendBuffer, IoRequest),
) -> MmioResult {
    let result = execute(holder, operation, token, args, reserve_fn, submit_fn);
    result.unwrap_or_else(error_response)
}

fn error_response(error: Error) -> MmioResult {
    response(
        match error {
            Error::AccessDenied => -abi::NOT_OWNED,
            Error::InvalidArgs => -abi::INVALID,
            _ => -abi::LIMIT,
        },
        0,
    )
}

fn private_link_live(holder: &Participant, connection: u64) -> bool {
    holder
        .peers
        .lock()
        .get(&connection)
        .filter(|peer| holder.host_local || peer.host_local)
        .and_then(Peer::upgrade)
        .is_some_and(|peer| peer.live.load(Ordering::Acquire))
}

fn execute(
    holder: &Arc<Participant>,
    operation: u32,
    token: u64,
    args: [u64; 3],
    reserve_fn: impl FnOnce(usize) -> Result<Box<dyn Send + Sync>>,
    submit_fn: impl FnOnce(BackendBuffer, IoRequest),
) -> Result<MmioResult> {
    if !holder.live.load(Ordering::Acquire) {
        return Err(Error::AccessDenied);
    }
    if operation == ALLOCATE || operation == SHARED_NET_ALLOCATE {
        let private_net = operation == SHARED_NET_ALLOCATE;
        let capacity = usize::try_from(args[0]).map_err(|_| Error::InvalidArgs)?;
        if capacity == 0 || capacity > MAX_CAPACITY {
            return Err(Error::InvalidArgs);
        }
        if private_net
            && (token != 0
                || capacity != PAGE_SIZE
                || args[2] != 0
                || !private_link_live(holder, args[1]))
        {
            return Err(Error::AccessDenied);
        }
        let bytes = capacity.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let reservation = if private_net {
            Reservation::with_limits(
                &holder.net_allocations,
                bytes,
                SHARED_NET_POOL_SIZE,
                SHARED_NET_POOL_SIZE * PAGE_SIZE,
            )?
        } else {
            Reservation::new(&holder.allocations, bytes)?
        };
        let charge = Charge::new(
            holder,
            bytes,
            reserve_fn(bytes + RECORD_RESERVE)?,
            reservation,
        )?;
        let dma = DmaStream::alloc(bytes / PAGE_SIZE, false)?;
        let allocation = Arc::new(Allocation {
            dma,
            _charge: charge,
        });
        let slot = u32::try_from(identity()?).map_err(|_| Error::Overflow)?;
        let token = (1u64 << 32) | slot as u64;
        let mut pool = POOL.lock();
        if !holder.live.load(Ordering::Acquire)
            || (private_net && !private_link_live(holder, args[1]))
        {
            drop(pool);
            return Err(Error::AccessDenied);
        }
        pool.insert(
            slot,
            Record {
                token,
                allocation,
                holder: holder.clone(),
                state: State::Issued,
                writable: true,
                payload: capacity,
                connection: None,
                _credit: None,
                _local_data_credit: None,
                backend: Weak::new(),
                abandoned: false,
            },
        );
        return Ok(response(0, token));
    }

    let mut pool = POOL.lock();
    if !holder.live.load(Ordering::Acquire) {
        return Err(Error::AccessDenied);
    }
    if operation == CONNECTION {
        let connection = holder
            .peers
            .lock()
            .keys()
            .nth(usize::try_from(args[0]).map_err(|_| Error::InvalidArgs)?)
            .copied();
        return Ok(response(0, connection.unwrap_or(0)));
    }
    if operation == RECEIVE {
        // Receipt is nondestructive: repeated polling sees the same issued
        // grant until REDEEM or DISCARD consumes it.
        let peer_live = holder
            .peers
            .lock()
            .get(&args[0])
            .ok_or(Error::AccessDenied)?
            .upgrade()
            .is_some_and(|peer| peer.live.load(Ordering::Acquire));
        let token = holder
            .inbox
            .lock()
            .iter()
            .find_map(|&(connection, token)| (connection == args[0]).then_some(token));
        if token.is_none() && !peer_live {
            return Err(Error::AccessDenied);
        }
        return Ok(response(0, token.unwrap_or(0)));
    }
    let record = owned(&mut pool, holder, token)?;
    match operation {
        REDEEM => {
            if !matches!(record.state, State::Issued) {
                return Err(Error::InvalidArgs);
            }
            // Reading the raw cursor does not read or borrow payload bytes.
            let address = record.allocation.dma.reader()?.cursor().addr() as u64;
            record.state = State::Active;
            holder.inbox.lock().retain(|&(_, pending)| pending != token);
            Ok(response(
                mapping_info(
                    record.allocation.dma.size(),
                    record.payload,
                    record.writable,
                ),
                address,
            ))
        }
        RELEASE | DISCARD => {
            if !matches!(
                (&record.state, operation),
                (State::Active, RELEASE) | (State::Issued, DISCARD)
            ) {
                return Err(Error::InvalidArgs);
            }
            holder.inbox.lock().retain(|&(_, pending)| pending != token);
            let removed = pool.remove(&(token as u32));
            drop(pool);
            drop(removed);
            Ok(response(0, 0))
        }
        HANDOFF => {
            if !matches!(record.state, State::Active)
                || args[1] > READ_WRITE
                || args[2] > record.allocation.dma.size() as u64
                || (!record.writable && (args[1] == READ_WRITE || args[2] > record.payload as u64))
            {
                return Err(Error::InvalidArgs);
            }
            let peer = holder
                .peers
                .lock()
                .get(&args[0])
                .and_then(Peer::upgrade)
                .ok_or(Error::AccessDenied)?;
            if !peer.live.load(Ordering::Acquire) {
                return Err(Error::AccessDenied);
            }
            let data_credit = if peer.host_local && args[2] != 0 {
                Some(Reservation::private_data(
                    &peer.data_imports,
                    record.allocation.dma.size(),
                )?)
            } else {
                None
            };
            let credit = if peer.host_local {
                Reservation::private_net(&peer.net_imports, record.allocation.dma.size())?
            } else {
                Reservation::new(&peer.imports, record.allocation.dma.size())?
            };
            let next = advance(token)?;
            let notify = peer.notifiers.lock().get(&args[0]).cloned();
            peer.inbox.lock().push((args[0], next));
            record.publish(Delivery {
                holder: peer,
                token: next,
                connection: args[0],
                access: if args[1] == READ_WRITE {
                    GrantAccess::ReadWrite
                } else {
                    GrantAccess::ReadOnly
                },
                payload: args[2] as usize,
                credit,
                local_data_credit: data_credit,
            });
            drop(pool);
            if let Some(notify) = notify {
                notify();
            }
            Ok(response(0, 0))
        }
        SUBMIT => {
            let request = IoRequest {
                device: args[0].try_into().map_err(|_| Error::InvalidArgs)?,
                offset: args[1],
                len: args[2] as u32 as usize,
                device_writes: args[2] >> 32 == DEVICE_WRITE as u64,
            };
            if !matches!(record.state, State::Active)
                || args[2] >> 32 > DEVICE_WRITE as u64
                || request.len == 0
                || request.len > record.allocation.dma.size()
                || (!record.writable && (request.device_writes || request.len > record.payload))
                || request.offset.checked_add(request.len as u64).is_none()
            {
                return Err(Error::InvalidArgs);
            }
            // Synchronize before acceptance, while the old grant remains valid.
            record.allocation.dma.sync_to_device(0..request.len)?;
            let next = advance(token)?;
            // Reserve a generation for the return grant before acceptance.
            advance(next)?;
            let backend = Arc::new(BackendLease {
                token: next,
                allocation: record.allocation.clone(),
                request,
                cancelled: AtomicBool::new(false),
                result: SpinLock::new(None),
            });
            record.token = next;
            record.state = State::Backend;
            record.backend = Arc::downgrade(&backend);
            drop(pool);
            // Install the record before publishing: immediate completion is legal.
            submit_fn(BackendBuffer(backend), request);
            Ok(response(0, next))
        }
        POLL => {
            let State::Completed(status) = record.state else {
                return if matches!(record.state, State::Backend) {
                    Ok(response(0, 0))
                } else {
                    Err(Error::InvalidArgs)
                };
            };
            let next = advance(token)?;
            record.token = next;
            record.state = State::Issued;
            record.connection = None;
            Ok(response(status, next))
        }
        CANCEL => {
            if let Some(backend) = record.backend.upgrade() {
                backend.cancelled.store(true, Ordering::Release);
                // Never drop the last backend handle while holding POOL.
                drop(pool);
                drop(backend);
                Ok(response(0, 0))
            } else if matches!(record.state, State::Completed(_)) {
                Ok(response(0, 0))
            } else {
                Err(Error::InvalidArgs)
            }
        }
        ABANDON => {
            match record.state {
                State::Backend => {
                    record.abandoned = true;
                    let backend = record.backend.upgrade();
                    if let Some(backend) = &backend {
                        backend.cancelled.store(true, Ordering::Release);
                    }
                    drop(pool);
                    drop(backend);
                }
                State::Completed(_) => {
                    let removed = pool.remove(&(token as u32));
                    drop(pool);
                    drop(removed);
                }
                _ => return Err(Error::InvalidArgs),
            }
            Ok(response(0, 0))
        }
        _ => Err(Error::InvalidArgs),
    }
}
