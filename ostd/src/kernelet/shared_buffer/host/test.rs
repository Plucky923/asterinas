// SPDX-License-Identifier: MPL-2.0

use alloc::vec::Vec;
use core::cell::RefCell;

use super::*;
use crate::{kernelet::control::KerneletPolicy, prelude::*, sync::WaitQueue};

struct Owner(Arc<Participant>);

struct NetScratch {
    memory: Arc<crate::kernelet::guest_memory::GrantMemory>,
    base: u64,
}

impl NetScratch {
    fn new() -> Self {
        use crate::{
            kernelet::{
                abi::GRAIN_SIZE, control::identity::Registration, dma, guest_memory::GrantMemory,
            },
            mm::{
                FrameAllocOptions, HasPaddr,
                frame::meta::{META_IO_STATE_OFFSET, META_SLOT_SIZE},
            },
        };

        let identity = Registration::new().unwrap();
        let memory = GrantMemory::new(identity.owner()).unwrap();
        memory.bind_identity(Arc::new(identity));
        let frames = FrameAllocOptions::new()
            .alloc_segment_aligned(GRAIN_SIZE / PAGE_SIZE, GRAIN_SIZE)
            .unwrap();
        let base = frames.paddr() as u64;
        let metadata: Vec<_> = (0..GRAIN_SIZE / PAGE_SIZE * META_SLOT_SIZE / PAGE_SIZE)
            .map(|_| FrameAllocOptions::new().alloc_frame().unwrap())
            .collect();
        let address = crate::mm::paddr_to_vaddr(metadata[0].paddr()) + META_IO_STATE_OFFSET;
        // SAFETY: Fresh zeroed metadata has an aligned atomic I/O state word.
        // No other accessor exists before the pending run is published.
        let state = unsafe { &*(address as *const AtomicU64) };
        dma::register_owner(state).unwrap();
        let mut pending = memory.prepare(frames).unwrap();
        pending.set_metadata(metadata).unwrap();
        pending.publish();
        Self { memory, base }
    }

    fn capability(&self) -> crate::kernelet::guest_memory::GuestMemory {
        crate::kernelet::guest_memory::GuestMemory::new(&self.memory)
    }

    fn exchange(&self, image: &Owner, connection: u64, returns: &[u64]) -> MmioResult {
        let bytes = ostd_pod::IntoBytes::as_bytes(returns);
        self.capability().write(self.base, bytes).unwrap();
        dispatch_net_exchange(
            &image.0,
            &self.capability(),
            0,
            [connection, self.base, returns.len() as u64],
        )
    }

    fn descriptor(&self, index: usize) -> NetGrantDescriptor {
        let mut bytes = [0; size_of::<NetGrantDescriptor>()];
        self.capability()
            .read(
                self.base + NET_RETURN_BYTES as u64 + (index * bytes.len()) as u64,
                &mut bytes,
            )
            .unwrap();
        <NetGrantDescriptor as ostd_pod::Pod>::from_bytes(&bytes)
    }
}

impl Drop for NetScratch {
    fn drop(&mut self) {
        assert_eq!(self.memory.close(), 0);
        self.memory.reclaim();
    }
}

#[ktest]
fn net_exchange_pins_output_before_activation_and_preserves_empty_output() {
    let image = Owner::new();
    let local = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
    let scratch = NetScratch::new();
    let connection = local.connection();
    let grant = local.allocate(PAGE_SIZE, Box::new(())).unwrap();
    let address = grant
        .with_bytes(0..32, |bytes| bytes.as_ptr() as u64)
        .unwrap();
    grant
        .handoff(local.reserve_send(PAGE_SIZE).unwrap(), 32)
        .unwrap_or_else(|_| panic!("Host handoff failed"));
    let token = image.call(RECEIVE, 0, [connection, 0, 0]).value;
    // Only the first scratch page is DMA-registered. The output would cross
    // into an unregistered page, so validation must reject before activation.
    let reply = dispatch_net_exchange(
        &image.0,
        &scratch.capability(),
        0,
        [connection, scratch.base + PAGE_SIZE as u64 - 8, 0],
    );
    assert!(reply.status < 0);
    assert_eq!(image.call(RECEIVE, 0, [connection, 0, 0]).value, token);
    assert_eq!(scratch.exchange(&image, connection, &[]).value, 1);
    assert_eq!(scratch.descriptor(0).token, token);
    assert_eq!(scratch.descriptor(0).address, address);
    assert_eq!(
        mapping_fields(scratch.descriptor(0).mapping),
        (PAGE_SIZE, 32, true)
    );
    assert_eq!(image.call(REDEEM, token, [0; 3]).status, -abi::INVALID);
    local
        .allocate(PAGE_SIZE, Box::new(()))
        .unwrap()
        .handoff(local.reserve_send(PAGE_SIZE).unwrap(), 64)
        .unwrap_or_else(|_| panic!("Host handoff failed"));
    assert_eq!(scratch.exchange(&image, connection, &[token]).value, 1);
    assert_eq!(local.receive().unwrap().unwrap().payload_len(), 0);
    assert_eq!(image.call(RELEASE, token, [0; 3]).status, -abi::INVALID);
    let next = scratch.descriptor(0);
    assert_ne!(next.token, token);
    assert_eq!(image.call(RELEASE, next.token, [0; 3]).status, 0);
    let sentinel = [0xa5; size_of::<NetGrantDescriptor>()];
    scratch
        .capability()
        .write(scratch.base + NET_RETURN_BYTES as u64, &sentinel)
        .unwrap();
    assert_eq!(scratch.exchange(&image, connection, &[]).value, 0);
    let mut output = [0; size_of::<NetGrantDescriptor>()];
    scratch
        .capability()
        .read(scratch.base + NET_RETURN_BYTES as u64, &mut output)
        .unwrap();
    assert_eq!(output, sentinel);
}

#[ktest]
fn net_exchange_rejections_preserve_owners_and_pending_deliveries() {
    let image = Owner::new();
    let other = Owner::new();
    let local = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
    let scratch = NetScratch::new();
    let connection = local.connection();
    let first = image.allocate(PAGE_SIZE);
    let second = image.allocate(PAGE_SIZE);
    image.call(REDEEM, first, [0; 3]);
    image.call(REDEEM, second, [0; 3]);
    let grant = local.allocate(PAGE_SIZE, Box::new(())).unwrap();
    grant
        .handoff(local.reserve_send(PAGE_SIZE).unwrap(), 32)
        .unwrap_or_else(|_| panic!("Host handoff failed"));
    let pending = image.call(RECEIVE, 0, [connection, 0, 0]).value;
    assert_eq!(
        scratch.exchange(&image, connection, &[first, first]).status,
        -abi::INVALID
    );
    let foreign = other.allocate(PAGE_SIZE);
    other.call(REDEEM, foreign, [0; 3]);
    assert_eq!(
        scratch
            .exchange(&image, connection, &[first, foreign])
            .status,
        -abi::NOT_OWNED
    );
    let exhausted = (u32::MAX as u64) << 32 | second as u32 as u64;
    POOL.lock().get_mut(&(second as u32)).unwrap().token = exhausted;
    assert_eq!(
        scratch
            .exchange(&image, connection, &[first, exhausted])
            .status,
        -abi::STATE
    );
    assert_eq!(image.call(RECEIVE, 0, [connection, 0, 0]).value, pending);
    let host = image
        .0
        .peers
        .lock()
        .get(&connection)
        .unwrap()
        .upgrade()
        .unwrap();
    assert_eq!(host.net_imports.count.load(Ordering::Acquire), 0);
    let generic = Participant::connect(&image.0, &other.0).unwrap();
    assert_eq!(
        scratch.exchange(&image, generic, &[first]).status,
        -abi::NOT_OWNED
    );
    assert_eq!(
        other.call(HANDOFF, foreign, [generic, READ_ONLY, 8]).status,
        0
    );
    let readonly = image.call(RECEIVE, 0, [generic, 0, 0]).value;
    assert!(image.call(REDEEM, readonly, [0; 3]).status >= 0);
    assert_eq!(
        scratch
            .exchange(&image, connection, &[first, readonly])
            .status,
        -abi::INVALID
    );
    assert_eq!(image.call(RELEASE, readonly, [0; 3]).status, 0);
    assert_eq!(image.call(RELEASE, first, [0; 3]).status, 0);
    assert_eq!(image.call(RELEASE, exhausted, [0; 3]).status, 0);
    local.close();
    // Already issued grants remain recoverable through the retired NIC link.
    assert_eq!(scratch.exchange(&image, connection, &[]).value, 1);
    assert_eq!(scratch.descriptor(0).token, pending);
    assert_eq!(image.call(RELEASE, pending, [0; 3]).status, 0);
    assert_eq!(
        scratch.exchange(&image, connection, &[]).status,
        -abi::NOT_OWNED
    );
}

#[ktest]
fn net_exchange_saturated_data_and_empty_returns_keep_making_progress() {
    let image = Owner::new();
    let local = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
    let scratch = NetScratch::new();
    let connection = local.connection();
    let host = image
        .0
        .peers
        .lock()
        .get(&connection)
        .unwrap()
        .upgrade()
        .unwrap();
    let host_notified = Arc::new(AtomicUsize::new(0));
    let count = host_notified.clone();
    local
        .set_notifiers(
            Arc::new(move || {
                assert!(POOL.try_lock().is_some());
                count.fetch_add(1, Ordering::Relaxed);
            }),
            Arc::new(|| {}),
        )
        .unwrap();
    for _ in 0..SHARED_NET_POOL_SIZE {
        let token = image.allocate(PAGE_SIZE);
        image.call(REDEEM, token, [0; 3]);
        assert_eq!(
            image
                .call(HANDOFF, token, [connection, READ_WRITE, 32])
                .status,
            0
        );
        local
            .allocate(PAGE_SIZE, Box::new(()))
            .unwrap()
            .handoff(local.reserve_send(PAGE_SIZE).unwrap(), 32)
            .unwrap_or_else(|_| panic!("Host handoff failed"));
    }
    let mut returns = Vec::new();
    for _ in 0..SHARED_NET_POOL_SIZE / SHARED_NET_BATCH_SIZE {
        assert_eq!(
            scratch.exchange(&image, connection, &[]).value,
            SHARED_NET_BATCH_SIZE as u64
        );
        returns.extend((0..SHARED_NET_BATCH_SIZE).map(|index| scratch.descriptor(index).token));
    }
    for chunk in returns.chunks(SHARED_NET_BATCH_SIZE) {
        let before = host_notified.load(Ordering::Relaxed);
        assert_eq!(scratch.exchange(&image, connection, chunk).value, 0);
        assert_eq!(host_notified.load(Ordering::Relaxed), before + 1);
        assert_eq!(
            scratch.exchange(&image, connection, &chunk[..1]).status,
            -abi::INVALID
        );
    }
    assert_eq!(
        host.net_imports.count.load(Ordering::Acquire),
        PRIVATE_NET_IMPORTS
    );
    assert_eq!(
        host.data_imports.count.load(Ordering::Acquire),
        SHARED_NET_POOL_SIZE
    );
    for _ in 0..3 {
        let grants: Vec<_> = (0..PRIVATE_NET_IMPORTS)
            .map(|_| local.receive().unwrap().unwrap())
            .collect();
        for grant in grants {
            let payload = if grant.payload_len() == 0 { 32 } else { 0 };
            grant
                .handoff(local.reserve_send(PAGE_SIZE).unwrap(), payload)
                .unwrap_or_else(|_| panic!("Host handoff failed"));
        }
        assert_eq!(
            image.0.net_imports.count.load(Ordering::Acquire),
            PRIVATE_NET_IMPORTS
        );
        let mut data = Vec::new();
        let mut empty = Vec::new();
        for batch in 0..PRIVATE_NET_IMPORTS / SHARED_NET_BATCH_SIZE {
            let reply = scratch.exchange(&image, connection, &[]);
            assert_eq!(reply.value, SHARED_NET_BATCH_SIZE as u64);
            assert_eq!(
                reply.status,
                i64::from(batch + 1 < PRIVATE_NET_IMPORTS / SHARED_NET_BATCH_SIZE)
            );
            for index in 0..SHARED_NET_BATCH_SIZE {
                let descriptor = scratch.descriptor(index);
                let (_, payload, writable) = mapping_fields(descriptor.mapping);
                assert!(writable);
                if payload == 0 {
                    empty.push(descriptor.token);
                } else {
                    data.push(descriptor.token);
                }
            }
        }
        assert_eq!(data.len(), SHARED_NET_POOL_SIZE);
        assert_eq!(empty.len(), SHARED_NET_POOL_SIZE);
        for chunk in data.chunks(SHARED_NET_BATCH_SIZE) {
            scratch.exchange(&image, connection, chunk);
        }
        for token in empty {
            assert_eq!(
                image
                    .call(HANDOFF, token, [connection, READ_WRITE, 32])
                    .status,
                0
            );
        }
        assert_eq!(
            host.net_imports.count.load(Ordering::Acquire),
            PRIVATE_NET_IMPORTS
        );
    }
}

#[ktest]
fn closing_host_connections_retires_both_notifiers_outside_pool() {
    struct CallbackDrop(Arc<AtomicUsize>);
    impl Drop for CallbackDrop {
        fn drop(&mut self) {
            assert!(POOL.try_lock().is_some());
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let image = Owner::new();
    let destroyed = Arc::new(AtomicUsize::new(0));
    for iteration in 0..MAX_CONNECTIONS * 4 {
        let local = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
        let host_drop = CallbackDrop(destroyed.clone());
        let image_drop = CallbackDrop(destroyed.clone());
        local
            .set_notifiers(
                Arc::new(move || {
                    let _ = &host_drop;
                }),
                Arc::new(move || {
                    let _ = &image_drop;
                }),
            )
            .unwrap();
        assert_eq!(image.0.notifiers.lock().len(), 1);
        assert_eq!(image.0.peers.lock().len(), 1);
        drop(local);
        assert!(image.0.notifiers.lock().is_empty());
        assert_eq!(destroyed.load(Ordering::Relaxed), (iteration + 1) * 2);
    }
}

#[ktest]
fn issued_nic_delivery_stays_private_after_host_notifier_retirement() {
    let image = Owner::new();
    let local = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
    local
        .set_notifiers(Arc::new(|| {}), Arc::new(|| {}))
        .unwrap();
    let connection = local.connection();
    let grant = local.allocate(PAGE_SIZE, Box::new(())).unwrap();
    let credit = local.reserve_send(PAGE_SIZE).unwrap();
    grant
        .handoff(credit, 32)
        .unwrap_or_else(|_| panic!("Host handoff failed"));
    drop(local);
    assert!(image.0.notifiers.lock().is_empty());
    assert_eq!(network_info(&image, 0).value, 0);
    let token = image.call(RECEIVE, 0, [connection, 0, 0]).value;
    assert_ne!(token, 0);
    assert!(image.call(REDEEM, token, [0; 3]).status >= 0);
    assert_eq!(image.call(RELEASE, token, [0; 3]).status, 0);
    assert_eq!(image.bytes(), 0);
    let next = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
    assert_eq!(image.0.peers.lock().len(), 1);
    assert_ne!(next.connection(), connection);
}

#[ktest]
fn host_data_imports_preserve_sixty_four_empty_return_slots() {
    let image = Owner::new();
    let extra = Owner::new();
    let link = Participant::connect(&extra.0, &image.0).unwrap();
    let local = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
    let connection = local.connection();
    let host = image
        .0
        .peers
        .lock()
        .get(&connection)
        .unwrap()
        .upgrade()
        .unwrap();
    for _ in 0..SHARED_NET_POOL_SIZE {
        let token = image.allocate(PAGE_SIZE);
        assert!(image.call(REDEEM, token, [0; 3]).status >= 0);
        assert_eq!(
            image
                .call(HANDOFF, token, [connection, READ_WRITE, 1])
                .status,
            0
        );
    }
    for index in 0..SHARED_NET_POOL_SIZE {
        let token = extra.allocate(PAGE_SIZE);
        extra.call(REDEEM, token, [0; 3]);
        assert_eq!(extra.call(HANDOFF, token, [link, READ_WRITE, 1]).status, 0);
        let received = image.call(RECEIVE, 0, [link, 0, 0]).value;
        image.call(REDEEM, received, [0; 3]);
        if index == 0 {
            assert_eq!(
                image
                    .call(HANDOFF, received, [connection, READ_WRITE, 1])
                    .status,
                -abi::LIMIT
            );
            assert_eq!(
                host.data_imports.count.load(Ordering::Acquire),
                SHARED_NET_POOL_SIZE
            );
        }
        assert_eq!(
            image
                .call(HANDOFF, received, [connection, READ_WRITE, 0])
                .status,
            0
        );
    }
    assert_eq!(
        host.net_imports.count.load(Ordering::Acquire),
        PRIVATE_NET_IMPORTS
    );
    let grants: Vec<_> = (0..PRIVATE_NET_IMPORTS)
        .map(|_| local.receive().unwrap().unwrap())
        .collect();
    assert_eq!(
        grants
            .iter()
            .filter(|grant| grant.payload_len() == 0)
            .count(),
        SHARED_NET_POOL_SIZE
    );
    drop(grants);
    assert_eq!(host.net_imports.count.load(Ordering::Acquire), 0);
    assert_eq!(host.data_imports.count.load(Ordering::Acquire), 0);
    assert_eq!(image.bytes(), 0);
    assert_eq!(extra.bytes(), 0);
}

#[ktest]
fn large_host_data_imports_preserve_empty_return_byte_capacity() {
    let image = Owner::new();
    let local = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
    let connection = local.connection();
    let host = image
        .0
        .peers
        .lock()
        .get(&connection)
        .unwrap()
        .upgrade()
        .unwrap();
    let data_count = (MAX_BYTES / 2) / MAX_CAPACITY;
    for _ in 0..data_count {
        let token = image.allocate(MAX_CAPACITY);
        assert!(image.call(REDEEM, token, [0; 3]).status >= 0);
        assert_eq!(
            image
                .call(HANDOFF, token, [connection, READ_WRITE, 1])
                .status,
            0
        );
    }
    let extra = image.allocate(MAX_CAPACITY);
    assert!(image.call(REDEEM, extra, [0; 3]).status >= 0);
    assert_eq!(
        image
            .call(HANDOFF, extra, [connection, READ_WRITE, 1])
            .status,
        -abi::LIMIT
    );
    assert_eq!(
        host.net_imports.bytes.load(Ordering::Acquire),
        MAX_BYTES / 2
    );
    assert_eq!(
        host.data_imports.bytes.load(Ordering::Acquire),
        MAX_BYTES / 2
    );
    for _ in 0..MAX_BUFFERS / 2 {
        let token = image.allocate(PAGE_SIZE);
        assert!(image.call(REDEEM, token, [0; 3]).status >= 0);
        assert_eq!(
            image
                .call(HANDOFF, token, [connection, READ_WRITE, 0])
                .status,
            0
        );
    }
    for _ in 0..data_count + MAX_BUFFERS / 2 {
        drop(local.receive().unwrap().unwrap());
    }
    assert_eq!(host.net_imports.bytes.load(Ordering::Acquire), 0);
    assert_eq!(host.data_imports.bytes.load(Ordering::Acquire), 0);
    assert_eq!(image.call(RELEASE, extra, [0; 3]).status, 0);
    assert_eq!(image.bytes(), 0);
}

#[ktest]
fn host_local_grants_reuse_exclusive_storage_and_notify_after_unlock() {
    let image = Owner::new();
    let local = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
    let host_notified = Arc::new(AtomicUsize::new(0));
    let image_notified = Arc::new(AtomicUsize::new(0));
    let host_count = host_notified.clone();
    let image_count = image_notified.clone();
    local
        .set_notifiers(
            Arc::new(move || {
                assert!(POOL.try_lock().is_some());
                host_count.fetch_add(1, Ordering::Relaxed);
            }),
            Arc::new(move || {
                assert!(POOL.try_lock().is_some());
                image_count.fetch_add(1, Ordering::Relaxed);
            }),
        )
        .unwrap();
    // NIC-private connections do not enter the old datagram device list.
    assert_eq!(network_info(&image, 0).value, 0);
    let mut grant = local.allocate(PAGE_SIZE, Box::new(())).unwrap();
    grant
        .with_bytes_mut(0..32, |bytes| bytes.fill(0xa5))
        .unwrap();
    for _ in 0..96 {
        let credit = local.reserve_send(PAGE_SIZE).unwrap();
        grant
            .handoff(credit, 32)
            .unwrap_or_else(|_| panic!("Host handoff failed"));
        let token = image.call(RECEIVE, 0, [local.connection(), 0, 0]).value;
        assert_ne!(token, 0);
        assert!(image.call(REDEEM, token, [0; 3]).status >= 0);
        assert_eq!(
            image
                .call(HANDOFF, token, [local.connection(), READ_WRITE, 32])
                .status,
            0
        );
        grant = local.receive().unwrap().unwrap();
        grant
            .with_bytes(0..32, |bytes| assert_eq!(bytes, &[0xa5; 32]))
            .unwrap();
        assert_eq!(image.0.allocations.count.load(Ordering::Acquire), 0);
        assert_eq!(image.bytes(), PAGE_SIZE + RECORD_RESERVE);
    }
    assert_eq!(host_notified.load(Ordering::Relaxed), 96);
    assert_eq!(image_notified.load(Ordering::Relaxed), 96);
    // Teardown cannot invalidate even a currently active callback's slice.
    let charged = image.bytes();
    grant
        .with_bytes(0..32, |bytes| {
            local.close();
            assert_eq!(image.bytes(), charged);
            assert_eq!(bytes, &[0xa5; 32]);
        })
        .unwrap();
    assert!(local.reserve_send(PAGE_SIZE).is_err());
    drop(grant);
    assert_eq!(image.bytes(), 0);
}

#[ktest]
fn host_transmit_credit_is_reserved_before_production_and_refunded_on_drop() {
    let image = Owner::new();
    let local = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
    let credits: Vec<_> = (0..PRIVATE_NET_IMPORTS)
        .map(|_| local.reserve_send(PAGE_SIZE).unwrap())
        .collect();
    assert!(matches!(
        local.reserve_send(PAGE_SIZE),
        Err(Error::NotEnoughResources)
    ));
    assert_eq!(
        image.0.net_imports.count.load(Ordering::Acquire),
        PRIVATE_NET_IMPORTS
    );
    drop(credits);
    assert_eq!(image.0.net_imports.count.load(Ordering::Acquire), 0);
    assert_eq!(image.0.net_imports.bytes.load(Ordering::Acquire), 0);
    let grant = local.allocate(PAGE_SIZE, Box::new(())).unwrap();
    let credit = local.reserve_send(PAGE_SIZE).unwrap();
    image.0.mark_dying();
    let (grant, credit, error) = grant.handoff(credit, 1).err().unwrap();
    assert_eq!(error, Error::AccessDenied);
    assert_eq!(image.0.net_imports.count.load(Ordering::Acquire), 1);
    drop(credit);
    drop(grant);
    assert_eq!(image.bytes(), 0);
    assert_eq!(image.0.net_imports.count.load(Ordering::Acquire), 0);
}

#[ktest]
fn shared_ethernet_header_rejects_unknown_flags_and_ranges() {
    use super::super::SharedNetHeader;

    for copied in [false, true] {
        let header = SharedNetHeader::new(160, 1514, copied).unwrap();
        let decoded = SharedNetHeader::decode(header.encode()).unwrap();
        assert_eq!(decoded.frame_offset(), 160);
        assert_eq!(decoded.frame_len(), 1514);
        assert_eq!(decoded.copied(), copied);
    }
    assert!(SharedNetHeader::new(11, 14, false).is_none());
    assert!(SharedNetHeader::new(12, 13, false).is_none());
    assert!(SharedNetHeader::new(12, 1515, false).is_none());
    let mut bytes = SharedNetHeader::new(12, 14, false).unwrap().encode();
    bytes[0] |= 2;
    assert!(SharedNetHeader::decode(bytes).is_none());
}

fn network_info(owner: &Owner, index: u64) -> MmioResult {
    dispatch_device(
        &owner.0,
        NET_INFO,
        0,
        [index, 0, 0],
        |_| panic!("network enumeration used a block attachment"),
        |_| panic!("network enumeration allocated a buffer"),
        |_, _| panic!("network enumeration submitted I/O"),
    )
}

#[ktest]
fn connections_are_explicit_bounded_and_idempotent_in_both_directions() {
    let a = Owner::new();
    let b = Owner::new();
    let unauthorized = Owner::new();
    assert_eq!(Participant::connect(&a.0, &a.0), Err(Error::InvalidArgs));
    let connection = Participant::connect(&a.0, &b.0).unwrap();
    for _ in 0..MAX_CONNECTIONS * 2 {
        assert_eq!(Participant::connect(&a.0, &b.0).unwrap(), connection);
        assert_eq!(Participant::connect(&b.0, &a.0).unwrap(), connection);
    }
    assert_eq!(a.0.peers.lock().len(), 1);
    assert_eq!(b.0.peers.lock().len(), 1);
    assert_eq!(
        unauthorized.call(RECEIVE, 0, [connection, 0, 0]).status,
        -abi::NOT_OWNED
    );
    assert_eq!(network_info(&a, 0).value, connection);
    assert_eq!(
        network_info(&a, 0).status,
        super::super::MAX_DATAGRAM_PAYLOAD as i64
    );
    assert_eq!(network_info(&a, 1).value, 0);
    b.0.mark_dying();
    assert_eq!(Participant::connect(&a.0, &b.0), Err(Error::AccessDenied));
    assert_eq!(network_info(&a, 0).value, 0);
    assert_eq!(
        a.call(RECEIVE, 0, [connection, 0, 0]).status,
        -abi::NOT_OWNED
    );
}

#[ktest]
fn closed_connections_release_quota_before_authorizing_new_peers() {
    let receiver = Owner::new();
    let peers: Vec<_> = (0..MAX_CONNECTIONS).map(|_| Owner::new()).collect();
    for peer in &peers {
        Participant::connect(&receiver.0, &peer.0).unwrap();
    }
    let next = Owner::new();
    assert_eq!(
        Participant::connect(&receiver.0, &next.0),
        Err(Error::NotEnoughResources)
    );
    peers[0].0.close();
    let connection = Participant::connect(&receiver.0, &next.0).unwrap();
    assert_ne!(connection, 0);
    assert_eq!(receiver.0.peers.lock().len(), MAX_CONNECTIONS);
    assert_eq!(next.0.peers.lock().len(), 1);
}

#[ktest]
fn accepted_datagrams_remain_discoverable_after_the_sender_exits() {
    let sender = Owner::new();
    let receiver = Owner::new();
    let connection = Participant::connect(&sender.0, &receiver.0).unwrap();
    let token = sender.allocate(1);
    assert!(sender.call(REDEEM, token, [0; 3]).status >= 0);
    assert_eq!(
        sender
            .call(HANDOFF, token, [connection, READ_ONLY, 1])
            .status,
        0
    );
    sender.0.close();
    let other = Owner::new();
    Participant::connect(&receiver.0, &other.0).unwrap();
    assert!(receiver.0.peers.lock().contains_key(&connection));
    assert_eq!(network_info(&receiver, 0).value, connection);
    let delivered = receiver.call(RECEIVE, 0, [connection, 0, 0]).value;
    assert_ne!(delivered, 0);
    assert!(receiver.call(REDEEM, delivered, [0; 3]).status >= 0);
    assert_eq!(receiver.call(RELEASE, delivered, [0; 3]).status, 0);
    assert_eq!(sender.bytes(), 0);
    assert_eq!(
        receiver.call(RECEIVE, 0, [connection, 0, 0]).status,
        -abi::NOT_OWNED
    );
    assert_ne!(network_info(&receiver, 0).value, connection);
    Participant::connect(&receiver.0, &other.0).unwrap();
    assert!(!receiver.0.peers.lock().contains_key(&connection));
}

#[ktest]
fn concurrent_receive_observations_cannot_consume_another_delivery() {
    let sender = Owner::new();
    let receiver = Owner::new();
    let connection = Participant::connect(&sender.0, &receiver.0).unwrap();
    for _ in 0..2 {
        let token = sender.allocate(1);
        assert!(sender.call(REDEEM, token, [0; 3]).status >= 0);
        assert_eq!(
            sender
                .call(HANDOFF, token, [connection, READ_ONLY, 1])
                .status,
            0
        );
    }
    let first = receiver.call(RECEIVE, 0, [connection, 0, 0]).value;
    assert_eq!(receiver.call(RECEIVE, 0, [connection, 0, 0]).value, first);
    assert!(receiver.call(REDEEM, first, [0; 3]).status >= 0);
    assert!(receiver.call(REDEEM, first, [0; 3]).status < 0);
    let second = receiver.call(RECEIVE, 0, [connection, 0, 0]).value;
    assert_ne!(second, 0);
    assert_ne!(second, first);
    assert!(receiver.call(REDEEM, second, [0; 3]).status >= 0);
    assert_eq!(receiver.call(RECEIVE, 0, [connection, 0, 0]).value, 0);
    assert_eq!(receiver.call(RELEASE, first, [0; 3]).status, 0);
    assert_eq!(receiver.call(RELEASE, second, [0; 3]).status, 0);
    assert_eq!(sender.bytes(), 0);
}

impl Owner {
    fn transmit_batch(
        &self,
        scratch: &NetScratch,
        connection: u64,
        frames: &[NetTransmitDescriptor],
    ) -> MmioResult {
        scratch
            .capability()
            .write(scratch.base, ostd_pod::IntoBytes::as_bytes(frames))
            .unwrap();
        dispatch_net_transmit(
            &self.0,
            &scratch.capability(),
            0,
            [connection, scratch.base, frames.len() as u64],
        )
    }

    fn new() -> Self {
        Self(Participant::new(Account::new(
            Arc::new(WaitQueue::new()),
            KerneletPolicy::default(),
        )))
    }

    fn call(&self, operation: u32, token: u64, args: [u64; 3]) -> MmioResult {
        dispatch(
            &self.0,
            operation,
            token,
            args,
            |_| Ok(Box::new(())),
            |buffer, _| {
                buffer.complete(0, 0).unwrap();
            },
        )
    }

    fn allocate(&self, capacity: usize) -> u64 {
        let reply = self.call(ALLOCATE, 0, [capacity as u64, 0, 0]);
        assert_eq!(reply.status, 0);
        assert_ne!(reply.value, 0);
        reply.value
    }

    fn bytes(&self) -> usize {
        self.0.account.host_bytes.load(Ordering::Acquire)
    }
}

#[ktest]
fn private_nic_transmit_batch_preserves_bytes_and_notifies_once() {
    let image = Owner::new();
    let local = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
    let scratch = NetScratch::new();
    let notified = Arc::new(AtomicUsize::new(0));
    let count = notified.clone();
    local
        .set_notifiers(
            Arc::new(move || {
                assert!(POOL.try_lock().is_some());
                count.fetch_add(1, Ordering::Relaxed);
            }),
            Arc::new(|| {}),
        )
        .unwrap();
    let mut frames = [NetTransmitDescriptor::default(); SHARED_NET_BATCH_SIZE];
    for (index, frame) in frames.iter_mut().enumerate() {
        let token = image.allocate(PAGE_SIZE);
        let mapping = image.call(REDEEM, token, [0; 3]);
        assert!(mapping.status >= 0);
        let record = POOL.lock();
        record
            .get(&(token as u32))
            .unwrap()
            .allocation
            .dma
            .writer()
            .unwrap()
            .write_val(&(index as u64))
            .unwrap();
        *frame = NetTransmitDescriptor { token, payload: 8 };
    }
    let reply = image.transmit_batch(&scratch, local.connection(), &frames);
    assert_eq!(
        (reply.status, reply.value),
        (0, SHARED_NET_BATCH_SIZE as u64)
    );
    assert_eq!(notified.load(Ordering::Relaxed), 1);
    let mut received = core::array::from_fn(|_| None);
    assert_eq!(
        local.receive_batch(&mut received).unwrap(),
        SHARED_NET_BATCH_SIZE
    );
    for (index, grant) in received.into_iter().enumerate() {
        let grant = grant.unwrap();
        assert_eq!(grant.payload_len(), 8);
        grant
            .with_bytes(0..8, |bytes| {
                assert_eq!(bytes, (index as u64).to_ne_bytes())
            })
            .unwrap();
    }
    assert_eq!(image.bytes(), 0);
}

#[ktest]
fn private_nic_transmit_batch_rejection_preserves_every_owner() {
    let image = Owner::new();
    let local = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
    let scratch = NetScratch::new();
    let first = image.allocate(PAGE_SIZE);
    let second = image.allocate(PAGE_SIZE);
    image.call(REDEEM, first, [0; 3]);
    image.call(REDEEM, second, [0; 3]);
    for bad in [first, second ^ (1 << 32)] {
        let frames = [
            NetTransmitDescriptor {
                token: first,
                payload: 8,
            },
            NetTransmitDescriptor {
                token: bad,
                payload: 8,
            },
        ];
        assert!(
            image
                .transmit_batch(&scratch, local.connection(), &frames)
                .status
                < 0
        );
        assert!(local.receive().unwrap().is_none());
        let mut pool = POOL.lock();
        for token in [first, second] {
            assert!(matches!(
                owned(&mut pool, &image.0, token).unwrap().state,
                State::Active
            ));
        }
    }
    // A full real data-import quota rejects a whole batch without consuming a
    // prefix; releasing the credits permits the same original tokens to retry.
    let host = image
        .0
        .peers
        .lock()
        .get(&local.connection())
        .unwrap()
        .upgrade()
        .unwrap();
    let held: Vec<_> = (0..SHARED_NET_POOL_SIZE)
        .map(|_| {
            Reservation::with_limits(
                &host.data_imports,
                PAGE_SIZE,
                SHARED_NET_POOL_SIZE,
                MAX_BYTES / 2,
            )
            .unwrap()
        })
        .collect();
    let frames = [
        NetTransmitDescriptor {
            token: first,
            payload: 8,
        },
        NetTransmitDescriptor {
            token: second,
            payload: 8,
        },
    ];
    assert_eq!(
        image
            .transmit_batch(&scratch, local.connection(), &frames)
            .status,
        -abi::LIMIT
    );
    assert_eq!(host.net_imports.count.load(Ordering::Acquire), 0);
    drop(held);
    assert_eq!(
        image
            .transmit_batch(&scratch, local.connection(), &frames)
            .value,
        2
    );
    drop(local.receive().unwrap().unwrap());
    drop(local.receive().unwrap().unwrap());
    assert_eq!(image.bytes(), 0);
}

#[ktest]
fn host_private_batch_keeps_failed_deliveries_and_notifies_after_unlock() {
    let image = Owner::new();
    let local = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
    let notified = Arc::new(AtomicUsize::new(0));
    let count = notified.clone();
    local
        .set_notifiers(
            Arc::new(|| {}),
            Arc::new(move || {
                assert!(POOL.try_lock().is_some());
                count.fetch_add(1, Ordering::Relaxed);
            }),
        )
        .unwrap();
    let mut batch = core::array::from_fn(|_| None);
    for slot in &mut batch {
        *slot = Some((
            local.allocate(PAGE_SIZE, Box::new(())).unwrap(),
            local.reserve_send(PAGE_SIZE).unwrap(),
            8,
        ));
    }
    batch[SHARED_NET_BATCH_SIZE - 1].as_mut().unwrap().2 = PAGE_SIZE + 1;
    assert_eq!(local.handoff_batch(&mut batch), Err(Error::InvalidArgs));
    assert!(batch.iter().all(Option::is_some));
    assert_eq!(notified.load(Ordering::Relaxed), 0);
    batch[SHARED_NET_BATCH_SIZE - 1].as_mut().unwrap().2 = 8;
    assert_eq!(
        local.handoff_batch(&mut batch).unwrap(),
        SHARED_NET_BATCH_SIZE
    );
    assert!(batch.iter().all(Option::is_none));
    assert_eq!(notified.load(Ordering::Relaxed), 1);
    for _ in 0..SHARED_NET_BATCH_SIZE {
        let token = image.call(RECEIVE, 0, [local.connection(), 0, 0]).value;
        assert_eq!(image.call(DISCARD, token, [0; 3]).status, 0);
    }
    assert_eq!(image.bytes(), 0);
}

#[ktest]
fn private_nic_batch_generation_exhaustion_is_terminal_and_keeps_owners() {
    let image = Owner::new();
    let local = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
    let scratch = NetScratch::new();
    let first = image.allocate(PAGE_SIZE);
    let second = image.allocate(PAGE_SIZE);
    image.call(REDEEM, first, [0; 3]);
    image.call(REDEEM, second, [0; 3]);
    let exhausted = (u32::MAX as u64) << 32 | second as u32 as u64;
    POOL.lock().get_mut(&(second as u32)).unwrap().token = exhausted;
    let frames = [
        NetTransmitDescriptor {
            token: first,
            payload: 8,
        },
        NetTransmitDescriptor {
            token: exhausted,
            payload: 8,
        },
    ];
    assert_eq!(
        image
            .transmit_batch(&scratch, local.connection(), &frames)
            .status,
        -abi::STATE
    );
    assert!(local.receive().unwrap().is_none());
    assert_eq!(image.call(RELEASE, first, [0; 3]).status, 0);
    assert_eq!(image.call(RELEASE, exhausted, [0; 3]).status, 0);
    assert_eq!(image.bytes(), 0);
}

#[ktest]
fn private_credit_observation_does_not_acquire_the_grant_pool() {
    let image = Owner::new();
    let local = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
    let pool = POOL.lock();
    assert!(local.can_send(PAGE_SIZE));
    let credit = local.reserve_send(PAGE_SIZE).unwrap();
    drop(credit);
    drop(pool);
    assert_eq!(image.0.net_imports.count.load(Ordering::Acquire), 0);
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.0.close();
    }
}

#[ktest]
fn private_nic_pool_keeps_general_block_and_datagram_allocations_available() {
    let image = Owner::new();
    let peer = Owner::new();
    let local = HostLocalEndpoint::bind(image.0.account.clone(), &image.0).unwrap();
    let mut nic = Vec::new();
    for _ in 0..SHARED_NET_POOL_SIZE {
        let reply = image.call(
            SHARED_NET_ALLOCATE,
            0,
            [PAGE_SIZE as u64, local.connection(), 0],
        );
        assert_eq!(reply.status, 0);
        nic.push(reply.value);
    }
    assert_eq!(
        image
            .call(
                SHARED_NET_ALLOCATE,
                0,
                [PAGE_SIZE as u64, local.connection(), 0]
            )
            .status,
        -abi::LIMIT
    );
    assert!(
        image
            .call(
                SHARED_NET_ALLOCATE,
                0,
                [(PAGE_SIZE * 2) as u64, local.connection(), 0]
            )
            .status
            < 0
    );
    let connection = Participant::connect(&image.0, &peer.0).unwrap();
    assert!(
        image
            .call(SHARED_NET_ALLOCATE, 0, [PAGE_SIZE as u64, connection, 0])
            .status
            < 0
    );
    for _ in 0..SHARED_NET_POOL_SIZE {
        local
            .allocate_net(Box::new(()))
            .unwrap()
            .handoff(local.reserve_send(PAGE_SIZE).unwrap(), 8)
            .unwrap_or_else(|_| panic!("private pool delivery failed"));
    }
    assert_eq!(
        image.0.net_imports.count.load(Ordering::Acquire),
        SHARED_NET_POOL_SIZE
    );
    // Recycled NIC ownership must not reduce ordinary incoming datagram slots.
    let inbound = peer.allocate(PAGE_SIZE);
    peer.call(REDEEM, inbound, [0; 3]);
    assert_eq!(
        peer.call(HANDOFF, inbound, [connection, READ_WRITE, 1])
            .status,
        0
    );
    let inbound = image.call(RECEIVE, 0, [connection, 0, 0]).value;
    assert_ne!(inbound, 0);
    assert_eq!(image.call(DISCARD, inbound, [0; 3]).status, 0);
    assert_eq!(image.0.imports.count.load(Ordering::Acquire), 0);
    let mut general: Vec<_> = (0..MAX_BUFFERS)
        .map(|_| image.allocate(PAGE_SIZE))
        .collect();
    assert_eq!(
        image.call(ALLOCATE, 0, [PAGE_SIZE as u64, 0, 0]).status,
        -abi::LIMIT
    );
    let block = general.pop().unwrap();
    image.call(REDEEM, block, [0; 3]);
    // Uses the actual backend ownership protocol with Owner's synthetic
    // completion adapter. Real block content is checked by the runtime suite.
    let submitted = image.call(SUBMIT, block, [0, 0, 512]);
    assert_eq!(submitted.status, 0);
    let returned = image.call(POLL, submitted.value, [0; 3]);
    assert_eq!(returned.status, 0);
    assert_ne!(returned.value, 0);
    assert_eq!(image.call(DISCARD, returned.value, [0; 3]).status, 0);
    let datagram = general.pop().unwrap();
    image.call(REDEEM, datagram, [0; 3]);
    assert_eq!(
        image
            .call(HANDOFF, datagram, [connection, READ_WRITE, 1])
            .status,
        0
    );
    let received = peer.call(RECEIVE, 0, [connection, 0, 0]).value;
    assert_ne!(received, 0);
    assert_eq!(peer.call(DISCARD, received, [0; 3]).status, 0);
    for _ in 0..SHARED_NET_POOL_SIZE {
        let token = image.call(RECEIVE, 0, [local.connection(), 0, 0]).value;
        assert_eq!(image.call(DISCARD, token, [0; 3]).status, 0);
    }
    for token in general.into_iter().chain(nic) {
        assert_eq!(image.call(DISCARD, token, [0; 3]).status, 0);
    }
    assert_eq!(image.bytes(), 0);
    local.close();
    assert!(
        image
            .call(
                SHARED_NET_ALLOCATE,
                0,
                [PAGE_SIZE as u64, local.connection(), 0]
            )
            .status
            < 0
    );
}

#[ktest]
fn device_rejection_preserves_the_original_grant_and_device_namespace() {
    use super::super::ZeroCopyBlockInfo;

    let owner = Owner::new();
    let token = owner.allocate(PAGE_SIZE);
    let mapping = owner.call(REDEEM, token, [0; 3]);
    let info = ZeroCopyBlockInfo {
        capacity_bytes: 4096,
        read_only: true,
    };
    let query = |operation, token, args| {
        dispatch_device(
            &owner.0,
            operation,
            token,
            args,
            |id| (id == 0).then_some(info),
            |_| panic!("device query must not allocate"),
            |_, _| panic!("rejected request reached the backend"),
        )
    };
    let found = query(BLOCK_INFO, 0, [0, 0, 0]);
    assert_eq!((found.status, found.value), (DEVICE_READ_ONLY, 4096));
    assert_eq!(query(BLOCK_INFO, 0, [1, 0, 0]).value, 0);
    for args in [
        [1, 0, 512],                // A copying MMIO slot does not authorize this device.
        [0, 0, 512],                // Disk write on a read-only attachment.
        [0, 1, (1 << 32) | 512],    // Misaligned offset.
        [0, 4096, (1 << 32) | 512], // Past the device's end.
        [0, 0, (1 << 32) | 511],    // Misaligned length.
        [0, 0, (2 << 32) | 512],    // Unknown direction.
    ] {
        assert!(query(SUBMIT, token, args).status < 0);
    }
    // All failed requests preserve both the active generation and its storage.
    assert_eq!(owner.call(RELEASE, token, [0; 3]).status, 0);
    assert_ne!(mapping.value, 0);
    assert_eq!(owner.bytes(), 0);
}

#[ktest]
fn handoff_preserves_storage_and_sender_charge_after_sender_exit() {
    let sender = Owner::new();
    let receiver = Owner::new();
    let connection = Participant::connect(&sender.0, &receiver.0).unwrap();
    let token = sender.allocate(513);
    let mapping = sender.call(REDEEM, token, [0; 3]);
    assert_eq!(mapping_fields(mapping.status), (PAGE_SIZE, 513, true));
    assert_ne!(mapping.value, 0);
    assert!(receiver.call(REDEEM, token, [0; 3]).status < 0);
    assert!(sender.call(REDEEM, token, [0; 3]).status < 0);
    {
        // SAFETY: This test has the only activated grant; access ends before
        // handoff. Full capacity was initialized by DmaStream::alloc.
        let mut reader =
            unsafe { VmReader::from_kernel_space(mapping.value as *const u8, PAGE_SIZE) };
        let mut bytes = [1; PAGE_SIZE];
        reader.read(&mut VmWriter::from(&mut bytes[..]));
        assert!(bytes.iter().all(|&byte| byte == 0));
        // SAFETY: The preceding reader is no longer used; the exclusive
        // activated grant permits this scoped write before transfer.
        let mut writer = unsafe { VmWriter::from_kernel_space(mapping.value as *mut u8, 4) };
        writer.write(&mut VmReader::from(&b"data"[..]));
    }
    assert!(
        sender
            .call(HANDOFF, token, [connection + 1, READ_ONLY, 4])
            .status
            < 0
    );
    assert_eq!(
        sender
            .call(HANDOFF, token, [connection, READ_ONLY, 4])
            .status,
        0
    );
    sender.0.close();
    assert_eq!(sender.bytes(), PAGE_SIZE + RECORD_RESERVE);
    let incoming = receiver.call(RECEIVE, 0, [connection, 0, 0]).value;
    assert_ne!(incoming, 0);
    assert_ne!(incoming, token);
    assert_eq!(
        receiver.call(RECEIVE, 0, [connection, 0, 0]).value,
        incoming
    );
    let imported = receiver.call(REDEEM, incoming, [0; 3]);
    assert_eq!(imported.value, mapping.value);
    assert_eq!(mapping_fields(imported.status), (PAGE_SIZE, 4, false));
    assert_eq!(receiver.call(RECEIVE, 0, [connection, 0, 0]).value, 0);
    assert!(
        receiver
            .call(HANDOFF, incoming, [connection, READ_WRITE, 4])
            .status
            < 0
    );
    assert!(
        receiver
            .call(SUBMIT, incoming, [0, 0, (DEVICE_WRITE as u64) << 32 | 4])
            .status
            < 0
    );
    assert!(receiver.call(SUBMIT, incoming, [0, 0, 5]).status < 0);
    // A read-only device operation cannot erase the original payload length,
    // including when completion reports zero transferred bytes.
    let request = receiver.call(SUBMIT, incoming, [0, 0, 4]);
    assert_eq!(request.status, 0);
    let returned = receiver.call(POLL, request.value, [0; 3]);
    assert_ne!(returned.value, 0);
    let restored = receiver.call(REDEEM, returned.value, [0; 3]);
    assert_eq!(restored.value, imported.value);
    assert_eq!(mapping_fields(restored.status), (PAGE_SIZE, 4, false));
    assert_eq!(receiver.call(RELEASE, returned.value, [0; 3]).status, 0);
    assert_eq!(sender.bytes(), 0);
    assert_eq!(receiver.0.imports.bytes.load(Ordering::Acquire), 0);
    assert!(receiver.call(RELEASE, incoming, [0; 3]).status < 0);
}

#[ktest]
fn cancellation_and_completion_do_not_return_storage_while_a_callback_holds_it() {
    let owner = Owner::new();
    let token = owner.allocate(PAGE_SIZE);
    let original = owner.call(REDEEM, token, [0; 3]).value;
    let pending = RefCell::new(None);
    let request = dispatch(
        &owner.0,
        SUBMIT,
        token,
        [0, 0, (DEVICE_WRITE as u64) << 32 | 512],
        |_| Ok(Box::new(())),
        |buffer, request| {
            assert_eq!(request.len, 512);
            *pending.borrow_mut() = Some(Arc::new(buffer));
        },
    );
    assert_eq!(request.status, 0);
    assert_ne!(request.value, token);
    let backend = pending.borrow_mut().take().unwrap();
    let callback = backend.clone();
    assert_eq!(owner.call(CANCEL, request.value, [0; 3]).status, 0);
    assert!(backend.cancel_requested());
    backend.complete(0, 512).unwrap();
    assert!(backend.complete(0, 512).is_err());
    assert_eq!(owner.call(POLL, request.value, [0; 3]).value, 0);
    drop(backend);
    assert_eq!(owner.call(POLL, request.value, [0; 3]).value, 0);
    assert!(owner.call(RELEASE, token, [0; 3]).status < 0);
    drop(callback);
    let returned = owner.call(POLL, request.value, [0; 3]);
    assert_eq!(returned.status, 0);
    assert_ne!(returned.value, request.value);
    assert_ne!(returned.value, 0);
    assert!(owner.call(POLL, request.value, [0; 3]).status < 0);
    let mapping = owner.call(REDEEM, returned.value, [0; 3]);
    assert_eq!(mapping.value, original);
    assert_eq!(mapping_fields(mapping.status).1, 512);
    owner.call(RELEASE, returned.value, [0; 3]);
    assert_eq!(owner.bytes(), 0);
}

#[ktest]
fn dying_submitter_retains_backend_storage_without_a_return_grant() {
    let owner = Owner::new();
    let token = owner.allocate(PAGE_SIZE);
    owner.call(REDEEM, token, [0; 3]);
    let pending = RefCell::new(None);
    let request = dispatch(
        &owner.0,
        SUBMIT,
        token,
        [0, 0, 512],
        |_| Ok(Box::new(())),
        |buffer, _| *pending.borrow_mut() = Some(buffer),
    );
    assert_eq!(request.status, 0);
    owner.0.close();
    assert_eq!(owner.bytes(), PAGE_SIZE + RECORD_RESERVE);
    let buffer = pending.borrow_mut().take().unwrap();
    assert!(buffer.complete(0, 513).is_err());
    buffer.complete(-abi::INVALID, 0).unwrap();
    drop(buffer);
    assert_eq!(owner.bytes(), 0);
    assert!(!POOL.lock().contains_key(&(request.value as u32)));
}

#[ktest]
fn unredeemed_grants_are_bounded_and_recycled_tokens_remain_invalid() {
    let owner = Owner::new();
    let tokens: Vec<_> = (0..MAX_BUFFERS).map(|_| owner.allocate(1)).collect();
    assert!(owner.call(ALLOCATE, 0, [1, 0, 0]).status < 0);
    assert_eq!(owner.bytes(), MAX_BUFFERS * (PAGE_SIZE + RECORD_RESERVE));
    let stale = tokens[0];
    assert_eq!(owner.call(DISCARD, stale, [0; 3]).status, 0);
    let current = owner.allocate(1);
    assert_ne!(stale, current);
    assert!(owner.call(REDEEM, stale, [0; 3]).status < 0);
    owner.0.close();
    assert_eq!(owner.bytes(), 0);
    assert_eq!(owner.0.allocations.count.load(Ordering::Acquire), 0);
}

#[ktest]
fn dropping_a_request_retains_dma_until_the_last_backend_access_ends() {
    let owner = Owner::new();
    let token = owner.allocate(PAGE_SIZE);
    owner.call(REDEEM, token, [0; 3]);
    let pending = RefCell::new(None);
    let request = dispatch(
        &owner.0,
        SUBMIT,
        token,
        [0, 0, 512],
        |_| Ok(Box::new(())),
        |buffer, _| *pending.borrow_mut() = Some(buffer),
    );
    let buffer = pending.borrow_mut().take().unwrap();
    assert_eq!(owner.call(ABANDON, request.value, [0; 3]).status, 0);
    assert!(buffer.cancel_requested());
    assert_eq!(owner.bytes(), PAGE_SIZE + RECORD_RESERVE);
    buffer.complete(-abi::STATE, 0).unwrap();
    drop(buffer);
    assert_eq!(owner.bytes(), 0);
    assert!(!POOL.lock().contains_key(&(request.value as u32)));
}

#[ktest]
fn receiver_credit_rejection_preserves_the_senders_active_grant() {
    let sender = Owner::new();
    let receiver = Owner::new();
    let other = Owner::new();
    let connection = Participant::connect(&sender.0, &receiver.0).unwrap();
    let other_connection = Participant::connect(&other.0, &receiver.0).unwrap();
    for _ in 0..MAX_BUFFERS {
        let token = sender.allocate(1);
        sender.call(REDEEM, token, [0; 3]);
        assert_eq!(
            sender
                .call(HANDOFF, token, [connection, READ_ONLY, 1])
                .status,
            0
        );
    }
    let token = other.allocate(1);
    other.call(REDEEM, token, [0; 3]);
    assert!(
        other
            .call(HANDOFF, token, [other_connection, READ_ONLY, 1])
            .status
            < 0
    );
    assert_eq!(other.bytes(), PAGE_SIZE + RECORD_RESERVE);
    let incoming = receiver.call(RECEIVE, 0, [connection, 0, 0]).value;
    assert_eq!(receiver.call(DISCARD, incoming, [0; 3]).status, 0);
    // The rejected wrapper's original token is still active and usable.
    assert_eq!(
        other
            .call(HANDOFF, token, [other_connection, READ_ONLY, 1])
            .status,
        0
    );
    receiver.0.close();
    assert_eq!(sender.bytes(), 0);
    assert_eq!(other.bytes(), 0);
}

#[ktest]
fn exhausted_generations_reject_transfer_without_losing_the_active_grant() {
    let owner = Owner::new();
    let receiver = Owner::new();
    let connection = Participant::connect(&owner.0, &receiver.0).unwrap();
    let original = owner.allocate(1);
    owner.call(REDEEM, original, [0; 3]);
    let slot = original as u32;
    let exhausted = (u32::MAX as u64) << 32 | slot as u64;
    // This isolated record has no live accessor. Exercise the real wrap
    // boundary without billions of accepted transfers.
    POOL.lock().get_mut(&slot).unwrap().token = exhausted;
    assert!(
        owner
            .call(HANDOFF, exhausted, [connection, READ_ONLY, 1])
            .status
            < 0
    );
    assert_eq!(receiver.0.imports.count.load(Ordering::Acquire), 0);
    assert!(owner.call(RELEASE, original, [0; 3]).status < 0);
    assert_eq!(owner.call(RELEASE, exhausted, [0; 3]).status, 0);
    assert_eq!(owner.bytes(), 0);
}

#[ktest]
fn external_charge_outlives_the_sender_until_the_import_is_discarded() {
    struct Observe(Arc<AtomicUsize>);
    impl Drop for Observe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Release);
        }
    }
    let owner = Owner::new();
    let receiver = Owner::new();
    let released = Arc::new(AtomicUsize::new(0));
    let connection = Participant::connect(&owner.0, &receiver.0).unwrap();
    let token = dispatch(
        &owner.0,
        ALLOCATE,
        0,
        [1, 0, 0],
        |_| Ok(Box::new(Observe(released.clone()))),
        |_, _| panic!("allocation cannot submit I/O"),
    )
    .value;
    assert_ne!(token, 0);
    owner.call(REDEEM, token, [0; 3]);
    assert_eq!(
        owner
            .call(HANDOFF, token, [connection, READ_ONLY, 1])
            .status,
        0
    );
    owner.0.close();
    assert_eq!(released.load(Ordering::Acquire), 0);
    let incoming = receiver.call(RECEIVE, 0, [connection, 0, 0]).value;
    receiver.call(DISCARD, incoming, [0; 3]);
    assert_eq!(released.load(Ordering::Acquire), 1);
    assert_eq!(owner.bytes(), 0);
}
