// SPDX-License-Identifier: MPL-2.0

//! High-performance ring buffer for RRef packets.
//!
//! This module provides an optimized ring buffer for FrameVsock communication.
//! Designed for MPSC (Multi-Producer Single-Consumer) without external locks.
//!
//! # Design
//!
//! - **MPSC optimized**: Multiple producers reserve slots via atomic head
//! - **Two-phase publish**: Reserve -> write -> publish in order
//! - **Per-slot Mutex**: Each slot has its own lock for data access
//! - **Cache-line aligned**: Counters are padded to prevent false sharing
//! - **Power-of-two capacity**: Fast modulo via bitmask
//!
//! # Correctness
//!
//! The key to correctness is the ordering:
//! 1. Producer reserves a slot by advancing `head` (ticket)
//! 2. Producer writes data to slot[head]
//! 3. Producer waits for `published == head`, then publishes `head + 1`
//! 4. Consumer reads `published` with Acquire ordering
//! 5. Consumer reads slot[tail], then advances `tail`
//!
//! This design achieves high performance while remaining 100% safe Rust.

use alloc::{boxed::Box, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use aster_framevisor_exchangeable::{DomainId, Exchangeable, RRef};
use spin::Mutex;

/// Cache line size for x86_64/aarch64
#[cfg(test)]
const CACHE_LINE_SIZE: usize = 64;

/// Cache-line padded wrapper to prevent false sharing.
#[repr(C, align(64))]
struct CachePadded<T> {
    value: T,
}

enum RingSlot<T: Exchangeable + 'static> {
    Packet(RRef<T>),
    Hole,
}

impl<T> CachePadded<T> {
    const fn new(value: T) -> Self {
        Self { value }
    }
}

impl<T> core::ops::Deref for CachePadded<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// High-performance ring buffer for `RRef<T>` packets.
///
/// Optimized for MPSC (multi-producer, single-consumer).
/// Uses two-phase publish: producers reserve via CAS on `head`, write data,
/// then spin-wait to publish in order via the global `published` counter.
pub struct PacketRingBuffer<T: Exchangeable + 'static> {
    /// Per-slot storage
    slots: Box<[Mutex<Option<RingSlot<T>>>]>,
    /// Producer reservation position (cache-line padded)
    head: CachePadded<AtomicUsize>,
    /// Published position — only slots before this are visible to consumer (cache-line padded)
    published: CachePadded<AtomicUsize>,
    /// Consumer position (cache-line padded)
    tail: CachePadded<AtomicUsize>,
    /// Capacity (must be power of 2)
    capacity: usize,
    /// Mask for fast modulo
    mask: usize,
}

impl<T: Exchangeable + 'static> PacketRingBuffer<T> {
    /// Create a new PacketRingBuffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        assert!(
            capacity.is_power_of_two(),
            "capacity must be power of two, got {}",
            capacity
        );

        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(Mutex::new(None));
        }

        Self {
            slots: slots.into_boxed_slice(),
            head: CachePadded::new(AtomicUsize::new(0)),
            published: CachePadded::new(AtomicUsize::new(0)),
            tail: CachePadded::new(AtomicUsize::new(0)),
            capacity,
            mask: capacity - 1,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        let published = self.published.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        published.wrapping_sub(tail)
    }

    #[inline]
    pub fn reserved_len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Transfers a packet to `owner` after a slot is reserved and pushes it.
    ///
    /// If the queue is full, the packet is returned without changing ownership.
    #[inline]
    pub fn push_transfer_to(&self, packet: RRef<T>, owner: DomainId) -> Result<(), RRef<T>> {
        if !packet.is_owned_by_current() {
            return Err(packet);
        }

        self.push_with(packet, |packet| {
            packet
                .try_transfer_to(owner)
                .map_err(|error| error.into_rref())
        })
    }

    #[inline]
    fn push_with<F>(&self, packet: RRef<T>, prepare_packet: F) -> Result<(), RRef<T>>
    where
        F: FnOnce(RRef<T>) -> Result<RRef<T>, RRef<T>>,
    {
        let mut packet = Some(packet);
        let mut prepare_packet = Some(prepare_packet);

        loop {
            let head = self.head.load(Ordering::Relaxed);
            let tail = self.tail.load(Ordering::Acquire);

            // Check if full (include in-flight reservations)
            if head.wrapping_sub(tail) >= self.capacity {
                let Some(packet) = packet.take() else {
                    unreachable!("ring push retries retain packet ownership");
                };
                return Err(packet);
            }

            // Reserve slot by advancing head
            if self
                .head
                .compare_exchange_weak(
                    head,
                    head.wrapping_add(1),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_err()
            {
                core::hint::spin_loop();
                continue;
            }

            // Write data to slot for our ticket
            let index = head & self.mask;
            let packet = packet.take().expect("reserved ring slot must own packet");
            let prepare_packet = prepare_packet
                .take()
                .expect("packet preparation runs exactly once after reservation");
            let packet = match prepare_packet(packet) {
                Ok(packet) => packet,
                Err(packet) => {
                    *self.slots[index].lock() = Some(RingSlot::Hole);
                    self.publish_reserved_slot(head);
                    return Err(packet);
                }
            };
            *self.slots[index].lock() = Some(RingSlot::Packet(packet));

            self.publish_reserved_slot(head);

            return Ok(());
        }
    }

    fn publish_reserved_slot(&self, head: usize) {
        // Publish in order: wait for our turn, then advance published.
        while self.published.load(Ordering::Acquire) != head {
            core::hint::spin_loop();
        }
        self.published
            .store(head.wrapping_add(1), Ordering::Release);
    }

    /// Pop a packet from the buffer (single-consumer).
    #[inline]
    pub fn pop(&self) -> Option<RRef<T>> {
        self.pop_internal()
    }

    /// Internal pop used by `pop_batch` to avoid repeated empty checks.
    #[inline]
    fn pop_internal(&self) -> Option<RRef<T>> {
        loop {
            let tail = self.tail.load(Ordering::Relaxed);
            let published = self.published.load(Ordering::Acquire);

            if tail == published {
                return None;
            }

            // Single consumer: read slot before advancing tail.
            let index = tail & self.mask;
            let slot = self.slots[index].lock().take();

            // Publish tail after data is removed to avoid producer overwrite.
            self.tail.store(tail.wrapping_add(1), Ordering::Release);

            match slot {
                Some(RingSlot::Packet(packet)) => return Some(packet),
                Some(RingSlot::Hole) => {
                    continue;
                }
                None => {
                    // This should never happen with correct publish ordering.
                    log::error!(
                        "[RingBuffer] BUG: slot {} empty but published! tail={}, published={}",
                        index,
                        tail,
                        published
                    );
                    continue;
                }
            }
        }
    }

    /// Pop multiple packets at once.
    ///
    /// Uses internal pop to reduce overhead.
    pub fn pop_batch(&self, max_count: usize) -> Vec<RRef<T>> {
        // Fast path: check if empty before allocating
        if self.is_empty() {
            return Vec::new();
        }

        // Keep temporary batch buffers within slab allocation classes.
        //
        // If capacity * size_of::<RRef<T>>() exceeds 2048 bytes, it falls back
        // to large-slot allocation, which is expensive and can cause memory
        // pressure under high-frequency small-packet workloads.
        const MAX_SLAB_SLOT_BYTES: usize = 2048;
        let entry_size = size_of::<RRef<T>>().max(1);
        let slab_safe_cap = (MAX_SLAB_SLOT_BYTES / entry_size).max(1);
        let batch_cap = max_count.min(32).min(slab_safe_cap);

        let mut result = Vec::with_capacity(batch_cap);
        for _ in 0..batch_cap {
            match self.pop_internal() {
                Some(packet) => result.push(packet),
                None => break,
            }
        }
        result
    }

    #[inline]
    pub fn has_pending(&self) -> bool {
        !self.is_empty()
    }
}

impl<T: Exchangeable + 'static> Drop for PacketRingBuffer<T> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use alloc::{collections::BTreeMap, sync::Arc};

    use aster_framevisor_exchangeable::{
        RRefId, RRefMetadata, RRefRegistryOps, enter_domain, init_registry,
    };
    use framev_sock_common::{FrameVsockAddr, FrameVsockPacket, HOST_CID};
    use spin::Once;

    use super::*;

    struct TestRegistry {
        entries: Mutex<BTreeMap<RRefId, RRefMetadata>>,
    }

    impl TestRegistry {
        fn new() -> Self {
            Self {
                entries: Mutex::new(BTreeMap::new()),
            }
        }
    }

    impl RRefRegistryOps for TestRegistry {
        fn register(&self, metadata: RRefMetadata) {
            let mut entries = self.entries.lock();
            assert!(entries.insert(metadata.id(), metadata).is_none());
        }

        fn unregister(&self, id: RRefId) -> RRefMetadata {
            self.entries.lock().remove(&id).unwrap()
        }

        fn transfer(&self, id: RRefId, current_owner: DomainId, new_owner: DomainId) -> bool {
            let mut entries = self.entries.lock();
            let Some(metadata) = entries.get_mut(&id) else {
                return false;
            };
            metadata.try_transfer_to(current_owner, new_owner)
        }

        fn begin_borrow(&self, id: RRefId) -> bool {
            let mut entries = self.entries.lock();
            let Some(metadata) = entries.get_mut(&id) else {
                return false;
            };
            metadata.begin_borrow()
        }

        fn end_borrow(&self, id: RRefId) -> bool {
            let mut entries = self.entries.lock();
            let Some(metadata) = entries.get_mut(&id) else {
                return false;
            };
            metadata.end_borrow()
        }

        fn metadata(&self, id: RRefId) -> Option<RRefMetadata> {
            self.entries.lock().get(&id).copied()
        }

        fn reclaim_domain(&self, domain: DomainId) -> Vec<RRefId> {
            let mut reclaimed = Vec::new();
            for metadata in self.entries.lock().values_mut() {
                if metadata.owner() == domain && metadata.mark_reclaim_candidate() {
                    reclaimed.push(metadata.id());
                }
            }
            reclaimed
        }
    }

    fn ensure_test_registry() {
        init_registry(Arc::new(TestRegistry::new()));
    }

    fn framevsock_packet_ref(src_port: u32) -> RRef<FrameVsockPacket> {
        RRef::new_with_owner(
            FrameVsockPacket::request(
                FrameVsockAddr::new(3, src_port),
                FrameVsockAddr::new(HOST_CID, 2048),
                4096,
                0,
            ),
            DomainId::Host,
        )
    }

    #[test]
    fn test_cache_padded_size() {
        assert!(size_of::<CachePadded<AtomicUsize>>() >= CACHE_LINE_SIZE);
    }

    #[test]
    fn test_cache_padded_alignment() {
        assert!(align_of::<CachePadded<AtomicUsize>>() >= CACHE_LINE_SIZE);
    }

    #[test]
    fn failed_transfer_without_current_ownership_does_not_publish_slot() {
        ensure_test_registry();
        let _guard = enter_domain(DomainId::Host);
        let ring = PacketRingBuffer::<u64>::new(2);
        let packet = RRef::new_with_owner(7, DomainId::Guest(1));

        let packet = match ring.push_transfer_to(packet, DomainId::Host) {
            Ok(()) => panic!("push must fail when current domain does not own the RRef"),
            Err(packet) => packet,
        };

        assert_eq!(packet.owner(), DomainId::Guest(1));
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.reserved_len(), 0);
        assert!(ring.pop().is_none());
    }

    #[test]
    fn failed_prepare_publishes_hole_and_returns_packet() {
        ensure_test_registry();
        let _guard = enter_domain(DomainId::Host);
        let ring = PacketRingBuffer::<u64>::new(2);
        let packet = RRef::new_with_owner(13, DomainId::Host);

        let packet = match ring.push_with(packet, Err) {
            Ok(()) => panic!("prepare failure must return the original packet"),
            Err(packet) => packet,
        };

        assert_eq!(packet.owner(), DomainId::Host);
        assert_eq!(*packet.get(), 13);
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.reserved_len(), 1);
        assert!(ring.pop().is_none());
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.reserved_len(), 0);
    }

    #[test]
    fn successful_transfer_publishes_packet_for_new_owner() {
        ensure_test_registry();
        let _guard = enter_domain(DomainId::Host);
        let ring = PacketRingBuffer::<u64>::new(2);
        let packet = RRef::new_with_owner(11, DomainId::Host);

        assert!(ring.push_transfer_to(packet, DomainId::Guest(1)).is_ok());
        let packet = ring.pop().expect("transferred packet should be visible");
        assert_eq!(packet.owner(), DomainId::Guest(1));
        assert!(packet.try_get().is_none());

        let _guest_guard = enter_domain(DomainId::Guest(1));
        assert_eq!(*packet.get(), 11);
    }

    #[test]
    fn framevsock_packet_ring_preserves_ownership_when_full() {
        ensure_test_registry();
        let _guard = enter_domain(DomainId::Host);
        let ring = PacketRingBuffer::<FrameVsockPacket>::new(1);

        assert!(
            ring.push_transfer_to(framevsock_packet_ref(1000), DomainId::Guest(1))
                .is_ok()
        );
        let packet = ring
            .push_transfer_to(framevsock_packet_ref(1001), DomainId::Guest(1))
            .expect_err("full queue must return unpublished packet");

        assert_eq!(packet.owner(), DomainId::Host);
        assert_eq!(packet.src_addr().port, 1001);
        assert_eq!(ring.reserved_len(), 1);
    }
}
