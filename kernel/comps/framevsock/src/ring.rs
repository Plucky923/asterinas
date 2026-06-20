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
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use exchangeable::{DomainId, Exchangeable, RRef};
use spin::Mutex;

use crate::trace;

// ============================================================================
// Debug Statistics
// ============================================================================

/// Debug statistics for ring buffer operations
pub struct RingDebugStats {
    /// Total push operations
    pub push_count: AtomicU64,
    /// Total pop operations
    pub pop_count: AtomicU64,
    /// Push CAS retries (reservation conflicts)
    pub push_cas_retries: AtomicU64,
    /// Pop CAS retries (unused for single-consumer)
    pub pop_cas_retries: AtomicU64,
    /// Pop returned None (slot was empty after reservation - indicates bug)
    pub pop_slot_empty: AtomicU64,
    /// Push failed (queue full)
    pub push_full: AtomicU64,
    /// Push reserved a slot but packet preparation failed.
    pub push_prepare_failed: AtomicU64,
    /// Pop failed (queue empty)
    pub pop_empty: AtomicU64,
    /// Pop skipped a reserved slot that intentionally carried no packet.
    pub pop_hole: AtomicU64,
    /// Pop had to wait for producer (should be 0 with publish ordering)
    pub pop_wait_producer: AtomicU64,
}

impl RingDebugStats {
    pub const fn new() -> Self {
        Self {
            push_count: AtomicU64::new(0),
            pop_count: AtomicU64::new(0),
            push_cas_retries: AtomicU64::new(0),
            pop_cas_retries: AtomicU64::new(0),
            pop_slot_empty: AtomicU64::new(0),
            push_full: AtomicU64::new(0),
            push_prepare_failed: AtomicU64::new(0),
            pop_empty: AtomicU64::new(0),
            pop_hole: AtomicU64::new(0),
            pop_wait_producer: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> RingDebugSnapshot {
        RingDebugSnapshot {
            push_count: self.push_count.load(Ordering::Relaxed),
            pop_count: self.pop_count.load(Ordering::Relaxed),
            push_cas_retries: self.push_cas_retries.load(Ordering::Relaxed),
            pop_cas_retries: self.pop_cas_retries.load(Ordering::Relaxed),
            pop_slot_empty: self.pop_slot_empty.load(Ordering::Relaxed),
            push_full: self.push_full.load(Ordering::Relaxed),
            push_prepare_failed: self.push_prepare_failed.load(Ordering::Relaxed),
            pop_empty: self.pop_empty.load(Ordering::Relaxed),
            pop_hole: self.pop_hole.load(Ordering::Relaxed),
            pop_wait_producer: self.pop_wait_producer.load(Ordering::Relaxed),
        }
    }

    pub fn reset(&self) {
        self.push_count.store(0, Ordering::Relaxed);
        self.pop_count.store(0, Ordering::Relaxed);
        self.push_cas_retries.store(0, Ordering::Relaxed);
        self.pop_cas_retries.store(0, Ordering::Relaxed);
        self.pop_slot_empty.store(0, Ordering::Relaxed);
        self.push_full.store(0, Ordering::Relaxed);
        self.push_prepare_failed.store(0, Ordering::Relaxed);
        self.pop_empty.store(0, Ordering::Relaxed);
        self.pop_hole.store(0, Ordering::Relaxed);
        self.pop_wait_producer.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone)]
pub struct RingDebugSnapshot {
    pub push_count: u64,
    pub pop_count: u64,
    pub push_cas_retries: u64,
    pub pop_cas_retries: u64,
    pub pop_slot_empty: u64,
    pub push_full: u64,
    pub push_prepare_failed: u64,
    pub pop_empty: u64,
    pub pop_hole: u64,
    pub pop_wait_producer: u64,
}

/// Global debug stats for data packet ring
pub static DATA_RING_STATS: RingDebugStats = RingDebugStats::new();

/// Global debug stats for control packet ring
pub static CONTROL_RING_STATS: RingDebugStats = RingDebugStats::new();

/// Get debug stats snapshot
pub fn get_debug_stats() -> (RingDebugSnapshot, RingDebugSnapshot) {
    (DATA_RING_STATS.snapshot(), CONTROL_RING_STATS.snapshot())
}

/// Reset debug stats
pub fn reset_debug_stats() {
    DATA_RING_STATS.reset();
    CONTROL_RING_STATS.reset();
}

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
    /// Debug statistics
    stats: &'static RingDebugStats,
}

impl<T: Exchangeable + 'static> PacketRingBuffer<T> {
    /// Create a new PacketRingBuffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self::new_with_stats(capacity, &DATA_RING_STATS)
    }

    /// Create a new PacketRingBuffer with custom debug stats.
    pub fn new_with_stats(capacity: usize, stats: &'static RingDebugStats) -> Self {
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
            stats,
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
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

    #[inline]
    pub fn is_full(&self) -> bool {
        self.reserved_len() >= self.capacity
    }

    #[inline]
    pub fn free_len(&self) -> usize {
        self.capacity.saturating_sub(self.reserved_len())
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
        let _trace = trace::TraceGuard::new(&trace::RING_PUSH);
        let mut packet = Some(packet);
        let mut prepare_packet = Some(prepare_packet);

        loop {
            let head = self.head.load(Ordering::Relaxed);
            let tail = self.tail.load(Ordering::Acquire);

            // Check if full (include in-flight reservations)
            if head.wrapping_sub(tail) >= self.capacity {
                self.stats.push_full.fetch_add(1, Ordering::Relaxed);
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
                self.stats.push_cas_retries.fetch_add(1, Ordering::Relaxed);
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
                    self.stats
                        .push_prepare_failed
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(packet);
                }
            };
            *self.slots[index].lock() = Some(RingSlot::Packet(packet));

            self.publish_reserved_slot(head);

            self.stats.push_count.fetch_add(1, Ordering::Relaxed);
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
        let _trace = trace::TraceGuard::new(&trace::RING_POP);
        self.pop_internal()
    }

    /// Internal pop without tracing - used by pop_batch to avoid nested traces.
    #[inline]
    fn pop_internal(&self) -> Option<RRef<T>> {
        loop {
            let tail = self.tail.load(Ordering::Relaxed);
            let published = self.published.load(Ordering::Acquire);

            if tail == published {
                self.stats.pop_empty.fetch_add(1, Ordering::Relaxed);
                return None;
            }

            // Single consumer: read slot before advancing tail.
            let index = tail & self.mask;
            let slot = self.slots[index].lock().take();

            // Publish tail after data is removed to avoid producer overwrite.
            self.tail.store(tail.wrapping_add(1), Ordering::Release);

            match slot {
                Some(RingSlot::Packet(packet)) => {
                    self.stats.pop_count.fetch_add(1, Ordering::Relaxed);
                    return Some(packet);
                }
                Some(RingSlot::Hole) => {
                    self.stats.pop_hole.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                None => {
                    // This should never happen with correct publish ordering.
                    self.stats.pop_slot_empty.fetch_add(1, Ordering::Relaxed);
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
    /// Uses internal pop without individual tracing to reduce overhead.
    /// The batch operation is traced as a whole.
    pub fn pop_batch(&self, max_count: usize) -> Vec<RRef<T>> {
        let _trace = trace::TraceGuard::new(&trace::RING_POP_BATCH);

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

    #[inline]
    pub fn peek(&self) -> bool {
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

    use exchangeable::{
        RRefId, RRefMetadata, RRefRegistryOps, enter_domain, init_registry,
    };
    use spin::Once;

    use super::*;

    static FAILED_OWNERSHIP_STATS: RingDebugStats = RingDebugStats::new();
    static PREPARE_FAILURE_STATS: RingDebugStats = RingDebugStats::new();
    static SUCCESSFUL_TRANSFER_STATS: RingDebugStats = RingDebugStats::new();

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
        static INIT: Once<()> = Once::new();
        INIT.call_once(|| init_registry(Arc::new(TestRegistry::new())));
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
        FAILED_OWNERSHIP_STATS.reset();
        let _guard = enter_domain(DomainId::Host);
        let ring = PacketRingBuffer::<u64>::new_with_stats(2, &FAILED_OWNERSHIP_STATS);
        let packet = RRef::new_with_owner(7, DomainId::Service(1));

        let packet = match ring.push_transfer_to(packet, DomainId::Host) {
            Ok(()) => panic!("push must fail when current domain does not own the RRef"),
            Err(packet) => packet,
        };

        assert_eq!(packet.owner(), DomainId::Service(1));
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.reserved_len(), 0);
        assert!(ring.pop().is_none());

        let stats = ring.stats.snapshot();
        assert_eq!(stats.push_count, 0);
        assert_eq!(stats.push_prepare_failed, 0);
        assert_eq!(stats.pop_hole, 0);
    }

    #[test]
    fn failed_prepare_publishes_hole_and_returns_packet() {
        ensure_test_registry();
        PREPARE_FAILURE_STATS.reset();
        let _guard = enter_domain(DomainId::Host);
        let ring = PacketRingBuffer::<u64>::new_with_stats(2, &PREPARE_FAILURE_STATS);
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

        let stats = ring.stats.snapshot();
        assert_eq!(stats.push_count, 0);
        assert_eq!(stats.push_prepare_failed, 1);
        assert_eq!(stats.pop_hole, 1);
        assert_eq!(stats.pop_count, 0);
    }

    #[test]
    fn successful_transfer_publishes_packet_for_new_owner() {
        ensure_test_registry();
        SUCCESSFUL_TRANSFER_STATS.reset();
        let _guard = enter_domain(DomainId::Host);
        let ring = PacketRingBuffer::<u64>::new_with_stats(2, &SUCCESSFUL_TRANSFER_STATS);
        let packet = RRef::new_with_owner(11, DomainId::Host);

        assert!(ring.push_transfer_to(packet, DomainId::Service(1)).is_ok());
        let packet = ring.pop().expect("transferred packet should be visible");
        assert_eq!(packet.owner(), DomainId::Service(1));
        assert!(packet.try_get().is_none());

        let _guest_guard = enter_domain(DomainId::Service(1));
        assert_eq!(*packet.get(), 11);
    }
}
