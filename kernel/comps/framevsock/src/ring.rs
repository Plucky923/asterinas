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

use exchangeable::{Exchangeable, RRef};
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
    /// Pop failed (queue empty)
    pub pop_empty: AtomicU64,
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
            pop_empty: AtomicU64::new(0),
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
            pop_empty: self.pop_empty.load(Ordering::Relaxed),
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
        self.pop_empty.store(0, Ordering::Relaxed);
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
    pub pop_empty: u64,
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
const CACHE_LINE_SIZE: usize = 64;

/// Cache-line padded wrapper to prevent false sharing.
#[repr(C, align(64))]
struct CachePadded<T> {
    value: T,
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
pub struct PacketRingBuffer<T: Exchangeable> {
    /// Per-slot storage
    slots: Box<[Mutex<Option<RRef<T>>>]>,
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

impl<T: Exchangeable> PacketRingBuffer<T> {
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

    /// Push a packet into the buffer.
    ///
    /// Multi-producer safe. Reserves a slot via CAS, writes data,
    /// then spin-waits for `published == head` before publishing `head + 1`.
    #[inline]
    pub fn push(&self, packet: RRef<T>) -> Result<(), RRef<T>> {
        let _trace = trace::TraceGuard::new(&trace::RING_PUSH);
        let mut packet = Some(packet);

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
            *self.slots[index].lock() = packet.take();

            // Publish in order: wait for our turn, then advance published
            while self.published.load(Ordering::Acquire) != head {
                core::hint::spin_loop();
            }
            self.published
                .store(head.wrapping_add(1), Ordering::Release);

            self.stats.push_count.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
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
        let tail = self.tail.load(Ordering::Relaxed);
        let published = self.published.load(Ordering::Acquire);

        if tail == published {
            self.stats.pop_empty.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // Single consumer: read slot before advancing tail
        let index = tail & self.mask;
        let packet = self.slots[index].lock().take();

        if packet.is_some() {
            self.stats.pop_count.fetch_add(1, Ordering::Relaxed);
        } else {
            // This should never happen with correct publish ordering
            self.stats.pop_slot_empty.fetch_add(1, Ordering::Relaxed);
            log::error!(
                "[RingBuffer] BUG: slot {} empty but published! tail={}, published={}",
                index,
                tail,
                published
            );
        }

        // Publish tail after data is removed to avoid producer overwrite
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        packet
    }

    /// Push multiple packets at once with optimized single-CAS reservation.
    ///
    /// This is more efficient than calling push() in a loop because:
    /// 1. Single CAS operation reserves all slots at once
    /// 2. All packets are written before marking ready
    /// 3. Reduces contention for multi-producer scenarios
    ///
    /// Returns (success_count, remaining_packets) where remaining_packets
    /// contains packets that couldn't be pushed due to capacity limits.
    pub fn push_batch_optimized(&self, mut packets: Vec<RRef<T>>) -> (usize, Vec<RRef<T>>) {
        let _trace = trace::TraceGuard::new(&trace::RING_PUSH_BATCH);

        if packets.is_empty() {
            return (0, packets);
        }

        let batch_size = packets.len();

        loop {
            let head = self.head.load(Ordering::Relaxed);
            let tail = self.tail.load(Ordering::Acquire);

            // Calculate available space
            let used = head.wrapping_sub(tail);
            let available = self.capacity.saturating_sub(used);

            if available == 0 {
                self.stats.push_full.fetch_add(1, Ordering::Relaxed);
                return (0, packets);
            }

            // Determine how many we can push
            let to_push = batch_size.min(available);

            // Try to reserve all slots at once with single CAS
            if self
                .head
                .compare_exchange_weak(
                    head,
                    head.wrapping_add(to_push),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_err()
            {
                self.stats.push_cas_retries.fetch_add(1, Ordering::Relaxed);
                core::hint::spin_loop();
                continue;
            }

            // Successfully reserved `to_push` slots [head, head + to_push)
            // Drain packets from the front and write to slots
            let mut drain_iter = packets.drain(0..to_push);
            for i in 0..to_push {
                let index = (head.wrapping_add(i)) & self.mask;
                if let Some(packet) = drain_iter.next() {
                    *self.slots[index].lock() = Some(packet);
                }
            }
            drop(drain_iter);

            // Publish in order: wait for our turn, then advance published past all slots
            while self.published.load(Ordering::Acquire) != head {
                core::hint::spin_loop();
            }
            self.published
                .store(head.wrapping_add(to_push), Ordering::Release);

            self.stats
                .push_count
                .fetch_add(to_push as u64, Ordering::Relaxed);

            // packets now contains only the unpushed items (drain removed the first to_push)
            return (to_push, packets);
        }
    }

    /// Push multiple packets at once (simple version, calls push in loop).
    pub fn push_batch<I: Iterator<Item = RRef<T>>>(&self, packets: I) -> usize {
        let _trace = trace::TraceGuard::new(&trace::RING_PUSH_BATCH);
        let mut count = 0;
        for packet in packets {
            match self.push(packet) {
                Ok(()) => count += 1,
                Err(_) => break,
            }
        }
        count
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
        let entry_size = core::mem::size_of::<RRef<T>>().max(1);
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

impl<T: Exchangeable> Drop for PacketRingBuffer<T> {
    fn drop(&mut self) {
        while self.pop().is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_padded_size() {
        assert!(core::mem::size_of::<CachePadded<AtomicUsize>>() >= CACHE_LINE_SIZE);
    }

    #[test]
    fn test_cache_padded_alignment() {
        assert!(core::mem::align_of::<CachePadded<AtomicUsize>>() >= CACHE_LINE_SIZE);
    }
}
