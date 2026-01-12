// SPDX-License-Identifier: MPL-2.0

//! Per-vCPU packet queues for FrameVsock backend.
//!
//! Uses MPSC ring buffers for high-performance Host ↔ Guest communication.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use aster_framevisor_exchangeable::RRef;
use aster_framevsock::{
    ControlPacket, DataPacket, flow_control::MAX_PENDING_PACKETS, notify::InterruptStrategy,
    ring::PacketRingBuffer, trace, tuning,
};
// ============================================================================
// Constants
// ============================================================================

/// Maximum data packets per vCPU queue (must be power of 2).
///
/// Keep this aligned with the receive credit window to avoid queue overflow
/// when the sender uses very small packets (e.g., 64B).
const MAX_DATA_QUEUE_SIZE: usize = MAX_PENDING_PACKETS;

/// Maximum control packets per vCPU queue (must be power of 2)
const MAX_CONTROL_QUEUE_SIZE: usize = 1024;

// ============================================================================
// Per-vCPU Queues
// ============================================================================

/// Per-vCPU packet queues for Host → Guest communication.
///
/// Each vCPU has its own set of MPSC ring buffers to avoid contention.
/// Packets are enqueued by the backend when Host sends to Guest,
/// and dequeued by the Frontend Driver's IRQ handler.
///
/// # Performance
///
/// Uses `PacketRingBuffer` which provides near lock-free performance
/// in SPSC scenarios - producer and consumer access different slots.
pub struct VcpuQueues {
    /// Control packet queue (connection management)
    control: PacketRingBuffer<ControlPacket>,
    /// Data packet queue (payload transfer)
    data: PacketRingBuffer<DataPacket>,
    /// IRQ coalescing strategy (per vCPU)
    irq_strategy: InterruptStrategy,
    /// Last observed global IRQ tuning epoch.
    irq_config_epoch: AtomicU64,
    /// Stats: data packets enqueued
    data_push_count: AtomicU64,
    /// Stats: control packets enqueued
    control_push_count: AtomicU64,
    /// Stats: data packets dequeued
    data_pop_count: AtomicU64,
    /// Stats: control packets dequeued
    control_pop_count: AtomicU64,
}

/// Snapshot of per-vCPU queue stats.
#[derive(Debug, Clone, Copy)]
pub struct VcpuQueueStats {
    pub data_push_count: u64,
    pub control_push_count: u64,
    pub data_pop_count: u64,
    pub control_pop_count: u64,
}

impl VcpuQueues {
    /// Create a new set of queues for a vCPU.
    ///
    /// Pre-allocates ring buffers with fixed capacity.
    pub fn new() -> Self {
        let config = tuning::irq_config();
        Self {
            control: PacketRingBuffer::new(MAX_CONTROL_QUEUE_SIZE),
            data: PacketRingBuffer::new(MAX_DATA_QUEUE_SIZE),
            irq_strategy: InterruptStrategy::with_time_threshold(
                config.batch_threshold(),
                config.time_threshold_us(),
            ),
            irq_config_epoch: AtomicU64::new(config.epoch()),
            data_push_count: AtomicU64::new(0),
            control_push_count: AtomicU64::new(0),
            data_pop_count: AtomicU64::new(0),
            control_pop_count: AtomicU64::new(0),
        }
    }

    /// Push a data packet to the queue.
    ///
    /// Returns `Err` with the packet if queue is full.
    #[inline]
    pub fn push_data(&self, packet: RRef<DataPacket>) -> Result<(), RRef<DataPacket>> {
        let _trace = trace::TraceGuard::new(&trace::FRAMEVISOR_QUEUE_PUSH_DATA);
        match self.data.push(packet) {
            Ok(()) => {
                self.data_push_count.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(packet) => Err(packet),
        }
    }

    /// Push multiple data packets at once with optimized single-CAS reservation.
    ///
    /// Returns (success_count, remaining_packets) where remaining_packets
    /// contains packets that couldn't be pushed due to capacity limits.
    #[inline]
    pub fn push_data_batch(
        &self,
        packets: Vec<RRef<DataPacket>>,
    ) -> (usize, Vec<RRef<DataPacket>>) {
        let _trace = trace::TraceGuard::new(&trace::FRAMEVISOR_QUEUE_PUSH_DATA);
        let (count, remaining) = self.data.push_batch_optimized(packets);
        if count > 0 {
            self.data_push_count
                .fetch_add(count as u64, Ordering::Relaxed);
        }
        (count, remaining)
    }

    /// Push a control packet to the queue.
    ///
    /// Returns `Err` with the packet if queue is full.
    #[inline]
    pub fn push_control(&self, packet: RRef<ControlPacket>) -> Result<(), RRef<ControlPacket>> {
        let _trace = trace::TraceGuard::new(&trace::FRAMEVISOR_QUEUE_PUSH_CONTROL);
        match self.control.push(packet) {
            Ok(()) => {
                self.control_push_count.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(packet) => Err(packet),
        }
    }

    /// Pop a data packet from the queue.
    #[inline]
    pub fn pop_data(&self) -> Option<RRef<DataPacket>> {
        let _trace = trace::TraceGuard::new(&trace::FRAMEVISOR_QUEUE_POP_DATA);
        let packet = self.data.pop();
        if packet.is_some() {
            self.data_pop_count.fetch_add(1, Ordering::Relaxed);
        }
        packet
    }

    /// Pop multiple data packets from the queue.
    #[inline]
    pub fn pop_data_batch(&self, max_count: usize) -> Vec<RRef<DataPacket>> {
        let _trace = trace::TraceGuard::new(&trace::FRAMEVISOR_QUEUE_POP_DATA);
        let packets = self.data.pop_batch(max_count);
        if !packets.is_empty() {
            self.data_pop_count
                .fetch_add(packets.len() as u64, Ordering::Relaxed);
        }
        packets
    }

    /// Pop a control packet from the queue.
    #[inline]
    pub fn pop_control(&self) -> Option<RRef<ControlPacket>> {
        let _trace = trace::TraceGuard::new(&trace::FRAMEVISOR_QUEUE_POP_CONTROL);
        let packet = self.control.pop();
        if packet.is_some() {
            self.control_pop_count.fetch_add(1, Ordering::Relaxed);
        }
        packet
    }

    /// Pop multiple control packets from the queue.
    #[inline]
    pub fn pop_control_batch(&self, max_count: usize) -> Vec<RRef<ControlPacket>> {
        let _trace = trace::TraceGuard::new(&trace::FRAMEVISOR_QUEUE_POP_CONTROL);
        let packets = self.control.pop_batch(max_count);
        if !packets.is_empty() {
            self.control_pop_count
                .fetch_add(packets.len() as u64, Ordering::Relaxed);
        }
        packets
    }

    /// Update IRQ coalescing thresholds from the global config.
    #[inline]
    pub fn refresh_irq_strategy(&self) {
        let config = tuning::irq_config();
        let epoch = config.epoch();
        if self.irq_config_epoch.load(Ordering::Relaxed) == epoch {
            return;
        }
        self.irq_strategy
            .set_thresholds(config.batch_threshold(), config.time_threshold_us());
        self.irq_config_epoch.store(epoch, Ordering::Relaxed);
    }

    /// Decide whether to inject IRQ for this event.
    #[inline]
    pub fn should_inject_irq(
        &self,
        is_urgent: bool,
        has_waiters: bool,
        current_time_ns: u64,
    ) -> bool {
        let _trace = trace::TraceGuard::new(&trace::FRAMEVISOR_QUEUE_SHOULD_INJECT_IRQ);
        self.irq_strategy
            .should_inject_with_time(is_urgent, has_waiters, current_time_ns)
    }

    /// Check if there are pending data packets.
    #[inline]
    pub fn has_pending_data(&self) -> bool {
        self.data.has_pending()
    }

    /// Check if there are pending control packets.
    #[inline]
    pub fn has_pending_control(&self) -> bool {
        self.control.has_pending()
    }

    /// Get the number of pending data packets.
    #[inline]
    pub fn data_queue_len(&self) -> usize {
        self.data.len()
    }

    /// Get the reserved length of data queue (includes in-flight producer slots).
    ///
    /// This matches the queue-full check used by push path.
    #[inline]
    pub fn data_queue_reserved_len(&self) -> usize {
        self.data.reserved_len()
    }

    /// Get the number of pending control packets.
    #[inline]
    pub fn control_queue_len(&self) -> usize {
        self.control.len()
    }

    /// Snapshot current queue stats.
    #[inline]
    pub fn stats(&self) -> VcpuQueueStats {
        VcpuQueueStats {
            data_push_count: self.data_push_count.load(Ordering::Relaxed),
            control_push_count: self.control_push_count.load(Ordering::Relaxed),
            data_pop_count: self.data_pop_count.load(Ordering::Relaxed),
            control_pop_count: self.control_pop_count.load(Ordering::Relaxed),
        }
    }
}

impl Default for VcpuQueues {
    fn default() -> Self {
        Self::new()
    }
}
