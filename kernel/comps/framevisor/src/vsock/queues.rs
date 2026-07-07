// SPDX-License-Identifier: MPL-2.0

//! Per-vCPU packet queues for FrameVsock backend.
//!
//! Uses MPSC ring buffers for high-performance Host ↔ Guest communication.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use aster_framevisor_exchangeable::{DomainId, RRef};
use framev_sock_common::{FrameVsockPacket, flow_control::MAX_PENDING_PACKETS};

use super::{notify::InterruptStrategy, ring::PacketRingBuffer};
use crate::sync::SpinLock;
// ============================================================================
// Constants
// ============================================================================

/// Maximum unified packets per vCPU queue (must be power of 2).
const MAX_PACKET_QUEUE_SIZE: usize = MAX_PENDING_PACKETS;

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
    /// Unified virtio-vsock semantic packet queue.
    packet: PacketRingBuffer<FrameVsockPacket>,
    /// Queue lifecycle state for VM/device start and stop.
    lifecycle: SpinLock<QueueLifecycle>,
    /// IRQ coalescing strategy (per vCPU)
    irq_strategy: InterruptStrategy,
    /// Last observed device-local IRQ coalescing epoch.
    irq_config_epoch: AtomicU64,
}

struct QueueLifecycle {
    stopped: bool,
}

impl VcpuQueues {
    /// Create a new set of queues for a vCPU.
    ///
    /// Pre-allocates ring buffers with fixed capacity.
    pub(crate) fn new(irq_config: IrqCoalescingConfig) -> Self {
        Self {
            packet: PacketRingBuffer::new(MAX_PACKET_QUEUE_SIZE),
            lifecycle: SpinLock::new(QueueLifecycle { stopped: true }),
            irq_strategy: InterruptStrategy::with_time_threshold(
                irq_config.batch_threshold(),
                irq_config.time_threshold_us(),
            ),
            irq_config_epoch: AtomicU64::new(irq_config.epoch()),
        }
    }

    /// Transfers a unified packet after queue reservation and pushes it.
    #[inline]
    pub fn push_packet_to_domain(
        &self,
        packet: RRef<FrameVsockPacket>,
        owner: DomainId,
    ) -> Result<(), RRef<FrameVsockPacket>> {
        let lifecycle = self.lifecycle.lock();
        if lifecycle.stopped {
            return Err(packet);
        }

        match self.packet.push_transfer_to(packet, owner) {
            Ok(()) => Ok(()),
            Err(packet) => Err(packet),
        }
    }

    /// Pop a unified packet from the queue.
    #[inline]
    pub fn pop_packet(&self) -> Option<RRef<FrameVsockPacket>> {
        self.packet.pop()
    }

    /// Pop multiple unified packets from the queue.
    #[inline]
    pub fn pop_packet_batch(&self, max_count: usize) -> Vec<RRef<FrameVsockPacket>> {
        self.packet.pop_batch(max_count)
    }

    /// Starts queue admission and drops stale packets from a previous VM run.
    pub(crate) fn start(&self) {
        {
            let mut lifecycle = self.lifecycle.lock();
            lifecycle.stopped = true;
        }
        self.clear_queued_packets();
        let mut lifecycle = self.lifecycle.lock();
        lifecycle.stopped = false;
    }

    /// Stops queue admission and drains packets during VM stop or device reset.
    pub(crate) fn stop_and_clear(&self) -> Option<usize> {
        {
            let mut lifecycle = self.lifecycle.lock();
            lifecycle.stopped = true;
        }

        let queue_reserved_len = self.packet_queue_reserved_len();
        self.clear_queued_packets();

        (queue_reserved_len != 0).then_some(queue_reserved_len)
    }

    fn clear_queued_packets(&self) {
        while self.pop_packet().is_some() {}
    }

    /// Updates IRQ coalescing thresholds from device-local configuration.
    #[inline]
    pub(crate) fn refresh_irq_strategy(&self, irq_config: IrqCoalescingConfig) {
        let epoch = irq_config.epoch();
        if self.irq_config_epoch.load(Ordering::Relaxed) == epoch {
            return;
        }
        self.irq_strategy
            .set_thresholds(irq_config.batch_threshold(), irq_config.time_threshold_us());
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
        self.irq_strategy
            .should_inject_with_time(is_urgent, has_waiters, current_time_ns)
    }

    /// Check if there are pending unified packets.
    #[inline]
    pub fn has_pending_packet(&self) -> bool {
        self.packet.has_pending()
    }

    /// Get the number of pending unified packets.
    #[inline]
    pub fn packet_queue_len(&self) -> usize {
        self.packet.len()
    }

    /// Get the reserved length of unified packet queue.
    #[inline]
    pub fn packet_queue_reserved_len(&self) -> usize {
        self.packet.reserved_len()
    }
}

impl Default for VcpuQueues {
    fn default() -> Self {
        Self::new(IrqCoalescingConfig::default())
    }
}

/// A snapshot of device-local IRQ coalescing policy.
#[derive(Clone, Copy)]
pub(crate) struct IrqCoalescingConfig {
    batch_threshold: u32,
    time_threshold_us: u64,
    epoch: u64,
}

impl IrqCoalescingConfig {
    pub(crate) const fn new(batch_threshold: u32, time_threshold_us: u64, epoch: u64) -> Self {
        Self {
            batch_threshold,
            time_threshold_us,
            epoch,
        }
    }

    #[inline]
    pub(crate) const fn batch_threshold(self) -> u32 {
        self.batch_threshold
    }

    #[inline]
    pub(crate) const fn time_threshold_us(self) -> u64 {
        self.time_threshold_us
    }

    #[inline]
    pub(crate) const fn epoch(self) -> u64 {
        self.epoch
    }
}

impl Default for IrqCoalescingConfig {
    fn default() -> Self {
        Self::new(1, 20, 1)
    }
}

#[cfg(ktest)]
mod tests {
    use aster_framevisor_exchangeable::enter_domain;
    use framev_sock_common::{FrameVsockAddr, FrameVsockPacket, HOST_CID};
    use host_ostd::prelude::ktest;

    use super::*;
    use crate::rref_registry;

    fn unified_packet(src_port: u32) -> RRef<FrameVsockPacket> {
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

    #[ktest]
    fn queues_reject_packets_until_started() {
        rref_registry::init();
        let _host_domain = enter_domain(DomainId::Host);
        let queues = VcpuQueues::default();
        let packet = unified_packet(1000);

        let packet = queues
            .push_packet_to_domain(packet, DomainId::Guest(1))
            .expect_err("stopped queue must return packet");
        assert_eq!(packet.owner(), DomainId::Host);
        assert_eq!(queues.packet_queue_reserved_len(), 0);

        queues.start();
        assert!(
            queues
                .push_packet_to_domain(packet, DomainId::Guest(1))
                .is_ok()
        );
        assert_eq!(queues.packet_queue_reserved_len(), 1);
    }

    #[ktest]
    fn stop_and_clear_drains_packets_and_rejects_new_pushes() {
        rref_registry::init();
        let _host_domain = enter_domain(DomainId::Host);
        let queues = VcpuQueues::default();
        queues.start();

        assert!(
            queues
                .push_packet_to_domain(unified_packet(1000), DomainId::Guest(1))
                .is_ok()
        );
        assert_eq!(queues.stop_and_clear(), Some(1));
        assert_eq!(queues.packet_queue_reserved_len(), 0);

        let packet = unified_packet(1001);
        let packet = queues
            .push_packet_to_domain(packet, DomainId::Guest(1))
            .expect_err("stopped queue must reject packets after stop");
        assert_eq!(packet.owner(), DomainId::Host);
    }

    #[ktest]
    fn unified_queue_preserves_packet_ownership_on_stop_and_full() {
        rref_registry::init();
        let _host_domain = enter_domain(DomainId::Host);
        let queues = VcpuQueues::default();

        let packet = queues
            .push_packet_to_domain(unified_packet(1000), DomainId::Guest(1))
            .expect_err("stopped queue must return unified packet");
        assert_eq!(packet.owner(), DomainId::Host);
        assert_eq!(queues.packet_queue_reserved_len(), 0);

        queues.start();
        assert!(
            queues
                .push_packet_to_domain(packet, DomainId::Guest(1))
                .is_ok()
        );
        assert_eq!(queues.packet_queue_reserved_len(), 1);
        assert_eq!(queues.stop_and_clear(), Some(1));
        assert_eq!(queues.packet_queue_reserved_len(), 0);
    }

    #[ktest]
    fn unified_queue_publish_precedes_coalesced_notification_decision() {
        rref_registry::init();
        let _host_domain = enter_domain(DomainId::Host);
        let queues = VcpuQueues::new(IrqCoalescingConfig::new(2, 100, 1));
        queues.start();

        assert!(
            queues
                .push_packet_to_domain(unified_packet(1000), DomainId::Guest(1))
                .is_ok()
        );
        assert_eq!(queues.packet_queue_reserved_len(), 1);
        assert!(!queues.should_inject_irq(false, true, 1));
        assert_eq!(
            queues
                .pop_packet()
                .expect("published packet is visible")
                .owner(),
            DomainId::Guest(1)
        );

        assert!(
            queues
                .push_packet_to_domain(unified_packet(1001), DomainId::Guest(1))
                .is_ok()
        );
        assert!(
            queues
                .push_packet_to_domain(unified_packet(1002), DomainId::Guest(1))
                .is_ok()
        );
        assert_eq!(queues.packet_queue_reserved_len(), 2);
        assert!(
            queues.should_inject_irq(false, true, 2),
            "the second event reaches the coalescing threshold"
        );
    }
}
