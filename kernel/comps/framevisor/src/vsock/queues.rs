// SPDX-License-Identifier: MPL-2.0

//! Per-vCPU packet queues for FrameVsock backend.
//!
//! Uses bounded ownership-moving queues for Host → Guest communication.

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

use aster_framevisor_exchangeable::{RRef, VmId};
use framev_sock_common::{FrameVsockPacket, flow_control::MAX_PENDING_PACKETS};

use super::ring::{PacketRingBuffer, RingPushError};
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
/// Each vCPU has one bounded packet queue. Packets are enqueued by the backend
/// and drained by the frontend after a receive notification.
pub struct VcpuQueues {
    /// Unified virtio-vsock semantic packet queue.
    packet: PacketRingBuffer<FrameVsockPacket>,
    /// Whether a receive notification covers the current published work.
    notification_pending: AtomicBool,
    /// Queue lifecycle state for VM/device start and stop.
    lifecycle: SpinLock<QueueLifecycle>,
}

pub(super) enum QueuePushError {
    InvalidOwner(RRef<FrameVsockPacket>),
    Full(RRef<FrameVsockPacket>),
    Stopped(RRef<FrameVsockPacket>),
}

impl QueuePushError {
    #[cfg(ktest)]
    fn into_packet(self) -> RRef<FrameVsockPacket> {
        match self {
            Self::InvalidOwner(packet) | Self::Full(packet) | Self::Stopped(packet) => packet,
        }
    }
}

struct QueueLifecycle {
    stopped: bool,
}

impl VcpuQueues {
    /// Create a new set of queues for a vCPU.
    ///
    /// Pre-allocates ring buffers with fixed capacity.
    pub(crate) fn new() -> Self {
        Self {
            packet: PacketRingBuffer::new(MAX_PACKET_QUEUE_SIZE),
            notification_pending: AtomicBool::new(false),
            lifecycle: SpinLock::new(QueueLifecycle { stopped: true }),
        }
    }

    /// Transfers and publishes a packet, returning whether notification is needed.
    #[inline]
    pub(super) fn push_packet_to_vm(
        &self,
        packet: RRef<FrameVsockPacket>,
        owner: VmId,
    ) -> Result<bool, QueuePushError> {
        let lifecycle = self.lifecycle.lock();
        if lifecycle.stopped {
            return Err(QueuePushError::Stopped(packet));
        }

        self.packet
            .push_transfer_to(packet, owner)
            .map_err(|error| match error {
                RingPushError::InvalidOwner(packet) => QueuePushError::InvalidOwner(packet),
                RingPushError::Full(packet) => QueuePushError::Full(packet),
            })?;

        Ok(!self.notification_pending.swap(true, Ordering::AcqRel))
    }

    /// Removes one published packet from the queue.
    #[inline]
    pub(super) fn pop_packet(&self) -> Option<RRef<FrameVsockPacket>> {
        self.packet.pop()
    }

    /// Clears a drained notification and rechecks publication for lost-wakeup safety.
    ///
    /// Returns `true` when a producer published during the clear window but did
    /// not request another notification because the old one was still pending.
    pub(super) fn rearm_notification_if_drained(&self) -> bool {
        if self.packet.len() != 0 {
            return false;
        }

        self.notification_pending.store(false, Ordering::Release);
        if self.packet.len() == 0 {
            return false;
        }

        !self.notification_pending.swap(true, Ordering::AcqRel)
    }

    /// Starts queue admission and drops stale packets from a previous VM run.
    pub(crate) fn start(&self) {
        {
            let mut lifecycle = self.lifecycle.lock();
            lifecycle.stopped = true;
        }
        self.clear_queued_packets();
        self.notification_pending.store(false, Ordering::Release);
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
        self.notification_pending.store(false, Ordering::Release);

        (queue_reserved_len != 0).then_some(queue_reserved_len)
    }

    fn clear_queued_packets(&self) {
        while self.pop_packet().is_some() {}
    }

    /// Get the reserved length of unified packet queue.
    #[inline]
    pub fn packet_queue_reserved_len(&self) -> usize {
        self.packet.len()
    }
}

#[cfg(ktest)]
mod tests {
    use aster_framevisor_exchangeable::enter_vm;
    use framev_sock_common::{FrameVsockAddr, HOST_CID};
    use host_ostd::prelude::ktest;

    use super::*;
    use crate::rref_accounting;

    fn unified_packet(src_port: u32) -> RRef<FrameVsockPacket> {
        RRef::new_with_owner(
            FrameVsockPacket::request(
                FrameVsockAddr::new(3, src_port),
                FrameVsockAddr::new(HOST_CID, 2048),
                4096,
                0,
            ),
            VmId::Host,
        )
    }

    #[ktest]
    fn queues_reject_packets_until_started() {
        rref_accounting::init();
        let _host_vm = enter_vm(VmId::Host);
        let queues = VcpuQueues::new();
        let packet = unified_packet(1000);

        let packet = queues
            .push_packet_to_vm(packet, VmId::new(1))
            .expect_err("stopped queue must return packet")
            .into_packet();
        assert_eq!(packet.owner(), VmId::Host);
        assert_eq!(queues.packet_queue_reserved_len(), 0);

        queues.start();
        assert!(queues.push_packet_to_vm(packet, VmId::new(1)).is_ok());
        assert_eq!(queues.packet_queue_reserved_len(), 1);
    }

    #[ktest]
    fn stop_and_clear_drains_packets_and_rejects_new_pushes() {
        rref_accounting::init();
        let _host_vm = enter_vm(VmId::Host);
        let queues = VcpuQueues::new();
        queues.start();

        assert!(
            queues
                .push_packet_to_vm(unified_packet(1000), VmId::new(1))
                .is_ok()
        );
        assert_eq!(queues.stop_and_clear(), Some(1));
        assert_eq!(queues.packet_queue_reserved_len(), 0);

        let packet = unified_packet(1001);
        let packet = queues
            .push_packet_to_vm(packet, VmId::new(1))
            .expect_err("stopped queue must reject packets after stop")
            .into_packet();
        assert_eq!(packet.owner(), VmId::Host);
    }

    #[ktest]
    fn unified_queue_preserves_packet_ownership_on_stop_and_full() {
        rref_accounting::init();
        let _host_vm = enter_vm(VmId::Host);
        let queues = VcpuQueues::new();

        let packet = queues
            .push_packet_to_vm(unified_packet(1000), VmId::new(1))
            .expect_err("stopped queue must return unified packet")
            .into_packet();
        assert_eq!(packet.owner(), VmId::Host);
        assert_eq!(queues.packet_queue_reserved_len(), 0);

        queues.start();
        assert!(queues.push_packet_to_vm(packet, VmId::new(1)).is_ok());
        assert_eq!(queues.packet_queue_reserved_len(), 1);
        assert_eq!(queues.stop_and_clear(), Some(1));
        assert_eq!(queues.packet_queue_reserved_len(), 0);
    }

    #[ktest]
    fn unified_queue_publication_is_immediately_visible() {
        rref_accounting::init();
        let _host_vm = enter_vm(VmId::Host);
        let queues = VcpuQueues::new();
        queues.start();
        let packet = unified_packet(1000);

        assert!(matches!(
            queues.push_packet_to_vm(packet, VmId::new(1)),
            Ok(true)
        ));
        assert_eq!(queues.packet_queue_reserved_len(), 1);
        let packet = queues.pop_packet().expect("published packet is visible");
        assert_eq!(packet.owner(), VmId::new(1));

        assert!(!queues.rearm_notification_if_drained());
        assert!(matches!(
            queues.push_packet_to_vm(unified_packet(1001), VmId::new(1)),
            Ok(true)
        ));
        assert!(matches!(
            queues.push_packet_to_vm(unified_packet(1002), VmId::new(1)),
            Ok(false)
        ));
        assert_eq!(queues.packet_queue_reserved_len(), 2);
    }
}
