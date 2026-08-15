// SPDX-License-Identifier: MPL-2.0

//! Bounded ownership-moving ring for FrameV Sock packets.

use alloc::collections::VecDeque;

use aster_framevisor_exchangeable::{Exchangeable, RRef, VmId};

use crate::sync::SpinLock;

struct RingState<T: Exchangeable + 'static> {
    packets: VecDeque<RRef<T>>,
    capacity: usize,
}

/// A bounded MPSC queue whose publication is transactional with owner transfer.
pub(super) struct PacketRingBuffer<T: Exchangeable + 'static> {
    state: SpinLock<RingState<T>>,
}

pub(super) enum RingPushError<T: Exchangeable + 'static> {
    InvalidOwner(RRef<T>),
    Full(RRef<T>),
}

impl<T: Exchangeable + 'static> RingPushError<T> {
    #[cfg(ktest)]
    fn into_packet(self) -> RRef<T> {
        match self {
            Self::InvalidOwner(packet) | Self::Full(packet) => packet,
        }
    }
}

impl<T: Exchangeable + 'static> PacketRingBuffer<T> {
    /// Creates a queue with storage reserved up front.
    pub(super) fn new(capacity: usize) -> Self {
        assert!(capacity != 0, "ring capacity must be nonzero");
        Self {
            state: SpinLock::new(RingState {
                packets: VecDeque::with_capacity(capacity),
                capacity,
            }),
        }
    }

    /// Transfers and publishes one packet, or returns the unchanged packet.
    pub(super) fn push_transfer_to(
        &self,
        packet: RRef<T>,
        new_owner: VmId,
    ) -> Result<bool, RingPushError<T>> {
        if !packet.is_owned_by_current() {
            return Err(RingPushError::InvalidOwner(packet));
        }

        let mut state = self.state.lock();
        if state.packets.len() == state.capacity {
            return Err(RingPushError::Full(packet));
        }

        let was_empty = state.packets.is_empty();
        let packet = packet
            .try_transfer_to(new_owner)
            .map_err(|error| RingPushError::InvalidOwner(error.into_rref()))?;
        state.packets.push_back(packet);
        Ok(was_empty)
    }

    /// Removes one published packet.
    pub(super) fn pop(&self) -> Option<RRef<T>> {
        self.state.lock().packets.pop_front()
    }

    /// Returns the number of published packets.
    pub(super) fn len(&self) -> usize {
        self.state.lock().packets.len()
    }
}

#[cfg(ktest)]
mod tests {
    use aster_framevisor_exchangeable::enter_vm;
    use host_ostd::prelude::ktest;

    use super::*;
    use crate::rref_accounting;

    #[ktest]
    fn failed_transfer_returns_same_packet_without_publication() {
        rref_accounting::init();
        let _host_vm = enter_vm(VmId::Host);
        let ring = PacketRingBuffer::<u64>::new(1);
        let packet = RRef::new_with_owner(7, VmId::new(1));

        let packet = ring
            .push_transfer_to(packet, VmId::Host)
            .expect_err("the current domain does not own the packet")
            .into_packet();

        assert_eq!(packet.owner(), VmId::new(1));
        assert_eq!(ring.len(), 0);
    }

    #[ktest]
    fn full_ring_returns_same_sender_owned_packet() {
        rref_accounting::init();
        let _host_vm = enter_vm(VmId::Host);
        let ring = PacketRingBuffer::<u64>::new(1);
        assert!(
            ring.push_transfer_to(RRef::new_with_owner(1, VmId::Host), VmId::new(1))
                .is_ok()
        );
        let packet = RRef::new_with_owner(2, VmId::Host);

        let packet = ring
            .push_transfer_to(packet, VmId::new(1))
            .expect_err("full ring must reject before transfer")
            .into_packet();

        assert_eq!(packet.owner(), VmId::Host);
        assert_eq!(ring.len(), 1);
    }
}
