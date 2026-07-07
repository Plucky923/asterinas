// SPDX-License-Identifier: MPL-2.0

//! Frontend socket transport boundary.
//!
//! This module keeps service socket code separate from the transport
//! binding. It constructs virtio-vsock semantic packets and selects a queue,
//! while the host-side transport binding owns cross-domain submission.

extern crate alloc;

use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec::Vec,
};

use framev_sock_common::{
    FlowAffinityTable, FrameVsockAddr, FrameVsockFlowKey, FrameVsockPacket, FrameVsockPacketError,
    HOST_CID, MAX_PACKET_PAYLOAD_LEN, VsockOp,
};
use ostd::sync::{Once, SpinLock, WaitQueue};

use super::VsockSocketAddr;
use crate::{
    error::{Errno, Error, Result},
    events::IoEvents,
    pollee::Pollee,
};

mod port;

pub(super) use port::BoundPort;

const RX_DRAIN_BUDGET: usize = 256;
const CONTROL_SEND_RETRIES: usize = 1024;

static INBOUND_PACKETS: Once<SpinLock<InboundPackets>> = Once::new();
static FLOW_AFFINITY: Once<SpinLock<FlowAffinityTable>> = Once::new();
static FLOW_POLLEES: Once<SpinLock<BTreeMap<FrameVsockFlowKey, Pollee>>> = Once::new();
static FLOW_WAIT_QUEUES: Once<SpinLock<BTreeMap<FrameVsockFlowKey, Arc<WaitQueue>>>> = Once::new();
static FLOW_WAIT_INTERESTS: Once<SpinLock<BTreeMap<FrameVsockFlowKey, IoEvents>>> = Once::new();

#[derive(Default)]
struct InboundPackets {
    packets_by_flow: BTreeMap<FrameVsockFlowKey, VecDeque<FrameVsockPacket>>,
}

impl InboundPackets {
    fn push(&mut self, packet: FrameVsockPacket) {
        let key = FrameVsockFlowKey::from_packet(&packet);
        self.packets_by_flow
            .entry(key)
            .or_default()
            .push_back(packet);
    }

    fn pop_matching(
        &mut self,
        key: FrameVsockFlowKey,
        accept_fn: impl Fn(&FrameVsockPacket) -> bool,
    ) -> Option<FrameVsockPacket> {
        let queue = self.packets_by_flow.get_mut(&key)?;
        let index = queue.iter().position(accept_fn)?;
        let packet = queue.remove(index);
        if queue.is_empty() {
            self.packets_by_flow.remove(&key);
        }
        packet
    }
}

/// Builds and submits a frontend-to-backend connection request.
pub(super) fn submit_connect_request(
    local_addr: VsockSocketAddr,
    remote_addr: VsockSocketAddr,
    recv_buffer_size: u32,
) -> Result<()> {
    drain_inbound_queues(RX_DRAIN_BUDGET);

    let packet = FrameVsockPacket::request(
        local_transport_addr(local_addr),
        remote_transport_addr(remote_addr),
        recv_buffer_size,
        0,
    );

    submit_packet(select_queue(&packet), packet).map_err(|(error, _packet)| error.into_error())
}

/// Receives a bounded batch from the current vCPU's RX queue.
#[expect(dead_code, reason = "used when connected streams drain transport RX")]
pub(super) fn recv_current_queue(max_count: usize) -> Vec<FrameVsockPacket> {
    let queue_id = current_queue_id();
    recv_queue_packets(queue_id, max_count)
}

/// Polls inbound queues and returns one packet for a connected flow.
pub(super) fn poll_flow_packet(
    local_addr: VsockSocketAddr,
    remote_addr: VsockSocketAddr,
    accept_fn: impl Fn(&FrameVsockPacket) -> bool,
) -> Option<FrameVsockPacket> {
    drain_inbound_queues(RX_DRAIN_BUDGET);
    let key = FrameVsockFlowKey::new(
        local_transport_addr(local_addr),
        remote_transport_addr(remote_addr),
    );
    inbound_packets().lock().pop_matching(key, accept_fn)
}

/// Polls inbound queues and returns one connect-result packet for a flow.
pub(super) fn poll_connect_result(
    local_addr: VsockSocketAddr,
    remote_addr: VsockSocketAddr,
) -> Option<FrameVsockPacket> {
    poll_flow_packet(local_addr, remote_addr, |packet| {
        matches!(packet.operation(), VsockOp::Response | VsockOp::Rst)
    })
}

/// Submits one connected-flow packet on its selected transport queue.
pub(super) fn submit_connected_packet(packet: FrameVsockPacket) -> Result<()> {
    submit_packet(select_queue(&packet), packet).map_err(|(error, _packet)| error.into_error())
}

/// Submits a connected-flow control packet with bounded retry.
pub(super) fn submit_control_packet(mut packet: FrameVsockPacket) -> Result<()> {
    for _ in 0..CONTROL_SEND_RETRIES {
        match submit_packet(select_queue(&packet), packet) {
            Ok(()) => return Ok(()),
            Err((_error, returned_packet)) => {
                packet = returned_packet;
                ostd::task::Task::yield_now();
            }
        }
    }

    Err(Error::with_message(
        Errno::EAGAIN,
        "the FrameV Sock control queue is full",
    ))
}

/// Registers readiness waiters for a connected or connecting flow.
pub(super) fn register_flow_waiters(
    local_addr: VsockSocketAddr,
    remote_addr: VsockSocketAddr,
    pollee: &Pollee,
    wait_queue: &Arc<WaitQueue>,
) {
    let key = flow_key_for_socket_addrs(local_addr, remote_addr);
    flow_pollees().lock().insert(key, pollee.clone());
    flow_wait_queues().lock().insert(key, wait_queue.clone());
}

/// Sets the current blocking wait interest for a flow.
pub(super) fn set_flow_wait_interest(
    local_addr: VsockSocketAddr,
    remote_addr: VsockSocketAddr,
    events: IoEvents,
) {
    let key = flow_key_for_socket_addrs(local_addr, remote_addr);
    flow_wait_interests().lock().insert(key, events);
}

/// Clears the current blocking wait interest for a flow.
pub(super) fn clear_flow_wait_interest(local_addr: VsockSocketAddr, remote_addr: VsockSocketAddr) {
    let key = flow_key_for_socket_addrs(local_addr, remote_addr);
    flow_wait_interests().lock().remove(&key);
}

/// Removes readiness waiters for a connected or connecting flow.
pub(super) fn unregister_flow_waiters(local_addr: VsockSocketAddr, remote_addr: VsockSocketAddr) {
    let key = flow_key_for_socket_addrs(local_addr, remote_addr);
    flow_pollees().lock().remove(&key);
    flow_wait_queues().lock().remove(&key);
    flow_wait_interests().lock().remove(&key);
}

/// Removes learned queue affinity for a closed flow.
pub(super) fn forget_flow_affinity(local_addr: VsockSocketAddr, remote_addr: VsockSocketAddr) {
    flow_affinity()
        .lock()
        .remove(flow_key_for_socket_addrs(local_addr, remote_addr));
}

/// Returns whether direct TX submission can make progress.
pub(super) fn has_tx_capacity() -> bool {
    framev_sock_frontend::is_active()
}

/// Sends a reset packet for an inbound packet.
pub(super) fn submit_reset_for_packet(packet: &FrameVsockPacket) -> Result<()> {
    submit_connected_packet(FrameVsockPacket::rst(packet.dst_addr(), packet.src_addr()))
}

/// Builds `Rw` packets for a connected stream send operation.
pub(super) fn build_rw_packets(
    local_addr: VsockSocketAddr,
    remote_addr: VsockSocketAddr,
    payload: &[u8],
    peer_credit: usize,
    recv_buffer_size: u32,
    fwd_cnt: u32,
) -> core::result::Result<Vec<FrameVsockPacket>, FrameVsockPacketError> {
    if payload.is_empty() {
        return Ok(Vec::new());
    }

    let mut packets = Vec::new();
    let mut offset = 0;
    let sendable_len = payload.len().min(peer_credit);
    while offset < sendable_len {
        let packet_len = (sendable_len - offset).min(MAX_PACKET_PAYLOAD_LEN);
        let packet_payload = payload[offset..offset + packet_len].to_vec();
        packets.push(FrameVsockPacket::rw(
            local_transport_addr(local_addr),
            remote_transport_addr(remote_addr),
            packet_payload,
            recv_buffer_size,
            fwd_cnt,
        )?);
        offset += packet_len;
    }

    Ok(packets)
}

/// Builds a shutdown packet for a connected stream.
pub(super) fn build_shutdown_packet(
    local_addr: VsockSocketAddr,
    remote_addr: VsockSocketAddr,
    flags: u32,
) -> FrameVsockPacket {
    FrameVsockPacket::shutdown(
        local_transport_addr(local_addr),
        remote_transport_addr(remote_addr),
        flags,
    )
}

/// Updates learned queue affinity for a received packet.
#[expect(dead_code, reason = "used by the receive path once wired")]
pub(super) fn observe_received_packet(
    affinity: &mut FlowAffinityTable,
    queue_id: usize,
    packet: &FrameVsockPacket,
) -> core::result::Result<usize, Error> {
    affinity
        .observe(FrameVsockFlowKey::from_packet(packet), queue_id)
        .map_err(|_| Error::with_message(Errno::EINVAL, "wrong socket queue"))
}

fn submit_packet(
    queue_id: usize,
    packet: FrameVsockPacket,
) -> core::result::Result<(), (TransportError, FrameVsockPacket)> {
    let flow_key = FrameVsockFlowKey::from_packet(&packet);
    let removes_flow = packet.operation() == VsockOp::Rst;
    framev_sock_frontend::submit_packet(queue_id, packet)
        .map_err(|packet| (TransportError::Unavailable, packet))?;
    if removes_flow {
        flow_affinity().lock().remove(flow_key);
    }
    Ok(())
}

fn select_queue(packet: &FrameVsockPacket) -> usize {
    let queue_count = framev_sock_frontend::queue_count().max(1);
    let key = FrameVsockFlowKey::from_packet(packet);
    let first = key.first();
    let second = key.second();
    let hash = first
        .cid
        .wrapping_add(u64::from(first.port))
        .wrapping_add(second.cid.rotate_left(17))
        .wrapping_add(u64::from(second.port).rotate_left(7));
    let preferred_queue = (hash as usize) % queue_count;
    let mut affinity = flow_affinity().lock();
    if packet.operation() == VsockOp::Rst {
        return affinity.get(key).unwrap_or(preferred_queue);
    }
    affinity.bind_or_get(key, preferred_queue)
}

fn current_queue_id() -> usize {
    let queue_count = framev_sock_frontend::queue_count().max(1);
    framev_sock_frontend::current_vcpu_index()
        .unwrap_or(0)
        .min(queue_count - 1)
}

pub(super) fn drain_inbound_queues(max_count: usize) -> bool {
    drain_inbound_queues_with(max_count, Some)
}

pub(super) fn drain_inbound_queues_with(
    max_count: usize,
    mut handle_packet_fn: impl FnMut(FrameVsockPacket) -> Option<FrameVsockPacket>,
) -> bool {
    let queue_count = framev_sock_frontend::queue_count().max(1);
    let mut remaining = max_count;
    for queue_id in 0..queue_count {
        if remaining == 0 {
            break;
        }
        let packets = recv_queue_packets(queue_id, remaining);
        remaining = remaining.saturating_sub(packets.len());
        if packets.is_empty() {
            continue;
        }
        for packet in packets {
            let key = FrameVsockFlowKey::from_packet(&packet);
            let is_wrong_queue = { flow_affinity().lock().observe(key, queue_id).is_err() };
            if is_wrong_queue {
                reset_wrong_queue_flow(key, &packet);
                continue;
            }
            let events = readiness_events_for_packet(&packet);
            if let Some(packet) = handle_packet_fn(packet) {
                inbound_packets().lock().push(packet);
                notify_flow_waiters(key, events);
            }
        }
    }
    remaining == 0
}

fn inbound_packets() -> &'static SpinLock<InboundPackets> {
    INBOUND_PACKETS.call_once(|| SpinLock::new(InboundPackets::default()))
}

fn flow_affinity() -> &'static SpinLock<FlowAffinityTable> {
    FLOW_AFFINITY.call_once(|| SpinLock::new(FlowAffinityTable::new()))
}

fn flow_pollees() -> &'static SpinLock<BTreeMap<FrameVsockFlowKey, Pollee>> {
    FLOW_POLLEES.call_once(|| SpinLock::new(BTreeMap::new()))
}

fn flow_wait_queues() -> &'static SpinLock<BTreeMap<FrameVsockFlowKey, Arc<WaitQueue>>> {
    FLOW_WAIT_QUEUES.call_once(|| SpinLock::new(BTreeMap::new()))
}

fn flow_wait_interests() -> &'static SpinLock<BTreeMap<FrameVsockFlowKey, IoEvents>> {
    FLOW_WAIT_INTERESTS.call_once(|| SpinLock::new(BTreeMap::new()))
}

fn flow_key_for_socket_addrs(
    local_addr: VsockSocketAddr,
    remote_addr: VsockSocketAddr,
) -> FrameVsockFlowKey {
    FrameVsockFlowKey::new(
        local_transport_addr(local_addr),
        remote_transport_addr(remote_addr),
    )
}

fn notify_flow_waiters(key: FrameVsockFlowKey, events: IoEvents) {
    let pollee = flow_pollees().lock().get(&key).cloned();
    let wait_queue = flow_wait_queues().lock().get(&key).cloned();
    let wait_interest = flow_wait_interests().lock().get(&key).copied();
    if let Some(pollee) = pollee {
        pollee.notify(events);
    }
    let should_wake_wait_queue = wait_interest.is_none_or(|interest| interest.intersects(events));
    if should_wake_wait_queue && let Some(wait_queue) = wait_queue {
        wait_queue.wake_all();
    }
}

fn reset_wrong_queue_flow(key: FrameVsockFlowKey, packet: &FrameVsockPacket) {
    let _ = submit_reset_for_packet(packet);
    flow_affinity().lock().remove(key);
    notify_flow_waiters(key, IoEvents::ERR | IoEvents::HUP);
}

fn readiness_events_for_packet(packet: &FrameVsockPacket) -> IoEvents {
    match packet.operation() {
        VsockOp::Rw => IoEvents::IN | IoEvents::RDNORM,
        VsockOp::Response | VsockOp::CreditUpdate | VsockOp::CreditRequest => IoEvents::OUT,
        VsockOp::Shutdown => IoEvents::IN | IoEvents::RDNORM | IoEvents::RDHUP,
        VsockOp::Rst => IoEvents::ERR | IoEvents::HUP,
        VsockOp::Request | VsockOp::Invalid => IoEvents::empty(),
    }
}

fn recv_queue_packets(queue_id: usize, max_count: usize) -> Vec<FrameVsockPacket> {
    let mut packets = Vec::new();
    while packets.len() < max_count {
        let Some(packet) = framev_sock_frontend::recv_packet(queue_id) else {
            break;
        };
        packets.push(packet);
    }
    packets
}

fn local_transport_addr(local_addr: VsockSocketAddr) -> FrameVsockAddr {
    FrameVsockAddr::new(current_guest_cid(), local_addr.port)
}

fn remote_transport_addr(remote_addr: VsockSocketAddr) -> FrameVsockAddr {
    FrameVsockAddr::new(HOST_CID, remote_addr.port)
}

pub(super) fn current_guest_cid() -> u64 {
    let Some(guest_cid) = framev_sock_frontend::guest_cid() else {
        panic!("FrameV Sock frontend must be active before resolving the guest CID");
    };
    guest_cid
}

enum TransportError {
    Unavailable,
}

impl TransportError {
    fn into_error(self) -> Error {
        match self {
            Self::Unavailable => {
                Error::with_message(Errno::EOPNOTSUPP, "socket transport is not connected")
            }
        }
    }
}
