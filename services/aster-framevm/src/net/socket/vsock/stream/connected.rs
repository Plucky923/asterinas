// SPDX-License-Identifier: MPL-2.0

//! Connected state for a Linux `AF_VSOCK` stream socket.

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use framev_sock_common::{
    FrameVsockPacket, SHUTDOWN_FLAG_BOTH, SHUTDOWN_FLAG_RECV, SHUTDOWN_FLAG_SEND, VsockOp,
    flow_control::{advance_fwd_cnt, available_peer_credit},
};
use ostd::sync::{SpinLock, WaitQueue};

use super::{
    super::transport::{self, BoundPort},
    VsockSocketAddr,
};
use crate::{
    error::{Errno, Error, Result},
    events::IoEvents,
    net::socket::{MessageHeader, SendRecvFlags, SockShutdownCmd},
};

pub(super) struct ConnectedStream {
    bound_port: BoundPort,
    peer_addr: VsockSocketAddr,
    state: SpinLock<ConnectedState>,
}

#[derive(Default)]
struct ConnectedState {
    rx_payloads: VecDeque<FrameVsockPacket>,
    recv_buffer_size: u32,
    peer_buf_alloc: u32,
    peer_fwd_cnt: u32,
    tx_cnt: u32,
    fwd_cnt: u32,
    local_write_closed: bool,
    local_read_closed: bool,
    peer_write_closed: bool,
    peer_read_closed: bool,
    reset: bool,
}

impl ConnectedStream {
    pub(super) fn new(
        bound_port: BoundPort,
        peer_addr: VsockSocketAddr,
        recv_buffer_size: u32,
        peer_buf_alloc: u32,
        peer_fwd_cnt: u32,
    ) -> Self {
        Self {
            bound_port,
            peer_addr,
            state: SpinLock::new(ConnectedState {
                rx_payloads: VecDeque::new(),
                recv_buffer_size,
                peer_buf_alloc,
                peer_fwd_cnt,
                tx_cnt: 0,
                fwd_cnt: 0,
                local_write_closed: false,
                local_read_closed: false,
                peer_write_closed: false,
                peer_read_closed: false,
                reset: false,
            }),
        }
    }

    pub(super) fn sendmsg(&self, input: &[u8], _flags: SendRecvFlags) -> Result<usize> {
        self.drain_transport_packets();

        if input.is_empty() {
            return Ok(FrameVsockPacket::zero_len_send_result());
        }

        let mut state = self.state.lock();
        if state.reset {
            return Err(Error::new(Errno::ECONNRESET));
        }
        if !transport::has_tx_capacity() {
            state.reset = true;
            return Err(Error::new(Errno::ECONNRESET));
        }
        if state.local_write_closed || state.peer_read_closed {
            return Err(Error::new(Errno::EPIPE));
        }

        let peer_credit =
            available_peer_credit(state.tx_cnt, state.peer_buf_alloc, state.peer_fwd_cnt);
        if peer_credit == 0 {
            return Err(Error::new(Errno::EAGAIN));
        }

        let packets = transport::build_rw_packets(
            self.local_addr(),
            self.peer_addr,
            input,
            peer_credit,
            state.recv_buffer_size,
            state.fwd_cnt,
        )
        .map_err(|_| Error::new(Errno::EMSGSIZE))?;
        if packets.is_empty() {
            return Err(Error::new(Errno::EAGAIN));
        }

        let mut sent_len = 0usize;
        for packet in packets {
            let packet_len = packet.payload().len();
            if let Err(error) = transport::submit_connected_packet(packet) {
                if sent_len == 0 {
                    return Err(error);
                }
                return Ok(sent_len);
            }
            sent_len = sent_len.saturating_add(packet_len);
            state.tx_cnt = state.tx_cnt.wrapping_add(packet_len as u32);
        }

        Ok(sent_len)
    }

    pub(super) fn recvmsg(
        &self,
        output: &mut [u8],
        _flags: SendRecvFlags,
    ) -> Result<(usize, MessageHeader)> {
        self.drain_transport_packets();

        let mut state = self.state.lock();
        if state.reset {
            return Err(Error::new(Errno::ECONNRESET));
        }
        if !transport::has_tx_capacity() {
            state.reset = true;
            return Err(Error::new(Errno::ECONNRESET));
        }
        if state.local_read_closed {
            return Err(Error::new(Errno::ENOTCONN));
        }

        let Some(packet) = state.rx_payloads.pop_front() else {
            if state.peer_write_closed {
                return Ok((0, MessageHeader::new(None, Vec::new())));
            }
            return Err(Error::new(Errno::EAGAIN));
        };

        let payload = packet.into_payload();
        let copy_len = output.len().min(payload.len());
        output[..copy_len].copy_from_slice(&payload[..copy_len]);
        if copy_len < payload.len() {
            let remaining = payload[copy_len..].to_vec();
            let packet = FrameVsockPacket::rw(
                transport_src_addr(self.local_addr()),
                transport_dst_addr(self.peer_addr),
                remaining,
                state.recv_buffer_size,
                state.fwd_cnt,
            )
            .map_err(|_| Error::new(Errno::EIO))?;
            state.rx_payloads.push_front(packet);
        }

        state.fwd_cnt = advance_fwd_cnt(state.fwd_cnt, copy_len);
        let credit_update = FrameVsockPacket::credit_update(
            transport_src_addr(self.local_addr()),
            transport_dst_addr(self.peer_addr),
            state.recv_buffer_size,
            state.fwd_cnt,
        );
        drop(state);
        let _ = transport::submit_connected_packet(credit_update);

        Ok((copy_len, MessageHeader::new(None, Vec::new())))
    }

    pub(super) fn shutdown(&self, cmd: SockShutdownCmd) -> Result<()> {
        let flags = match cmd {
            SockShutdownCmd::SHUT_RD => SHUTDOWN_FLAG_RECV,
            SockShutdownCmd::SHUT_WR => SHUTDOWN_FLAG_SEND,
            SockShutdownCmd::SHUT_RDWR => SHUTDOWN_FLAG_BOTH,
        };

        let mut state = self.state.lock();
        match cmd {
            SockShutdownCmd::SHUT_RD => state.local_read_closed = true,
            SockShutdownCmd::SHUT_WR => state.local_write_closed = true,
            SockShutdownCmd::SHUT_RDWR => {
                state.local_read_closed = true;
                state.local_write_closed = true;
            }
        }
        drop(state);

        transport::submit_control_packet(transport::build_shutdown_packet(
            self.local_addr(),
            self.peer_addr,
            flags,
        ))
    }

    pub(super) fn local_addr(&self) -> VsockSocketAddr {
        self.bound_port.local_addr()
    }

    pub(super) const fn remote_addr(&self) -> VsockSocketAddr {
        self.peer_addr
    }

    pub(super) fn register_waiters(
        &self,
        pollee: &crate::pollee::Pollee,
        wait_queue: &Arc<WaitQueue>,
    ) {
        transport::register_flow_waiters(self.local_addr(), self.peer_addr, pollee, wait_queue);
    }

    pub(super) fn set_wait_interest(&self, events: IoEvents) {
        transport::set_flow_wait_interest(self.local_addr(), self.peer_addr, events);
    }

    pub(super) fn clear_wait_interest(&self) {
        transport::clear_flow_wait_interest(self.local_addr(), self.peer_addr);
    }

    pub(super) fn check_io_events(&self) -> IoEvents {
        self.drain_transport_packets();
        let mut state = self.state.lock();
        if !transport::has_tx_capacity() {
            state.reset = true;
        }
        if state.reset {
            return IoEvents::ERR | IoEvents::HUP;
        }

        let mut events = IoEvents::empty();
        if !state.rx_payloads.is_empty() {
            events |= IoEvents::IN | IoEvents::RDNORM;
        }
        if state.peer_write_closed {
            events |= IoEvents::IN | IoEvents::RDNORM | IoEvents::RDHUP;
        }
        if !state.local_write_closed
            && !state.peer_read_closed
            && transport::has_tx_capacity()
            && available_peer_credit(state.tx_cnt, state.peer_buf_alloc, state.peer_fwd_cnt) != 0
        {
            events |= IoEvents::OUT;
        }
        events
    }

    fn drain_transport_packets(&self) {
        while let Some(packet) =
            transport::poll_flow_packet(self.local_addr(), self.peer_addr, |_| true)
        {
            self.apply_packet(packet);
        }
    }

    fn apply_packet(&self, packet: FrameVsockPacket) {
        let credit_update = {
            let mut state = self.state.lock();
            let header = packet.header();
            if header.buf_alloc != 0 {
                state.peer_buf_alloc = header.buf_alloc;
                state.peer_fwd_cnt = header.fwd_cnt;
            }

            match packet.operation() {
                VsockOp::Rw => {
                    if !state.local_read_closed {
                        state.rx_payloads.push_back(packet);
                    }
                    None
                }
                VsockOp::CreditUpdate => None,
                VsockOp::CreditRequest => Some(FrameVsockPacket::credit_update(
                    transport_src_addr(self.local_addr()),
                    transport_dst_addr(self.peer_addr),
                    state.recv_buffer_size,
                    state.fwd_cnt,
                )),
                VsockOp::Shutdown => {
                    let flags = header.flags;
                    if flags & SHUTDOWN_FLAG_SEND != 0 {
                        state.peer_write_closed = true;
                    }
                    if flags & SHUTDOWN_FLAG_RECV != 0 {
                        state.peer_read_closed = true;
                    }
                    None
                }
                VsockOp::Rst => {
                    state.reset = true;
                    None
                }
                VsockOp::Request | VsockOp::Response | VsockOp::Invalid => None,
            }
        };

        if let Some(packet) = credit_update {
            let _ = transport::submit_connected_packet(packet);
        }
    }

    #[cfg(test)]
    fn state_for_test(&self) -> ConnectedStateSnapshot {
        let state = self.state.lock();
        ConnectedStateSnapshot {
            recv_buffer_size: state.recv_buffer_size,
            peer_buf_alloc: state.peer_buf_alloc,
            peer_fwd_cnt: state.peer_fwd_cnt,
        }
    }
}

impl Drop for ConnectedStream {
    fn drop(&mut self) {
        let local_addr = self.bound_port.local_addr();
        let should_shutdown = {
            let mut state = self.state.lock();
            if state.reset || (state.local_read_closed && state.local_write_closed) {
                false
            } else {
                state.local_read_closed = true;
                state.local_write_closed = true;
                true
            }
        };
        if should_shutdown {
            let packet =
                transport::build_shutdown_packet(local_addr, self.peer_addr, SHUTDOWN_FLAG_BOTH);
            let _ = transport::submit_connected_packet(packet);
        }
        transport::unregister_flow_waiters(local_addr, self.peer_addr);
        transport::forget_flow_affinity(local_addr, self.peer_addr);
    }
}

#[cfg(test)]
struct ConnectedStateSnapshot {
    recv_buffer_size: u32,
    peer_buf_alloc: u32,
    peer_fwd_cnt: u32,
}

fn transport_src_addr(addr: VsockSocketAddr) -> framev_sock_common::FrameVsockAddr {
    framev_sock_common::FrameVsockAddr::new(transport::current_guest_cid(), addr.port)
}

fn transport_dst_addr(addr: VsockSocketAddr) -> framev_sock_common::FrameVsockAddr {
    framev_sock_common::FrameVsockAddr::new(framev_sock_common::HOST_CID, addr.port)
}
