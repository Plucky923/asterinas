// SPDX-License-Identifier: MPL-2.0

//! Connecting state for a Linux `AF_VSOCK` stream socket.

use alloc::sync::Arc;

use ostd::sync::WaitQueue;

use super::{
    super::transport::{self, BoundPort},
    ConnectedStream, InitStream, VsockSocketAddr,
};
use crate::{
    error::{Errno, Error},
    events::IoEvents,
    pollee::Pollee,
};

pub(super) struct ConnectingStream {
    bound_port: BoundPort,
    remote_addr: VsockSocketAddr,
    recv_buffer_size: u32,
    result: Option<ConnectResult>,
}

pub(super) enum ConnResult {
    Connecting(ConnectingStream),
    Connected(ConnectedStream),
    Failed(InitStream),
}

enum ConnectResult {
    Connected {
        peer_buf_alloc: u32,
        peer_fwd_cnt: u32,
    },
    Failed(Error),
}

impl ConnectingStream {
    pub(super) fn new(
        bound_port: BoundPort,
        remote_addr: VsockSocketAddr,
        recv_buffer_size: u32,
        pollee: &Pollee,
        wait_queue: &Arc<WaitQueue>,
    ) -> Result<Self, (Error, BoundPort)> {
        transport::register_flow_waiters(bound_port.local_addr(), remote_addr, pollee, wait_queue);
        if transport::submit_connect_request(bound_port.local_addr(), remote_addr, recv_buffer_size)
            .is_err()
        {
            transport::unregister_flow_waiters(bound_port.local_addr(), remote_addr);
            pollee.notify(IoEvents::OUT | IoEvents::ERR);
            return Err((Error::new(Errno::ECONNREFUSED), bound_port));
        }

        Ok(Self {
            bound_port,
            remote_addr,
            recv_buffer_size,
            result: None,
        })
    }

    pub(super) fn local_addr(&self) -> VsockSocketAddr {
        self.bound_port.local_addr()
    }

    pub(super) fn set_wait_interest(&self, events: IoEvents) {
        transport::set_flow_wait_interest(self.bound_port.local_addr(), self.remote_addr, events);
    }

    pub(super) fn clear_wait_interest(&self) {
        transport::clear_flow_wait_interest(self.bound_port.local_addr(), self.remote_addr);
    }

    pub(super) fn has_result(&mut self) -> bool {
        self.poll_result();
        self.result.is_some()
    }

    pub(super) fn into_result(self, pollee: &Pollee, wait_queue: &Arc<WaitQueue>) -> ConnResult {
        match self.result {
            Some(ConnectResult::Connected {
                peer_buf_alloc,
                peer_fwd_cnt,
            }) => {
                let connected = ConnectedStream::new(
                    self.bound_port,
                    self.remote_addr,
                    self.recv_buffer_size,
                    peer_buf_alloc,
                    peer_fwd_cnt,
                );
                connected.register_waiters(pollee, wait_queue);
                ConnResult::Connected(connected)
            }
            Some(ConnectResult::Failed(error)) => {
                transport::unregister_flow_waiters(self.bound_port.local_addr(), self.remote_addr);
                transport::forget_flow_affinity(self.bound_port.local_addr(), self.remote_addr);
                ConnResult::Failed(InitStream::new_connect_failed(self.bound_port, error))
            }
            None => ConnResult::Connecting(self),
        }
    }

    pub(super) fn cleanup_flow(&self) {
        let local_addr = self.bound_port.local_addr();
        transport::unregister_flow_waiters(local_addr, self.remote_addr);
        transport::forget_flow_affinity(local_addr, self.remote_addr);
    }

    pub(super) fn check_io_events(&mut self) -> IoEvents {
        self.poll_result();
        match self.result {
            Some(ConnectResult::Connected { .. }) => IoEvents::OUT,
            Some(ConnectResult::Failed(_)) => IoEvents::OUT | IoEvents::ERR,
            None => IoEvents::empty(),
        }
    }

    fn poll_result(&mut self) {
        if self.result.is_some() {
            return;
        }
        if !transport::has_tx_capacity() {
            self.result = Some(ConnectResult::Failed(Error::new(Errno::ECONNRESET)));
            return;
        }

        let Some(packet) =
            transport::poll_connect_result(self.bound_port.local_addr(), self.remote_addr)
        else {
            return;
        };

        self.result = match packet.operation() {
            framev_sock_common::VsockOp::Response => {
                let header = packet.header();
                Some(ConnectResult::Connected {
                    peer_buf_alloc: header.buf_alloc,
                    peer_fwd_cnt: header.fwd_cnt,
                })
            }
            framev_sock_common::VsockOp::Rst => {
                Some(ConnectResult::Failed(Error::new(Errno::ECONNREFUSED)))
            }
            _ => None,
        };
    }
}
