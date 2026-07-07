// SPDX-License-Identifier: MPL-2.0

//! Listening state for a Linux `AF_VSOCK` stream socket.

use alloc::{
    collections::{BTreeMap, VecDeque, btree_map::Entry},
    sync::Arc,
};

use framev_sock_common::{FrameVsockPacket, VsockOp};
use ostd::sync::{Once, SpinLock, WaitQueue};

use super::{
    super::transport::{self, BoundPort},
    ConnectedStream, VsockSocketAddr, VsockStreamSocket,
};
use crate::{
    error::{Errno, Error, Result},
    events::IoEvents,
    fs::file::FileLike,
    net::socket::SocketAddr,
    pollee::Pollee,
    return_errno_with_message,
};

const LISTEN_DRAIN_BUDGET: usize = 256;

static LISTENERS: Once<SpinLock<BTreeMap<u32, Arc<ListenState>>>> = Once::new();

pub(super) struct ListenStream {
    bound_port: BoundPort,
    state: Arc<ListenState>,
}

struct ListenState {
    local_addr: VsockSocketAddr,
    recv_buffer_size: u32,
    pollee: Pollee,
    wait_queue: Arc<WaitQueue>,
    inner: SpinLock<ListenInner>,
}

struct ListenInner {
    backlog: usize,
    accepted: VecDeque<AcceptedStream>,
}

struct AcceptedStream {
    stream: ConnectedStream,
    peer_addr: VsockSocketAddr,
}

impl ListenStream {
    pub(super) fn new(
        bound_port: BoundPort,
        backlog: usize,
        recv_buffer_size: u32,
        pollee: &Pollee,
        wait_queue: &Arc<WaitQueue>,
    ) -> core::result::Result<Self, (Error, BoundPort)> {
        let local_addr = bound_port.local_addr();
        let state = Arc::new(ListenState {
            local_addr,
            recv_buffer_size,
            pollee: pollee.clone(),
            wait_queue: wait_queue.clone(),
            inner: SpinLock::new(ListenInner {
                backlog,
                accepted: VecDeque::new(),
            }),
        });

        let listeners = listeners();
        match listeners.lock().entry(local_addr.port) {
            Entry::Vacant(entry) => {
                entry.insert(state.clone());
            }
            Entry::Occupied(_) => {
                return Err((
                    Error::with_message(Errno::EADDRINUSE, "the vsock listener exists"),
                    bound_port,
                ));
            }
        }

        drain_inbound_requests();
        Ok(Self { bound_port, state })
    }

    pub(super) fn try_accept(&self) -> Result<(Arc<dyn FileLike>, SocketAddr)> {
        drain_inbound_requests();
        let Some(accepted) = self.state.inner.lock().accepted.pop_front() else {
            return_errno_with_message!(Errno::EAGAIN, "the vsock accept queue is empty");
        };

        let socket = Arc::new(VsockStreamSocket::new_connected(
            accepted.stream,
            self.state.recv_buffer_size,
            false,
        ));
        Ok((socket, SocketAddr::Vsock(accepted.peer_addr)))
    }

    pub(super) fn set_backlog(&mut self, backlog: usize) {
        self.state.inner.lock().backlog = backlog;
    }

    pub(super) const fn local_addr(&self) -> VsockSocketAddr {
        self.bound_port.local_addr()
    }

    pub(super) fn check_io_events(&self) -> IoEvents {
        drain_inbound_requests();
        if self.state.inner.lock().accepted.is_empty() {
            IoEvents::empty()
        } else {
            IoEvents::IN | IoEvents::RDNORM
        }
    }
}

impl Drop for ListenStream {
    fn drop(&mut self) {
        listeners()
            .lock()
            .remove(&self.bound_port.local_addr().port);
    }
}

impl ListenState {
    fn accept_request(&self, packet: FrameVsockPacket) -> Result<()> {
        let header = packet.header();
        let peer_addr = VsockSocketAddr {
            cid: header.src_cid as u32,
            port: header.src_port,
        };
        let local_addr = self.local_addr;
        let bound_port = BoundPort::new_listener_child(local_addr);
        let connected = ConnectedStream::new(
            bound_port,
            peer_addr,
            self.recv_buffer_size,
            header.buf_alloc,
            header.fwd_cnt,
        );

        {
            let mut inner = self.inner.lock();
            if inner.accepted.len() >= inner.backlog {
                return Err(Error::new(Errno::ECONNREFUSED));
            }
            inner.accepted.push_back(AcceptedStream {
                stream: connected,
                peer_addr,
            });
        }

        if let Err(error) = transport::submit_connected_packet(FrameVsockPacket::response(
            packet.dst_addr(),
            packet.src_addr(),
            self.recv_buffer_size,
            0,
        )) {
            let mut inner = self.inner.lock();
            if let Some(index) = inner
                .accepted
                .iter()
                .position(|accepted| accepted.peer_addr == peer_addr)
            {
                inner.accepted.remove(index);
            }
            return Err(error);
        }
        self.pollee.notify(IoEvents::IN | IoEvents::RDNORM);
        self.wait_queue.wake_all();
        Ok(())
    }
}

pub(super) fn drain_inbound_requests() -> bool {
    transport::drain_inbound_queues_with(LISTEN_DRAIN_BUDGET, |packet| {
        if packet.operation() != VsockOp::Request {
            return Some(packet);
        }

        let listener = listeners().lock().get(&packet.dst_addr().port).cloned();
        if let Some(listener) = listener {
            let reset = FrameVsockPacket::rst(packet.dst_addr(), packet.src_addr());
            if listener.accept_request(packet).is_err() {
                let _ = transport::submit_connected_packet(reset);
            }
            return None;
        }

        let _ = transport::submit_reset_for_packet(&packet);
        None
    })
}

fn listeners() -> &'static SpinLock<BTreeMap<u32, Arc<ListenState>>> {
    LISTENERS.call_once(|| SpinLock::new(BTreeMap::new()))
}
