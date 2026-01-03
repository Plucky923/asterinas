// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use aster_framevsock::ConnectionId;

use crate::{
    events::IoEvents,
    net::socket::framevsock::{FRAME_VSOCK_GLOBAL, addr::FrameVsockAddr},
    process::signal::{PollHandle, Pollee},
};

pub struct Connecting {
    id: ConnectionId,
    is_connected: AtomicBool,
    pollee: Pollee,
    /// Peer's buffer allocation (received from Response packet)
    peer_buf_alloc: AtomicU32,
    /// Peer's forward count (received from Response packet)
    peer_fwd_cnt: AtomicU32,
}

impl Connecting {
    pub fn new(peer_addr: FrameVsockAddr, local_addr: FrameVsockAddr) -> Self {
        Self {
            id: ConnectionId::from_addrs(local_addr, peer_addr),
            is_connected: AtomicBool::new(false),
            pollee: Pollee::new(),
            peer_buf_alloc: AtomicU32::new(0),
            peer_fwd_cnt: AtomicU32::new(0),
        }
    }

    pub fn peer_addr(&self) -> FrameVsockAddr {
        self.id.peer_addr
    }

    pub fn local_addr(&self) -> FrameVsockAddr {
        self.id.local_addr
    }

    pub fn id(&self) -> ConnectionId {
        self.id
    }

    pub fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(mask, poller, || self.check_io_events())
    }

    fn check_io_events(&self) -> IoEvents {
        if self.is_connected.load(Ordering::Relaxed) {
            IoEvents::IN
        } else {
            IoEvents::empty()
        }
    }

    pub fn set_connected(&self) {
        self.is_connected.store(true, Ordering::Relaxed);
        self.pollee.notify(IoEvents::IN);
    }

    /// Set connected with peer credit info from Response packet
    pub fn set_connected_with_credit(&self, peer_buf_alloc: u32, peer_fwd_cnt: u32) {
        self.peer_buf_alloc.store(peer_buf_alloc, Ordering::Relaxed);
        self.peer_fwd_cnt.store(peer_fwd_cnt, Ordering::Relaxed);
        self.set_connected();
    }

    pub fn is_connected(&self) -> bool {
        self.is_connected.load(Ordering::Relaxed)
    }

    /// Get peer buffer allocation (for initializing Connected socket)
    pub fn peer_buf_alloc(&self) -> u32 {
        self.peer_buf_alloc.load(Ordering::Relaxed)
    }

    /// Get peer forward count (for initializing Connected socket)
    pub fn peer_fwd_cnt(&self) -> u32 {
        self.peer_fwd_cnt.load(Ordering::Relaxed)
    }
}

impl Drop for Connecting {
    fn drop(&mut self) {
        // Cleanup is only needed when connection failed (is_connected == false).
        //
        // When connection succeeds:
        // - is_connected is set to true via set_connected_with_credit()
        // - socket.rs::connect() transfers the port to Connected socket
        // - No cleanup needed here
        //
        // When connection fails (timeout, refused, etc.):
        // - is_connected remains false
        // - We need to recycle the port and remove from vsockspace
        if !self.is_connected.load(Ordering::Relaxed) {
            if let Some(vsockspace) = FRAME_VSOCK_GLOBAL.get() {
                vsockspace.recycle_port(&self.local_addr().port);
                let _ = vsockspace.remove_connecting_socket(&self.local_addr());
            }
        }
    }
}
