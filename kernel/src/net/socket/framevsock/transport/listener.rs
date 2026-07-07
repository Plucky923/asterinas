// SPDX-License-Identifier: MPL-2.0

//! FrameVsock transport listener state.

use core::sync::atomic::{AtomicUsize, Ordering};

use super::{Connected, MAX_BACKLOG};
use crate::{
    events::IoEvents,
    net::socket::framevsock::addr::FrameVsockAddr,
    prelude::*,
    process::signal::{PollHandle, Pollee},
};

/// A host-side FrameVsock listener handle.
pub(in crate::net::socket::framevsock) struct Listener {
    addr: FrameVsockAddr,
    backlog: AtomicUsize,
    incoming_connection: SpinLock<VecDeque<Arc<Connected>>>,
    pollee: Pollee,
}

impl Listener {
    /// Creates a listener for `addr`.
    pub(in crate::net::socket::framevsock) fn new(addr: FrameVsockAddr, backlog: usize) -> Self {
        let backlog = backlog.min(MAX_BACKLOG);
        Self {
            addr,
            pollee: Pollee::new(),
            backlog: AtomicUsize::new(backlog),
            incoming_connection: SpinLock::new(VecDeque::with_capacity(backlog)),
        }
    }

    /// Returns the local listening address.
    pub(in crate::net::socket::framevsock) fn addr(&self) -> FrameVsockAddr {
        self.addr
    }

    /// Adds an incoming connection to the accept queue.
    pub(in crate::net::socket::framevsock) fn push_incoming(
        &self,
        connect: Arc<Connected>,
    ) -> Result<()> {
        let mut incoming_connections = self.incoming_connection.disable_irq().lock();
        if incoming_connections.len() >= self.backlog.load(Ordering::Relaxed) {
            return_errno_with_message!(Errno::ECONNREFUSED, "queue in listening socket is full")
        }

        incoming_connections.push_back(connect);
        self.pollee.notify(IoEvents::IN);

        Ok(())
    }

    /// Accepts one pending connection.
    pub(in crate::net::socket::framevsock) fn try_accept(&self) -> Result<Arc<Connected>> {
        let connection = self
            .incoming_connection
            .disable_irq()
            .lock()
            .pop_front()
            .ok_or_else(|| {
                Error::with_message(Errno::EAGAIN, "no pending connection is available")
            })?;
        self.pollee.invalidate();

        Ok(connection)
    }

    /// Updates the listen backlog.
    pub(in crate::net::socket::framevsock) fn set_backlog(&self, backlog: usize) {
        self.backlog
            .store(backlog.min(MAX_BACKLOG), Ordering::Relaxed);
    }

    /// Polls the listener readiness.
    pub(in crate::net::socket::framevsock) fn poll(
        &self,
        mask: IoEvents,
        poller: Option<&mut PollHandle>,
    ) -> IoEvents {
        self.pollee
            .poll_with(mask, poller, || self.check_io_events())
    }

    fn check_io_events(&self) -> IoEvents {
        let incoming_connection = self.incoming_connection.disable_irq().lock();

        if !incoming_connection.is_empty() {
            IoEvents::IN
        } else {
            IoEvents::empty()
        }
    }
}
