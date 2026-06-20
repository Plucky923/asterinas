// SPDX-License-Identifier: MPL-2.0

//! Listening state for a Linux `AF_VSOCK` stream socket.

use alloc::sync::Arc;

use super::{super::port::BoundPort, VsockSocketAddr};
use crate::{
    error::{Errno, Result},
    events::IoEvents,
    fd_table::FileLike,
    net::socket::SocketAddr,
    return_errno_with_message,
};

pub(super) struct ListenStream {
    bound_port: BoundPort,
    backlog: usize,
}

impl ListenStream {
    pub(super) const fn new(bound_port: BoundPort, backlog: usize) -> Self {
        Self {
            bound_port,
            backlog,
        }
    }

    pub(super) fn try_accept(&self) -> Result<(Arc<dyn FileLike>, SocketAddr)> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "no transport is connected")
    }

    pub(super) fn set_backlog(&mut self, backlog: usize) {
        self.backlog = backlog;
    }

    pub(super) const fn local_addr(&self) -> VsockSocketAddr {
        self.bound_port.local_addr()
    }

    pub(super) const fn check_io_events(&self) -> IoEvents {
        let _ = self.backlog;
        IoEvents::empty()
    }
}
