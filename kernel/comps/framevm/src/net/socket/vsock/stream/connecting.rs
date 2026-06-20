// SPDX-License-Identifier: MPL-2.0

//! Connecting state for a Linux `AF_VSOCK` stream socket.

use super::{super::port::BoundPort, ConnectedStream, InitStream, VsockSocketAddr};
use crate::{
    error::{Errno, Error},
    events::IoEvents,
    pollee::Pollee,
};

pub(super) struct ConnectingStream {
    bound_port: BoundPort,
    remote_addr: VsockSocketAddr,
}

#[expect(
    dead_code,
    reason = "Connected and failed results are produced once the transport exists"
)]
pub(super) enum ConnResult {
    Connecting(ConnectingStream),
    Connected(ConnectedStream),
    Failed(InitStream),
}

impl ConnectingStream {
    pub(super) fn new(
        bound_port: BoundPort,
        remote_addr: VsockSocketAddr,
        pollee: &Pollee,
    ) -> Result<Self, (Error, BoundPort)> {
        let _ = remote_addr;
        pollee.notify(IoEvents::OUT | IoEvents::ERR);
        Err((
            Error::with_message(Errno::ECONNREFUSED, "no transport is connected"),
            bound_port,
        ))
    }

    pub(super) fn local_addr(&self) -> VsockSocketAddr {
        self.bound_port.local_addr()
    }

    pub(super) const fn has_result(&self) -> bool {
        false
    }

    pub(super) fn into_result(self) -> ConnResult {
        ConnResult::Connecting(self)
    }

    pub(super) const fn check_io_events(&self) -> IoEvents {
        let _ = self.remote_addr;
        IoEvents::empty()
    }
}
