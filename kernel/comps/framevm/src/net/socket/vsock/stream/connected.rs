// SPDX-License-Identifier: MPL-2.0

//! Connected state for a Linux `AF_VSOCK` stream socket.

use super::VsockSocketAddr;
use crate::{
    error::{Errno, Result},
    events::IoEvents,
    net::socket::{MessageHeader, SendRecvFlags, SockShutdownCmd},
    return_errno_with_message,
};

pub(super) struct ConnectedStream {
    local_addr: VsockSocketAddr,
    peer_addr: VsockSocketAddr,
}

impl ConnectedStream {
    #[expect(
        dead_code,
        reason = "Only transport-backed connect/accept will construct connected sockets"
    )]
    pub(super) const fn new(local_addr: VsockSocketAddr, peer_addr: VsockSocketAddr) -> Self {
        Self {
            local_addr,
            peer_addr,
        }
    }

    pub(super) fn sendmsg(&self, _input: &[u8], _flags: SendRecvFlags) -> Result<usize> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "no transport is connected")
    }

    pub(super) fn recvmsg(
        &self,
        _output: &mut [u8],
        _flags: SendRecvFlags,
    ) -> Result<(usize, MessageHeader)> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "no transport is connected")
    }

    pub(super) fn shutdown(&self, _cmd: SockShutdownCmd) -> Result<()> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "no transport is connected")
    }

    pub(super) const fn local_addr(&self) -> VsockSocketAddr {
        self.local_addr
    }

    pub(super) const fn remote_addr(&self) -> VsockSocketAddr {
        self.peer_addr
    }

    pub(super) const fn check_io_events(&self) -> IoEvents {
        IoEvents::OUT
    }
}
