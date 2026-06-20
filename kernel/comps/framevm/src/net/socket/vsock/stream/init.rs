// SPDX-License-Identifier: MPL-2.0

//! Initial state for a Linux `AF_VSOCK` stream socket.

use super::{
    super::{VMADDR_CID_HOST, VMADDR_PORT_ANY, VsockSocketAddr, port::BoundPort},
    connecting::ConnectingStream,
    listen::ListenStream,
};
use crate::{
    error::{Errno, Error, Result},
    events::IoEvents,
    net::socket::SockShutdownCmd,
    pollee::Pollee,
    return_errno_with_message,
};

pub(super) struct InitStream {
    bound_port: Option<BoundPort>,
    is_connect_done: bool,
    last_connect_error: Option<Error>,
}

impl InitStream {
    pub(super) fn new() -> Self {
        Self {
            bound_port: None,
            is_connect_done: true,
            last_connect_error: None,
        }
    }

    #[expect(
        dead_code,
        reason = "Used once the service vsock transport is connected"
    )]
    pub(super) fn new_bound(bound_port: BoundPort) -> Self {
        Self {
            bound_port: Some(bound_port),
            is_connect_done: true,
            last_connect_error: None,
        }
    }

    pub(super) fn new_connect_failed(bound_port: BoundPort, error: Error) -> Self {
        Self {
            bound_port: Some(bound_port),
            is_connect_done: false,
            last_connect_error: Some(error),
        }
    }

    pub(super) fn bind(&mut self, addr: VsockSocketAddr) -> Result<()> {
        if !self.is_connect_done {
            return_errno_with_message!(Errno::EINVAL, "a previous connection attempt exists");
        }
        if self.bound_port.is_some() {
            return_errno_with_message!(Errno::EINVAL, "the socket is already bound");
        }

        self.bound_port = Some(BoundPort::new_exclusive(addr)?);
        Ok(())
    }

    pub(super) fn connect(
        self,
        remote_addr: VsockSocketAddr,
        pollee: &Pollee,
    ) -> core::result::Result<ConnectingStream, (Error, Self)> {
        if !self.is_connect_done {
            return Err((
                Error::with_message(Errno::EALREADY, "a previous connection attempt exists"),
                self,
            ));
        }
        if remote_addr.cid != VMADDR_CID_HOST {
            return Err((
                Error::with_message(Errno::ENETUNREACH, "only the host vsock CID is supported"),
                self,
            ));
        }
        if remote_addr.port == VMADDR_PORT_ANY {
            return Err((
                Error::with_message(Errno::EINVAL, "the vsock port is invalid"),
                self,
            ));
        }

        let bound_port = if let Some(bound_port) = self.bound_port {
            bound_port
        } else {
            match BoundPort::new_ephemeral() {
                Ok(bound_port) => bound_port,
                Err(error) => return Err((error, Self::new())),
            }
        };

        ConnectingStream::new(bound_port, remote_addr, pollee)
            .map_err(|(error, bound_port)| (error, Self::new_connect_failed(bound_port, error)))
    }

    pub(super) fn shutdown(&self, _cmd: SockShutdownCmd) -> Result<()> {
        if !self.is_connect_done {
            return Ok(());
        }

        Err(Error::new(Errno::ENOTCONN))
    }

    pub(super) fn local_addr(&self) -> Option<VsockSocketAddr> {
        self.bound_port
            .as_ref()
            .map(|bound_port| bound_port.local_addr())
    }

    pub(super) const fn is_connect_done(&self) -> bool {
        self.is_connect_done
    }

    pub(super) fn listen(
        self,
        backlog: usize,
    ) -> core::result::Result<ListenStream, (Error, Self)> {
        if !self.is_connect_done {
            return Err((
                Error::with_message(Errno::EINVAL, "a previous connection attempt exists"),
                self,
            ));
        }

        let Some(bound_port) = self.bound_port else {
            return Err((
                Error::with_message(Errno::EINVAL, "the socket is not bound"),
                Self::new(),
            ));
        };

        Ok(ListenStream::new(bound_port, backlog))
    }

    pub(super) fn test_and_clear_error(&mut self, pollee: &Pollee) -> Option<Error> {
        let error = self.last_connect_error.take()?;
        pollee.notify(IoEvents::IN | IoEvents::RDHUP | IoEvents::HUP);
        Some(error)
    }

    pub(super) fn check_io_events(&self) -> IoEvents {
        if self.last_connect_error.is_some() {
            return IoEvents::OUT | IoEvents::ERR;
        }
        if !self.is_connect_done {
            return IoEvents::IN | IoEvents::RDHUP | IoEvents::HUP;
        }

        IoEvents::OUT
    }
}
