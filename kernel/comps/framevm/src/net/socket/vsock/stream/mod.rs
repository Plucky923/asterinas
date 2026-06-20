// SPDX-License-Identifier: MPL-2.0

//! Stream socket state for Linux `AF_VSOCK`.

mod connected;
mod connecting;
mod init;
mod listen;

use alloc::{sync::Arc, vec::Vec};
use core::{
    mem,
    sync::atomic::{AtomicBool, Ordering},
};

use connected::ConnectedStream;
use connecting::{ConnResult, ConnectingStream};
use init::InitStream;
use listen::ListenStream;
use ostd::sync::SpinLock;

use super::{VMADDR_CID_ANY, VMADDR_PORT_ANY, VsockSocketAddr};
use crate::{
    error::{Errno, Error, Result},
    events::IoEvents,
    fd_table::{AccessMode, FileLike, StatusFlags},
    net::socket::{
        MessageHeader, SO_ERROR, SOL_SOCKET, SendRecvFlags, SockShutdownCmd, Socket, SocketAddr,
        SocketBufferOptions,
    },
    pollee::{PollHandle, Pollee},
    return_errno_with_message,
};

const SOCK_STREAM: i32 = 1;
const VSOCK_STREAM_BUF_SIZE: u32 = 128 * 1024;

/// A Linux `SOCK_STREAM` vsock endpoint.
pub struct VsockStreamSocket {
    state: SpinLock<VsockStreamState>,
    options: SpinLock<SocketBufferOptions>,
    is_nonblocking: AtomicBool,
    pollee: Pollee,
}

enum VsockStreamState {
    Init(InitStream),
    Connecting(ConnectingStream),
    Listen(ListenStream),
    Connected(ConnectedStream),
}

impl VsockStreamSocket {
    /// Creates a stream socket.
    pub fn new(is_nonblocking: bool) -> Self {
        Self {
            state: SpinLock::new(VsockStreamState::Init(InitStream::new())),
            options: SpinLock::new(SocketBufferOptions::new(VSOCK_STREAM_BUF_SIZE)),
            is_nonblocking: AtomicBool::new(is_nonblocking),
            pollee: Pollee::new(),
        }
    }

    fn check_io_events(&self) -> IoEvents {
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state);

        match &*state {
            VsockStreamState::Init(init_stream) => init_stream.check_io_events(),
            VsockStreamState::Connecting(connecting_stream) => connecting_stream.check_io_events(),
            VsockStreamState::Listen(listen_stream) => listen_stream.check_io_events(),
            VsockStreamState::Connected(connected_stream) => connected_stream.check_io_events(),
        }
    }

    fn test_and_clear_error(&self) -> Option<Error> {
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state);

        match &mut *state {
            VsockStreamState::Init(init_stream) => init_stream.test_and_clear_error(&self.pollee),
            VsockStreamState::Connecting(_)
            | VsockStreamState::Listen(_)
            | VsockStreamState::Connected(_) => None,
        }
    }

    fn update_state_locked(state: &mut VsockStreamState) {
        let VsockStreamState::Connecting(connecting_stream) = state else {
            return;
        };
        if !connecting_stream.has_result() {
            return;
        }

        let old_state = mem::replace(state, VsockStreamState::Init(InitStream::new()));
        let VsockStreamState::Connecting(connecting_stream) = old_state else {
            *state = old_state;
            return;
        };

        *state = match connecting_stream.into_result() {
            ConnResult::Connecting(connecting_stream) => {
                VsockStreamState::Connecting(connecting_stream)
            }
            ConnResult::Connected(connected_stream) => {
                VsockStreamState::Connected(connected_stream)
            }
            ConnResult::Failed(init_stream) => VsockStreamState::Init(init_stream),
        };
    }
}

impl Socket for VsockStreamSocket {
    fn bind(&self, socket_addr: SocketAddr) -> Result<()> {
        let addr = VsockSocketAddr::try_from(socket_addr)?;
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state);

        let VsockStreamState::Init(init_stream) = &mut *state else {
            return_errno_with_message!(
                Errno::EINVAL,
                "cannot bind a listening or connected socket"
            );
        };

        init_stream.bind(addr)
    }

    fn connect(&self, socket_addr: SocketAddr) -> Result<()> {
        let remote_addr = VsockSocketAddr::try_from(socket_addr)?;
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state);

        let old_state = mem::replace(&mut *state, VsockStreamState::Init(InitStream::new()));
        let (new_state, result) = match old_state {
            VsockStreamState::Init(init_stream) => {
                if !init_stream.is_connect_done() {
                    (
                        VsockStreamState::Init(init_stream),
                        Err(Error::with_message(
                            Errno::EALREADY,
                            "a previous connection attempt exists",
                        )),
                    )
                } else {
                    match init_stream.connect(remote_addr, &self.pollee) {
                        Ok(connecting_stream) => (
                            VsockStreamState::Connecting(connecting_stream),
                            Err(Error::with_message(
                                Errno::EINPROGRESS,
                                "the socket is connecting",
                            )),
                        ),
                        Err((error, init_stream)) => {
                            (VsockStreamState::Init(init_stream), Err(error))
                        }
                    }
                }
            }
            VsockStreamState::Connecting(connecting_stream) => (
                VsockStreamState::Connecting(connecting_stream),
                Err(Error::with_message(
                    Errno::EALREADY,
                    "the socket is connecting",
                )),
            ),
            VsockStreamState::Listen(listen_stream) => (
                VsockStreamState::Listen(listen_stream),
                Err(Error::with_message(
                    Errno::EINVAL,
                    "the socket is listening",
                )),
            ),
            VsockStreamState::Connected(connected_stream) => (
                VsockStreamState::Connected(connected_stream),
                Err(Error::with_message(
                    Errno::EISCONN,
                    "the socket is already connected",
                )),
            ),
        };
        *state = new_state;
        result
    }

    fn listen(&self, backlog: usize) -> Result<()> {
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state);

        let old_state = mem::replace(&mut *state, VsockStreamState::Init(InitStream::new()));
        let (new_state, result) = match old_state {
            VsockStreamState::Init(init_stream) => {
                if !init_stream.is_connect_done() {
                    (
                        VsockStreamState::Init(init_stream),
                        Err(Error::with_message(
                            Errno::EINVAL,
                            "a previous connection attempt exists",
                        )),
                    )
                } else {
                    match init_stream.listen(backlog) {
                        Ok(listen_stream) => (VsockStreamState::Listen(listen_stream), Ok(())),
                        Err((error, init_stream)) => {
                            (VsockStreamState::Init(init_stream), Err(error))
                        }
                    }
                }
            }
            VsockStreamState::Listen(mut listen_stream) => {
                listen_stream.set_backlog(backlog);
                (VsockStreamState::Listen(listen_stream), Ok(()))
            }
            VsockStreamState::Connecting(connecting_stream) => (
                VsockStreamState::Connecting(connecting_stream),
                Err(Error::with_message(
                    Errno::EINVAL,
                    "the socket is already connected",
                )),
            ),
            VsockStreamState::Connected(connected_stream) => (
                VsockStreamState::Connected(connected_stream),
                Err(Error::with_message(
                    Errno::EINVAL,
                    "the socket is already connected",
                )),
            ),
        };
        *state = new_state;
        if result.is_ok() {
            self.pollee.invalidate();
        }
        result
    }

    fn accept(&self) -> Result<(Arc<dyn FileLike>, SocketAddr)> {
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state);

        match &*state {
            VsockStreamState::Listen(listen_stream) => listen_stream.try_accept(),
            VsockStreamState::Init(_)
            | VsockStreamState::Connecting(_)
            | VsockStreamState::Connected(_) => {
                return_errno_with_message!(Errno::EINVAL, "the socket is not listening")
            }
        }
    }

    fn shutdown(&self, cmd: SockShutdownCmd) -> Result<()> {
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state);

        match &*state {
            VsockStreamState::Init(init_stream) => init_stream.shutdown(cmd),
            VsockStreamState::Connecting(_) => Err(Error::new(Errno::ENOTCONN)),
            VsockStreamState::Listen(_) => Err(Error::new(Errno::ENOTCONN)),
            VsockStreamState::Connected(connected_stream) => connected_stream.shutdown(cmd),
        }
    }

    fn addr(&self) -> Result<SocketAddr> {
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state);

        let local_addr = match &*state {
            VsockStreamState::Init(init_stream) => {
                init_stream.local_addr().unwrap_or(VsockSocketAddr {
                    cid: VMADDR_CID_ANY,
                    port: VMADDR_PORT_ANY,
                })
            }
            VsockStreamState::Connecting(connecting_stream) => connecting_stream.local_addr(),
            VsockStreamState::Listen(listen_stream) => listen_stream.local_addr(),
            VsockStreamState::Connected(connected_stream) => connected_stream.local_addr(),
        };
        Ok(SocketAddr::Vsock(local_addr))
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state);

        let VsockStreamState::Connected(connected_stream) = &*state else {
            return Err(Error::new(Errno::ENOTCONN));
        };
        Ok(SocketAddr::Vsock(connected_stream.remote_addr()))
    }

    fn sendmsg(
        &self,
        input: &[u8],
        message_header: MessageHeader,
        flags: SendRecvFlags,
    ) -> Result<usize> {
        flags.ensure_supported_by(SendRecvFlags::MSG_DONTWAIT | SendRecvFlags::MSG_NOSIGNAL)?;

        if message_header.has_control_messages() {
            return Err(Error::new(Errno::EOPNOTSUPP));
        }

        if message_header.addr().is_some() {
            let mut state = self.state.lock();
            Self::update_state_locked(&mut *state);

            match &*state {
                VsockStreamState::Connected(_) => return Err(Error::new(Errno::EISCONN)),
                VsockStreamState::Init(_)
                | VsockStreamState::Connecting(_)
                | VsockStreamState::Listen(_) => {
                    return Err(Error::new(Errno::EOPNOTSUPP));
                }
            }
        }

        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state);

        let VsockStreamState::Connected(connected_stream) = &*state else {
            let _ = input;
            return Err(Error::new(Errno::ENOTCONN));
        };
        connected_stream.sendmsg(input, flags)
    }

    fn recvmsg(&self, output: &mut [u8], flags: SendRecvFlags) -> Result<(usize, MessageHeader)> {
        flags.ensure_supported_by(SendRecvFlags::MSG_DONTWAIT)?;

        if output.is_empty() {
            return Ok((0, MessageHeader::new(None, Vec::new())));
        }

        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state);

        let VsockStreamState::Connected(connected_stream) = &*state else {
            return Err(Error::new(Errno::ENOTCONN));
        };
        connected_stream.recvmsg(output, flags)
    }

    fn get_option(&self, level: i32, optname: i32) -> Result<Vec<u8>> {
        match (level, optname) {
            (SOL_SOCKET, SO_ERROR) => {
                let errno = self
                    .test_and_clear_error()
                    .map_or(0, |error| error.errno() as i32);
                Ok(errno.to_ne_bytes().to_vec())
            }
            _ => self
                .options
                .lock()
                .get_common_option(self.socket_type(), level, optname)
                .ok_or_else(|| Error::new(Errno::EOPNOTSUPP)),
        }
    }

    fn set_option(&self, level: i32, optname: i32, optval: &[u8]) -> Result<()> {
        if self
            .options
            .lock()
            .set_common_option(level, optname, optval)?
            .is_some()
        {
            return Ok(());
        }

        return_errno_with_message!(Errno::EOPNOTSUPP, "setsockopt() is not supported")
    }

    fn poll(&self, events: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(events, poller, || self.check_io_events())
    }

    fn socket_type(&self) -> i32 {
        SOCK_STREAM
    }
}

impl FileLike for VsockStreamSocket {
    fn read(&self, output: &mut [u8]) -> Result<usize> {
        self.recvmsg(output, SendRecvFlags::empty())
            .map(|(len, _)| len)
    }

    fn write(&self, input: &[u8]) -> Result<usize> {
        self.sendmsg(
            input,
            MessageHeader::new(None, Vec::new()),
            SendRecvFlags::empty(),
        )
    }

    fn poll_revents(&self, events: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.poll(events, poller)
    }

    fn access_mode(&self) -> AccessMode {
        AccessMode::O_RDWR
    }

    fn status_flags(&self) -> StatusFlags {
        if self.is_nonblocking.load(Ordering::Relaxed) {
            StatusFlags::O_NONBLOCK
        } else {
            StatusFlags::empty()
        }
    }

    fn set_status_flags(&self, status_flags: StatusFlags) -> Result<()> {
        self.is_nonblocking.store(
            status_flags.contains(StatusFlags::O_NONBLOCK),
            Ordering::Relaxed,
        );
        Ok(())
    }

    fn as_socket(&self) -> Option<&dyn Socket> {
        Some(self)
    }
}
