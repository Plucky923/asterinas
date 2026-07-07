// SPDX-License-Identifier: MPL-2.0

//! Host `AF_VSOCK` provider selection.
//!
//! Asterinas can expose two vsock transports at the same time: the existing
//! outer virtio-vsock device and the inner FrameV Sock device used by FrameVM.
//! The mux keeps the Linux socket ABI stable while choosing the transport.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::{
    events::IoEvents,
    fs::{file::FileLike, pseudofs::SockFs, vfs::path::Path},
    net::socket::{
        Socket,
        framevsock::FrameVsockStreamSocket,
        options::SocketOption,
        private::SocketPrivate,
        util::{MessageHeader, SendRecvFlags, SockShutdownCmd, SocketAddr},
        vsock::{VsockSocketAddr, VsockStreamSocket},
    },
    prelude::*,
    process::signal::{PollHandle, Pollable},
    util::{MultiRead, MultiWrite},
};

pub struct VsockMuxStreamSocket {
    state: RwLock<State>,
    is_nonblocking: AtomicBool,
    pseudo_path: Path,
}

enum State {
    Init(ProviderPair),
    Listen(ProviderPair),
    Connected(Provider),
}

struct ProviderPair {
    virtio: Arc<VsockStreamSocket>,
    framev: Arc<FrameVsockStreamSocket>,
    virtio_bound: bool,
    framev_bound: bool,
    virtio_listening: bool,
    framev_listening: bool,
}

enum Provider {
    Virtio(Arc<VsockStreamSocket>),
    FrameV(Arc<FrameVsockStreamSocket>),
}

impl VsockMuxStreamSocket {
    pub fn new(is_nonblocking: bool) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            state: RwLock::new(State::Init(ProviderPair::new(is_nonblocking)?)),
            is_nonblocking: AtomicBool::new(is_nonblocking),
            pseudo_path: SockFs::new_path(),
        }))
    }

    fn try_accept(&self) -> Result<(Arc<dyn FileLike>, SocketAddr)> {
        let state = self.state.read();
        let State::Listen(pair) = &*state else {
            return_errno_with_message!(Errno::EINVAL, "the socket is not listening");
        };

        if pair.framev_listening && pair.framev.poll(IoEvents::IN, None).contains(IoEvents::IN) {
            return pair.framev.accept();
        }
        if pair.virtio_listening && pair.virtio.poll(IoEvents::IN, None).contains(IoEvents::IN) {
            return pair.virtio.accept();
        }

        return_errno_with_message!(Errno::EAGAIN, "no pending vsock connection");
    }

    fn connected_provider(&self) -> Result<Provider> {
        let state = self.state.read();
        match &*state {
            State::Connected(provider) => Ok(provider.clone()),
            State::Init(_) | State::Listen(_) => {
                return_errno_with_message!(Errno::ENOTCONN, "the socket is not connected")
            }
        }
    }

    fn choose_connect_provider(&self, vsock_addr: VsockSocketAddr) -> Result<Provider> {
        let state = self.state.read();
        let State::Init(pair) = &*state else {
            return_errno_with_message!(Errno::EINVAL, "the socket cannot start a new connection");
        };

        if crate::net::socket::framevsock::is_framevm_cid(vsock_addr.cid.into()) {
            Ok(Provider::FrameV(pair.framev.clone()))
        } else {
            Ok(Provider::Virtio(pair.virtio.clone()))
        }
    }
}

impl Clone for Provider {
    fn clone(&self) -> Self {
        match self {
            Self::Virtio(socket) => Self::Virtio(socket.clone()),
            Self::FrameV(socket) => Self::FrameV(socket.clone()),
        }
    }
}

impl ProviderPair {
    fn new(is_nonblocking: bool) -> Result<Self> {
        Ok(Self {
            virtio: VsockStreamSocket::new(is_nonblocking)?,
            framev: Arc::new(FrameVsockStreamSocket::new(is_nonblocking)?),
            virtio_bound: false,
            framev_bound: false,
            virtio_listening: false,
            framev_listening: false,
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) {
        self.virtio.set_nonblocking(nonblocking);
        self.framev.set_nonblocking(nonblocking);
    }

    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        let Some(poller) = poller else {
            let framev_events = self.poll_framev(mask, None);
            let virtio_events = self.poll_virtio(mask, None);
            return (framev_events | virtio_events) & mask;
        };

        let framev_events = self.poll_framev(mask, Some(&mut *poller));
        let virtio_events = self.poll_virtio(mask, Some(poller));
        (framev_events | virtio_events) & mask
    }

    fn poll_framev(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        if !mask.contains(IoEvents::IN) || self.framev_listening {
            return self.framev.poll(mask, poller);
        }
        IoEvents::empty()
    }

    fn poll_virtio(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        if !mask.contains(IoEvents::IN) || self.virtio_listening {
            return self.virtio.poll(mask, poller);
        }
        IoEvents::empty()
    }

    fn has_bound_provider(&self) -> bool {
        self.virtio_bound || self.framev_bound
    }

    fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        self.virtio.get_option(option)
    }

    fn set_option(&self, option: &dyn SocketOption) -> Result<()> {
        self.virtio.set_option(option)?;
        self.framev.set_option(option)
    }
}

impl Provider {
    fn set_nonblocking(&self, nonblocking: bool) {
        match self {
            Self::Virtio(socket) => socket.set_nonblocking(nonblocking),
            Self::FrameV(socket) => socket.set_nonblocking(nonblocking),
        }
    }

    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        match self {
            Self::Virtio(socket) => socket.poll(mask, poller),
            Self::FrameV(socket) => socket.poll(mask, poller),
        }
    }

    fn shutdown(&self, cmd: SockShutdownCmd) -> Result<()> {
        match self {
            Self::Virtio(socket) => socket.shutdown(cmd),
            Self::FrameV(socket) => socket.shutdown(cmd),
        }
    }

    fn connect(&self, socket_addr: SocketAddr) -> Result<()> {
        match self {
            Self::Virtio(socket) => socket.connect(socket_addr),
            Self::FrameV(socket) => socket.connect(socket_addr),
        }
    }

    fn addr(&self) -> Result<SocketAddr> {
        match self {
            Self::Virtio(socket) => socket.addr(),
            Self::FrameV(socket) => socket.addr(),
        }
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        match self {
            Self::Virtio(socket) => socket.peer_addr(),
            Self::FrameV(socket) => socket.peer_addr(),
        }
    }

    fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        match self {
            Self::Virtio(socket) => socket.get_option(option),
            Self::FrameV(socket) => socket.get_option(option),
        }
    }

    fn set_option(&self, option: &dyn SocketOption) -> Result<()> {
        match self {
            Self::Virtio(socket) => socket.set_option(option),
            Self::FrameV(socket) => socket.set_option(option),
        }
    }

    fn sendmsg(
        &self,
        reader: &mut dyn MultiRead,
        message_header: MessageHeader,
        flags: SendRecvFlags,
    ) -> Result<usize> {
        match self {
            Self::Virtio(socket) => socket.sendmsg(reader, message_header, flags),
            Self::FrameV(socket) => socket.sendmsg(reader, message_header, flags),
        }
    }

    fn recvmsg(
        &self,
        writer: &mut dyn MultiWrite,
        flags: SendRecvFlags,
    ) -> Result<(usize, MessageHeader)> {
        match self {
            Self::Virtio(socket) => socket.recvmsg(writer, flags),
            Self::FrameV(socket) => socket.recvmsg(writer, flags),
        }
    }
}

impl Pollable for VsockMuxStreamSocket {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        let state = self.state.read();
        match &*state {
            State::Init(pair) | State::Listen(pair) => pair.poll(mask, poller),
            State::Connected(provider) => provider.poll(mask, poller),
        }
    }
}

impl SocketPrivate for VsockMuxStreamSocket {
    fn is_nonblocking(&self) -> bool {
        self.is_nonblocking.load(Ordering::Relaxed)
    }

    fn set_nonblocking(&self, nonblocking: bool) {
        self.is_nonblocking.store(nonblocking, Ordering::Relaxed);
        let state = self.state.read();
        match &*state {
            State::Init(pair) | State::Listen(pair) => pair.set_nonblocking(nonblocking),
            State::Connected(provider) => provider.set_nonblocking(nonblocking),
        }
    }
}

impl Socket for VsockMuxStreamSocket {
    fn bind(&self, socket_addr: SocketAddr) -> Result<()> {
        let vsock_addr = VsockSocketAddr::try_from(socket_addr)?;
        let mut state = self.state.write();
        let State::Init(pair) = &mut *state else {
            return_errno_with_message!(Errno::EINVAL, "the socket is not bindable");
        };

        let virtio_result = pair.virtio.bind(SocketAddr::Vsock(vsock_addr));
        let framev_result = pair.framev.bind(SocketAddr::Vsock(vsock_addr));
        pair.virtio_bound = virtio_result.is_ok();
        pair.framev_bound = framev_result.is_ok();

        if pair.has_bound_provider() {
            return Ok(());
        }

        *state = State::Init(ProviderPair::new(self.is_nonblocking())?);
        virtio_result.and(framev_result)
    }

    fn connect(&self, socket_addr: SocketAddr) -> Result<()> {
        let vsock_addr = VsockSocketAddr::try_from(socket_addr)?;
        let provider = self.choose_connect_provider(vsock_addr)?;
        provider.connect(SocketAddr::Vsock(vsock_addr))?;
        *self.state.write() = State::Connected(provider);
        Ok(())
    }

    fn listen(&self, backlog: usize) -> Result<()> {
        let mut state = self.state.write();
        let was_listening = match &*state {
            State::Init(_) => false,
            State::Listen(_) => true,
            State::Connected(_) => {
                return_errno_with_message!(Errno::EINVAL, "the socket is already connected")
            }
        };
        let (State::Init(pair) | State::Listen(pair)) = &mut *state else {
            unreachable!();
        };

        let should_listen_virtio = pair.virtio_bound || !pair.has_bound_provider();
        let should_listen_framev = pair.framev_bound || !pair.has_bound_provider();
        let virtio_result = if should_listen_virtio {
            pair.virtio.listen(backlog)
        } else {
            Ok(())
        };
        let framev_result = if should_listen_framev {
            pair.framev.listen(backlog)
        } else {
            Ok(())
        };

        if should_listen_virtio && virtio_result.is_ok() {
            pair.virtio_listening = true;
        }
        if should_listen_framev && framev_result.is_ok() {
            pair.framev_listening = true;
        }
        if !pair.virtio_listening && !pair.framev_listening {
            *state = State::Init(ProviderPair::new(self.is_nonblocking())?);
            return virtio_result.and(framev_result);
        }

        if was_listening {
            return Ok(());
        }

        let State::Init(pair) = core::mem::replace(
            &mut *state,
            State::Init(ProviderPair::new(self.is_nonblocking())?),
        ) else {
            unreachable!();
        };
        *state = State::Listen(pair);
        Ok(())
    }

    fn accept(&self) -> Result<(Arc<dyn FileLike>, SocketAddr)> {
        self.block_on(IoEvents::IN, || self.try_accept())
    }

    fn shutdown(&self, cmd: SockShutdownCmd) -> Result<()> {
        self.connected_provider()?.shutdown(cmd)
    }

    fn addr(&self) -> Result<SocketAddr> {
        let state = self.state.read();
        match &*state {
            State::Init(pair) | State::Listen(pair) => pair.virtio.addr(),
            State::Connected(provider) => provider.addr(),
        }
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        self.connected_provider()?.peer_addr()
    }

    fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        let state = self.state.read();
        match &*state {
            State::Init(pair) | State::Listen(pair) => pair.get_option(option),
            State::Connected(provider) => provider.get_option(option),
        }
    }

    fn set_option(&self, option: &dyn SocketOption) -> Result<()> {
        let state = self.state.read();
        match &*state {
            State::Init(pair) | State::Listen(pair) => pair.set_option(option),
            State::Connected(provider) => provider.set_option(option),
        }
    }

    fn sendmsg(
        &self,
        reader: &mut dyn MultiRead,
        message_header: MessageHeader,
        flags: SendRecvFlags,
    ) -> Result<usize> {
        self.connected_provider()?
            .sendmsg(reader, message_header, flags)
    }

    fn recvmsg(
        &self,
        writer: &mut dyn MultiWrite,
        flags: SendRecvFlags,
    ) -> Result<(usize, MessageHeader)> {
        self.connected_provider()?.recvmsg(writer, flags)
    }

    fn pseudo_path(&self) -> &Path {
        &self.pseudo_path
    }
}
