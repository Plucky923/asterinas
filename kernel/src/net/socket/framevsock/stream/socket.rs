// SPDX-License-Identifier: MPL-2.0

//! Host-side stream socket wrapper for FrameVsock.

use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use aster_framevsock::flow_control::DEFAULT_BUF_ALLOC;

use super::{connected::Connected, connecting::Connecting, init::Init, listen::Listen};
use crate::{
    events::IoEvents,
    fs::{file::FileLike, pseudofs::SockFs, vfs::path::Path},
    net::socket::{
        Socket,
        framevsock::{
            FRAME_VSOCK_GLOBAL,
            addr::{self, FrameVsockAddr},
            transport::{DEFAULT_CONNECT_TIMEOUT, FrameVsockSpace},
        },
        options::{Error as SocketError, SocketOption, macros::sock_option_mut},
        private::SocketPrivate,
        util::{
            MessageHeader, SendRecvFlags, SockShutdownCmd, SocketAddr,
            options::{GetSocketLevelOption, SetSocketLevelOption, SocketOptionSet},
        },
    },
    prelude::*,
    process::signal::{PollHandle, Pollable, Poller},
    thread::Thread,
    util::{MultiRead, MultiWrite},
};

pub struct FrameVsockStreamSocket {
    status: RwLock<Status>,
    is_nonblocking: AtomicBool,
    pseudo_path: Path,
    options: RwLock<SocketOptionSet>,
}

enum Status {
    Init(Arc<Init>),
    Connecting(ConnectAttempt),
    Listen(Arc<Listen>),
    Connected(Arc<Connected>),
}

#[derive(Clone)]
struct ConnectAttempt {
    init: Arc<Init>,
    connecting: Arc<Connecting>,
    auto_bound: bool,
}

const SEND_RETRY_TIMEOUT: Duration = Duration::from_millis(1);
const SEND_QUEUE_BLOCK_TIMEOUT_MIN_MS: u64 = 2;
const SEND_QUEUE_BLOCK_TIMEOUT_MAX_MS: u64 = 16;

impl FrameVsockStreamSocket {
    pub fn new(nonblocking: bool) -> Result<Self> {
        let init = Arc::new(Init::new());
        Ok(Self {
            status: RwLock::new(Status::Init(init)),
            is_nonblocking: AtomicBool::new(nonblocking),
            pseudo_path: SockFs::new_path(),
            options: RwLock::new(SocketOptionSet::default()),
        })
    }

    pub(super) fn new_from_connected(connected: Arc<Connected>) -> Self {
        Self {
            status: RwLock::new(Status::Connected(connected)),
            is_nonblocking: AtomicBool::new(false),
            pseudo_path: SockFs::new_path(),
            options: RwLock::new(SocketOptionSet::default()),
        }
    }

    fn framevsock_space() -> Result<&'static FrameVsockSpace> {
        FRAME_VSOCK_GLOBAL
            .get()
            .map(Arc::as_ref)
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "FrameVsock is not initialized"))
    }

    fn start_connect(&self, remote_addr: FrameVsockAddr) -> Result<ConnectAttempt> {
        let init = match &*self.status.read() {
            Status::Init(init) => init.clone(),
            Status::Connecting(_) => {
                return_errno_with_message!(Errno::EALREADY, "the socket is connecting");
            }
            Status::Listen(_) => {
                return_errno_with_message!(Errno::EINVAL, "the socket is listening");
            }
            Status::Connected(_) => {
                return_errno_with_message!(Errno::EISCONN, "the socket is connected");
            }
        };

        let auto_bound = if let Some(addr) = init.bound_addr() {
            if addr == remote_addr {
                return_errno_with_message!(Errno::EINVAL, "connecting to self is invalid");
            }
            false
        } else {
            init.bind(FrameVsockAddr::any())?;
            true
        };

        let local_addr = init
            .bound_addr()
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "the socket is not bound"))?;
        let connecting = Arc::new(Connecting::new(remote_addr, local_addr));
        if let Err(error) =
            Self::framevsock_space()?.insert_connecting_socket(local_addr, connecting.clone())
        {
            if auto_bound {
                init.clear_bound_addr_if(local_addr);
            } else {
                connecting.preserve_local_port();
            }
            return Err(error);
        }

        Ok(ConnectAttempt {
            init,
            connecting,
            auto_bound,
        })
    }

    fn fail_connect(&self, attempt: &ConnectAttempt) {
        let Ok(vsockspace) = Self::framevsock_space() else {
            return;
        };

        let local_addr = attempt.connecting.local_addr();
        let _ = vsockspace.remove_connecting_socket(&local_addr);
        if attempt.auto_bound {
            attempt.init.clear_bound_addr_if(local_addr);
        } else {
            attempt.connecting.preserve_local_port();
        }
    }

    fn send_connect_request(
        &self,
        attempt: &ConnectAttempt,
        remote_addr: FrameVsockAddr,
    ) -> Result<()> {
        use aster_framevsock::create_request_with_credit;

        use crate::net::socket::framevsock::backend;

        let local_addr = attempt.connecting.local_addr();
        let request_packet = create_request_with_credit(
            local_addr.cid,
            local_addr.port,
            remote_addr.cid,
            remote_addr.port,
            DEFAULT_BUF_ALLOC,
            0,
        );

        if backend::send_control(0, request_packet).is_err() {
            self.fail_connect(attempt);
            return_errno_with_message!(Errno::EIO, "failed to send connection request");
        }

        Ok(())
    }

    fn wait_for_connect(&self, attempt: ConnectAttempt) -> Result<()> {
        let connecting = attempt.connecting.clone();
        let mut poller = Poller::new(Some(&DEFAULT_CONNECT_TIMEOUT));
        if !connecting
            .poll(IoEvents::OUT, Some(poller.as_handle_mut()))
            .contains(IoEvents::OUT)
        {
            match poller.wait() {
                Ok(_) => {}
                Err(e) if e.error() == Errno::ETIME => {
                    self.fail_connect(&attempt);
                    self.restore_init_after_failed_connect(&attempt);
                    return_errno_with_message!(Errno::ETIMEDOUT, "connection timed out");
                }
                Err(e) => {
                    self.fail_connect(&attempt);
                    self.restore_init_after_failed_connect(&attempt);
                    return Err(e);
                }
            }
        }

        self.finish_connect(attempt)
    }

    fn restore_init_after_failed_connect(&self, attempt: &ConnectAttempt) {
        let mut status = self.status.write();
        if matches!(&*status, Status::Connecting(current) if Arc::ptr_eq(&current.connecting, &attempt.connecting))
        {
            *status = Status::Init(attempt.init.clone());
        }
    }

    fn finish_connect(&self, attempt: ConnectAttempt) -> Result<()> {
        let connecting = attempt.connecting.clone();
        if !connecting.is_connected() {
            self.fail_connect(&attempt);
            self.restore_init_after_failed_connect(&attempt);
            return_errno_with_message!(Errno::ECONNREFUSED, "connection refused");
        }

        let connected = Arc::new(Connected::new_with_credit(
            connecting.peer_addr(),
            connecting.local_addr(),
            connecting.peer_buf_alloc(),
            connecting.peer_fwd_cnt(),
        ));

        let vsockspace = Self::framevsock_space()?;
        let _ = vsockspace.remove_connecting_socket(&connecting.local_addr());
        if let Err(error) = vsockspace.insert_connected_socket(connected.id(), connected.clone()) {
            let local_addr = connecting.local_addr();
            if attempt.auto_bound {
                attempt.init.clear_bound_addr_if(local_addr);
                let _ = vsockspace.recycle_port(&local_addr.port);
            } else {
                connecting.preserve_local_port();
            }
            self.restore_init_after_failed_connect(&attempt);
            return Err(error);
        }
        *self.status.write() = Status::Connected(connected);

        Ok(())
    }

    fn try_accept(&self) -> Result<(Arc<dyn FileLike>, SocketAddr)> {
        let listen = match &*self.status.read() {
            Status::Listen(listen) => listen.clone(),
            Status::Init(_) | Status::Connecting(_) | Status::Connected(_) => {
                return_errno_with_message!(Errno::EINVAL, "the socket is not listening");
            }
        };

        let connected = listen.try_accept()?;

        let peer_addr = addr::to_socketaddr(connected.peer_addr())?;

        let socket = Arc::new(FrameVsockStreamSocket::new_from_connected(connected));
        Ok((socket, peer_addr))
    }

    fn send(&self, reader: &mut dyn MultiRead, flags: SendRecvFlags) -> Result<usize> {
        let connected = match &*self.status.read() {
            Status::Connected(connected) => connected.clone(),
            Status::Init(_) | Status::Connecting(_) | Status::Listen(_) => {
                return_errno_with_message!(Errno::ENOTCONN, "the socket is not connected");
            }
        };

        if self.is_nonblocking() {
            let mut pending_packet = None;
            return connected.try_send(reader, flags, &mut pending_packet);
        }

        let mut pending_packet = None;
        let mut queue_block_timeout_ms = SEND_QUEUE_BLOCK_TIMEOUT_MIN_MS;

        loop {
            let epoch_before = connected.tx_progress_epoch();

            match connected.try_send(reader, flags, &mut pending_packet) {
                Ok(sent) => return Ok(sent),
                Err(err) if err.error() == Errno::EAGAIN => {
                    // Fall through to event wait.
                }
                Err(err) => return Err(err),
            }

            let tx_blocked_on_queue = connected.is_tx_blocked_on_queue();
            let retry_timeout = if tx_blocked_on_queue {
                Duration::from_millis(queue_block_timeout_ms)
            } else {
                queue_block_timeout_ms = SEND_QUEUE_BLOCK_TIMEOUT_MIN_MS;
                SEND_RETRY_TIMEOUT
            };

            let mut poller = Poller::new(Some(&retry_timeout));
            if connected
                .poll(IoEvents::OUT, Some(poller.as_handle_mut()))
                .is_empty()
            {
                // Avoid missed-wakeup race: if progress already happened after
                // we observed EAGAIN, skip blocking wait and retry immediately.
                let epoch_after_register = connected.tx_progress_epoch();
                if epoch_after_register == epoch_before {
                    match poller.wait() {
                        Ok(_) => {
                            queue_block_timeout_ms = SEND_QUEUE_BLOCK_TIMEOUT_MIN_MS;
                        }
                        Err(e) if e.error() == Errno::ETIME => {
                            let blocked_after_timeout = connected.is_tx_blocked_on_queue();
                            if blocked_after_timeout {
                                queue_block_timeout_ms = (queue_block_timeout_ms << 1)
                                    .min(SEND_QUEUE_BLOCK_TIMEOUT_MAX_MS);
                            } else {
                                queue_block_timeout_ms = SEND_QUEUE_BLOCK_TIMEOUT_MIN_MS;
                            }
                            // Progress can be time-driven (e.g., credit-request retry)
                            // without generating a new OUT edge. Retry proactively.
                            //
                            // Under tiny-packet queue pressure, aggressive retry loops can
                            // starve FrameVM receiver execution on shared CPUs. Yield here to
                            // guarantee the peer gets a scheduling chance to drain.
                            Thread::yield_now();
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }

    fn try_recv(
        &self,
        writer: &mut dyn MultiWrite,
        _flags: SendRecvFlags,
    ) -> Result<(usize, SocketAddr)> {
        let connected = match &*self.status.read() {
            Status::Connected(connected) => connected.clone(),
            Status::Init(_) | Status::Connecting(_) | Status::Listen(_) => {
                return_errno_with_message!(Errno::ENOTCONN, "the socket is not connected");
            }
        };

        let read_size = connected.try_recv(writer)?;

        let peer_addr = self.peer_addr()?;
        // If buffer is now empty and the peer requested shutdown, finish shutting down the
        // connection.
        if connected.should_close()
            && let Err(e) = self.shutdown(SockShutdownCmd::SHUT_RDWR)
        {
            debug!("The error is {:?}", e);
        }

        Ok((read_size, peer_addr))
    }

    fn test_and_clear_error(&self) -> Option<Error> {
        match &*self.status.read() {
            Status::Connected(connected) => connected.test_and_clear_error(),
            Status::Init(_) | Status::Connecting(_) | Status::Listen(_) => None,
        }
    }
}

impl Pollable for FrameVsockStreamSocket {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        match &*self.status.read() {
            Status::Init(init) => init.poll(mask, poller),
            Status::Connecting(attempt) => attempt.connecting.poll(mask, poller),
            Status::Listen(listen) => listen.poll(mask, poller),
            Status::Connected(connected) => connected.poll(mask, poller),
        }
    }
}

impl SocketPrivate for FrameVsockStreamSocket {
    fn is_nonblocking(&self) -> bool {
        self.is_nonblocking.load(Ordering::Relaxed)
    }

    fn set_nonblocking(&self, nonblocking: bool) {
        self.is_nonblocking.store(nonblocking, Ordering::Relaxed);
    }
}

impl GetSocketLevelOption for FrameVsockStreamSocket {
    fn is_listening(&self) -> bool {
        matches!(&*self.status.read(), Status::Listen(_))
    }
}

impl SetSocketLevelOption for FrameVsockStreamSocket {}

impl Socket for FrameVsockStreamSocket {
    fn bind(&self, sockaddr: SocketAddr) -> Result<()> {
        let addr = addr::try_from_socketaddr(sockaddr)?;
        let inner = self.status.read();
        match &*inner {
            Status::Init(init) => init.bind(addr),
            Status::Connecting(_) | Status::Listen(_) | Status::Connected(_) => {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "cannot bind a connecting, listening, or connected socket"
                )
            }
        }
    }

    fn connect(&self, sockaddr: SocketAddr) -> Result<()> {
        let remote_addr = addr::try_from_socketaddr(sockaddr)?;
        if let Status::Connecting(attempt) = &*self.status.read() {
            if attempt.connecting.has_result() {
                return self.finish_connect(attempt.clone());
            }
            if self.is_nonblocking() {
                return_errno_with_message!(Errno::EALREADY, "the socket is connecting");
            }
            return self.wait_for_connect(attempt.clone());
        }

        let attempt = self.start_connect(remote_addr)?;
        self.send_connect_request(&attempt, remote_addr)?;

        if self.is_nonblocking() {
            *self.status.write() = Status::Connecting(attempt);
            return_errno_with_message!(Errno::EINPROGRESS, "the socket is connecting");
        }

        self.wait_for_connect(attempt)
    }

    fn listen(&self, backlog: usize) -> Result<()> {
        let init = match &*self.status.read() {
            Status::Init(init) => init.clone(),
            Status::Connecting(_) => {
                return_errno_with_message!(Errno::EINVAL, "the socket is connecting");
            }
            Status::Listen(listen) => {
                listen.set_backlog(backlog);
                return Ok(());
            }
            Status::Connected(_) => {
                return_errno_with_message!(Errno::EISCONN, "the socket is already connected");
            }
        };
        let addr = init.bound_addr().ok_or(Error::with_message(
            Errno::EINVAL,
            "the socket is not bound",
        ))?;
        let listen = Arc::new(Listen::new(addr, backlog));

        // push listen socket into vsockspace
        Self::framevsock_space()?.insert_listen_socket(listen.addr(), listen.clone())?;
        *self.status.write() = Status::Listen(listen);

        Ok(())
    }

    fn accept(&self) -> Result<(Arc<dyn FileLike>, SocketAddr)> {
        self.block_on(IoEvents::IN, || self.try_accept())
    }

    fn shutdown(&self, cmd: SockShutdownCmd) -> Result<()> {
        match &*self.status.read() {
            Status::Connected(connected) => connected.shutdown(cmd),
            Status::Init(_) | Status::Connecting(_) | Status::Listen(_) => {
                return_errno_with_message!(Errno::ENOTCONN, "the socket is not connected");
            }
        }
    }

    fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        sock_option_mut!(match option {
            socket_errors @ SocketError => {
                socket_errors.set(self.test_and_clear_error());
                return Ok(());
            }
            _ => {}
        });

        self.options.read().get_option(option, self)
    }

    fn set_option(&self, option: &dyn SocketOption) -> Result<()> {
        self.options.write().set_option(option, self)?;
        Ok(())
    }

    fn sendmsg(
        &self,
        reader: &mut dyn MultiRead,
        message_header: MessageHeader,
        flags: SendRecvFlags,
    ) -> Result<usize> {
        // TODO: Deal with flags
        if !flags.is_all_supported() {
            warn!("unsupported flags: {:?}", flags);
        }

        let MessageHeader {
            control_messages,
            addr,
        } = message_header;

        if addr.is_some() {
            let status = self.status.read();
            match &*status {
                Status::Init(_) | Status::Connecting(_) | Status::Listen(_) => {
                    return_errno_with_message!(
                        Errno::EOPNOTSUPP,
                        "sending to a specific address is not allowed on FrameVsock stream sockets"
                    );
                }
                Status::Connected(_) => {
                    return_errno_with_message!(
                        Errno::EISCONN,
                        "sending to a specific address is not allowed on FrameVsock stream sockets"
                    );
                }
            }
        }

        if !control_messages.is_empty() {
            warn!("sending control message is not supported");
        }

        self.send(reader, flags)
    }

    fn recvmsg(
        &self,
        writer: &mut dyn MultiWrite,
        flags: SendRecvFlags,
    ) -> Result<(usize, MessageHeader)> {
        // TODO: Deal with flags
        if !flags.is_all_supported() {
            warn!("unsupported flags: {:?}", flags);
        }

        let (received_bytes, _) = self.block_on(IoEvents::IN, || self.try_recv(writer, flags))?;

        let message_header = MessageHeader::new(None, Vec::new());

        Ok((received_bytes, message_header))
    }

    fn addr(&self) -> Result<SocketAddr> {
        let inner = self.status.read();
        let addr = match &*inner {
            Status::Init(init) => init.bound_addr(),
            Status::Connecting(attempt) => Some(attempt.connecting.local_addr()),
            Status::Listen(listen) => Some(listen.addr()),
            Status::Connected(connected) => Some(connected.local_addr().into()),
        };
        addr::to_socketaddr(addr.unwrap_or_else(FrameVsockAddr::any))
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        let inner = self.status.read();
        if let Status::Connected(connected) = &*inner {
            addr::to_socketaddr(connected.peer_addr())
        } else {
            return_errno_with_message!(Errno::ENOTCONN, "the socket is not connected");
        }
    }

    fn pseudo_path(&self) -> &Path {
        &self.pseudo_path
    }
}

impl Drop for FrameVsockStreamSocket {
    fn drop(&mut self) {
        let Some(vsockspace) = FRAME_VSOCK_GLOBAL.get() else {
            return;
        };
        let inner = self.status.get_mut();
        match inner {
            Status::Init(init) => {
                if let Some(addr) = init.bound_addr() {
                    vsockspace.recycle_port(&addr.port);
                }
            }
            Status::Connecting(_) => {}
            Status::Listen(listen) => {
                vsockspace.recycle_port(&listen.addr().port);
                vsockspace.remove_listen_socket(&listen.addr());
            }
            Status::Connected(connected) => {
                if !connected.is_closed() {
                    let _ = connected.shutdown(SockShutdownCmd::SHUT_RDWR);
                }
                vsockspace.remove_connected_socket(&connected.id());
                if connected.owns_local_port() {
                    vsockspace.recycle_port(&connected.local_addr().port);
                }
            }
        }
    }
}
