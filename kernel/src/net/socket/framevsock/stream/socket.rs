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
    fs::{file_handle::FileLike, path::Path, pseudofs::SockFs},
    net::socket::{
        Socket,
        framevsock::{
            FRAME_VSOCK_GLOBAL,
            addr::{self, FrameVsockAddr},
        },
        options::SocketOption,
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

pub enum Status {
    Init(Arc<Init>),
    Listen(Arc<Listen>),
    Connected(Arc<Connected>),
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

    fn try_accept(&self) -> Result<(Arc<dyn FileLike>, SocketAddr)> {
        let listen = match &*self.status.read() {
            Status::Listen(listen) => listen.clone(),
            Status::Init(_) | Status::Connected(_) => {
                return_errno_with_message!(Errno::EINVAL, "the socket is not listening");
            }
        };

        let connected = listen.try_accept()?;

        // Return the real peer address (vsock-compatible behavior).
        let peer_addr = SocketAddr::FrameVsock(connected.peer_addr());

        let vsockspace = FRAME_VSOCK_GLOBAL
            .get()
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "FrameVsock is not initialized"))?;
        vsockspace.insert_connected_socket(connected.id(), connected.clone());

        // TODO: Pass the peer credit info to the new socket?
        // The connected socket already has it.

        let socket = Arc::new(FrameVsockStreamSocket::new_from_connected(connected));
        Ok((socket, peer_addr))
    }

    fn send(&self, reader: &mut dyn MultiRead, flags: SendRecvFlags) -> Result<usize> {
        let connected = match &*self.status.read() {
            Status::Connected(connected) => connected.clone(),
            Status::Init(_) | Status::Listen(_) => {
                return_errno_with_message!(Errno::EINVAL, "the socket is not connected");
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
            Status::Init(_) | Status::Listen(_) => {
                return_errno_with_message!(Errno::EINVAL, "the socket is not connected");
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
}

impl Pollable for FrameVsockStreamSocket {
    fn poll(&self, mask: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        match &*self.status.read() {
            Status::Init(init) => init.poll(mask, poller),
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
            Status::Listen(_) | Status::Connected(_) => {
                return_errno_with_message!(
                    Errno::EINVAL,
                    "cannot bind a listening or connected socket"
                )
            }
        }
    }

    fn connect(&self, sockaddr: SocketAddr) -> Result<()> {
        use core::time::Duration;

        use aster_framevisor::vsock as framevisor_vsock;
        use aster_framevsock::create_request_with_credit;

        use crate::process::signal::Poller;

        let init = match &*self.status.read() {
            Status::Init(init) => init.clone(),
            Status::Listen(_) => {
                return_errno_with_message!(Errno::EINVAL, "the socket is listened");
            }
            Status::Connected(_) => {
                return_errno_with_message!(Errno::EINVAL, "the socket is connected");
            }
        };
        let remote_addr = addr::try_from_socketaddr(sockaddr)?;
        let local_addr = init.bound_addr();
        if let Some(addr) = local_addr {
            if addr == remote_addr {
                return_errno_with_message!(Errno::EINVAL, "try to connect to self is invalid");
            }
        } else {
            init.bind(FrameVsockAddr::any())?;
        }

        let local_addr = init
            .bound_addr()
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "the socket is not bound"))?;
        let connecting = Arc::new(Connecting::new(remote_addr, local_addr));
        let vsockspace = FRAME_VSOCK_GLOBAL
            .get()
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "FrameVsock is not initialized"))?;
        vsockspace.insert_connecting_socket(connecting.local_addr(), connecting.clone());

        // Send connection request to Guest with our credit info
        let request_packet = create_request_with_credit(
            local_addr.cid,
            local_addr.port,
            remote_addr.cid,
            remote_addr.port,
            DEFAULT_BUF_ALLOC,
            0, // Initial fwd_cnt is 0
        );

        // Select vCPU 0 for connection request (Guest will handle it)
        if framevisor_vsock::deliver_control_packet(0, request_packet).is_err() {
            // Connecting::drop() will handle cleanup (remove from vsockspace, recycle port)
            return_errno_with_message!(Errno::EIO, "failed to send connection request");
        }

        // Wait for response from Guest with timeout
        // Use a short timeout since the virtual IRQ handler runs synchronously
        const CONNECT_TIMEOUT: Duration = Duration::from_millis(100);
        let mut poller = Poller::new(Some(&CONNECT_TIMEOUT));
        if !connecting
            .poll(IoEvents::IN, Some(poller.as_handle_mut()))
            .contains(IoEvents::IN)
        {
            // Block waiting for response with timeout
            match poller.wait() {
                Ok(_) => {}
                Err(e) if e.error() == Errno::ETIME => {
                    // Timeout - Connecting::drop() will handle cleanup
                    return_errno_with_message!(Errno::ETIMEDOUT, "connection timed out");
                }
                Err(e) => {
                    // Connecting::drop() will handle cleanup
                    return Err(e);
                }
            }
        }

        // Check if connection was successful
        if !connecting.is_connected() {
            // Connecting::drop() will handle cleanup
            return_errno_with_message!(Errno::ECONNREFUSED, "connection refused");
        }

        // Move to connected state with peer credit info
        let connected = Arc::new(Connected::new_with_credit(
            connecting.peer_addr(),
            connecting.local_addr(),
            connecting.peer_buf_alloc(),
            connecting.peer_fwd_cnt(),
        ));
        *self.status.write() = Status::Connected(connected.clone());

        vsockspace.remove_connecting_socket(&connecting.local_addr());
        vsockspace.insert_connected_socket(connected.id(), connected);

        Ok(())
    }

    fn listen(&self, backlog: usize) -> Result<()> {
        let init = match &*self.status.read() {
            Status::Init(init) => init.clone(),
            Status::Listen(_) => {
                return_errno_with_message!(Errno::EINVAL, "the socket is already listened");
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
        *self.status.write() = Status::Listen(listen.clone());

        // push listen socket into vsockspace
        let vsockspace = FRAME_VSOCK_GLOBAL
            .get()
            .ok_or_else(|| Error::with_message(Errno::EINVAL, "FrameVsock is not initialized"))?;
        vsockspace.insert_listen_socket(listen.addr(), listen);

        Ok(())
    }

    fn accept(&self) -> Result<(Arc<dyn FileLike>, SocketAddr)> {
        self.block_on(IoEvents::IN, || self.try_accept())
    }

    fn shutdown(&self, cmd: SockShutdownCmd) -> Result<()> {
        match &*self.status.read() {
            Status::Connected(connected) => connected.shutdown(cmd),
            Status::Init(_) | Status::Listen(_) => {
                return_errno_with_message!(Errno::EINVAL, "the socket is not connected");
            }
        }
    }

    fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
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
            control_messages, ..
        } = message_header;

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

        let messsge_header = MessageHeader::new(None, Vec::new());

        Ok((received_bytes, messsge_header))
    }

    fn addr(&self) -> Result<SocketAddr> {
        let inner = self.status.read();
        let addr = match &*inner {
            Status::Init(init) => init.bound_addr(),
            Status::Listen(listen) => Some(listen.addr()),
            Status::Connected(connected) => Some(connected.local_addr().into()),
        };
        // FIXME: Support conversion to generic SocketAddr
        addr.map(Into::<SocketAddr>::into)
            .ok_or(Error::with_message(
                Errno::EINVAL,
                "The socket does not bind to addr",
            ))
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        let inner = self.status.read();
        if let Status::Connected(connected) = &*inner {
            // FIXME: Support conversion to generic SocketAddr
            Ok(Into::<FrameVsockAddr>::into(connected.peer_addr()).into())
        } else {
            return_errno_with_message!(Errno::EINVAL, "the socket is not connected");
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
            Status::Listen(listen) => {
                vsockspace.recycle_port(&listen.addr().port);
                vsockspace.remove_listen_socket(&listen.addr());
            }
            Status::Connected(connected) => {
                if !connected.is_closed() {
                    // Send RST to peer to reset the connection
                    let _ = connected.reset();
                }
                vsockspace.remove_connected_socket(&connected.id());
                vsockspace.recycle_port(&connected.local_addr().port);
            }
        }
    }
}
