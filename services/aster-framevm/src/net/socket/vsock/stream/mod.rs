// SPDX-License-Identifier: MPL-2.0

//! Stream socket state for Linux `AF_VSOCK`.

mod connected;
mod connecting;
mod init;
mod listen;

use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    mem,
    sync::atomic::{AtomicBool, Ordering},
};

use aster_softirq::Taskless;
use connected::ConnectedStream;
use connecting::{ConnResult, ConnectingStream};
use init::InitStream;
use listen::ListenStream;
use ostd::sync::{Once, SpinLock, WaitQueue};

use super::{VMADDR_CID_ANY, VMADDR_PORT_ANY, VsockSocketAddr};
use crate::{
    error::{Errno, Error, Result},
    events::IoEvents,
    fs::{file::FileLike, pseudofs::SockFs, vfs::path::Path},
    net::socket::{
        MessageHeader, SendRecvFlags, SockShutdownCmd, Socket, SocketAddr,
        options::{Error as SocketError, SocketOption, macros::sock_option_mut},
        private::SocketPrivate,
    },
    pollee::{PollHandle, Pollable, Pollee},
    prelude::{VmReader, VmWriter},
    return_errno_with_message,
    util::{MultiRead, MultiWrite},
};

const VSOCK_STREAM_BUF_SIZE: u32 = 128 * 1024;

static RX_TASKLESS: Once<Arc<Taskless>> = Once::new();

/// A Linux `SOCK_STREAM` vsock endpoint.
pub struct VsockStreamSocket {
    state: SpinLock<VsockStreamState>,
    is_nonblocking: AtomicBool,
    pollee: Pollee,
    wait_queue: Arc<WaitQueue>,
    pseudo_path: Path,
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
            is_nonblocking: AtomicBool::new(is_nonblocking),
            pollee: Pollee::new(),
            wait_queue: Arc::new(WaitQueue::new()),
            pseudo_path: SockFs::new_path(),
        }
    }

    fn new_connected(
        connected_stream: ConnectedStream,
        _recv_buffer_size: u32,
        is_nonblocking: bool,
    ) -> Self {
        let socket = Self {
            state: SpinLock::new(VsockStreamState::Connected(connected_stream)),
            is_nonblocking: AtomicBool::new(is_nonblocking),
            pollee: Pollee::new(),
            wait_queue: Arc::new(WaitQueue::new()),
            pseudo_path: SockFs::new_path(),
        };
        if let VsockStreamState::Connected(connected_stream) = &*socket.state.lock() {
            connected_stream.register_waiters(&socket.pollee, &socket.wait_queue);
        }
        socket
    }

    fn check_io_events(&self) -> IoEvents {
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state, &self.pollee, &self.wait_queue);

        match &mut *state {
            VsockStreamState::Init(init_stream) => init_stream.check_io_events(),
            VsockStreamState::Connecting(connecting_stream) => connecting_stream.check_io_events(),
            VsockStreamState::Listen(listen_stream) => listen_stream.check_io_events(),
            VsockStreamState::Connected(connected_stream) => connected_stream.check_io_events(),
        }
    }

    fn test_and_clear_error(&self) -> Option<Error> {
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state, &self.pollee, &self.wait_queue);

        match &mut *state {
            VsockStreamState::Init(init_stream) => init_stream.test_and_clear_error(&self.pollee),
            VsockStreamState::Connecting(_)
            | VsockStreamState::Listen(_)
            | VsockStreamState::Connected(_) => None,
        }
    }

    fn update_state_locked(
        state: &mut VsockStreamState,
        pollee: &Pollee,
        wait_queue: &Arc<WaitQueue>,
    ) {
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

        *state = match connecting_stream.into_result(pollee, wait_queue) {
            ConnResult::Connecting(connecting_stream) => {
                VsockStreamState::Connecting(connecting_stream)
            }
            ConnResult::Connected(connected_stream) => {
                VsockStreamState::Connected(connected_stream)
            }
            ConnResult::Failed(init_stream) => VsockStreamState::Init(init_stream),
        };
        pollee.invalidate();
    }

    fn wait_for_connect(&self) -> Result<()> {
        self.set_wait_interest(IoEvents::OUT | IoEvents::ERR | IoEvents::HUP);
        let result = self.wait_queue.wait_until(|| {
            if let Some(result) = self.try_finish_connect() {
                return Some(result);
            }
            None
        });
        self.clear_wait_interest();
        result
    }

    fn try_finish_connect(&self) -> Option<Result<()>> {
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state, &self.pollee, &self.wait_queue);

        match &mut *state {
            VsockStreamState::Connected(_) => Some(Ok(())),
            VsockStreamState::Init(init_stream) => Some(Err(init_stream
                .test_and_clear_error(&self.pollee)
                .unwrap_or_else(|| Error::new(Errno::ECONNREFUSED)))),
            VsockStreamState::Connecting(_) => None,
            VsockStreamState::Listen(_) => Some(Err(Error::new(Errno::EINVAL))),
        }
    }

    fn should_wait(&self, flags: SendRecvFlags) -> bool {
        !self.is_nonblocking.load(Ordering::Relaxed) && !flags.contains(SendRecvFlags::MSG_DONTWAIT)
    }

    fn wait_for_io(&self, events: IoEvents) -> Result<()> {
        self.set_wait_interest(events);
        self.wait_queue.wait_until(|| {
            let ready = self.check_io_events();
            if ready.intersects(events) {
                return Some(ready);
            }
            None
        });
        self.clear_wait_interest();
        Ok(())
    }

    fn set_wait_interest(&self, events: IoEvents) {
        let state = self.state.lock();
        match &*state {
            VsockStreamState::Connecting(connecting_stream) => {
                connecting_stream.set_wait_interest(events);
            }
            VsockStreamState::Connected(connected_stream) => {
                connected_stream.set_wait_interest(events);
            }
            VsockStreamState::Init(_) | VsockStreamState::Listen(_) => {}
        }
    }

    fn clear_wait_interest(&self) {
        let state = self.state.lock();
        match &*state {
            VsockStreamState::Connecting(connecting_stream) => {
                connecting_stream.clear_wait_interest();
            }
            VsockStreamState::Connected(connected_stream) => {
                connected_stream.clear_wait_interest();
            }
            VsockStreamState::Init(_) | VsockStreamState::Listen(_) => {}
        }
    }

    fn try_sendmsg_once(
        &self,
        input: &[u8],
        has_addr: bool,
        flags: SendRecvFlags,
    ) -> Result<usize> {
        if has_addr {
            let mut state = self.state.lock();
            Self::update_state_locked(&mut *state, &self.pollee, &self.wait_queue);

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
        Self::update_state_locked(&mut *state, &self.pollee, &self.wait_queue);

        let VsockStreamState::Connected(connected_stream) = &*state else {
            let _ = input;
            return Err(Error::new(Errno::ENOTCONN));
        };
        connected_stream.sendmsg(input, flags)
    }

    fn try_recvmsg_once(
        &self,
        output: &mut [u8],
        flags: SendRecvFlags,
    ) -> Result<(usize, MessageHeader)> {
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state, &self.pollee, &self.wait_queue);

        let VsockStreamState::Connected(connected_stream) = &*state else {
            return Err(Error::new(Errno::ENOTCONN));
        };
        connected_stream.recvmsg(output, flags)
    }
}

impl Drop for VsockStreamSocket {
    fn drop(&mut self) {
        if let VsockStreamState::Connecting(connecting_stream) = &*self.state.lock() {
            connecting_stream.cleanup_flow();
        }
    }
}

pub(super) fn init_rx_taskless() {
    RX_TASKLESS.call_once(|| Taskless::new(process_rx_notification));
}

/// Schedules service-side RX work after a FrameV-sock notification.
///
/// The FrameV IRQ/IHT callback must only reach this scheduler hook. It must not
/// drain socket packets or listener queues directly; that data-path work is
/// owned by the FrameVM service `Taskless` callback below.
pub(super) fn schedule_rx_notification() {
    RX_TASKLESS
        .get()
        .expect("FrameV Sock RX taskless must be initialized")
        .schedule();
}

fn process_rx_notification() {
    if listen::drain_inbound_requests() {
        schedule_rx_notification();
    }
}

impl Pollable for VsockStreamSocket {
    fn poll(&self, events: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee
            .poll_with(events, poller, || self.check_io_events())
    }
}

impl SocketPrivate for VsockStreamSocket {
    fn is_nonblocking(&self) -> bool {
        self.is_nonblocking.load(Ordering::Relaxed)
    }

    fn set_nonblocking(&self, nonblocking: bool) {
        self.is_nonblocking.store(nonblocking, Ordering::Relaxed);
    }
}

impl Socket for VsockStreamSocket {
    fn bind(&self, socket_addr: SocketAddr) -> Result<()> {
        let addr = VsockSocketAddr::try_from(socket_addr)?;
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state, &self.pollee, &self.wait_queue);

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
        Self::update_state_locked(&mut *state, &self.pollee, &self.wait_queue);

        let old_state = mem::replace(&mut *state, VsockStreamState::Init(InitStream::new()));
        let (new_state, result, should_wait) = match old_state {
            VsockStreamState::Init(init_stream) => {
                if !init_stream.is_connect_done() {
                    (
                        VsockStreamState::Init(init_stream),
                        Err(Error::with_message(
                            Errno::EALREADY,
                            "a previous connection attempt exists",
                        )),
                        false,
                    )
                } else {
                    match init_stream.connect(
                        remote_addr,
                        VSOCK_STREAM_BUF_SIZE,
                        &self.pollee,
                        &self.wait_queue,
                    ) {
                        Ok(connecting_stream) => (
                            VsockStreamState::Connecting(connecting_stream),
                            Err(Error::with_message(
                                Errno::EINPROGRESS,
                                "the socket is connecting",
                            )),
                            true,
                        ),
                        Err((error, init_stream)) => {
                            (VsockStreamState::Init(init_stream), Err(error), false)
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
                false,
            ),
            VsockStreamState::Listen(listen_stream) => (
                VsockStreamState::Listen(listen_stream),
                Err(Error::with_message(
                    Errno::EINVAL,
                    "the socket is listening",
                )),
                false,
            ),
            VsockStreamState::Connected(connected_stream) => (
                VsockStreamState::Connected(connected_stream),
                Err(Error::with_message(
                    Errno::EISCONN,
                    "the socket is already connected",
                )),
                false,
            ),
        };
        *state = new_state;
        drop(state);

        if should_wait && !self.is_nonblocking.load(Ordering::Relaxed) {
            self.wait_for_connect()
        } else {
            result
        }
    }

    fn listen(&self, backlog: usize) -> Result<()> {
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state, &self.pollee, &self.wait_queue);

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
                    match init_stream.listen(
                        backlog,
                        VSOCK_STREAM_BUF_SIZE,
                        &self.pollee,
                        &self.wait_queue,
                    ) {
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
        loop {
            let result = {
                let mut state = self.state.lock();
                Self::update_state_locked(&mut *state, &self.pollee, &self.wait_queue);

                match &*state {
                    VsockStreamState::Listen(listen_stream) => listen_stream.try_accept(),
                    VsockStreamState::Init(_)
                    | VsockStreamState::Connecting(_)
                    | VsockStreamState::Connected(_) => {
                        return_errno_with_message!(Errno::EINVAL, "the socket is not listening")
                    }
                }
            };

            match result {
                Err(error)
                    if error.error() == Errno::EAGAIN
                        && !self.is_nonblocking.load(Ordering::Relaxed) =>
                {
                    self.wait_for_io(IoEvents::IN | IoEvents::RDNORM)?;
                }
                result => return result,
            }
        }
    }

    fn shutdown(&self, cmd: SockShutdownCmd) -> Result<()> {
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state, &self.pollee, &self.wait_queue);

        match &*state {
            VsockStreamState::Init(init_stream) => init_stream.shutdown(cmd),
            VsockStreamState::Connecting(_) => Err(Error::new(Errno::ENOTCONN)),
            VsockStreamState::Listen(_) => Err(Error::new(Errno::ENOTCONN)),
            VsockStreamState::Connected(connected_stream) => connected_stream.shutdown(cmd),
        }
    }

    fn addr(&self) -> Result<SocketAddr> {
        let mut state = self.state.lock();
        Self::update_state_locked(&mut *state, &self.pollee, &self.wait_queue);

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
        Self::update_state_locked(&mut *state, &self.pollee, &self.wait_queue);

        let VsockStreamState::Connected(connected_stream) = &*state else {
            return Err(Error::new(Errno::ENOTCONN));
        };
        Ok(SocketAddr::Vsock(connected_stream.remote_addr()))
    }

    fn sendmsg(
        &self,
        reader: &mut dyn MultiRead,
        message_header: MessageHeader,
        flags: SendRecvFlags,
    ) -> Result<usize> {
        flags.ensure_supported_by(SendRecvFlags::MSG_DONTWAIT | SendRecvFlags::MSG_NOSIGNAL)?;
        if message_header.has_control_messages() {
            return Err(Error::new(Errno::EOPNOTSUPP));
        }

        let mut input = vec![0; reader.sum_lens()];
        let input_len = reader.read(&mut VmWriter::from(input.as_mut_slice()))?;
        input.truncate(input_len);

        let should_wait = self.should_wait(flags);
        let has_addr = message_header.addr().is_some();
        loop {
            match self.try_sendmsg_once(&input, has_addr, flags) {
                Err(error) if error.error() == Errno::EAGAIN && should_wait => {
                    self.wait_for_io(IoEvents::OUT | IoEvents::ERR | IoEvents::HUP)?;
                }
                result => return result,
            }
        }
    }

    fn recvmsg(
        &self,
        writer: &mut dyn MultiWrite,
        flags: SendRecvFlags,
    ) -> Result<(usize, MessageHeader)> {
        flags.ensure_supported_by(SendRecvFlags::MSG_DONTWAIT)?;

        if writer.is_empty() {
            return Ok((0, MessageHeader::new(None, Vec::new())));
        }

        let mut output = vec![0; writer.sum_lens()];
        let should_wait = self.should_wait(flags);
        let (len, header) = loop {
            match self.try_recvmsg_once(&mut output, flags) {
                Err(error) if error.error() == Errno::EAGAIN && should_wait => {
                    self.wait_for_io(
                        IoEvents::IN
                            | IoEvents::RDNORM
                            | IoEvents::RDHUP
                            | IoEvents::ERR
                            | IoEvents::HUP,
                    )?;
                }
                result => break result?,
            }
        };
        if len == 0 {
            return Ok((0, header));
        }

        let copied_len = writer.write(&mut VmReader::from(&output[..len]))?;
        Ok((copied_len, header))
    }

    fn get_option(&self, option: &mut dyn SocketOption) -> Result<()> {
        sock_option_mut!(match option {
            socket_errors @ SocketError => {
                socket_errors.set(self.test_and_clear_error());
                return Ok(());
            }
            _ => (),
        });
        return_errno_with_message!(Errno::ENOPROTOOPT, "the socket option to get is unknown")
    }

    fn set_option(&self, _option: &dyn SocketOption) -> Result<()> {
        return_errno_with_message!(Errno::ENOPROTOOPT, "the socket option to set is unknown")
    }

    fn pseudo_path(&self) -> &Path {
        &self.pseudo_path
    }
}
