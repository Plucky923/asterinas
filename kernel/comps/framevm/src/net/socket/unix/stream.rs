// SPDX-License-Identifier: MPL-2.0

//! Connected Unix stream sockets.

use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ostd::sync::{SpinLock, WaitQueue};

use super::UnixSocketAddr;
use crate::{
    error::{Errno, Error, Result},
    events::IoEvents,
    fd_table::{AccessMode, FileLike, StatusFlags},
    net::socket::{
        MessageHeader, SendRecvFlags, SockShutdownCmd, Socket, SocketAddr, SocketBufferOption,
        SocketBufferOptions,
    },
    pollee::PollHandle,
};

const SOCK_STREAM: i32 = 1;
const UNIX_STREAM_BUF_SIZE: usize = 128 * 1024;

/// A Linux `SOCK_STREAM` Unix-domain socket endpoint.
pub struct UnixStreamSocket {
    state: SpinLock<UnixStreamState>,
    options: SpinLock<SocketBufferOptions>,
    is_nonblocking: AtomicBool,
}

enum UnixStreamState {
    Init {
        read_shutdown: bool,
        write_shutdown: bool,
    },
    Connected {
        incoming: Arc<StreamBuffer>,
        outgoing: Arc<StreamBuffer>,
    },
}

struct StreamBuffer {
    state: SpinLock<StreamBufferState>,
    capacity: AtomicUsize,
    wait_queue: WaitQueue,
    pollee: crate::pollee::Pollee,
}

struct StreamBufferState {
    buffer: VecDeque<u8>,
    readers: usize,
    writers: usize,
    read_shutdown: bool,
    write_shutdown: bool,
}

impl StreamBuffer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: SpinLock::new(StreamBufferState {
                buffer: VecDeque::new(),
                readers: 1,
                writers: 1,
                read_shutdown: false,
                write_shutdown: false,
            }),
            capacity: AtomicUsize::new(UNIX_STREAM_BUF_SIZE),
            wait_queue: WaitQueue::new(),
            pollee: crate::pollee::Pollee::new(),
        })
    }

    fn read(&self, output: &mut [u8], nonblocking: bool) -> Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }

        if nonblocking {
            let read_result = {
                let mut state = self.state.lock();
                Self::try_read_locked(&mut state, output)
            };
            if read_result.is_ok_and(|len| len != 0) {
                self.notify_writable();
            }
            return read_result;
        }

        let read_len = self.wait_queue.wait_until(|| {
            let mut state = self.state.lock();
            match Self::try_read_locked(&mut state, output) {
                Ok(0)
                    if state.buffer.is_empty()
                        && state.writers != 0
                        && !state.read_shutdown
                        && !state.write_shutdown =>
                {
                    None
                }
                result => Some(result),
            }
        })?;
        if read_len != 0 {
            self.notify_writable();
        }
        Ok(read_len)
    }

    fn write(&self, input: &[u8], nonblocking: bool) -> Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }

        if nonblocking {
            let write_result = {
                let capacity = self.capacity.load(Ordering::Relaxed);
                let mut state = self.state.lock();
                Self::try_write_locked(&mut state, input, capacity)
            };
            if write_result.is_ok_and(|len| len != 0) {
                self.notify_readable();
            }
            return write_result;
        }

        let write_len = self.wait_queue.wait_until(|| {
            let capacity = self.capacity.load(Ordering::Relaxed);
            let mut state = self.state.lock();
            match Self::try_write_locked(&mut state, input, capacity) {
                Err(error)
                    if error.errno() == Errno::EAGAIN
                        && state.readers != 0
                        && !state.write_shutdown =>
                {
                    None
                }
                result => Some(result),
            }
        })?;
        if write_len != 0 {
            self.notify_readable();
        }
        Ok(write_len)
    }

    fn try_read_locked(state: &mut StreamBufferState, output: &mut [u8]) -> Result<usize> {
        if state.buffer.is_empty() {
            if state.writers == 0 || state.read_shutdown || state.write_shutdown {
                return Ok(0);
            }
            return Err(Error::new(Errno::EAGAIN));
        }

        let read_len = output.len().min(state.buffer.len());
        for byte in &mut output[..read_len] {
            if let Some(next_byte) = state.buffer.pop_front() {
                *byte = next_byte;
            }
        }
        Ok(read_len)
    }

    fn try_write_locked(
        state: &mut StreamBufferState,
        input: &[u8],
        capacity: usize,
    ) -> Result<usize> {
        if state.readers == 0 || state.write_shutdown {
            return Err(Error::new(Errno::EPIPE));
        }

        let available = capacity.saturating_sub(state.buffer.len());
        if available == 0 {
            return Err(Error::new(Errno::EAGAIN));
        }

        let write_len = input.len().min(available);
        state.buffer.extend(&input[..write_len]);
        Ok(write_len)
    }

    fn close_reader(&self) {
        let mut state = self.state.lock();
        state.readers = state.readers.saturating_sub(1);
        state.read_shutdown = true;
        drop(state);
        self.wait_queue.wake_all();
        self.pollee.notify(IoEvents::ERR | IoEvents::OUT);
    }

    fn close_writer(&self) {
        let mut state = self.state.lock();
        state.writers = state.writers.saturating_sub(1);
        state.write_shutdown = true;
        drop(state);
        self.wait_queue.wake_all();
        self.pollee
            .notify(IoEvents::HUP | IoEvents::RDHUP | IoEvents::IN | IoEvents::RDNORM);
    }

    fn shutdown_reader(&self) {
        let mut state = self.state.lock();
        state.read_shutdown = true;
        drop(state);
        self.wait_queue.wake_all();
        self.pollee.notify(IoEvents::HUP | IoEvents::IN);
    }

    fn shutdown_writer(&self) {
        let mut state = self.state.lock();
        state.write_shutdown = true;
        drop(state);
        self.wait_queue.wake_all();
        self.pollee.notify(IoEvents::ERR | IoEvents::OUT);
    }

    fn reader_revents(&self, events: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee.poll_with(events, poller, || {
            let state = self.state.lock();
            let mut revents = IoEvents::empty();
            if !state.buffer.is_empty()
                || state.writers == 0
                || state.read_shutdown
                || state.write_shutdown
            {
                revents |= IoEvents::IN | IoEvents::RDNORM;
            }
            if state.writers == 0 || state.read_shutdown || state.write_shutdown {
                revents |= IoEvents::HUP | IoEvents::RDHUP;
            }
            revents
        })
    }

    fn writer_revents(&self, events: IoEvents, poller: Option<&mut PollHandle>) -> IoEvents {
        self.pollee.poll_with(events, poller, || {
            let state = self.state.lock();
            if state.readers == 0 || state.write_shutdown {
                return IoEvents::ERR | IoEvents::OUT;
            }
            if state.buffer.len() < self.capacity.load(Ordering::Relaxed) {
                IoEvents::OUT
            } else {
                IoEvents::empty()
            }
        })
    }

    fn notify_readable(&self) {
        self.wait_queue.wake_all();
        self.pollee.notify(IoEvents::IN | IoEvents::RDNORM);
    }

    fn notify_writable(&self) {
        self.wait_queue.wake_all();
        self.pollee.notify(IoEvents::OUT);
    }

    fn set_capacity(&self, capacity: usize) {
        self.capacity.store(capacity, Ordering::Relaxed);
        self.notify_writable();
    }

    fn buffer_len(&self) -> usize {
        self.state.lock().buffer.len()
    }
}

impl UnixStreamSocket {
    /// Creates an unnamed, unconnected stream socket.
    pub fn new(is_nonblocking: bool) -> Arc<Self> {
        Arc::new(Self {
            state: SpinLock::new(UnixStreamState::Init {
                read_shutdown: false,
                write_shutdown: false,
            }),
            options: SpinLock::new(SocketBufferOptions::new(UNIX_STREAM_BUF_SIZE as u32)),
            is_nonblocking: AtomicBool::new(is_nonblocking),
        })
    }

    /// Creates a connected socket pair.
    pub fn new_pair(is_nonblocking: bool) -> (Arc<Self>, Arc<Self>) {
        let buffer_ab = StreamBuffer::new();
        let buffer_ba = StreamBuffer::new();
        let socket_a = Arc::new(Self {
            state: SpinLock::new(UnixStreamState::Connected {
                incoming: buffer_ba.clone(),
                outgoing: buffer_ab.clone(),
            }),
            options: SpinLock::new(SocketBufferOptions::new(UNIX_STREAM_BUF_SIZE as u32)),
            is_nonblocking: AtomicBool::new(is_nonblocking),
        });
        let socket_b = Arc::new(Self {
            state: SpinLock::new(UnixStreamState::Connected {
                incoming: buffer_ab,
                outgoing: buffer_ba,
            }),
            options: SpinLock::new(SocketBufferOptions::new(UNIX_STREAM_BUF_SIZE as u32)),
            is_nonblocking: AtomicBool::new(is_nonblocking),
        });
        (socket_a, socket_b)
    }

    fn is_nonblocking(&self) -> bool {
        self.is_nonblocking.load(Ordering::Relaxed)
    }

    fn apply_buffer_option(&self, option_kind: SocketBufferOption, buffer_size: u32) {
        let buffer = {
            let state = self.state.lock();
            match &*state {
                UnixStreamState::Connected { incoming, outgoing } => match option_kind {
                    SocketBufferOption::Send => Some(outgoing.clone()),
                    SocketBufferOption::Recv => Some(incoming.clone()),
                },
                UnixStreamState::Init { .. } => None,
            }
        };

        if let Some(buffer) = buffer {
            buffer.set_capacity(buffer_size as usize);
        }
    }
}

impl Socket for UnixStreamSocket {
    fn bind(&self, socket_addr: SocketAddr) -> Result<()> {
        let SocketAddr::Unix(UnixSocketAddr::Unnamed) = socket_addr else {
            return Err(Error::new(Errno::EAFNOSUPPORT));
        };

        Ok(())
    }

    fn listen(&self, _backlog: usize) -> Result<()> {
        let state = self.state.lock();
        match *state {
            UnixStreamState::Init { .. } => Err(Error::new(Errno::EINVAL)),
            UnixStreamState::Connected { .. } => Err(Error::new(Errno::EINVAL)),
        }
    }

    fn accept(&self) -> Result<(Arc<dyn FileLike>, SocketAddr)> {
        Err(Error::new(Errno::EINVAL))
    }

    fn shutdown(&self, cmd: SockShutdownCmd) -> Result<()> {
        let mut state = self.state.lock();
        match &mut *state {
            UnixStreamState::Init {
                read_shutdown,
                write_shutdown,
            } => match cmd {
                SockShutdownCmd::Receive => *read_shutdown = true,
                SockShutdownCmd::Send => *write_shutdown = true,
                SockShutdownCmd::Both => {
                    *read_shutdown = true;
                    *write_shutdown = true;
                }
            },
            UnixStreamState::Connected { incoming, outgoing } => match cmd {
                SockShutdownCmd::Receive => incoming.shutdown_reader(),
                SockShutdownCmd::Send => outgoing.shutdown_writer(),
                SockShutdownCmd::Both => {
                    incoming.shutdown_reader();
                    outgoing.shutdown_writer();
                }
            },
        }
        Ok(())
    }

    fn addr(&self) -> Result<SocketAddr> {
        Ok(SocketAddr::Unix(UnixSocketAddr::Unnamed))
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        match *self.state.lock() {
            UnixStreamState::Connected { .. } => Ok(SocketAddr::Unix(UnixSocketAddr::Unnamed)),
            UnixStreamState::Init { .. } => Err(Error::new(Errno::ENOTCONN)),
        }
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
            let errno = match *self.state.lock() {
                UnixStreamState::Init { .. } => Errno::EOPNOTSUPP,
                UnixStreamState::Connected { .. } => Errno::EISCONN,
            };
            return Err(Error::new(errno));
        }

        let outgoing = match &*self.state.lock() {
            UnixStreamState::Connected { outgoing, .. } => outgoing.clone(),
            UnixStreamState::Init { .. } => return Err(Error::new(Errno::ENOTCONN)),
        };
        outgoing.write(
            input,
            self.is_nonblocking() || flags.contains(SendRecvFlags::MSG_DONTWAIT),
        )
    }

    fn recvmsg(&self, output: &mut [u8], flags: SendRecvFlags) -> Result<(usize, MessageHeader)> {
        flags.ensure_supported_by(SendRecvFlags::MSG_DONTWAIT)?;

        let incoming = match &*self.state.lock() {
            UnixStreamState::Connected { incoming, .. } => incoming.clone(),
            UnixStreamState::Init { .. } => return Err(Error::new(Errno::EINVAL)),
        };
        let read_len = incoming.read(
            output,
            self.is_nonblocking() || flags.contains(SendRecvFlags::MSG_DONTWAIT),
        )?;
        Ok((read_len, MessageHeader::new(None, Vec::new())))
    }

    fn poll(&self, events: IoEvents, mut poller: Option<&mut PollHandle>) -> IoEvents {
        let (incoming, outgoing) = {
            let state = self.state.lock();
            match &*state {
                UnixStreamState::Init {
                    read_shutdown,
                    write_shutdown,
                } => {
                    let mut revents = IoEvents::OUT | IoEvents::HUP;
                    if *read_shutdown {
                        revents |= IoEvents::RDHUP | IoEvents::IN | IoEvents::RDNORM;
                    }
                    if *write_shutdown {
                        revents |= IoEvents::OUT | IoEvents::HUP;
                    }
                    return revents & (events | IoEvents::ALWAYS_POLL);
                }
                UnixStreamState::Connected { incoming, outgoing } => {
                    (incoming.clone(), outgoing.clone())
                }
            }
        };

        let mut revents = IoEvents::empty();
        if events.intersects(IoEvents::IN | IoEvents::RDNORM | IoEvents::ALWAYS_POLL) {
            revents |= incoming.reader_revents(events, poller.as_deref_mut());
        }
        if events.intersects(IoEvents::OUT | IoEvents::ALWAYS_POLL) {
            revents |= outgoing.writer_revents(events, poller);
        }
        revents
    }

    fn get_option(&self, level: i32, optname: i32) -> Result<Vec<u8>> {
        self.options
            .lock()
            .get_common_option(self.socket_type(), level, optname)
            .ok_or_else(|| Error::new(Errno::EOPNOTSUPP))
    }

    fn set_option(&self, level: i32, optname: i32, optval: &[u8]) -> Result<()> {
        if let Some((option_kind, buffer_size)) = self
            .options
            .lock()
            .set_common_option(level, optname, optval)?
        {
            self.apply_buffer_option(option_kind, buffer_size);
            return Ok(());
        }

        Err(Error::new(Errno::EOPNOTSUPP))
    }

    fn socket_type(&self) -> i32 {
        SOCK_STREAM
    }
}

impl FileLike for UnixStreamSocket {
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
        if self.is_nonblocking() {
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

    fn bytes_to_read(&self) -> Result<usize> {
        match &*self.state.lock() {
            UnixStreamState::Connected { incoming, .. } => Ok(incoming.buffer_len()),
            UnixStreamState::Init { .. } => Err(Error::new(Errno::ENOTCONN)),
        }
    }

    fn as_socket(&self) -> Option<&dyn Socket> {
        Some(self)
    }
}

impl Drop for UnixStreamSocket {
    fn drop(&mut self) {
        if let UnixStreamState::Connected { incoming, outgoing } = &*self.state.lock() {
            incoming.close_reader();
            outgoing.close_writer();
        }
    }
}
