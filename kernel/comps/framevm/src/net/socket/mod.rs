// SPDX-License-Identifier: MPL-2.0

//! Socket abstractions copied in shape from the kernel socket layer.

use alloc::{sync::Arc, vec::Vec};

use bitflags::bitflags;

use crate::{
    error::{Errno, Error, Result},
    events::IoEvents,
    fd_table::FileLike,
    pollee::PollHandle,
    return_errno_with_message,
};

pub mod unix;
pub mod vsock;

const SOL_SOCKET: i32 = 1;
const SOL_IP: i32 = 0;
const SOL_TCP: i32 = 6;
const SOL_UDP: i32 = 17;
const SOL_IPV6: i32 = 41;
const SOL_RAW: i32 = 255;
const SOL_NETLINK: i32 = 270;
const SO_TYPE: i32 = 3;
const SO_ERROR: i32 = 4;
const SO_SNDBUF: i32 = 7;
const SO_RCVBUF: i32 = 8;

const MIN_SOCKET_BUFFER_SIZE: u32 = 2304;

/// Socket option access direction.
#[derive(Clone, Copy, Debug)]
pub enum SocketOptionAccess {
    Get,
    Set,
}

/// Validates that a socket option level has the same ABI status as kernel.
pub fn validate_socket_option_level(level: i32) -> Result<()> {
    match level {
        SOL_IP | SOL_SOCKET | SOL_TCP | SOL_UDP | SOL_IPV6 | SOL_RAW | SOL_NETLINK => Ok(()),
        _ => return_errno_with_message!(Errno::EOPNOTSUPP, "unsupported socket option level"),
    }
}

/// Validates the socket options implemented by this runtime.
pub fn validate_socket_option(level: i32, optname: i32, access: SocketOptionAccess) -> Result<()> {
    validate_socket_option_level(level)?;
    match (level, optname, access) {
        (SOL_SOCKET, SO_TYPE | SO_ERROR | SO_SNDBUF | SO_RCVBUF, SocketOptionAccess::Get)
        | (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF, SocketOptionAccess::Set) => Ok(()),
        (SOL_SOCKET, _, _) => {
            return_errno_with_message!(Errno::ENOPROTOOPT, "unsupported socket-level option")
        }
        _ => return_errno_with_message!(Errno::EOPNOTSUPP, "unsupported socket option level"),
    }
}

/// Socket-level buffer options shared by stream sockets.
#[derive(Debug)]
struct SocketBufferOptions {
    send_buf: u32,
    recv_buf: u32,
}

#[derive(Clone, Copy, Debug)]
enum SocketBufferOption {
    Send,
    Recv,
}

impl SocketBufferOptions {
    /// Creates buffer options with the Linux minimum buffer size applied.
    fn new(default_buffer_size: u32) -> Self {
        let buffer_size = default_buffer_size.max(MIN_SOCKET_BUFFER_SIZE);
        Self {
            send_buf: buffer_size,
            recv_buf: buffer_size,
        }
    }

    /// Gets a common socket-level option.
    fn get_common_option(&self, socket_type: i32, level: i32, optname: i32) -> Option<Vec<u8>> {
        let value = match (level, optname) {
            (SOL_SOCKET, SO_TYPE) => socket_type.to_ne_bytes().to_vec(),
            (SOL_SOCKET, SO_ERROR) => 0i32.to_ne_bytes().to_vec(),
            (SOL_SOCKET, SO_SNDBUF) => self.send_buf.to_ne_bytes().to_vec(),
            (SOL_SOCKET, SO_RCVBUF) => self.recv_buf.to_ne_bytes().to_vec(),
            _ => return None,
        };
        Some(value)
    }

    /// Sets a common socket-level option.
    fn set_common_option(
        &mut self,
        level: i32,
        optname: i32,
        optval: &[u8],
    ) -> Result<Option<(SocketBufferOption, u32)>> {
        let Some(option_kind) = (match (level, optname) {
            (SOL_SOCKET, SO_SNDBUF) => Some(SocketBufferOption::Send),
            (SOL_SOCKET, SO_RCVBUF) => Some(SocketBufferOption::Recv),
            _ => None,
        }) else {
            return Ok(None);
        };

        let buffer_size = Self::read_buffer_size(optval)?;
        match option_kind {
            SocketBufferOption::Send => {
                self.send_buf = buffer_size;
            }
            SocketBufferOption::Recv => {
                self.recv_buf = buffer_size;
            }
        }
        Ok(Some((option_kind, buffer_size)))
    }

    fn read_buffer_size(optval: &[u8]) -> Result<u32> {
        if optval.len() < size_of::<u32>() {
            return_errno_with_message!(Errno::EINVAL, "socket buffer option is too short");
        }

        let mut bytes = [0u8; size_of::<u32>()];
        bytes.copy_from_slice(&optval[..size_of::<u32>()]);
        Ok(u32::from_ne_bytes(bytes).max(MIN_SOCKET_BUFFER_SIZE))
    }
}

/// Full-duplex socket shutdown command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SockShutdownCmd {
    Receive,
    Send,
    Both,
}

impl TryFrom<i32> for SockShutdownCmd {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::Receive),
            1 => Ok(Self::Send),
            2 => Ok(Self::Both),
            _ => Err(Error::new(Errno::EINVAL)),
        }
    }
}

/// Generic socket address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketAddr {
    Unix(unix::UnixSocketAddr),
    Vsock(vsock::VsockSocketAddr),
}

/// Ancillary data and optional peer address for message-oriented socket calls.
pub struct MessageHeader {
    addr: Option<SocketAddr>,
    control_messages: Vec<()>,
}

impl MessageHeader {
    /// Creates a message header.
    pub fn new(addr: Option<SocketAddr>, control_messages: Vec<()>) -> Self {
        Self {
            addr,
            control_messages,
        }
    }

    /// Returns the optional socket address.
    pub fn addr(&self) -> Option<&SocketAddr> {
        self.addr.as_ref()
    }

    /// Returns whether control data is present.
    pub fn has_control_messages(&self) -> bool {
        !self.control_messages.is_empty()
    }
}

bitflags! {
    /// Flags used by send/receive socket syscalls.
    pub struct SendRecvFlags: i32 {
        const MSG_OOB = 1;
        const MSG_PEEK = 2;
        const MSG_DONTROUTE = 4;
        const MSG_CTRUNC = 8;
        const MSG_PROBE = 0x10;
        const MSG_TRUNC = 0x20;
        const MSG_DONTWAIT = 0x40;
        const MSG_EOR = 0x80;
        const MSG_WAITALL = 0x100;
        const MSG_FIN = 0x200;
        const MSG_SYN = 0x400;
        const MSG_CONFIRM = 0x800;
        const MSG_RST = 0x1000;
        const MSG_ERRQUEUE = 0x2000;
        const MSG_NOSIGNAL = 0x4000;
        const MSG_MORE = 0x8000;
        const MSG_WAITFORONE = 0x10000;
        const MSG_SENDPAGE_NOTLAST = 0x20000;
        const MSG_BATCH = 0x40000;
        const MSG_NO_SHARED_FRAGS = 0x80000;
        const MSG_SENDPAGE_DECRYPTED = 0x100000;
    }
}

impl SendRecvFlags {
    /// Parses userspace send/receive flags like the kernel syscall layer.
    pub fn from_user_bits(bits: i32) -> Result<Self> {
        Ok(Self::from_bits_truncate(bits))
    }

    /// Returns whether all flags are included in `supported`.
    pub fn are_all_supported_by(self, supported: Self) -> bool {
        supported.contains(self)
    }

    /// Fails if any flag is not included in `supported`.
    pub fn ensure_supported_by(self, supported: Self) -> Result<()> {
        if self.are_all_supported_by(supported) {
            Ok(())
        } else {
            return_errno_with_message!(Errno::EOPNOTSUPP, "send/receive flag is not supported");
        }
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::SendRecvFlags;

    #[ktest]
    fn send_recv_flags_match_kernel_truncation() {
        let flags =
            SendRecvFlags::from_user_bits(0x200000 | SendRecvFlags::MSG_DONTWAIT.bits()).unwrap();

        assert_eq!(flags.bits(), SendRecvFlags::MSG_DONTWAIT.bits());
    }
}

/// Operations defined on a socket.
pub trait Socket: Send + Sync {
    /// Assigns the specified address to the socket.
    fn bind(&self, _socket_addr: SocketAddr) -> Result<()> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "bind() is not supported");
    }

    /// Builds a connection for the given address.
    fn connect(&self, _socket_addr: SocketAddr) -> Result<()> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "connect() is not supported");
    }

    /// Listens for connections on the socket.
    fn listen(&self, _backlog: usize) -> Result<()> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "listen() is not supported");
    }

    /// Accepts a connection on the socket.
    fn accept(&self) -> Result<(Arc<dyn FileLike>, SocketAddr)> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "accept() is not supported");
    }

    /// Shuts down part of a full-duplex connection.
    fn shutdown(&self, _cmd: SockShutdownCmd) -> Result<()> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "shutdown() is not supported");
    }

    /// Gets the address of this socket.
    fn addr(&self) -> Result<SocketAddr> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "getsockname() is not supported");
    }

    /// Gets the address of the peer socket.
    fn peer_addr(&self) -> Result<SocketAddr> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "getpeername() is not supported");
    }

    /// Gets a raw socket option.
    fn get_option(&self, level: i32, optname: i32) -> Result<Vec<u8>> {
        match (level, optname) {
            (SOL_SOCKET, SO_TYPE) => Ok(self.socket_type().to_ne_bytes().to_vec()),
            (SOL_SOCKET, SO_ERROR) => Ok(0i32.to_ne_bytes().to_vec()),
            _ => return_errno_with_message!(Errno::EOPNOTSUPP, "getsockopt() is not supported"),
        }
    }

    /// Sets a raw socket option.
    fn set_option(&self, _level: i32, _optname: i32, _optval: &[u8]) -> Result<()> {
        return_errno_with_message!(Errno::EOPNOTSUPP, "setsockopt() is not supported");
    }

    /// Sends a message on the socket.
    fn sendmsg(
        &self,
        input: &[u8],
        message_header: MessageHeader,
        flags: SendRecvFlags,
    ) -> Result<usize>;

    /// Receives a message from the socket.
    fn recvmsg(&self, output: &mut [u8], flags: SendRecvFlags) -> Result<(usize, MessageHeader)>;

    /// Polls readiness for this socket.
    fn poll(&self, _events: IoEvents, _poller: Option<&mut PollHandle>) -> IoEvents {
        IoEvents::empty()
    }

    /// Returns the Linux socket type.
    fn socket_type(&self) -> i32;
}
