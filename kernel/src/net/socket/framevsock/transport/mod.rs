// SPDX-License-Identifier: MPL-2.0

//! FrameVsock transport state shared by host-side stream sockets.

use core::time::Duration;

mod connection;
mod listener;
mod port;
mod space;

pub(in crate::net::socket::framevsock) use connection::Connected;
pub(in crate::net::socket::framevsock) use listener::Listener;
pub(in crate::net::socket::framevsock) use port::PortTable;
pub(in crate::net::socket::framevsock) use space::FrameVsockSpace;

// Keep socket-visible timing and queue limits aligned with the virtio-vsock
// transport. FrameVsock may change the packet carrier, not Linux socket
// semantics.
pub(in crate::net::socket::framevsock) const DEFAULT_CONNECT_TIMEOUT: Duration =
    Duration::from_secs(2);
pub(in crate::net::socket::framevsock) const MAX_BACKLOG: usize = 4096;
