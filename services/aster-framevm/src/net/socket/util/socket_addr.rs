// SPDX-License-Identifier: MPL-2.0

use crate::net::socket::{unix::UnixSocketAddr, vsock::VsockSocketAddr};

#[derive(Debug, Eq, PartialEq)]
pub enum SocketAddr {
    Unix(UnixSocketAddr),
    Vsock(VsockSocketAddr),
}
