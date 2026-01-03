// SPDX-License-Identifier: MPL-2.0

use aster_framevsock::FrameVsockHeader;

use crate::{net::socket::util::SocketAddr, prelude::*};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct FrameVsockAddr {
    pub cid: u64,
    pub port: u32,
}

impl FrameVsockAddr {
    pub fn new(cid: u64, port: u32) -> Self {
        Self { cid, port }
    }

    pub fn any_addr() -> Self {
        Self {
            cid: VMADDR_CID_ANY,
            port: VMADDR_PORT_ANY,
        }
    }
}

impl TryFrom<SocketAddr> for FrameVsockAddr {
    type Error = Error;

    fn try_from(value: SocketAddr) -> Result<Self> {
        let SocketAddr::FrameVsock(framevsock_addr) = value else {
            return_errno_with_message!(Errno::EINVAL, "invalid framevsock socket addr");
        };
        Ok(framevsock_addr)
    }
}

impl From<FrameVsockAddr> for SocketAddr {
    fn from(value: FrameVsockAddr) -> Self {
        SocketAddr::FrameVsock(value)
    }
}

impl From<FrameVsockHeader> for FrameVsockAddr {
    fn from(value: FrameVsockHeader) -> Self {
        FrameVsockAddr {
            cid: value.src_cid,
            port: value.src_port,
        }
    }
}

/// The vSocket equivalent of INADDR_ANY.
pub const VMADDR_CID_ANY: u64 = u64::MAX;
/// Use this as the destination CID in an address when referring to the local communication (loopback).
pub const VMADDR_CID_LOCAL: u64 = 1;
/// Use this as the destination CID in an address when referring to the host (any process other than the hypervisor).
pub const VMADDR_CID_HOST: u64 = 2;
/// Bind to any available port.
pub const VMADDR_PORT_ANY: u32 = u32::MAX;
