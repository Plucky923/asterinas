pub use aster_framevsock::FrameVsockAddr;
use aster_framevsock::FrameVsockHeader;

use crate::{net::socket::util::SocketAddr, prelude::*};

impl From<FrameVsockAddr> for SocketAddr {
    fn from(value: FrameVsockAddr) -> Self {
        SocketAddr::FrameVsock(value)
    }
}

pub fn try_from_socketaddr(value: SocketAddr) -> Result<FrameVsockAddr> {
    let SocketAddr::FrameVsock(framevsock_addr) = value else {
        return_errno_with_message!(Errno::EINVAL, "invalid framevsock socket addr");
    };
    Ok(framevsock_addr)
}

pub fn from_header(value: FrameVsockHeader) -> FrameVsockAddr {
    FrameVsockAddr {
        cid: value.src_cid,
        port: value.src_port,
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
