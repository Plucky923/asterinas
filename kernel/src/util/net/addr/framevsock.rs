// SPDX-License-Identifier: MPL-2.0

use super::family::CSocketAddrFamily;
use crate::{net::socket::framevsock::addr::FrameVsockAddr, prelude::*};

/// FrameVsock socket address.
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod)]
pub struct CSocketAddrFrameVsock {
    /// Address family (AF_FRAMEVSOCK).
    svm_family: u16,
    /// Reserved (always zero).
    svm_reserved1: u16,
    /// Port number in host byte order.
    svm_port: u32,
    /// Address in host byte order.
    svm_cid: u64,
}

impl From<FrameVsockAddr> for CSocketAddrFrameVsock {
    fn from(value: FrameVsockAddr) -> Self {
        Self {
            svm_family: CSocketAddrFamily::AF_FRAMEVSOCK as u16,
            svm_reserved1: 0,
            svm_port: value.port,
            svm_cid: value.cid,
        }
    }
}

impl From<CSocketAddrFrameVsock> for FrameVsockAddr {
    fn from(value: CSocketAddrFrameVsock) -> Self {
        debug_assert_eq!(value.svm_family, CSocketAddrFamily::AF_FRAMEVSOCK as u16);
        Self {
            cid: value.svm_cid,
            port: value.svm_port,
        }
    }
}
