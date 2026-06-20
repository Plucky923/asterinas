// SPDX-License-Identifier: MPL-2.0

//! Linux `sockaddr_vm` representation.

use aster_framevsock::{
    HOST_CID as VSOCK_HOST_CID, VMADDR_CID_ANY as VSOCK_CID_ANY,
    VMADDR_CID_LOCAL as VSOCK_CID_LOCAL, VMADDR_PORT_ANY as VSOCK_PORT_ANY,
};

use crate::{
    error::{Errno, Error, Result},
    net::socket::SocketAddr,
    return_errno_with_message,
};

/// `AF_VSOCK`.
pub const AF_VSOCK: i32 = 40;

/// Wildcard context identifier.
pub const VMADDR_CID_ANY: u32 = VSOCK_CID_ANY as u32;

/// Local loopback context identifier.
pub const VMADDR_CID_LOCAL: u32 = VSOCK_CID_LOCAL as u32;

/// Host context identifier.
pub const VMADDR_CID_HOST: u32 = VSOCK_HOST_CID as u32;

/// Wildcard port.
pub const VMADDR_PORT_ANY: u32 = VSOCK_PORT_ANY;

/// A vsock socket address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VsockSocketAddr {
    pub cid: u32,
    pub port: u32,
}

impl TryFrom<SocketAddr> for VsockSocketAddr {
    type Error = Error;

    fn try_from(value: SocketAddr) -> Result<Self> {
        match value {
            SocketAddr::Vsock(addr) => Ok(addr),
            SocketAddr::Unix(_) => Err(Error::new(Errno::EINVAL)),
        }
    }
}

impl From<VsockSocketAddr> for SocketAddr {
    fn from(value: VsockSocketAddr) -> Self {
        SocketAddr::Vsock(value)
    }
}

/// Linux `struct sockaddr_vm`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CSocketAddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

impl CSocketAddrVm {
    pub const SIZE: usize = 16;

    /// Reads `sockaddr_vm` from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            return_errno_with_message!(Errno::EINVAL, "the socket address length is too small");
        }

        let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
        if i32::from(family) != AF_VSOCK {
            return_errno_with_message!(
                Errno::EAFNOSUPPORT,
                "the specified address family is not supported"
            );
        }

        Ok(Self {
            svm_family: family,
            svm_reserved1: u16::from_ne_bytes([bytes[2], bytes[3]]),
            svm_port: u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            svm_cid: u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            svm_zero: [bytes[12], bytes[13], bytes[14], bytes[15]],
        })
    }

    /// Serializes `sockaddr_vm` to raw bytes.
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..2].copy_from_slice(&self.svm_family.to_ne_bytes());
        bytes[2..4].copy_from_slice(&self.svm_reserved1.to_ne_bytes());
        bytes[4..8].copy_from_slice(&self.svm_port.to_ne_bytes());
        bytes[8..12].copy_from_slice(&self.svm_cid.to_ne_bytes());
        bytes[12..16].copy_from_slice(&self.svm_zero);
        bytes
    }
}

impl From<VsockSocketAddr> for CSocketAddrVm {
    fn from(value: VsockSocketAddr) -> Self {
        Self {
            svm_family: AF_VSOCK as u16,
            svm_reserved1: 0,
            svm_port: value.port,
            svm_cid: value.cid,
            svm_zero: [0; 4],
        }
    }
}

impl From<CSocketAddrVm> for VsockSocketAddr {
    fn from(value: CSocketAddrVm) -> Self {
        Self {
            cid: value.svm_cid,
            port: value.svm_port,
        }
    }
}
