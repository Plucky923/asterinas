// SPDX-License-Identifier: MPL-2.0

//! FrameVsock address definitions

pub use aster_framevsock::{FrameVsockAddr, VMADDR_CID_ANY, VMADDR_PORT_ANY};

/// AF_FRAMEVSOCK family
pub const AF_FRAMEVSOCK: i32 = 46;

/// sockaddr_vm for syscall interface (matches Linux structure)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct SockAddrVm {
    pub family: u16,
    pub reserved: u16,
    pub port: u32,
    pub cid: u64,
}

impl SockAddrVm {
    /// Size of SockAddrVm in bytes
    pub const SIZE: usize = 16;

    pub fn to_addr(&self) -> FrameVsockAddr {
        FrameVsockAddr::new(self.cid, self.port)
    }

    pub fn from_addr(addr: FrameVsockAddr) -> Self {
        Self {
            family: AF_FRAMEVSOCK as u16,
            reserved: 0,
            port: addr.port,
            cid: addr.cid,
        }
    }

    /// Parse SockAddrVm from bytes (safe alternative to ptr::read)
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            family: u16::from_ne_bytes([bytes[0], bytes[1]]),
            reserved: u16::from_ne_bytes([bytes[2], bytes[3]]),
            port: u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            cid: u64::from_ne_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ]),
        })
    }

    /// Convert to bytes (safe alternative to slice::from_raw_parts)
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..2].copy_from_slice(&self.family.to_ne_bytes());
        bytes[2..4].copy_from_slice(&self.reserved.to_ne_bytes());
        bytes[4..8].copy_from_slice(&self.port.to_ne_bytes());
        bytes[8..16].copy_from_slice(&self.cid.to_ne_bytes());
        bytes
    }
}
