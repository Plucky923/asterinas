// SPDX-License-Identifier: MPL-2.0

use crate::{FRAMEV_NET_MAX_ETHERNET_FRAME_BYTES, FRAMEV_NET_MTU};

/// A validated revision-1 FrameV-net PCI configuration.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameVNetConfig {
    mac_address: [u8; 6],
    mtu: u16,
    maximum_frame_bytes: u32,
    maximum_posted_receive_buffers: u32,
}

impl FrameVNetConfig {
    /// Creates a validated revision-1 FrameV-net PCI configuration.
    pub const fn new(
        mac_address: [u8; 6],
        mtu: u16,
        maximum_frame_bytes: u32,
        maximum_posted_receive_buffers: u32,
    ) -> Result<Self, FrameVNetConfigError> {
        if mac_address[0] == 0
            && mac_address[1] == 0
            && mac_address[2] == 0
            && mac_address[3] == 0
            && mac_address[4] == 0
            && mac_address[5] == 0
        {
            return Err(FrameVNetConfigError::ZeroMacAddress);
        }
        if mac_address[0] & 1 != 0 {
            return Err(FrameVNetConfigError::MulticastMacAddress);
        }
        if mtu != FRAMEV_NET_MTU {
            return Err(FrameVNetConfigError::InvalidMtu(mtu));
        }
        if maximum_frame_bytes != FRAMEV_NET_MAX_ETHERNET_FRAME_BYTES {
            return Err(FrameVNetConfigError::InvalidMaximumFrameBytes(
                maximum_frame_bytes,
            ));
        }
        if maximum_posted_receive_buffers == 0 {
            return Err(FrameVNetConfigError::ZeroReceiveBufferCapacity);
        }
        Ok(Self {
            mac_address,
            mtu,
            maximum_frame_bytes,
            maximum_posted_receive_buffers,
        })
    }

    /// Returns the immutable Ethernet MAC address.
    pub const fn mac_address(self) -> [u8; 6] {
        self.mac_address
    }

    /// Returns the network-layer MTU in bytes.
    pub const fn mtu(self) -> u16 {
        self.mtu
    }

    /// Returns the maximum untagged Ethernet frame length.
    pub const fn maximum_frame_bytes(self) -> u32 {
        self.maximum_frame_bytes
    }

    /// Returns the maximum number of posted receive buffers.
    pub const fn maximum_posted_receive_buffers(self) -> u32 {
        self.maximum_posted_receive_buffers
    }
}

/// Describes one invalid revision-1 FrameV-net configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVNetConfigError {
    InvalidMaximumFrameBytes(u32),
    InvalidMtu(u16),
    MulticastMacAddress,
    ZeroMacAddress,
    ZeroReceiveBufferCapacity,
}
