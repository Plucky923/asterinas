// SPDX-License-Identifier: MPL-2.0

//! Common FrameV-net configuration and owned receive-buffer types.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

mod buffer;
mod config;
mod error;

pub use buffer::{BufferDropGuard, OwnedNetworkBuffer};
pub use config::{FrameVNetConfig, FrameVNetConfigError};
pub use error::{FrameVNetError, FrameVNetReceiveStatus, NetworkEndpointError};

/// The fixed network-layer MTU of FrameV-net revision 1.
pub const FRAMEV_NET_MTU: u16 = 1_500;

/// The largest untagged Ethernet frame accepted by FrameV-net revision 1.
pub const FRAMEV_NET_MAX_ETHERNET_FRAME_BYTES: u32 = 1_514;

/// The default number of caller-owned receive buffers accepted by FrameV-net.
pub const FRAMEV_NET_DEFAULT_MAX_POSTED_RECEIVE_BUFFERS: u32 = 256;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
