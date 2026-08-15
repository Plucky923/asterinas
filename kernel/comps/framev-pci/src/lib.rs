// SPDX-License-Identifier: MPL-2.0

//! Shared pure types for the private FrameV PCI revision-1 ABI.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

mod config;
mod identity;
mod layout;
mod topology;

pub use self::{
    config::{
        BlockConfig, BlockConfigFlags, ConfigError, ConsoleConfig, NetConfig, RngConfig, SockConfig,
    },
    identity::{
        FRAMEV_PCI_CLASS, FRAMEV_PCI_PROGRAMMING_INTERFACE, FRAMEV_PCI_REVISION,
        FRAMEV_PCI_SUBCLASS, FRAMEV_PCI_VENDOR_ID, FrameVFunctionFamily, FrameVPciIdentity,
        IdentityError,
    },
    layout::{FrameVPciLayout, LayoutError},
    topology::{
        AssignedFunction, SyntheticFunction, TopologyError, TopologyFunction, VirtualPciBdf,
        allocate_topology,
    },
};
