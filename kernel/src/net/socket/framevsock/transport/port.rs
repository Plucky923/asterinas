// SPDX-License-Identifier: MPL-2.0

use alloc::collections::btree_map::Entry;

use crate::{
    error::return_errno_with_message, net::socket::framevsock::addr::VMADDR_PORT_ANY, prelude::*,
};

/// Tracks host-side FrameVsock port leases.
///
/// This mirrors the virtio-vsock transport port table shape: ephemeral ports are
/// allocated from the Linux ephemeral range and the table records a usage count
/// so later copied transport code can share a bound lease when needed.
pub(in crate::net::socket::framevsock) struct PortTable {
    next_ephemeral_port: u32,
    usage: BTreeMap<u32, usize>,
}

impl PortTable {
    const EPHEMERAL_PORT_START: u32 = 49152;

    pub(in crate::net::socket::framevsock) fn new() -> Self {
        Self {
            next_ephemeral_port: Self::EPHEMERAL_PORT_START,
            usage: BTreeMap::new(),
        }
    }

    pub(in crate::net::socket::framevsock) fn alloc_ephemeral_port(&mut self) -> Result<u32> {
        let start_port = self.next_ephemeral_port;
        let mut current_port = start_port;

        loop {
            let usage = self.usage.entry(current_port).or_insert(0);
            if *usage == 0 {
                *usage += 1;
                self.next_ephemeral_port = Self::next_ephemeral_port_after(current_port);
                return Ok(current_port);
            }

            current_port = Self::next_ephemeral_port_after(current_port);
            if current_port == start_port {
                return_errno_with_message!(
                    Errno::EADDRINUSE,
                    "no ephemeral vsock ports are available"
                );
            }
        }
    }

    pub(in crate::net::socket::framevsock) fn bind_exclusive(&mut self, port: u32) -> bool {
        let usage = self.usage.entry(port).or_insert(0);
        if *usage != 0 {
            return false;
        }
        *usage += 1;
        true
    }

    pub(in crate::net::socket::framevsock) fn recycle(&mut self, port: u32) -> bool {
        let Entry::Occupied(mut usage) = self.usage.entry(port) else {
            return false;
        };

        *usage.get_mut() -= 1;
        if *usage.get() == 0 {
            usage.remove();
        }
        true
    }

    fn next_ephemeral_port_after(port: u32) -> u32 {
        let mut next_port = if port == u32::MAX {
            Self::EPHEMERAL_PORT_START
        } else {
            port + 1
        };
        if next_port < Self::EPHEMERAL_PORT_START || next_port == VMADDR_PORT_ANY {
            next_port = Self::EPHEMERAL_PORT_START;
        }
        next_port
    }
}

impl Default for PortTable {
    fn default() -> Self {
        Self::new()
    }
}
