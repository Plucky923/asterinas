// SPDX-License-Identifier: MPL-2.0

//! Local port leases for `AF_VSOCK` sockets.

use alloc::collections::{BTreeMap, btree_map::Entry};

use ostd::sync::{Once, SpinLock};

use super::{VMADDR_CID_ANY, VMADDR_CID_LOCAL, VMADDR_PORT_ANY, VsockSocketAddr};
use crate::{
    error::{Errno, Result},
    return_errno_with_message,
};

static PORT_TABLE: Once<SpinLock<PortTable>> = Once::new();

/// An owned lease on a local vsock port.
pub(super) struct BoundPort {
    local_addr: VsockSocketAddr,
}

struct PortTable {
    next_ephemeral_port: u32,
    usage: BTreeMap<u32, usize>,
}

impl PortTable {
    const EPHEMERAL_PORT_START: u32 = 49152;

    fn new() -> Self {
        Self {
            next_ephemeral_port: Self::EPHEMERAL_PORT_START,
            usage: BTreeMap::new(),
        }
    }

    fn alloc_ephemeral_port(&mut self) -> Result<u32> {
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

    fn bind_exclusive(&mut self, port: u32) -> Result<()> {
        let usage = self.usage.entry(port).or_insert(0);
        if *usage != 0 {
            return_errno_with_message!(Errno::EADDRINUSE, "the vsock port is already in use");
        }
        *usage += 1;
        Ok(())
    }

    fn recycle(&mut self, port: u32) {
        let Entry::Occupied(mut usage) = self.usage.entry(port) else {
            return;
        };

        *usage.get_mut() = usage.get().saturating_sub(1);
        if *usage.get() == 0 {
            usage.remove();
        }
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

impl BoundPort {
    /// Binds exclusively to `addr` and returns the resulting port lease.
    pub(super) fn new_exclusive(addr: VsockSocketAddr) -> Result<Self> {
        let mut local_addr = addr;
        if local_addr.cid != VMADDR_CID_ANY && local_addr.cid != VMADDR_CID_LOCAL {
            return_errno_with_message!(Errno::EADDRNOTAVAIL, "the vsock CID is not local");
        }
        if local_addr.cid == VMADDR_CID_ANY {
            local_addr.cid = VMADDR_CID_LOCAL;
        }

        let port_table = PORT_TABLE.call_once(|| SpinLock::new(PortTable::new()));
        let mut port_table = port_table.lock();
        if local_addr.port == VMADDR_PORT_ANY {
            local_addr.port = port_table.alloc_ephemeral_port()?;
        } else {
            port_table.bind_exclusive(local_addr.port)?;
        }

        Ok(Self { local_addr })
    }

    /// Allocates and returns a fresh ephemeral port lease.
    pub(super) fn new_ephemeral() -> Result<Self> {
        Self::new_exclusive(VsockSocketAddr {
            cid: VMADDR_CID_ANY,
            port: VMADDR_PORT_ANY,
        })
    }

    /// Returns the local address described by this lease.
    pub(super) const fn local_addr(&self) -> VsockSocketAddr {
        self.local_addr
    }
}

impl Drop for BoundPort {
    fn drop(&mut self) {
        let port_table = PORT_TABLE.call_once(|| SpinLock::new(PortTable::new()));
        port_table.lock().recycle(self.local_addr.port);
    }
}
