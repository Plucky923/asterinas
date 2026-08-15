// SPDX-License-Identifier: MPL-2.0

//! FrameV Sock identities and immutable routing policy.

use alloc::collections::{BTreeMap, BTreeSet};

use framev_sock_common::{HOST_CID, VMADDR_CID_ANY, VMADDR_CID_LOCAL};

use crate::{
    Error, Result,
    sync::{Once, SpinLock},
    vm::VmId,
};

/// Immutable Host-supplied configuration for one FrameV Sock function.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SockConfiguration {
    guest_cid: u32,
    peer_cids: BTreeSet<u32>,
    guest_connect_host_ports: BTreeSet<u32>,
    host_connect_guest_ports: BTreeSet<u32>,
}

impl SockConfiguration {
    /// Creates a default-deny configuration for an explicit guest CID.
    pub fn new(guest_cid: u32) -> Result<Self> {
        validate_guest_cid(guest_cid)?;
        Ok(Self {
            guest_cid,
            peer_cids: BTreeSet::new(),
            guest_connect_host_ports: BTreeSet::new(),
            host_connect_guest_ports: BTreeSet::new(),
        })
    }

    /// Adds one directionally authorized destination guest CID.
    pub fn allow_peer(mut self, peer_cid: u32) -> Result<Self> {
        validate_guest_cid(peer_cid)?;
        if peer_cid == self.guest_cid {
            return Err(Error::InvalidArgs);
        }
        self.peer_cids.insert(peer_cid);
        Ok(self)
    }

    /// Adds one Host destination port for Guest-initiated connections.
    pub fn allow_guest_connect_host_port(mut self, port: u32) -> Result<Self> {
        validate_exact_port(port)?;
        self.guest_connect_host_ports.insert(port);
        Ok(self)
    }

    /// Adds one Guest destination port for Host-initiated connections.
    pub fn allow_host_connect_guest_port(mut self, port: u32) -> Result<Self> {
        validate_exact_port(port)?;
        self.host_connect_guest_ports.insert(port);
        Ok(self)
    }

    /// Returns the configured guest CID.
    pub const fn guest_cid(&self) -> u32 {
        self.guest_cid
    }

    pub(super) fn allows_peer(&self, peer_cid: u32) -> bool {
        self.peer_cids.contains(&peer_cid)
    }

    pub(super) fn allows_guest_connect_host_port(&self, port: u32) -> bool {
        self.guest_connect_host_ports.contains(&port)
    }

    pub(super) fn allows_host_connect_guest_port(&self, port: u32) -> bool {
        self.host_connect_guest_ports.contains(&port)
    }
}

fn validate_guest_cid(cid: u32) -> Result<()> {
    if matches!(cid as u64, 0 | VMADDR_CID_LOCAL | HOST_CID)
        || cid == u32::MAX
        || cid as u64 == VMADDR_CID_ANY
    {
        return Err(Error::InvalidArgs);
    }
    Ok(())
}

fn validate_exact_port(port: u32) -> Result<()> {
    if port == u32::MAX {
        return Err(Error::InvalidArgs);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CidRoute {
    pub(crate) vm_id: VmId,
    pub(crate) generation: u64,
}

struct CidRegistry {
    routes: BTreeMap<u32, CidRoute>,
}

impl CidRegistry {
    const fn new() -> Self {
        Self {
            routes: BTreeMap::new(),
        }
    }

    fn reserve(&mut self, cid: u32, vm_id: VmId) -> Result<()> {
        if self.routes.contains_key(&cid) {
            return Err(Error::InvalidArgs);
        }
        self.routes.insert(
            cid,
            CidRoute {
                vm_id,
                generation: 0,
            },
        );
        Ok(())
    }

    fn set_generation(&mut self, cid: u32, vm_id: VmId, generation: u64) -> Result<()> {
        let Some(route) = self.routes.get_mut(&cid) else {
            return Err(Error::AccessDenied);
        };
        if route.vm_id != vm_id || generation == 0 {
            return Err(Error::AccessDenied);
        }
        route.generation = generation;
        Ok(())
    }

    fn release(&mut self, cid: u32, vm_id: VmId) {
        if self
            .routes
            .get(&cid)
            .is_some_and(|route| route.vm_id == vm_id)
        {
            self.routes.remove(&cid);
        }
    }
}

static CID_REGISTRY: Once<SpinLock<CidRegistry>> = Once::new();

fn registry() -> &'static SpinLock<CidRegistry> {
    CID_REGISTRY.call_once(|| SpinLock::new(CidRegistry::new()))
}

/// An RAII reservation for one globally unique guest CID.
pub(crate) struct CidReservation {
    cid: u32,
    vm_id: VmId,
}

impl CidReservation {
    pub(crate) fn reserve(configuration: &SockConfiguration, vm_id: VmId) -> Result<Self> {
        let cid = configuration.guest_cid();
        registry().lock().reserve(cid, vm_id)?;
        Ok(Self { cid, vm_id })
    }

    pub(crate) const fn cid(&self) -> u32 {
        self.cid
    }

    pub(crate) fn set_generation(&self, generation: u64) -> Result<()> {
        registry()
            .lock()
            .set_generation(self.cid, self.vm_id, generation)
    }

    pub(crate) fn release(&self) {
        registry().lock().release(self.cid, self.vm_id);
    }
}

impl Drop for CidReservation {
    fn drop(&mut self) {
        self.release();
    }
}

pub(crate) fn route_for_cid(cid: u64) -> Option<CidRoute> {
    let cid = u32::try_from(cid).ok()?;
    registry().lock().routes.get(&cid).copied()
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn configuration_rejects_reserved_cids_and_wildcards() {
        assert!(SockConfiguration::new(0).is_err());
        assert!(SockConfiguration::new(1).is_err());
        assert!(SockConfiguration::new(2).is_err());
        assert!(SockConfiguration::new(u32::MAX).is_err());
        assert!(SockConfiguration::new(3).is_ok());
        assert!(
            SockConfiguration::new(3)
                .unwrap()
                .allow_guest_connect_host_port(u32::MAX)
                .is_err()
        );
    }

    #[ktest]
    fn reservation_is_unique_and_released_on_drop() {
        let configuration = SockConfiguration::new(4_000_000_001).unwrap();
        let first = CidReservation::reserve(&configuration, crate::vm::VmId::new(11)).unwrap();
        assert!(CidReservation::reserve(&configuration, crate::vm::VmId::new(12)).is_err());
        first.set_generation(9).unwrap();
        assert_eq!(
            route_for_cid(configuration.guest_cid() as u64),
            Some(CidRoute {
                vm_id: crate::vm::VmId::new(11),
                generation: 9
            })
        );

        drop(first);
        assert!(CidReservation::reserve(&configuration, crate::vm::VmId::new(12)).is_ok());
    }

    #[ktest]
    fn peer_and_host_policies_are_directional_and_default_deny() {
        let configuration = SockConfiguration::new(4001)
            .unwrap()
            .allow_peer(4002)
            .unwrap()
            .allow_guest_connect_host_port(1234)
            .unwrap()
            .allow_host_connect_guest_port(4321)
            .unwrap();

        assert!(configuration.allows_peer(4002));
        assert!(!configuration.allows_peer(4003));
        assert!(configuration.allows_guest_connect_host_port(1234));
        assert!(!configuration.allows_guest_connect_host_port(4321));
        assert!(configuration.allows_host_connect_guest_port(4321));
        assert!(!configuration.allows_host_connect_guest_port(1234));
    }
}
