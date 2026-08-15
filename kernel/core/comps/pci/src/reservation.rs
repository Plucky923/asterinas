// SPDX-License-Identifier: MPL-2.0

//! Boot-time PCI reservation for FrameVM assignment.

use alloc::{collections::BTreeMap, vec::Vec};
use core::{fmt, mem, str::FromStr};

#[cfg(target_arch = "x86_64")]
use ostd::mm::dma::PciRequesterLease;
use ostd::sync::Mutex;
use spin::Once;

use crate::{PciCommonDevice, PciDeviceLocation, common_device::PciDeviceInitialization};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ReservedPciAddress {
    segment: u16,
    location: PciDeviceLocation,
}

impl FromStr for ReservedPciAddress {
    type Err = ParsePciAddressError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (segment, remainder) = value.split_once(':').ok_or(ParsePciAddressError)?;
        let (bus, remainder) = remainder.split_once(':').ok_or(ParsePciAddressError)?;
        let (device, function) = remainder.split_once('.').ok_or(ParsePciAddressError)?;

        let segment = u16::from_str_radix(segment, 16).map_err(|_| ParsePciAddressError)?;
        let bus = u8::from_str_radix(bus, 16).map_err(|_| ParsePciAddressError)?;
        let device = u8::from_str_radix(device, 16).map_err(|_| ParsePciAddressError)?;
        let function = u8::from_str_radix(function, 16).map_err(|_| ParsePciAddressError)?;
        if segment != 0 || device > PciDeviceLocation::MAX_DEVICE || function != 0 {
            return Err(ParsePciAddressError);
        }

        Ok(Self {
            segment,
            location: PciDeviceLocation {
                bus,
                device,
                function,
            },
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct ParsePciAddressError;

impl fmt::Display for ParsePciAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected segment:bus:device.function with segment/function zero")
    }
}

#[derive(Debug)]
enum ReservationState {
    Reserved(Vec<PciCommonDevice>),
    Acquiring,
    Assigned(PciAssignmentIdentity),
    Revoking(PciAssignmentIdentity),
    QuarantineRequested(PciAssignmentIdentity),
    Quarantined {
        identity: PciAssignmentIdentity,
        _devices: Vec<PciCommonDevice>,
    },
}

#[derive(Debug)]
struct ReservationRegistry {
    groups: BTreeMap<ReservedPciAddress, ReservationState>,
}

impl ReservationRegistry {
    fn from_boot_configuration() -> Self {
        let mut groups = BTreeMap::new();
        for address in RESERVED_PCI_ADDRESSES.get().into_iter().flatten().copied() {
            groups
                .entry(address)
                .or_insert_with(|| ReservationState::Reserved(Vec::new()));
        }
        Self { groups }
    }

    fn group_key(&self, location: PciDeviceLocation) -> Option<ReservedPciAddress> {
        self.groups.keys().copied().find(|address| {
            address.location.bus == location.bus && address.location.device == location.device
        })
    }
}

/// Describes why a PCI reservation cannot be acquired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciReservationError {
    Busy,
    NotFound,
    NotReserved,
    Quarantined,
    StaleAssignment,
    UnsupportedGroup,
}

/// Identifies one committed owner generation without exposing its internals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciAssignmentIdentity {
    owner: u64,
    generation: u64,
}

impl PciAssignmentIdentity {
    /// Creates an assignment identity.
    pub const fn new(owner: u64, generation: u64) -> Option<Self> {
        if generation == 0 {
            return None;
        }
        Some(Self { owner, generation })
    }

    /// Returns the owner identifier.
    pub const fn owner(self) -> u64 {
        self.owner
    }

    /// Returns the assignment generation.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Owns one quiesced singleton PCI requester group during assignment.
#[must_use]
pub struct ReservedPciGroup {
    key: ReservedPciAddress,
    devices: Option<Vec<PciCommonDevice>>,
    #[cfg(target_arch = "x86_64")]
    requester_lease_issued: bool,
}

impl ReservedPciGroup {
    /// Returns the group's physical function.
    pub fn device(&self) -> &PciCommonDevice {
        self.devices
            .as_ref()
            .expect("a live PCI reservation owns its devices")
            .first()
            .expect("only non-empty PCI groups can be acquired")
    }

    /// Returns mutable access to the group's physical function.
    pub fn device_mut(&mut self) -> &mut PciCommonDevice {
        self.devices
            .as_mut()
            .expect("a live PCI reservation owns its devices")
            .first_mut()
            .expect("only non-empty PCI groups can be acquired")
    }

    /// Rebuilds the reserved function's software view after a function-level reset.
    pub fn refresh_after_function_reset(&mut self) -> Result<(), PciReservationError> {
        refresh_singleton_device(
            self.devices
                .as_mut()
                .expect("a live PCI reservation owns its devices"),
        )
    }

    /// Issues the single DMA requester lease for this reservation generation.
    ///
    /// The group was created from a `Reserved` PCI device, whose command
    /// register has bus mastering and address decoding disabled. The lease is
    /// consumed by the isolated DMA domain and cannot be issued twice from
    /// this group.
    #[cfg(target_arch = "x86_64")]
    pub fn requester_lease(&mut self) -> Result<PciRequesterLease, PciReservationError> {
        if self.requester_lease_issued {
            return Err(PciReservationError::Busy);
        }
        let location = *self.device().location();
        let lease =
            PciRequesterLease::from_quiesced(location.bus, location.device, location.function)
                .map_err(|error| match error {
                    ostd::mm::dma::PciDmaError::InvalidRequester => {
                        PciReservationError::UnsupportedGroup
                    }
                    ostd::mm::dma::PciDmaError::RequesterBusy => PciReservationError::Busy,
                    _ => PciReservationError::Busy,
                })?;
        self.requester_lease_issued = true;
        Ok(lease)
    }

    /// Commits this acquisition to one owner generation.
    pub fn assign(mut self, identity: PciAssignmentIdentity) -> AssignedPciGroup {
        let devices = self
            .devices
            .take()
            .expect("a live PCI reservation owns its devices");
        let mut registry = registry().lock();
        let state = registry
            .groups
            .get_mut(&self.key)
            .expect("an acquired PCI group remains registered");
        assert!(matches!(state, ReservationState::Acquiring));
        *state = ReservationState::Assigned(identity);
        drop(registry);

        AssignedPciGroup {
            key: self.key,
            identity,
            devices: Some(devices),
            revocation_started: false,
        }
    }
}

impl fmt::Debug for ReservedPciGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReservedPciGroup")
            .field("address", &self.key)
            .finish_non_exhaustive()
    }
}

impl Drop for ReservedPciGroup {
    fn drop(&mut self) {
        let Some(devices) = self.devices.take() else {
            return;
        };
        let mut registry = registry().lock();
        let state = registry
            .groups
            .get_mut(&self.key)
            .expect("an acquired PCI group remains registered");
        assert!(matches!(state, ReservationState::Acquiring));
        *state = ReservationState::Reserved(devices);
    }
}

/// Owns one committed, generation-scoped PCI assignment.
#[must_use]
pub struct AssignedPciGroup {
    key: ReservedPciAddress,
    identity: PciAssignmentIdentity,
    devices: Option<Vec<PciCommonDevice>>,
    revocation_started: bool,
}

impl AssignedPciGroup {
    /// Returns the assignment identity.
    pub const fn identity(&self) -> PciAssignmentIdentity {
        self.identity
    }

    /// Returns the assigned physical function.
    pub fn device(&self) -> &PciCommonDevice {
        self.devices
            .as_ref()
            .expect("a live PCI assignment owns its devices")
            .first()
            .expect("only non-empty PCI groups can be assigned")
    }

    /// Returns mutable access to the assigned physical function.
    pub fn device_mut(&mut self) -> &mut PciCommonDevice {
        self.devices
            .as_mut()
            .expect("a live PCI assignment owns its devices")
            .first_mut()
            .expect("only non-empty PCI groups can be assigned")
    }

    /// Rebuilds the assigned function's software view after a function-level reset.
    pub fn refresh_after_function_reset(&mut self) -> Result<(), PciReservationError> {
        refresh_singleton_device(
            self.devices
                .as_mut()
                .expect("a live PCI assignment owns its devices"),
        )
    }

    /// Quiesces the group and enters the revocation phase.
    pub fn begin_revocation(&mut self) -> Result<(), PciReservationError> {
        if self.revocation_started {
            return Ok(());
        }

        quiesce_devices(
            self.devices
                .as_ref()
                .expect("a live PCI assignment owns its devices"),
        );
        let mut registry = registry().lock();
        let state = registry
            .groups
            .get_mut(&self.key)
            .expect("an assigned PCI group remains registered");
        match state {
            ReservationState::Assigned(identity) if *identity == self.identity => {
                *state = ReservationState::Revoking(self.identity);
                self.revocation_started = true;
                Ok(())
            }
            ReservationState::QuarantineRequested(_) | ReservationState::Quarantined { .. } => {
                Err(PciReservationError::Quarantined)
            }
            _ => Err(PciReservationError::StaleAssignment),
        }
    }

    /// Finishes revocation after all DMA and interrupt authority is gone.
    pub fn finish_revocation(mut self) -> Result<(), PciReservationError> {
        if !self.revocation_started {
            return Err(PciReservationError::StaleAssignment);
        }

        let mut registry = registry().lock();
        let state = registry
            .groups
            .get_mut(&self.key)
            .expect("a revoking PCI group remains registered");
        finish_revocation_state(state, self.identity, &mut self.devices)
    }

    /// Permanently quarantines the group for this Host boot.
    pub fn quarantine(mut self) {
        let Some(devices) = self.devices.take() else {
            return;
        };
        quiesce_devices(&devices);
        let mut registry = registry().lock();
        let state = registry
            .groups
            .get_mut(&self.key)
            .expect("an assigned PCI group remains registered");
        *state = ReservationState::Quarantined {
            identity: self.identity,
            _devices: devices,
        };
    }
}

impl fmt::Debug for AssignedPciGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AssignedPciGroup")
            .field("address", &self.key)
            .field("identity", &self.identity)
            .field("revocation_started", &self.revocation_started)
            .finish_non_exhaustive()
    }
}

impl Drop for AssignedPciGroup {
    fn drop(&mut self) {
        let Some(devices) = self.devices.take() else {
            return;
        };
        quiesce_devices(&devices);
        let mut registry = registry().lock();
        let state = registry
            .groups
            .get_mut(&self.key)
            .expect("an assigned PCI group remains registered");
        *state = ReservationState::Quarantined {
            identity: self.identity,
            _devices: devices,
        };
    }
}

/// Acquires one boot-reserved singleton requester group.
pub fn claim_reserved_group(
    segment: u16,
    location: PciDeviceLocation,
) -> Result<ReservedPciGroup, PciReservationError> {
    let key = ReservedPciAddress { segment, location };
    let mut registry = registry().lock();
    let state = registry
        .groups
        .get_mut(&key)
        .ok_or(PciReservationError::NotReserved)?;
    let devices = take_reserved_devices(state)?;

    Ok(ReservedPciGroup {
        key,
        devices: Some(devices),
        #[cfg(target_arch = "x86_64")]
        requester_lease_issued: false,
    })
}

fn take_reserved_devices(
    state: &mut ReservationState,
) -> Result<Vec<PciCommonDevice>, PciReservationError> {
    if matches!(
        state,
        ReservationState::QuarantineRequested(_) | ReservationState::Quarantined { .. }
    ) {
        return Err(PciReservationError::Quarantined);
    }

    let previous = mem::replace(state, ReservationState::Acquiring);
    let ReservationState::Reserved(devices) = previous else {
        *state = previous;
        return Err(PciReservationError::Busy);
    };
    if devices.is_empty() {
        *state = ReservationState::Reserved(devices);
        return Err(PciReservationError::NotFound);
    }
    if devices.len() != 1 || devices[0].has_multi_funcs() {
        *state = ReservationState::Reserved(devices);
        return Err(PciReservationError::UnsupportedGroup);
    }
    Ok(devices)
}

fn finish_revocation_state(
    state: &mut ReservationState,
    identity: PciAssignmentIdentity,
    devices: &mut Option<Vec<PciCommonDevice>>,
) -> Result<(), PciReservationError> {
    match state {
        ReservationState::Revoking(current) if *current == identity => {
            *state = ReservationState::Reserved(
                devices
                    .take()
                    .expect("a live PCI assignment owns its devices"),
            );
            Ok(())
        }
        ReservationState::QuarantineRequested(current) if *current == identity => {
            *state = ReservationState::Quarantined {
                identity,
                _devices: devices
                    .take()
                    .expect("a live PCI assignment owns its devices"),
            };
            Err(PciReservationError::Quarantined)
        }
        ReservationState::Quarantined { .. } => Err(PciReservationError::Quarantined),
        _ => Err(PciReservationError::StaleAssignment),
    }
}

fn request_quarantine(
    state: &mut ReservationState,
) -> Result<PciAssignmentIdentity, PciReservationError> {
    let identity = match state {
        ReservationState::Assigned(identity) | ReservationState::Revoking(identity) => *identity,
        ReservationState::QuarantineRequested(identity)
        | ReservationState::Quarantined { identity, .. } => return Ok(*identity),
        ReservationState::Reserved(_) | ReservationState::Acquiring => {
            return Err(PciReservationError::StaleAssignment);
        }
    };
    *state = ReservationState::QuarantineRequested(identity);
    Ok(identity)
}

fn refresh_singleton_device(devices: &mut [PciCommonDevice]) -> Result<(), PciReservationError> {
    if devices.len() != 1 {
        return Err(PciReservationError::UnsupportedGroup);
    }
    // A BAR access is cached by the software device as well as cloned into its
    // driver. Assignment revocation has already drained and dropped the driver
    // clones. Drop the cache before constructing the replacement view so the
    // next owner can acquire an exclusive `IoMem` capability for the same BAR.
    devices[0].bar_manager_mut().release_cached_accesses();
    let location = *devices[0].location();
    let refreshed = PciCommonDevice::new(location, PciDeviceInitialization::Reserved)
        .ok_or(PciReservationError::NotFound)?;
    if refreshed.has_multi_funcs() {
        return Err(PciReservationError::UnsupportedGroup);
    }
    devices[0] = refreshed;
    Ok(())
}

/// Requests quarantine for the assignment that owns one physical requester ID.
pub fn request_quarantine_for_source(
    source_identifier: u16,
) -> Result<PciAssignmentIdentity, PciReservationError> {
    let bus = (source_identifier >> 8) as u8;
    let device = ((source_identifier >> 3) & 0x1f) as u8;
    let function = (source_identifier & 0x7) as u8;
    let location = PciDeviceLocation {
        bus,
        device,
        function,
    };
    let mut registry = registry().lock();
    let key = registry
        .group_key(location)
        .ok_or(PciReservationError::NotReserved)?;
    let state = registry
        .groups
        .get_mut(&key)
        .expect("a matched PCI reservation remains registered");
    request_quarantine(state)
}

/// Requests quarantine for every assignment that may be affected by lost fault records.
pub fn request_quarantine_for_active_assignments() -> Vec<PciAssignmentIdentity> {
    let mut registry = registry().lock();
    registry
        .groups
        .values_mut()
        .filter_map(|state| match state {
            ReservationState::Assigned(_)
            | ReservationState::Revoking(_)
            | ReservationState::QuarantineRequested(_) => request_quarantine(state).ok(),
            ReservationState::Reserved(_)
            | ReservationState::Acquiring
            | ReservationState::Quarantined { .. } => None,
        })
        .collect()
}

pub(super) fn is_reserved_group_member(location: PciDeviceLocation) -> bool {
    registry().lock().group_key(location).is_some()
}

pub(super) fn try_reserve(device: PciCommonDevice) -> Option<PciCommonDevice> {
    let location = *device.location();
    let mut registry = registry().lock();
    let Some(key) = registry.group_key(location) else {
        return Some(device);
    };
    let state = registry
        .groups
        .get_mut(&key)
        .expect("a matched PCI reservation remains registered");
    let ReservationState::Reserved(devices) = state else {
        panic!("PCI enumeration cannot race assignment acquisition");
    };
    devices.push(device);
    None
}

fn registry() -> &'static Mutex<ReservationRegistry> {
    REGISTRY.call_once(|| Mutex::new(ReservationRegistry::from_boot_configuration()))
}

fn quiesce_devices(devices: &[PciCommonDevice]) {
    use crate::cfg_space::Command;

    for device in devices {
        let command = device.read_command()
            - (Command::BUS_MASTER | Command::MEMORY_SPACE | Command::IO_SPACE);
        device.write_command(command);
    }
}

static RESERVED_PCI_ADDRESSES: Once<Vec<ReservedPciAddress>> = Once::new();
static REGISTRY: Once<Mutex<ReservationRegistry>> = Once::new();

aster_cmdline::define_repeatable_kv_param!("framevm.pci_reserve", RESERVED_PCI_ADDRESSES);

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn parses_only_segment_zero_function_zero_bdfs() {
        let address = "0000:02:1f.0".parse::<ReservedPciAddress>().unwrap();
        assert_eq!(address.segment, 0);
        assert_eq!(address.location.bus, 2);
        assert_eq!(address.location.device, 31);
        assert_eq!(address.location.function, 0);

        assert!("0001:02:1f.0".parse::<ReservedPciAddress>().is_err());
        assert!("0000:02:20.0".parse::<ReservedPciAddress>().is_err());
        assert!("0000:02:1f.1".parse::<ReservedPciAddress>().is_err());
    }

    #[ktest]
    fn assignment_identity_requires_nonzero_generation() {
        assert_eq!(PciAssignmentIdentity::new(7, 0), None);
        let identity = PciAssignmentIdentity::new(7, 1).unwrap();
        assert_eq!(identity.owner(), 7);
        assert_eq!(identity.generation(), 1);
    }

    #[ktest]
    fn busy_claim_preserves_assignment_identity() {
        let identity = PciAssignmentIdentity::new(7, 3).unwrap();
        let mut state = ReservationState::Assigned(identity);

        assert!(matches!(
            take_reserved_devices(&mut state),
            Err(PciReservationError::Busy)
        ));
        assert!(matches!(
            state,
            ReservationState::Assigned(current) if current == identity
        ));
    }

    #[ktest]
    fn quarantined_group_cannot_be_acquired() {
        let identity = PciAssignmentIdentity::new(9, 1).unwrap();
        let mut state = ReservationState::Quarantined {
            identity,
            _devices: Vec::new(),
        };

        assert!(matches!(
            take_reserved_devices(&mut state),
            Err(PciReservationError::Quarantined)
        ));
        assert!(matches!(
            state,
            ReservationState::Quarantined {
                identity: current,
                ..
            } if current == identity
        ));
    }

    #[ktest]
    fn fault_latch_prevents_orderly_release() {
        let identity = PciAssignmentIdentity::new(9, 2).unwrap();
        let mut state = ReservationState::Revoking(identity);
        let mut devices = Some(Vec::<PciCommonDevice>::new());

        assert_eq!(request_quarantine(&mut state), Ok(identity));
        assert!(matches!(
            state,
            ReservationState::QuarantineRequested(current) if current == identity
        ));
        assert_eq!(
            finish_revocation_state(&mut state, identity, &mut devices),
            Err(PciReservationError::Quarantined)
        );
        assert!(devices.is_none());
        assert!(matches!(
            state,
            ReservationState::Quarantined {
                identity: current,
                ..
            } if current == identity
        ));
    }
}
