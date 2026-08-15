// SPDX-License-Identifier: MPL-2.0

use alloc::collections::{BTreeMap, BTreeSet};

use super::{PciDeviceLocation, second_stage::IommuPtConfig};
use crate::{
    debug,
    mm::{
        Daddr, Frame, FrameAllocOptions, HasPaddr, PAGE_SIZE, Paddr, PageFlags, PageTable, VmIo,
        page_prop::{CachePolicy, PageProperty, PrivilegedPageFlags as PrivFlags},
        page_table::PageTableError,
    },
    task::disable_preempt,
};

pub(super) type DomainId = u16;

pub(super) const HOST_DOMAIN_ID: DomainId = 1;
pub(super) const DENY_ALL_DOMAIN_ID: DomainId = 2;
const FIRST_DYNAMIC_DOMAIN_ID: DomainId = 3;

/// Bit 0 is `Present` bit, indicating whether this entry is present.
/// Bit 63:12 is the context-table pointer pointing to this bus's context-table.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
pub struct RootEntry(u128);

impl RootEntry {
    pub const fn is_present(&self) -> bool {
        self.0 & 1 != 0
    }

    pub const fn addr(&self) -> u64 {
        (self.0 & 0xFFFF_FFFF_FFFF_F000) as u64
    }
}

#[derive(Debug)]
pub enum ContextTableError {
    AlreadyMapped,
    DeviceBusy,
    InvalidAddress,
    InvalidDeviceId,
    InvalidDomain,
    ModificationError(PageTableError),
    NoDomainIds,
    NotMapped,
}

#[derive(Clone, Copy, Debug)]
struct MappingRecord {
    paddr: Paddr,
    references: usize,
}

struct Domain {
    page_table: PageTable<IommuPtConfig>,
    devices: BTreeSet<PciDeviceLocation>,
    mappings: BTreeMap<Daddr, MappingRecord>,
}

/// Keeps a detached page table alive until hardware cache invalidation ends.
pub(super) struct DetachedDomain {
    pub(super) id: DomainId,
    _domain: Domain,
}

impl Domain {
    fn empty() -> Self {
        Self {
            page_table: PageTable::empty(),
            devices: BTreeSet::new(),
            mappings: BTreeMap::new(),
        }
    }
}

pub struct RootTable {
    /// Total 256 buses, each entry is 128 bits.
    root_frame: Frame<()>,
    context_tables: BTreeMap<Paddr, ContextTable>,
    device_domains: BTreeMap<PciDeviceLocation, DomainId>,
    claimed_devices: BTreeSet<PciDeviceLocation>,
    domains: BTreeMap<DomainId, Domain>,
    free_domain_ids: BTreeSet<DomainId>,
    next_domain_id: Option<DomainId>,
}

impl RootTable {
    pub fn root_paddr(&self) -> Paddr {
        self.root_frame.paddr()
    }

    pub(super) fn new() -> Self {
        // PCI discovery registers actual Host requesters after it has
        // enumerated them. Assignment requesters are attached later from a
        // reservation lease. Keeping the root table empty here avoids
        // allocating context entries for every possible BDF.
        Self::empty()
    }

    fn empty() -> Self {
        let mut domains = BTreeMap::new();
        domains.insert(HOST_DOMAIN_ID, Domain::empty());
        domains.insert(DENY_ALL_DOMAIN_ID, Domain::empty());

        Self {
            root_frame: FrameAllocOptions::new().alloc_frame().unwrap(),
            context_tables: BTreeMap::new(),
            device_domains: BTreeMap::new(),
            claimed_devices: BTreeSet::new(),
            domains,
            free_domain_ids: BTreeSet::new(),
            next_domain_id: Some(FIRST_DYNAMIC_DOMAIN_ID),
        }
    }

    pub(super) fn create_domain(&mut self) -> Result<DomainId, ContextTableError> {
        let domain_id = if let Some(domain_id) = self.free_domain_ids.pop_first() {
            domain_id
        } else {
            let domain_id = self
                .next_domain_id
                .take()
                .ok_or(ContextTableError::NoDomainIds)?;
            self.next_domain_id = domain_id.checked_add(1);
            domain_id
        };
        debug_assert!(!self.domains.contains_key(&domain_id));
        self.domains.insert(domain_id, Domain::empty());
        Ok(domain_id)
    }

    pub(super) fn recycle_domain_id(&mut self, domain_id: DomainId) {
        debug_assert!(domain_id >= FIRST_DYNAMIC_DOMAIN_ID);
        debug_assert!(!self.domains.contains_key(&domain_id));
        debug_assert!(!self.free_domain_ids.contains(&domain_id));
        self.free_domain_ids.insert(domain_id);
    }

    pub(super) fn claim_device(
        &mut self,
        device: PciDeviceLocation,
    ) -> Result<(), ContextTableError> {
        device.validate()?;
        if self
            .device_domains
            .get(&device)
            .is_some_and(|domain_id| *domain_id != DENY_ALL_DOMAIN_ID)
            || !self.claimed_devices.insert(device)
        {
            return Err(ContextTableError::DeviceBusy);
        }
        Ok(())
    }

    pub(super) fn release_device_claim(&mut self, device: PciDeviceLocation) {
        self.claimed_devices.remove(&device);
    }

    pub(super) fn attach_device(
        &mut self,
        device: PciDeviceLocation,
        domain_id: DomainId,
    ) -> Result<(), ContextTableError> {
        device.validate()?;
        let page_table_paddr = self
            .domains
            .get(&domain_id)
            .ok_or(ContextTableError::InvalidDomain)?
            .page_table
            .root_paddr();

        if self.device_domains.get(&device) == Some(&domain_id) {
            return Ok(());
        }

        if domain_id == HOST_DOMAIN_ID && self.claimed_devices.contains(&device) {
            return Err(ContextTableError::DeviceBusy);
        }

        if domain_id >= FIRST_DYNAMIC_DOMAIN_ID && !self.claimed_devices.contains(&device) {
            return Err(ContextTableError::DeviceBusy);
        }

        if let Some(previous_domain_id) = self.device_domains.get(&device).copied()
            && previous_domain_id != DENY_ALL_DOMAIN_ID
            && domain_id != DENY_ALL_DOMAIN_ID
        {
            return Err(ContextTableError::DeviceBusy);
        }

        self.get_or_create_context_table(device)
            .set_domain(device, domain_id, page_table_paddr);

        if let Some(previous_domain_id) = self.device_domains.insert(device, domain_id) {
            self.domains
                .get_mut(&previous_domain_id)
                .expect("every attached requester has a domain")
                .devices
                .remove(&device);
        }
        self.domains
            .get_mut(&domain_id)
            .expect("the target domain was validated")
            .devices
            .insert(device);
        if domain_id >= FIRST_DYNAMIC_DOMAIN_ID {
            self.claimed_devices.remove(&device);
        }
        Ok(())
    }

    pub(super) fn detach_domain(
        &mut self,
        domain_id: DomainId,
    ) -> Result<DetachedDomain, ContextTableError> {
        if domain_id == HOST_DOMAIN_ID || domain_id == DENY_ALL_DOMAIN_ID {
            return Err(ContextTableError::InvalidDomain);
        }
        let devices = self
            .domains
            .get(&domain_id)
            .ok_or(ContextTableError::InvalidDomain)?
            .devices
            .iter()
            .copied()
            .collect::<alloc::vec::Vec<_>>();
        for device in devices {
            self.attach_device(device, DENY_ALL_DOMAIN_ID)?;
        }
        let domain = self
            .domains
            .remove(&domain_id)
            .ok_or(ContextTableError::InvalidDomain)?;
        Ok(DetachedDomain {
            id: domain_id,
            _domain: domain,
        })
    }

    /// Maps one device-address page in a domain.
    ///
    /// # Safety
    ///
    /// The physical address must identify an untyped page that remains alive
    /// until the matching final [`Self::unmap`] call.
    pub(super) unsafe fn map(
        &mut self,
        domain_id: DomainId,
        daddr: Daddr,
        paddr: Paddr,
    ) -> Result<(), ContextTableError> {
        if !daddr.is_multiple_of(PAGE_SIZE) || !paddr.is_multiple_of(PAGE_SIZE) {
            return Err(ContextTableError::InvalidAddress);
        }
        daddr
            .checked_add(PAGE_SIZE)
            .ok_or(ContextTableError::InvalidAddress)?;
        paddr
            .checked_add(PAGE_SIZE)
            .ok_or(ContextTableError::InvalidAddress)?;

        let domain = self
            .domains
            .get_mut(&domain_id)
            .ok_or(ContextTableError::InvalidDomain)?;
        if let Some(mapping) = domain.mappings.get_mut(&daddr) {
            if mapping.paddr != paddr {
                return Err(ContextTableError::AlreadyMapped);
            }
            mapping.references = mapping
                .references
                .checked_add(1)
                .ok_or(ContextTableError::AlreadyMapped)?;
            return Ok(());
        }

        debug!(
            "Mapping Daddr: {:#x} to Paddr: {:#x} in domain: {}",
            daddr, paddr, domain_id
        );
        let from = daddr..daddr + PAGE_SIZE;
        let prop = PageProperty {
            flags: PageFlags::RW,
            cache: CachePolicy::Uncacheable,
            priv_flags: PrivFlags::empty(),
        };
        let preempt_guard = disable_preempt();
        let mut cursor = domain
            .page_table
            .cursor_mut(&preempt_guard, &from)
            .map_err(ContextTableError::ModificationError)?;

        // SAFETY: The safety is upheld by the caller and the page-alignment checks above.
        unsafe { cursor.map((paddr, 1, prop)) };
        domain.mappings.insert(
            daddr,
            MappingRecord {
                paddr,
                references: 1,
            },
        );
        Ok(())
    }

    pub(super) fn unmap(
        &mut self,
        domain_id: DomainId,
        daddr: Daddr,
    ) -> Result<(), ContextTableError> {
        if !daddr.is_multiple_of(PAGE_SIZE) {
            return Err(ContextTableError::InvalidAddress);
        }
        let domain = self
            .domains
            .get_mut(&domain_id)
            .ok_or(ContextTableError::InvalidDomain)?;
        let mapping = domain
            .mappings
            .get_mut(&daddr)
            .ok_or(ContextTableError::NotMapped)?;
        if mapping.references > 1 {
            mapping.references -= 1;
            return Ok(());
        }

        debug!("Unmapping Daddr: {:#x} in domain: {}", daddr, domain_id);
        let preempt_guard = disable_preempt();
        let mut cursor = domain
            .page_table
            .cursor_mut(&preempt_guard, &(daddr..daddr + PAGE_SIZE))
            .map_err(ContextTableError::ModificationError)?;
        // SAFETY: Removing a page-table mapping does not dereference its physical address.
        let fragment = unsafe { cursor.take_next(PAGE_SIZE) };
        if fragment.is_none() {
            return Err(ContextTableError::NotMapped);
        }
        domain.mappings.remove(&daddr);
        Ok(())
    }

    fn get_or_create_context_table(&mut self, device: PciDeviceLocation) -> &mut ContextTable {
        let root_entry = self
            .root_frame
            .read_val::<RootEntry>(device.bus as usize * size_of::<RootEntry>())
            .unwrap();

        if !root_entry.is_present() {
            let table = ContextTable::new();
            let address = table.paddr();
            self.context_tables.insert(address, table);
            self.root_frame
                .write_val::<RootEntry>(
                    device.bus as usize * size_of::<RootEntry>(),
                    &RootEntry(address as u128 | 1),
                )
                .unwrap();
            self.context_tables.get_mut(&address).unwrap()
        } else {
            self.context_tables
                .get_mut(&(root_entry.addr() as usize))
                .unwrap()
        }
    }
}

/// One legacy VT-d context entry.
#[repr(C)]
#[derive(Clone, Copy, Pod)]
pub struct ContextEntry(u128);

impl ContextEntry {
    const PRESENT: u128 = 1;
    const LEVEL_3_ADDRESS_WIDTH: u128 = 1 << 64;

    fn new(domain_id: DomainId, page_table_paddr: Paddr) -> Self {
        Self(
            page_table_paddr as u128
                | Self::PRESENT
                | Self::LEVEL_3_ADDRESS_WIDTH
                | (domain_id as u128) << 72,
        )
    }

    #[cfg(ktest)]
    const fn domain_identifier(self) -> DomainId {
        ((self.0 >> 72) & 0xffff) as DomainId
    }

    #[cfg(ktest)]
    const fn second_stage_pointer(self) -> Paddr {
        (self.0 & 0xFFFF_FFFF_FFFF_F000) as Paddr
    }
}

#[cfg(ktest)]
mod tests {
    use super::*;
    use crate::prelude::ktest;

    fn requester() -> PciDeviceLocation {
        PciDeviceLocation {
            bus: 2,
            device: 3,
            function: 1,
        }
    }

    fn context_entry(table: &mut RootTable, device: PciDeviceLocation) -> ContextEntry {
        table
            .get_or_create_context_table(device)
            .entries_frame
            .read_val::<ContextEntry>(
                (device.device as usize * 8 + device.function as usize) * size_of::<ContextEntry>(),
            )
            .unwrap()
    }

    #[ktest]
    fn requester_moves_between_independent_domains() {
        let mut table = RootTable::empty();
        let domain_id = table.create_domain().unwrap();
        let domain_root = table.domains[&domain_id].page_table.root_paddr();

        table.claim_device(requester()).unwrap();
        table.attach_device(requester(), domain_id).unwrap();
        let entry = context_entry(&mut table, requester());
        assert_eq!(entry.domain_identifier(), domain_id);
        assert_eq!(entry.second_stage_pointer(), domain_root);

        let detached = table.detach_domain(domain_id).unwrap();
        assert_eq!(table.device_domains[&requester()], DENY_ALL_DOMAIN_ID);
        assert!(!table.domains.contains_key(&domain_id));

        drop(detached);
        table.claim_device(requester()).unwrap();
        let replacement_domain = table.create_domain().unwrap();
        table
            .attach_device(requester(), replacement_domain)
            .unwrap();
    }

    #[ktest]
    fn requester_claims_are_exclusive() {
        let mut table = RootTable::empty();
        let requester = requester();

        table.claim_device(requester).unwrap();
        assert!(matches!(
            table.claim_device(requester),
            Err(ContextTableError::DeviceBusy)
        ));
        assert!(matches!(
            table.attach_device(requester, HOST_DOMAIN_ID),
            Err(ContextTableError::DeviceBusy)
        ));

        table.release_device_claim(requester);
        table.attach_device(requester, HOST_DOMAIN_ID).unwrap();
        assert_eq!(table.device_domains[&requester], HOST_DOMAIN_ID);
    }

    #[ktest]
    fn unclaimed_requester_cannot_enter_dynamic_domain() {
        let mut table = RootTable::empty();
        let domain_id = table.create_domain().unwrap();

        assert!(matches!(
            table.attach_device(requester(), domain_id),
            Err(ContextTableError::DeviceBusy)
        ));
    }

    #[ktest]
    fn identical_mapping_is_reference_counted() {
        let mut table = RootTable::empty();
        let domain_id = table.create_domain().unwrap();
        let frame = FrameAllocOptions::new().alloc_frame().unwrap();
        let daddr = PAGE_SIZE * 7;

        // SAFETY: `frame` is untyped and remains alive through both unmaps.
        unsafe { table.map(domain_id, daddr, frame.paddr()) }.unwrap();
        // SAFETY: This adds a compatible reference to the same live frame.
        unsafe { table.map(domain_id, daddr, frame.paddr()) }.unwrap();
        assert_eq!(table.domains[&domain_id].mappings[&daddr].references, 2);

        table.unmap(domain_id, daddr).unwrap();
        assert_eq!(table.domains[&domain_id].mappings[&daddr].references, 1);
        table.unmap(domain_id, daddr).unwrap();
        assert!(!table.domains[&domain_id].mappings.contains_key(&daddr));
        assert!(matches!(
            table.unmap(domain_id, daddr),
            Err(ContextTableError::NotMapped)
        ));
    }

    #[ktest]
    fn domains_isolate_identical_device_addresses() {
        let mut table = RootTable::empty();
        let first_domain = table.create_domain().unwrap();
        let second_domain = table.create_domain().unwrap();
        let first_frame = FrameAllocOptions::new().alloc_frame().unwrap();
        let second_frame = FrameAllocOptions::new().alloc_frame().unwrap();
        let daddr = PAGE_SIZE * 11;

        // SAFETY: Each frame is untyped and remains alive until its mapping is
        // removed below.
        unsafe { table.map(first_domain, daddr, first_frame.paddr()) }.unwrap();
        // SAFETY: The second frame satisfies the same lifetime requirement in
        // an independent domain.
        unsafe { table.map(second_domain, daddr, second_frame.paddr()) }.unwrap();

        assert_eq!(
            table.domains[&first_domain].mappings[&daddr].paddr,
            first_frame.paddr()
        );
        assert_eq!(
            table.domains[&second_domain].mappings[&daddr].paddr,
            second_frame.paddr()
        );

        table.unmap(first_domain, daddr).unwrap();
        assert!(table.domains[&first_domain].mappings.is_empty());
        assert_eq!(
            table.domains[&second_domain].mappings[&daddr].paddr,
            second_frame.paddr()
        );
        table.unmap(second_domain, daddr).unwrap();
    }

    #[ktest]
    fn conflicting_mapping_preserves_existing_authority() {
        let mut table = RootTable::empty();
        let domain_id = table.create_domain().unwrap();
        let original_frame = FrameAllocOptions::new().alloc_frame().unwrap();
        let conflicting_frame = FrameAllocOptions::new().alloc_frame().unwrap();
        let daddr = PAGE_SIZE * 13;

        // SAFETY: `original_frame` remains alive until the final unmap.
        unsafe { table.map(domain_id, daddr, original_frame.paddr()) }.unwrap();
        // SAFETY: `conflicting_frame` remains alive for this attempted map.
        let result = unsafe { table.map(domain_id, daddr, conflicting_frame.paddr()) };

        assert!(matches!(result, Err(ContextTableError::AlreadyMapped)));
        let mapping = table.domains[&domain_id].mappings[&daddr];
        assert_eq!(mapping.paddr, original_frame.paddr());
        assert_eq!(mapping.references, 1);
        table.unmap(domain_id, daddr).unwrap();
    }

    #[ktest]
    fn detached_domain_identifiers_are_recycled_after_invalidation() {
        let mut table = RootTable::empty();
        let detached_id = table.create_domain().unwrap();
        let detached = table.detach_domain(detached_id).unwrap();
        assert!(table.free_domain_ids.is_empty());
        drop(detached);
        table.recycle_domain_id(detached_id);
        let next_id = table.create_domain().unwrap();

        assert_eq!(next_id, detached_id);
        assert!(table.domains.contains_key(&detached_id));
    }

    #[ktest]
    fn final_domain_identifier_is_allocated_once() {
        let mut table = RootTable::empty();
        table.next_domain_id = Some(DomainId::MAX);

        assert_eq!(table.create_domain().unwrap(), DomainId::MAX);
        assert!(matches!(
            table.create_domain(),
            Err(ContextTableError::NoDomainIds)
        ));
    }
}

pub struct ContextTable {
    /// Total 32 devices with 8 functions each.
    entries_frame: Frame<()>,
}

impl ContextTable {
    fn new() -> Self {
        Self {
            entries_frame: FrameAllocOptions::new().alloc_frame().unwrap(),
        }
    }

    fn paddr(&self) -> Paddr {
        self.entries_frame.paddr()
    }

    fn set_domain(
        &mut self,
        device: PciDeviceLocation,
        domain_id: DomainId,
        page_table_paddr: Paddr,
    ) {
        self.entries_frame
            .write_val::<ContextEntry>(
                (device.device as usize * 8 + device.function as usize) * size_of::<ContextEntry>(),
                &ContextEntry::new(domain_id, page_table_paddr),
            )
            .unwrap();
    }
}
