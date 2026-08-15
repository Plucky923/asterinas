// SPDX-License-Identifier: MPL-2.0

//! Physical PCI assignment resources owned by one FrameVM.

use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};

use aster_pci::{
    AssignedPciGroup, PciAssignmentIdentity, PciDeviceLocation, ReservedPciGroup,
    cfg_space::{Bar, BarAccess, Command},
};
use host_ostd::{
    irq::{IrqLine as HostIrqLine, PciIrqRequester as HostPciIrqRequester},
    mm::{
        PodOnce, VmIoOnce,
        dma::{PciDmaDomain, PciDmaError},
    },
    sync::WaitQueue,
};

use crate::{
    Error, Result, irq,
    sync::{Mutex, SpinLock},
    vm::VmId,
};

const PCI_CONFIG_DWORD_COUNT: usize = 64;
const PCI_BAR0_OFFSET: u16 = 0x10;
const PCI_BAR_DWORD_COUNT: usize = 6;
const PCI_CAPABILITY_EXPRESS: u8 = 0x10;
const PCI_CAPABILITY_MSIX: u8 = 0x11;
const PCIE_DEVICE_CAPABILITIES_OFFSET: u16 = 0x04;
const PCIE_DEVICE_CONTROL_OFFSET: u16 = 0x08;
const PCIE_DEVICE_CAPABILITIES_FLR: u32 = 1 << 28;
const PCIE_DEVICE_CONTROL_INITIATE_FLR: u16 = 1 << 15;
const PCIE_FUNCTION_RESET_DELAY_MILLIS: u64 = 100;
const PCI_EXTENDED_CAPABILITY_START: u16 = 0x100;
const PCI_EXTENDED_CAPABILITY_END: u16 = 0xffc;
const PCI_EXTENDED_CAPABILITY_ATS: u16 = 0x000f;
const PCI_EXTENDED_CAPABILITY_PRI: u16 = 0x0013;
const PCI_EXTENDED_CAPABILITY_PASID: u16 = 0x001b;

struct PhysicalBar {
    index: u8,
    size: usize,
    io_mem: host_ostd::io::IoMem,
}

struct AccessState {
    accepting: bool,
    active_calls: u64,
}

/// Generation-scoped physical config-space and BAR authority.
pub(crate) struct AssignedPciAccess {
    location: PciDeviceLocation,
    identity: PciAssignmentIdentity,
    config: [u32; PCI_CONFIG_DWORD_COUNT],
    msix_control_offset: Option<u32>,
    function_reset: PciFunctionReset,
    bars: SpinLock<Option<Arc<Vec<PhysicalBar>>>>,
    state: SpinLock<AccessState>,
    idle_wait: WaitQueue,
    irq_routes: SpinLock<Vec<Weak<AssignedPciIrqRoute>>>,
}

#[derive(Clone, Copy)]
struct PciFunctionReset {
    location: PciDeviceLocation,
    device_control_offset: u16,
}

impl PciFunctionReset {
    fn from_config(
        location: PciDeviceLocation,
        config: &[u32; PCI_CONFIG_DWORD_COUNT],
    ) -> Result<Self> {
        let capability_offset = find_standard_capability_offset(config, PCI_CAPABILITY_EXPRESS)
            .ok_or(Error::InvalidArgs)?;
        let device_capabilities_offset = capability_offset
            .checked_add(u32::from(PCIE_DEVICE_CAPABILITIES_OFFSET))
            .ok_or(Error::Overflow)?;
        let device_capabilities = config
            .get(device_capabilities_offset as usize / 4)
            .ok_or(Error::InvalidArgs)?;
        if device_capabilities & PCIE_DEVICE_CAPABILITIES_FLR == 0 {
            return Err(Error::InvalidArgs);
        }
        let device_control_offset = u16::try_from(
            capability_offset
                .checked_add(u32::from(PCIE_DEVICE_CONTROL_OFFSET))
                .ok_or(Error::Overflow)?,
        )
        .map_err(|_| Error::Overflow)?;
        config
            .get(usize::from(device_control_offset) / 4)
            .ok_or(Error::InvalidArgs)?;
        Ok(Self {
            location,
            device_control_offset,
        })
    }

    fn reset(self, config: &[u32; PCI_CONFIG_DWORD_COUNT]) -> Result<()> {
        let control = self
            .location
            .try_read32(self.device_control_offset)
            .map_err(Error::from)?
            & 0xffff;
        self.location
            .try_write32(
                self.device_control_offset,
                control | u32::from(PCIE_DEVICE_CONTROL_INITIATE_FLR),
            )
            .map_err(Error::from)?;

        // PCIe requires software to wait 100 ms after initiating FLR before
        // issuing configuration requests to the function. This lifecycle-only
        // delay must remain on the current task: yielding here can transfer the
        // CPU to the not-yet-started FrameVM scheduling group and indefinitely
        // postpone the assignment transaction.
        let wait_cycles = host_ostd::arch::tsc_freq()
            .checked_mul(PCIE_FUNCTION_RESET_DELAY_MILLIS)
            .ok_or(Error::Overflow)?
            / 1_000;
        let start = host_ostd::arch::read_tsc();
        while host_ostd::arch::read_tsc().wrapping_sub(start) < wait_cycles {
            core::hint::spin_loop();
        }

        // FLR may clear the BAR addresses. Restore them while memory-space
        // decoding remains disabled, before rebuilding any software BAR view.
        for index in (0..PCI_BAR_DWORD_COUNT).rev() {
            let offset = PCI_BAR0_OFFSET
                .checked_add(u16::try_from(index * 4).map_err(|_| Error::Overflow)?)
                .ok_or(Error::Overflow)?;
            self.location
                .try_write32(offset, config[usize::from(offset) / 4])
                .map_err(Error::from)?;
        }

        let identity = self.location.try_read32(0).map_err(Error::from)?;
        if identity == u32::MAX {
            return Err(Error::IoError);
        }
        Ok(())
    }
}

/// Revocable host interrupt-remapping route for one FrameVM IRQ line.
pub(crate) struct AssignedPciIrqRoute {
    location: PciDeviceLocation,
    remapping_index: u16,
    irq_line: Mutex<Option<HostIrqLine>>,
}

impl AssignedPciIrqRoute {
    pub(crate) const fn remapping_index(&self) -> u16 {
        self.remapping_index
    }

    #[inline(always)]
    pub(crate) fn bind_requester(&self, location: PciDeviceLocation) -> Result<()> {
        if location != self.location {
            return Err(Error::AccessDenied);
        }
        let requester = HostPciIrqRequester::new(
            self.location.bus,
            self.location.device,
            self.location.function,
        )
        .map_err(Error::from)?;
        self.irq_line
            .lock()
            .as_ref()
            .ok_or(Error::AccessDenied)?
            .bind_pci_requester(requester)
            .map_err(Error::from)
    }

    fn close(&self) {
        drop(self.irq_line.lock().take());
    }
}

impl AssignedPciAccess {
    fn new(group: &mut ReservedPciGroup, identity: PciAssignmentIdentity) -> Result<Arc<Self>> {
        let location = *group.device().location();
        let mut config = [0; PCI_CONFIG_DWORD_COUNT];
        for (index, value) in config.iter_mut().enumerate() {
            let offset = u16::try_from(index * 4).map_err(|_| Error::Overflow)?;
            *value = location.try_read32(offset).map_err(Error::from)?;
        }
        let function_reset = PciFunctionReset::from_config(location, &config)?;
        function_reset.reset(&config)?;
        group
            .refresh_after_function_reset()
            .map_err(|_| Error::IoError)?;

        for (index, value) in config.iter_mut().enumerate() {
            let offset = u16::try_from(index * 4).map_err(|_| Error::Overflow)?;
            *value = location.try_read32(offset).map_err(Error::from)?;
        }
        let msix_control_offset = find_standard_capability_offset(&config, PCI_CAPABILITY_MSIX);
        if msix_control_offset.is_none() {
            return Err(Error::InvalidArgs);
        }

        let device = group.device_mut();
        let mut bars = Vec::new();
        for index in 0..6_u8 {
            let Some(bar) = device.bar_manager_mut().bar_mut(index) else {
                continue;
            };
            let size = match bar {
                Bar::Memory(memory) => {
                    usize::try_from(memory.size()).map_err(|_| Error::Overflow)?
                }
                Bar::Io(_) => return Err(Error::InvalidArgs),
            };
            let BarAccess::Memory(io_mem) = bar.acquire().map_err(Error::from)? else {
                return Err(Error::InvalidArgs);
            };
            bars.push(PhysicalBar {
                index,
                size,
                io_mem,
            });
        }
        if bars.iter().all(|bar| bar.index != 0) {
            return Err(Error::InvalidArgs);
        }
        Ok(Arc::new(Self {
            location,
            identity,
            config,
            msix_control_offset,
            function_reset,
            bars: SpinLock::new(Some(Arc::new(bars))),
            state: SpinLock::new(AccessState {
                accepting: true,
                active_calls: 0,
            }),
            idle_wait: WaitQueue::new(),
            irq_routes: SpinLock::new(Vec::new()),
        }))
    }

    pub(crate) const fn identity(&self) -> PciAssignmentIdentity {
        self.identity
    }

    pub(crate) const fn physical_location(&self) -> PciDeviceLocation {
        self.location
    }

    pub(crate) const fn config_snapshot(&self) -> &[u32; PCI_CONFIG_DWORD_COUNT] {
        &self.config
    }

    pub(crate) fn bars(&self) -> Vec<(u8, usize)> {
        self.bars
            .lock()
            .as_ref()
            .expect("an accepting PCI assignment owns its BAR capabilities")
            .iter()
            .map(|bar| (bar.index, bar.size))
            .collect()
    }

    pub(crate) fn write_config32(&self, offset: u32, value: u32) -> Result<u32> {
        let _call = self.enter()?;
        match offset {
            0x04 => {
                let allowed =
                    Command::MEMORY_SPACE | Command::BUS_MASTER | Command::INTERRUPT_DISABLE;
                let current = self.location.read32(0x04);
                let requested = Command::from_bits_truncate(value as u16) & allowed;
                let preserved = Command::from_bits_truncate(current as u16) - allowed;
                let command = preserved | requested;
                self.location.write16(0x04, command.bits());
                Ok(self.location.read32(0x04))
            }
            control_offset if Some(control_offset) == self.msix_control_offset => {
                let current = self.location.read32(control_offset as u16);
                let updated = (current & !0xc000_0000) | (value & 0xc000_0000);
                self.location.write32(control_offset as u16, updated);
                Ok(updated)
            }
            _ => Err(Error::AccessDenied),
        }
    }

    pub(crate) fn read_bar<T: PodOnce>(&self, index: u8, offset: usize) -> host_ostd::Result<T> {
        let call = self.enter().map_err(to_ostd_error)?;
        let bar = call.bar(index).map_err(to_ostd_error)?;
        validate_bar_access(bar.size, offset, size_of::<T>()).map_err(to_ostd_error)?;
        bar.io_mem.read_once(offset)
    }

    pub(crate) fn write_bar<T: PodOnce>(
        &self,
        index: u8,
        offset: usize,
        value: &T,
    ) -> host_ostd::Result<()> {
        let call = self.enter().map_err(to_ostd_error)?;
        let bar = call.bar(index).map_err(to_ostd_error)?;
        validate_bar_access(bar.size, offset, size_of::<T>()).map_err(to_ostd_error)?;
        bar.io_mem.write_once(offset, value)?;
        Ok(())
    }

    pub(crate) fn allocate_irq_route(
        &self,
        vm_id: VmId,
        irq_num: u8,
        generation: u64,
    ) -> Result<Arc<AssignedPciIrqRoute>> {
        let Some(owner) = vm_id.guest_id() else {
            return Err(Error::InvalidArgs);
        };
        if self.identity.owner() != u64::from(owner) {
            return Err(Error::AccessDenied);
        }
        let _call = self.enter()?;
        let mut irq_line = HostIrqLine::alloc().map_err(Error::from)?;
        let remapping_index = irq_line.remapping_index().ok_or(Error::AccessDenied)?;
        irq_line.on_active(move |_| {
            let _ = irq::enqueue_physical_irq(vm_id, 0, irq_num, generation);
        });
        let route = Arc::new(AssignedPciIrqRoute {
            location: self.location,
            remapping_index,
            irq_line: Mutex::new(Some(irq_line)),
        });
        let mut routes = self.irq_routes.lock();
        routes.retain(|route| route.strong_count() != 0);
        routes.push(Arc::downgrade(&route));
        Ok(route)
    }

    #[inline(always)]
    fn enter(&self) -> Result<AssignedPciCall<'_>> {
        let mut state = self.state.lock();
        if !state.accepting {
            return Err(Error::AccessDenied);
        }
        state.active_calls = state.active_calls.checked_add(1).ok_or(Error::Overflow)?;
        let bars = self
            .bars
            .lock()
            .as_ref()
            .expect("an accepting PCI assignment owns its BAR capabilities")
            .clone();
        Ok(AssignedPciCall { access: self, bars })
    }

    fn close_and_wait(&self) {
        {
            let mut state = self.state.lock();
            state.accepting = false;
        }
        self.idle_wait
            .wait_until(|| (self.state.lock().active_calls == 0).then_some(()));
        let routes = core::mem::take(&mut *self.irq_routes.lock());
        for route in routes {
            if let Some(route) = route.upgrade() {
                route.close();
            }
        }
        // Service modules are retained after shutdown and may keep stale
        // `AssignedPciAccess` handles alive. Release the uniquely acquired BAR
        // capabilities at the assignment boundary, after active calls drain,
        // so a later owner can acquire fresh generation-scoped handles.
        drop(self.bars.lock().take());
    }

    fn reset_function(&self) -> Result<()> {
        self.function_reset.reset(&self.config)
    }

    #[inline(always)]
    fn release_call(&self) {
        let became_idle = {
            let mut state = self.state.lock();
            state.active_calls = state.active_calls.saturating_sub(1);
            state.active_calls == 0
        };
        if became_idle {
            self.idle_wait.wake_all();
        }
    }
}

struct AssignedPciCall<'a> {
    access: &'a AssignedPciAccess,
    bars: Arc<Vec<PhysicalBar>>,
}

impl AssignedPciCall<'_> {
    #[inline(always)]
    fn bar(&self, index: u8) -> Result<&PhysicalBar> {
        self.bars
            .iter()
            .find(|bar| bar.index == index)
            .ok_or(Error::AccessDenied)
    }
}

impl Drop for AssignedPciCall<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        self.access.release_call();
    }
}

/// Owns the physical requester and its isolated DMA domain.
pub(crate) struct AssignedPciDevice {
    group: Option<AssignedPciGroup>,
    dma_domain: Option<Arc<PciDmaDomain>>,
    access: Arc<AssignedPciAccess>,
}

impl AssignedPciDevice {
    pub(crate) fn new(vm_id: VmId, mut reserved: ReservedPciGroup) -> Result<Self> {
        let Some(vm_id) = vm_id.guest_id() else {
            return Err(Error::InvalidArgs);
        };
        validate_nvme_function(&reserved)?;
        let identity = PciAssignmentIdentity::new(u64::from(vm_id), 1)
            .expect("the first PCI assignment generation is nonzero");
        let access = AssignedPciAccess::new(&mut reserved, identity)?;
        validate_nvme_function(&reserved)?;
        let requester = reserved
            .requester_lease()
            .map_err(|_| Error::AccessDenied)?;
        let dma_domain = PciDmaDomain::new(requester).map_err(map_dma_error)?;
        let group = reserved.assign(identity);
        Ok(Self {
            group: Some(group),
            dma_domain: Some(dma_domain),
            access,
        })
    }

    pub(crate) fn dma_domain(&self) -> Arc<PciDmaDomain> {
        self.dma_domain
            .as_ref()
            .expect("a live PCI assignment owns its DMA domain")
            .clone()
    }

    pub(crate) fn access(&self) -> Arc<AssignedPciAccess> {
        self.access.clone()
    }

    pub(crate) fn quarantine(&mut self) {
        let Some(mut group) = self.group.take() else {
            return;
        };
        self.access.close_and_wait();
        if group.begin_revocation().is_ok() && self.access.reset_function().is_err() {
            ::log::error!("[framevisor] failed to reset quarantined PCI function");
        }
        drop(self.dma_domain.take());
        group.quarantine();
    }

    /// Revokes the assignment and reports whether it reached the reusable state.
    pub(crate) fn release(&mut self) -> Result<()> {
        let Some(mut group) = self.group.take() else {
            return Ok(());
        };
        self.access.close_and_wait();
        if group.begin_revocation().is_err() {
            drop(self.dma_domain.take());
            group.quarantine();
            return Err(Error::InvalidArgs);
        }

        if self.access.reset_function().is_err() {
            ::log::error!("[framevisor] failed to reset assigned PCI function");
            drop(self.dma_domain.take());
            group.quarantine();
            return Err(Error::InvalidArgs);
        }
        if group.refresh_after_function_reset().is_err() {
            ::log::error!("[framevisor] failed to refresh reset PCI function");
            drop(self.dma_domain.take());
            group.quarantine();
            return Err(Error::InvalidArgs);
        }

        // The requester is quiesced before dropping the domain. Domain drop
        // moves it to deny-all and synchronously invalidates translations.
        drop(self.dma_domain.take());
        group.finish_revocation().map_err(|error| {
            ::log::error!("[framevisor] failed to finish PCI assignment revocation: {error:?}");
            Error::InvalidArgs
        })
    }
}

impl Drop for AssignedPciDevice {
    fn drop(&mut self) {
        if self.release().is_err() {
            ::log::error!("[framevisor] assigned PCI revocation failed; group quarantined");
        }
    }
}

fn find_standard_capability_offset(
    config: &[u32; PCI_CONFIG_DWORD_COUNT],
    capability_id: u8,
) -> Option<u32> {
    let status = config[1] >> 16;
    if status & (1 << 4) == 0 {
        return None;
    }
    let mut offset = config[0x34 / 4] & 0xfc;
    for _ in 0..48 {
        if !(0x40..0x100).contains(&offset) || !offset.is_multiple_of(4) {
            return None;
        }
        let header = config[offset as usize / 4];
        if header & 0xff == u32::from(capability_id) {
            return Some(offset);
        }
        let next = (header >> 8) & 0xfc;
        if next == 0 || next == offset {
            return None;
        }
        offset = next;
    }
    None
}

#[inline(always)]
fn validate_bar_access(size: usize, offset: usize, width: usize) -> Result<()> {
    if width == 0 || !matches!(width, 1 | 2 | 4 | 8) || !offset.is_multiple_of(width) {
        return Err(Error::InvalidArgs);
    }
    let end = offset.checked_add(width).ok_or(Error::Overflow)?;
    if end > size {
        return Err(Error::InvalidArgs);
    }
    Ok(())
}

#[inline(always)]
fn to_ostd_error(error: Error) -> host_ostd::Error {
    match error {
        Error::InvalidArgs => host_ostd::Error::InvalidArgs,
        Error::NoMemory => host_ostd::Error::NoMemory,
        Error::PageFault => host_ostd::Error::PageFault,
        Error::AccessDenied => host_ostd::Error::AccessDenied,
        Error::IoError => host_ostd::Error::IoError,
        Error::NotEnoughResources => host_ostd::Error::NotEnoughResources,
        Error::Overflow => host_ostd::Error::Overflow,
    }
}

fn validate_nvme_function(group: &ReservedPciGroup) -> Result<()> {
    let device = group.device();
    let identity = device.device_id();
    if identity.class != 0x01 || identity.subclass != 0x08 || identity.prog_if != 0x02 {
        return Err(Error::InvalidArgs);
    }
    let forbidden_command = Command::BUS_MASTER | Command::MEMORY_SPACE | Command::IO_SPACE;
    if device.read_command().intersects(forbidden_command) {
        return Err(Error::AccessDenied);
    }
    validate_disabled_address_translation_features(*device.location())
}

fn validate_disabled_address_translation_features(location: PciDeviceLocation) -> Result<()> {
    validate_extended_capability_chain(|offset| location.try_read32(offset).map_err(Error::from))
}

fn validate_extended_capability_chain(
    mut read_config32_fn: impl FnMut(u16) -> Result<u32>,
) -> Result<()> {
    let mut offset = PCI_EXTENDED_CAPABILITY_START;
    loop {
        let header = read_config32_fn(offset)?;
        if header == 0 || header == u32::MAX {
            return Ok(());
        }

        let capability_id = header as u16;
        let is_enabled = match capability_id {
            // PCI Express ATS, PRI and PASID place their enable bits in the
            // first capability-specific dword, but at distinct bit positions.
            PCI_EXTENDED_CAPABILITY_ATS => {
                read_extended_capability_control(offset, &mut read_config32_fn)? & (1 << 31) != 0
            }
            PCI_EXTENDED_CAPABILITY_PRI => {
                read_extended_capability_control(offset, &mut read_config32_fn)? & (1 << 0) != 0
            }
            PCI_EXTENDED_CAPABILITY_PASID => {
                read_extended_capability_control(offset, &mut read_config32_fn)? & (1 << 16) != 0
            }
            _ => false,
        };
        if is_enabled {
            return Err(Error::AccessDenied);
        }

        let next_offset = (header >> 20) as u16;
        if next_offset == 0 {
            return Ok(());
        }
        if next_offset <= offset
            || !next_offset.is_multiple_of(4)
            || !(PCI_EXTENDED_CAPABILITY_START..=PCI_EXTENDED_CAPABILITY_END).contains(&next_offset)
        {
            return Err(Error::InvalidArgs);
        }
        offset = next_offset;
    }
}

fn read_extended_capability_control(
    capability_offset: u16,
    read_config32_fn: &mut impl FnMut(u16) -> Result<u32>,
) -> Result<u32> {
    let control_offset = capability_offset.checked_add(4).ok_or(Error::Overflow)?;
    if control_offset > PCI_EXTENDED_CAPABILITY_END {
        return Err(Error::InvalidArgs);
    }
    read_config32_fn(control_offset)
}

fn map_dma_error(error: PciDmaError) -> Error {
    match error {
        PciDmaError::InvalidAddress | PciDmaError::InvalidRequester => Error::InvalidArgs,
        PciDmaError::RequesterBusy => Error::AccessDenied,
        PciDmaError::AddressExhausted
        | PciDmaError::MappingConflict
        | PciDmaError::MappingRollbackFailed
        | PciDmaError::NoDmaRemapping
        | PciDmaError::NoQueuedInvalidation
        | PciDmaError::ResourceExhausted => Error::NotEnoughResources,
    }
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn accepts_disabled_address_translation_capabilities() {
        let capability_headers = [
            extended_capability_header(PCI_EXTENDED_CAPABILITY_ATS, 0x120),
            extended_capability_header(PCI_EXTENDED_CAPABILITY_PRI, 0x140),
            extended_capability_header(PCI_EXTENDED_CAPABILITY_PASID, 0),
        ];

        let result = validate_extended_capability_chain(|offset| match offset {
            0x100 => Ok(capability_headers[0]),
            0x104 => Ok(0),
            0x120 => Ok(capability_headers[1]),
            0x124 => Ok(0),
            0x140 => Ok(capability_headers[2]),
            0x144 => Ok(0),
            _ => Err(Error::InvalidArgs),
        });

        assert!(result.is_ok());
    }

    #[ktest]
    fn rejects_enabled_address_translation_capabilities() {
        for (capability_id, control) in [
            (PCI_EXTENDED_CAPABILITY_ATS, 1 << 31),
            (PCI_EXTENDED_CAPABILITY_PRI, 1 << 0),
            (PCI_EXTENDED_CAPABILITY_PASID, 1 << 16),
        ] {
            let result = validate_extended_capability_chain(|offset| match offset {
                0x100 => Ok(extended_capability_header(capability_id, 0)),
                0x104 => Ok(control),
                _ => Err(Error::InvalidArgs),
            });

            assert!(result.is_err());
        }
    }

    #[ktest]
    fn rejects_backward_extended_capability_links() {
        let result = validate_extended_capability_chain(|offset| match offset {
            0x100 => Ok(extended_capability_header(1, 0x120)),
            0x104 => Ok(0),
            0x120 => Ok(extended_capability_header(2, 0x100)),
            0x124 => Ok(0),
            _ => Err(Error::InvalidArgs),
        });

        assert!(result.is_err());
    }

    #[ktest]
    fn rejects_unaligned_extended_capability_links() {
        let result = validate_extended_capability_chain(|offset| match offset {
            0x100 => Ok(extended_capability_header(1, 0x122)),
            0x104 => Ok(0),
            _ => Err(Error::InvalidArgs),
        });

        assert!(result.is_err());
    }

    #[ktest]
    fn accepts_terminal_unknown_capability_at_config_boundary() {
        let result = validate_extended_capability_chain(|offset| match offset {
            0x100 => Ok(extended_capability_header(1, 0xffc)),
            0x104 => Ok(0),
            0xffc => Ok(extended_capability_header(2, 0)),
            _ => Err(Error::InvalidArgs),
        });

        assert!(result.is_ok());
    }

    #[ktest]
    fn accepts_function_level_reset_capability() {
        let mut config = [0; PCI_CONFIG_DWORD_COUNT];
        config[1] = 1 << 20;
        config[0x34 / 4] = 0x40;
        config[0x40 / 4] = u32::from(PCI_CAPABILITY_EXPRESS);
        config[0x44 / 4] = PCIE_DEVICE_CAPABILITIES_FLR;

        let reset = PciFunctionReset::from_config(
            PciDeviceLocation {
                bus: 0,
                device: 1,
                function: 0,
            },
            &config,
        );

        assert!(reset.is_ok());
    }

    #[ktest]
    fn rejects_function_without_function_level_reset() {
        let mut config = [0; PCI_CONFIG_DWORD_COUNT];
        config[1] = 1 << 20;
        config[0x34 / 4] = 0x40;
        config[0x40 / 4] = u32::from(PCI_CAPABILITY_EXPRESS);

        let reset = PciFunctionReset::from_config(
            PciDeviceLocation {
                bus: 0,
                device: 1,
                function: 0,
            },
            &config,
        );

        assert!(reset.is_err());
    }

    fn extended_capability_header(capability_id: u16, next_offset: u16) -> u32 {
        u32::from(capability_id) | (1 << 16) | (u32::from(next_offset) << 20)
    }
}
