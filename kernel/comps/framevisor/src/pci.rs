// SPDX-License-Identifier: MPL-2.0

//! FrameVM-private virtual PCI configuration spaces.

use alloc::{sync::Arc, vec, vec::Vec};
use core::{fmt, ops::Range};

use framev_blk_common::FrameVBlkConfig;
use framev_console_common::{MAX_INPUT_CHUNK_BYTES, QUEUED_INPUT_CAPACITY_BYTES};
use framev_net_common::FrameVNetConfig;
use framev_pci_common::{
    AssignedFunction, BlockConfig, BlockConfigFlags, ConsoleConfig, FRAMEV_PCI_CLASS,
    FRAMEV_PCI_PROGRAMMING_INTERFACE, FRAMEV_PCI_REVISION, FRAMEV_PCI_SUBCLASS,
    FRAMEV_PCI_VENDOR_ID, FrameVFunctionFamily, FrameVPciLayout, NetConfig, RngConfig, SockConfig,
    SyntheticFunction, TopologyFunction, VirtualPciBdf, allocate_topology,
};
use framev_rng_common::MAX_FILL_BYTES;
use host_ostd::mm::{PodOnce, VmIoOnce};

use crate::{
    Error, Result,
    assigned_pci::AssignedPciAccess,
    device::{FunctionClaim, FunctionRuntime},
    irq::{self, VirtualIrqLine},
    sync::SpinLock,
    task, vm,
};

const CONFIG_DWORD_COUNT: usize = 64;
const VIRTUAL_MMIO_BASE: u64 = 0x4000_0000;
const VIRTUAL_MMIO_FUNCTION_STRIDE: u64 = 0x1000;
const VIRTUAL_MMIO_END: u64 = VIRTUAL_MMIO_BASE + 32 * VIRTUAL_MMIO_FUNCTION_STRIDE;
const ASSIGNED_MMIO_BASE: u64 = 0x5000_0000;
const ASSIGNED_MMIO_END: u64 = 0x6000_0000;
const BAR0_OFFSET: u32 = 0x10;
const BAR1_OFFSET: u32 = 0x14;
const CAPABILITIES_POINTER_INDEX: usize = 0x34 / 4;
const MSIX_CAPABILITY_OFFSET: u32 = 0x50;
const MSIX_CAPABILITY_ID: u32 = 0x11;
const MSIX_ENABLE: u16 = 1 << 15;
const MSIX_FUNCTION_MASK: u16 = 1 << 14;
const MAX_BLOCK_SEGMENTS: u16 = framev_blk_common::FRAMEV_BLK_MAX_EXTENTS as u16;
const MSIX_MESSAGE_ADDRESS: u64 = 0xfee0_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MsixDelivery {
    bdf: VirtualPciBdf,
    vector: u16,
    generation: u64,
    irq_line: VirtualIrqLine,
    target_vcpu: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PciRaiseOutcome {
    Deliver(MsixDelivery),
    Masked,
    Coalesced,
}

/// One FrameVM's virtual PCI configuration-space authority.
pub struct VirtualPciBus {
    vm_id: vm::VmId,
    functions: SpinLock<Vec<VirtualPciFunction>>,
    assigned: SpinLock<Option<Arc<AssignedPciFunction>>>,
}

impl VirtualPciBus {
    /// Creates the deterministic synthetic PCI topology for one FrameVM.
    pub(crate) fn new(
        vm_id: vm::VmId,
        vcpu_count: usize,
        guest_cid: u32,
        block_configs: &[FrameVBlkConfig],
        net_config: Option<FrameVNetConfig>,
    ) -> Result<Self> {
        if vm_id.is_host() {
            return Err(Error::InvalidArgs);
        }

        let mut families = Vec::from([
            FrameVFunctionFamily::Console,
            FrameVFunctionFamily::Rng,
            FrameVFunctionFamily::Sock,
        ]);
        if net_config.is_some() {
            families.push(FrameVFunctionFamily::Net);
        }
        let mut topology = families
            .into_iter()
            .map(|family| {
                TopologyFunction::Synthetic(SyntheticFunction {
                    family,
                    stable_id: 0,
                })
            })
            .collect::<Vec<_>>();
        topology.extend(block_configs.iter().enumerate().map(|(stable_id, _)| {
            TopologyFunction::Synthetic(SyntheticFunction {
                family: FrameVFunctionFamily::Block,
                stable_id: stable_id as u64,
            })
        }));
        let topology = allocate_topology(&mut topology).map_err(|_| Error::InvalidArgs)?;
        let receive_queue_count = u16::try_from(vcpu_count).map_err(|_| Error::Overflow)?;

        let functions = topology
            .into_iter()
            .map(|(bdf, function)| {
                let TopologyFunction::Synthetic(function) = function else {
                    return Err(Error::InvalidArgs);
                };
                VirtualPciFunction::new(
                    bdf,
                    function,
                    vm_id,
                    guest_cid,
                    receive_queue_count,
                    block_configs.get(function.stable_id as usize).copied(),
                    net_config,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            vm_id,
            functions: SpinLock::new(functions),
            assigned: SpinLock::new(None),
        })
    }

    pub(crate) fn attach_assigned(&self, access: Arc<AssignedPciAccess>) -> Result<()> {
        let Some(vm_id) = self.vm_id.guest_id() else {
            return Err(Error::InvalidArgs);
        };
        if access.identity().owner() != u64::from(vm_id) {
            return Err(Error::AccessDenied);
        }
        let physical = access.physical_location();
        let physical_bdf = VirtualPciBdf::new(physical.bus, physical.device, physical.function)
            .map_err(|_| Error::InvalidArgs)?;
        let mut topology = self
            .functions
            .lock()
            .iter()
            .map(|function| {
                TopologyFunction::Synthetic(SyntheticFunction {
                    family: function.family(),
                    stable_id: function.stable_id,
                })
            })
            .collect::<Vec<_>>();
        topology.push(TopologyFunction::Assigned(AssignedFunction {
            physical_bdf,
        }));
        let assigned_bdf = allocate_topology(&mut topology)
            .map_err(|_| Error::InvalidArgs)?
            .into_iter()
            .find_map(|(bdf, function)| {
                matches!(function, TopologyFunction::Assigned(_)).then_some(bdf)
            })
            .ok_or(Error::InvalidArgs)?;
        let function = Arc::new(AssignedPciFunction::new(assigned_bdf, access)?);
        let mut assigned = self.assigned.lock();
        if assigned.is_some() {
            return Err(Error::AccessDenied);
        }
        *assigned = Some(function);
        Ok(())
    }

    #[inline(always)]
    pub(crate) fn resolve_assigned_requester(
        &self,
        requester: irq::PciIrqRequester,
    ) -> Result<aster_pci::PciDeviceLocation> {
        let (bus, device, function) = requester.tuple();
        let assigned = self.assigned.lock();
        let assigned = assigned.as_ref().ok_or(Error::AccessDenied)?;
        if !assigned.bdf_matches(bus, device, function) {
            return Err(Error::AccessDenied);
        }
        Ok(assigned.access.physical_location())
    }

    /// Reads one aligned configuration-space dword.
    pub fn read32(&self, bus: u8, device: u8, function: u8, offset: u32) -> u32 {
        if !offset.is_multiple_of(4) || offset / 4 >= CONFIG_DWORD_COUNT as u32 {
            return u32::MAX;
        }
        let functions = self.functions.lock();
        if let Some(function) = find_function(&functions, bus, device, function) {
            return function.read32(offset);
        }
        drop(functions);
        self.assigned
            .lock()
            .as_ref()
            .filter(|entry| entry.bdf_matches(bus, device, function))
            .map_or(u32::MAX, |entry| entry.read32(offset))
    }

    /// Applies one configuration-space dword write after boundary validation.
    pub fn write32(&self, bus: u8, device: u8, function: u8, offset: u32, value: u32) {
        if !offset.is_multiple_of(4) || offset / 4 >= CONFIG_DWORD_COUNT as u32 {
            return;
        }
        let mut functions = self.functions.lock();
        let Some(index) = functions
            .iter()
            .position(|entry| entry.bdf_matches(bus, device, function))
        else {
            drop(functions);
            let assigned = self.assigned.lock().clone();
            if let Some(assigned) = assigned
                && assigned.bdf_matches(bus, device, function)
            {
                assigned.write32(offset, value);
            }
            return;
        };
        match offset {
            0x04 => functions[index].write_command(value),
            BAR0_OFFSET | BAR1_OFFSET => relocate_bar(&mut functions, index, offset, value),
            MSIX_CAPABILITY_OFFSET => functions[index].write_msix_control(value),
            _ => {}
        }
        let deliveries = prepare_pending_deliveries(&mut functions, self.vm_id);
        drop(functions);
        self.enqueue_deliveries(deliveries);
    }

    /// Returns the single virtual root-bus range.
    pub fn bus_range(&self) -> core::ops::RangeInclusive<u8> {
        0..=0
    }

    fn claim(
        &self,
        bus: u8,
        device: u8,
        function: u8,
        family: FrameVFunctionFamily,
    ) -> Result<FunctionClaim> {
        let mut functions = self.functions.lock();
        let entry = functions
            .iter_mut()
            .find(|entry| entry.bdf_matches(bus, device, function))
            .ok_or(Error::AccessDenied)?;
        entry.claim(family)
    }

    pub(crate) fn revoke_claims(&self) {
        for function in self.functions.lock().iter_mut() {
            function.revoke_claim();
        }
    }

    pub(crate) fn runtime(&self, family: FrameVFunctionFamily) -> Result<Arc<FunctionRuntime>> {
        self.functions
            .lock()
            .iter()
            .find(|function| function.family() == family)
            .map(|function| function.runtime.clone())
            .ok_or(Error::AccessDenied)
    }

    pub(crate) fn runtime_at(
        &self,
        family: FrameVFunctionFamily,
        stable_id: u64,
    ) -> Result<Arc<FunctionRuntime>> {
        self.functions
            .lock()
            .iter()
            .find(|function| function.family() == family && function.stable_id == stable_id)
            .map(|function| function.runtime.clone())
            .ok_or(Error::AccessDenied)
    }

    fn acquire_bar(&self, range: Range<usize>) -> Result<VirtualBarHandle> {
        if range.is_empty() {
            return Err(Error::InvalidArgs);
        }
        let start = u64::try_from(range.start).map_err(|_| Error::Overflow)?;
        let end = u64::try_from(range.end).map_err(|_| Error::Overflow)?;
        let functions = self.functions.lock();
        if let Some(function) = functions.iter().find(|function| {
            let Some(bar_end) = function.bar_base.checked_add(function.bar_size()) else {
                return false;
            };
            start >= function.bar_base && end <= bar_end
        }) {
            return Ok(VirtualBarHandle::Synthetic {
                bdf: function.bdf,
                base: start,
                len: range.len(),
            });
        }
        drop(functions);
        let assigned = self.assigned.lock().clone().ok_or(Error::AccessDenied)?;
        assigned.acquire_bar(start..end)
    }

    fn read_bar(&self, handle: &VirtualBarHandle, offset: usize, len: usize) -> Result<Vec<u8>> {
        let VirtualBarHandle::Synthetic { bdf, .. } = handle else {
            return Err(Error::AccessDenied);
        };
        let range = checked_handle_range(handle, offset, len)?;
        let functions = self.functions.lock();
        let function = find_function_by_bdf(&functions, *bdf).ok_or(Error::AccessDenied)?;
        let bar_offset = validated_bar_offset(function, handle, range)?;
        Ok(function.bar[bar_offset..bar_offset + len].to_vec())
    }

    fn write_bar(&self, handle: &VirtualBarHandle, offset: usize, bytes: &[u8]) -> Result<()> {
        let VirtualBarHandle::Synthetic { bdf, .. } = handle else {
            return Err(Error::AccessDenied);
        };
        let range = checked_handle_range(handle, offset, bytes.len())?;
        let mut functions = self.functions.lock();
        let function = find_function_by_bdf_mut(&mut functions, *bdf).ok_or(Error::AccessDenied)?;
        let bar_offset = validated_bar_offset(function, handle, range)?;
        if !function.msix_table_contains(bar_offset, bytes.len()) {
            return Err(Error::AccessDenied);
        }
        function.bar[bar_offset..bar_offset + bytes.len()].copy_from_slice(bytes);
        let deliveries = prepare_pending_deliveries(&mut functions, self.vm_id);
        drop(functions);
        self.enqueue_deliveries(deliveries);
        Ok(())
    }

    pub(crate) fn raise(
        &self,
        family: FrameVFunctionFamily,
        vector: u16,
        generation: u64,
    ) -> Result<PciRaiseOutcome> {
        let mut functions = self.functions.lock();
        let function = functions
            .iter_mut()
            .find(|function| function.family() == family)
            .ok_or(Error::AccessDenied)?;
        let outcome = function.prepare_raise(vector, generation, self.vm_id)?;
        let delivery = match outcome {
            PciRaiseOutcome::Deliver(delivery) => Some(delivery),
            _ => None,
        };
        drop(functions);
        if let Some(delivery) = delivery {
            self.enqueue_deliveries(Vec::from([delivery]));
        }
        Ok(outcome)
    }

    pub(crate) fn complete_irq(&self, irq_line: VirtualIrqLine, target_vcpu: usize) -> bool {
        self.functions
            .lock()
            .iter_mut()
            .any(|function| function.complete_irq(irq_line, target_vcpu))
    }

    fn enqueue_deliveries(&self, deliveries: Vec<MsixDelivery>) {
        for delivery in deliveries {
            if irq::enqueue_virtual_irq(self.vm_id, delivery.target_vcpu, delivery.irq_line)
                .is_err()
            {
                let mut functions = self.functions.lock();
                if let Some(function) = find_function_by_bdf_mut(&mut functions, delivery.bdf) {
                    function.rollback_delivery(delivery);
                }
            }
        }
    }
}

struct AssignedBar {
    index: u8,
    base: u64,
    size: usize,
    is_64_bit: bool,
    probe_low: bool,
    probe_high: bool,
}

struct AssignedConfig {
    dwords: [u32; CONFIG_DWORD_COUNT],
    bars: Vec<AssignedBar>,
}

struct AssignedPciFunction {
    bdf: VirtualPciBdf,
    access: Arc<AssignedPciAccess>,
    config: SpinLock<AssignedConfig>,
}

impl AssignedPciFunction {
    fn new(bdf: VirtualPciBdf, access: Arc<AssignedPciAccess>) -> Result<Self> {
        let mut dwords = *access.config_snapshot();
        let mut bars = Vec::new();
        let mut next_base = ASSIGNED_MMIO_BASE;
        for (index, size) in access.bars() {
            if size == 0 || !size.is_power_of_two() {
                return Err(Error::InvalidArgs);
            }
            let size_u64 = u64::try_from(size).map_err(|_| Error::Overflow)?;
            next_base =
                next_base.checked_add(size_u64 - 1).ok_or(Error::Overflow)? & !(size_u64 - 1);
            let end = next_base.checked_add(size_u64).ok_or(Error::Overflow)?;
            if end > ASSIGNED_MMIO_END {
                return Err(Error::NotEnoughResources);
            }

            let dword_index = (BAR0_OFFSET / 4) as usize + usize::from(index);
            let original = dwords[dword_index];
            if original & 1 != 0 {
                return Err(Error::InvalidArgs);
            }
            let is_64_bit = (original >> 1) & 0b11 == 0b10;
            dwords[dword_index] = next_base as u32 | (original & 0xf);
            if is_64_bit {
                let high = dwords.get_mut(dword_index + 1).ok_or(Error::InvalidArgs)?;
                *high = (next_base >> 32) as u32;
            }
            bars.push(AssignedBar {
                index,
                base: next_base,
                size,
                is_64_bit,
                probe_low: false,
                probe_high: false,
            });
            next_base = end;
        }

        Ok(Self {
            bdf,
            access,
            config: SpinLock::new(AssignedConfig { dwords, bars }),
        })
    }

    fn bdf_matches(&self, bus: u8, device: u8, function: u8) -> bool {
        self.bdf.bus() == bus && self.bdf.device() == device && self.bdf.function() == function
    }

    fn read32(&self, offset: u32) -> u32 {
        let config = self.config.lock();
        if let Some((bar, high)) = find_assigned_bar(&config.bars, offset)
            && ((!high && bar.probe_low) || (high && bar.probe_high))
        {
            return assigned_bar_probe_value(bar, high);
        }
        config.dwords[offset as usize / 4]
    }

    fn write32(&self, offset: u32, value: u32) {
        if (BAR0_OFFSET..=0x24).contains(&offset) {
            let mut config = self.config.lock();
            let Some((bar, high)) = find_assigned_bar_mut(&mut config.bars, offset) else {
                return;
            };
            if value == u32::MAX {
                if high {
                    bar.probe_high = true;
                } else {
                    bar.probe_low = true;
                }
            } else if high {
                bar.probe_high = false;
            } else {
                bar.probe_low = false;
            }
            return;
        }

        let Ok(updated) = self.access.write_config32(offset, value) else {
            return;
        };
        self.config.lock().dwords[offset as usize / 4] = updated;
    }

    fn acquire_bar(self: &Arc<Self>, range: Range<u64>) -> Result<VirtualBarHandle> {
        let config = self.config.lock();
        let bar = config
            .bars
            .iter()
            .find(|bar| {
                let Some(end) = bar.base.checked_add(bar.size as u64) else {
                    return false;
                };
                range.start >= bar.base && range.end <= end
            })
            .ok_or(Error::AccessDenied)?;
        let offset = usize::try_from(range.start - bar.base).map_err(|_| Error::Overflow)?;
        Ok(VirtualBarHandle::Assigned {
            access: self.access.clone(),
            bar_index: bar.index,
            offset,
            len: usize::try_from(range.end - range.start).map_err(|_| Error::Overflow)?,
        })
    }
}

fn find_assigned_bar(bars: &[AssignedBar], offset: u32) -> Option<(&AssignedBar, bool)> {
    bars.iter().find_map(|bar| {
        let low = BAR0_OFFSET + u32::from(bar.index) * 4;
        if offset == low {
            Some((bar, false))
        } else if bar.is_64_bit && offset == low + 4 {
            Some((bar, true))
        } else {
            None
        }
    })
}

fn find_assigned_bar_mut(
    bars: &mut [AssignedBar],
    offset: u32,
) -> Option<(&mut AssignedBar, bool)> {
    bars.iter_mut().find_map(|bar| {
        let low = BAR0_OFFSET + u32::from(bar.index) * 4;
        if offset == low {
            Some((bar, false))
        } else if bar.is_64_bit && offset == low + 4 {
            Some((bar, true))
        } else {
            None
        }
    })
}

fn assigned_bar_probe_value(bar: &AssignedBar, high: bool) -> u32 {
    let size_mask = !(u64::try_from(bar.size).expect("validated BAR size fits u64") - 1);
    if high {
        (size_mask >> 32) as u32
    } else {
        size_mask as u32 | if bar.is_64_bit { 0b100 } else { 0 }
    }
}

struct VirtualPciFunction {
    bdf: VirtualPciBdf,
    stable_id: u64,
    runtime: Arc<FunctionRuntime>,
    config: [u32; CONFIG_DWORD_COUNT],
    bar: Vec<u8>,
    bar_base: u64,
    probe_low: bool,
    probe_high: bool,
    msix_control: u16,
    msix_table: Option<Range<usize>>,
    pba_offset: Option<usize>,
    delivery_pending: Vec<bool>,
}

impl VirtualPciFunction {
    fn new(
        bdf: VirtualPciBdf,
        identity: SyntheticFunction,
        vm_id: vm::VmId,
        guest_cid: u32,
        receive_queue_count: u16,
        block_config: Option<FrameVBlkConfig>,
        net_config: Option<FrameVNetConfig>,
    ) -> Result<Self> {
        let family = identity.family;
        let vector_count = match family {
            FrameVFunctionFamily::Console | FrameVFunctionFamily::Net => 1,
            FrameVFunctionFamily::Sock => {
                receive_queue_count.checked_add(1).ok_or(Error::Overflow)?
            }
            FrameVFunctionFamily::Rng | FrameVFunctionFamily::Block => 0,
        };
        let layout = FrameVPciLayout::new(family, vector_count).map_err(|_| Error::InvalidArgs)?;
        let bar_base = VIRTUAL_MMIO_BASE
            .checked_add(u64::from(bdf.device()) * VIRTUAL_MMIO_FUNCTION_STRIDE)
            .ok_or(Error::Overflow)?;
        let mut config = [0; CONFIG_DWORD_COUNT];
        config[0] = u32::from(FRAMEV_PCI_VENDOR_ID) | (u32::from(family.device_id()) << 16);
        config[2] = u32::from(FRAMEV_PCI_REVISION)
            | (u32::from(FRAMEV_PCI_PROGRAMMING_INTERFACE) << 8)
            | (u32::from(FRAMEV_PCI_SUBCLASS) << 16)
            | (u32::from(FRAMEV_PCI_CLASS) << 24);
        config[BAR0_OFFSET as usize / 4] = bar_base as u32 | 0b100;
        config[BAR1_OFFSET as usize / 4] = (bar_base >> 32) as u32;
        config[0x2c / 4] = config[0];

        if family.has_msix() {
            config[1] = 1 << 20;
            config[CAPABILITIES_POINTER_INDEX] = MSIX_CAPABILITY_OFFSET;
            config[MSIX_CAPABILITY_OFFSET as usize / 4] = MSIX_CAPABILITY_ID
                | (u32::from(vector_count.checked_sub(1).ok_or(Error::InvalidArgs)?) << 16);
            config[MSIX_CAPABILITY_OFFSET as usize / 4 + 1] =
                u32::try_from(layout.table_offset_bytes().ok_or(Error::InvalidArgs)?)
                    .map_err(|_| Error::Overflow)?;
            config[MSIX_CAPABILITY_OFFSET as usize / 4 + 2] =
                u32::try_from(layout.pba_offset_bytes().ok_or(Error::InvalidArgs)?)
                    .map_err(|_| Error::Overflow)?;
        }

        let mut bar = family_config(
            family,
            guest_cid,
            receive_queue_count,
            block_config,
            net_config,
        )?;
        bar.resize(layout.bar_size_bytes(), 0);
        Ok(Self {
            bdf,
            stable_id: identity.stable_id,
            runtime: Arc::new(FunctionRuntime::new(vm_id, bdf, family)),
            config,
            bar,
            bar_base,
            probe_low: false,
            probe_high: false,
            msix_control: 0,
            msix_table: layout.table_offset_bytes().map(|start| {
                let len = usize::from(layout.vector_count()) * 16;
                start..start + len
            }),
            pba_offset: layout.pba_offset_bytes(),
            delivery_pending: vec![false; usize::from(vector_count)],
        })
    }

    fn bdf_matches(&self, bus: u8, device: u8, function: u8) -> bool {
        self.bdf.bus() == bus && self.bdf.device() == device && self.bdf.function() == function
    }

    fn family(&self) -> FrameVFunctionFamily {
        self.runtime.family()
    }

    fn claim(&mut self, family: FrameVFunctionFamily) -> Result<FunctionClaim> {
        if self.family() != family {
            return Err(Error::AccessDenied);
        }
        self.runtime.claim()
    }

    fn revoke_claim(&mut self) {
        self.runtime.revoke_claim();
        self.delivery_pending.fill(false);
        if let Some(pba_offset) = self.pba_offset {
            self.bar[pba_offset..pba_offset + 8].fill(0);
        }
    }

    fn bar_size(&self) -> u64 {
        self.bar.len() as u64
    }

    fn read32(&self, offset: u32) -> u32 {
        match offset {
            BAR0_OFFSET if self.probe_low => (!(self.bar_size() - 1) as u32) | 0b100,
            BAR1_OFFSET if self.probe_high => (!((self.bar_size() - 1) >> 32)) as u32,
            _ => self.config[offset as usize / 4],
        }
    }

    fn write_command(&mut self, value: u32) {
        const WRITABLE_COMMAND_BITS: u32 = 0x0000_0407;
        self.config[1] =
            (self.config[1] & !WRITABLE_COMMAND_BITS) | (value & WRITABLE_COMMAND_BITS);
    }

    fn write_msix_control(&mut self, value: u32) {
        if self.config[CAPABILITIES_POINTER_INDEX] != MSIX_CAPABILITY_OFFSET {
            return;
        }
        self.msix_control = (value >> 16) as u16 & (MSIX_ENABLE | MSIX_FUNCTION_MASK);
        let index = MSIX_CAPABILITY_OFFSET as usize / 4;
        self.config[index] =
            (self.config[index] & 0x3fff_ffff) | (u32::from(self.msix_control) << 16);
    }

    fn msix_table_contains(&self, offset: usize, len: usize) -> bool {
        let Some(table) = &self.msix_table else {
            return false;
        };
        let Some(end) = offset.checked_add(len) else {
            return false;
        };
        matches!(len, 4 | 8)
            && offset >= table.start
            && end <= table.end
            && offset.is_multiple_of(len)
    }

    fn prepare_raise(
        &mut self,
        vector: u16,
        generation: u64,
        vm_id: vm::VmId,
    ) -> Result<PciRaiseOutcome> {
        self.prepare_raise_with(vector, generation, |irq_num| {
            vm::get_vm_by_id(vm_id)
                .is_some_and(|frame_vm| frame_vm.irq().is_ostd_irq_allocated(irq_num))
        })
    }

    fn prepare_raise_with(
        &mut self,
        vector: u16,
        generation: u64,
        irq_is_allocated: impl FnOnce(u8) -> bool,
    ) -> Result<PciRaiseOutcome> {
        if self.runtime.claimed_generation() != Some(generation) {
            return Err(Error::AccessDenied);
        }
        let vector_index = usize::from(vector);
        if vector_index >= self.delivery_pending.len() {
            return Err(Error::InvalidArgs);
        }
        if self.delivery_pending[vector_index] {
            return Ok(PciRaiseOutcome::Coalesced);
        }
        if !self.vector_is_deliverable(vector_index) {
            self.set_pba(vector_index, true)?;
            return Ok(PciRaiseOutcome::Masked);
        }

        let irq_line = self.validated_irq_line(vector_index, irq_is_allocated)?;
        let target_vcpu = match self.family() {
            FrameVFunctionFamily::Sock if vector_index + 1 < self.delivery_pending.len() => {
                vector_index
            }
            _ => 0,
        };
        self.set_pba(vector_index, false)?;
        self.delivery_pending[vector_index] = true;
        Ok(PciRaiseOutcome::Deliver(MsixDelivery {
            bdf: self.bdf,
            vector,
            generation,
            irq_line,
            target_vcpu,
        }))
    }

    fn vector_is_deliverable(&self, vector: usize) -> bool {
        self.msix_control & MSIX_ENABLE != 0
            && self.msix_control & MSIX_FUNCTION_MASK == 0
            && self
                .vector_control(vector)
                .is_some_and(|control| control & 1 == 0)
    }

    fn validated_irq_line(
        &self,
        vector: usize,
        irq_is_allocated: impl FnOnce(u8) -> bool,
    ) -> Result<VirtualIrqLine> {
        let table_entry = self.table_entry_offset(vector)?;
        let message_address = u64::from(read_u32(&self.bar, table_entry)?)
            | (u64::from(read_u32(&self.bar, table_entry + 4)?) << 32);
        if message_address != MSIX_MESSAGE_ADDRESS {
            return Err(Error::AccessDenied);
        }
        let message_data = read_u32(&self.bar, table_entry + 8)?;
        let irq_num = u8::try_from(message_data).map_err(|_| Error::AccessDenied)?;
        if !irq_is_allocated(irq_num) {
            return Err(Error::AccessDenied);
        }
        VirtualIrqLine::parse(u16::from(irq_num)).map_err(|_| Error::AccessDenied)
    }

    fn table_entry_offset(&self, vector: usize) -> Result<usize> {
        let table = self.msix_table.as_ref().ok_or(Error::AccessDenied)?;
        let offset = vector.checked_mul(16).ok_or(Error::Overflow)?;
        let entry = table.start.checked_add(offset).ok_or(Error::Overflow)?;
        (entry + 16 <= table.end)
            .then_some(entry)
            .ok_or(Error::InvalidArgs)
    }

    fn vector_control(&self, vector: usize) -> Option<u32> {
        let entry = self.table_entry_offset(vector).ok()?;
        read_u32(&self.bar, entry + 12).ok()
    }

    fn pba_is_set(&self, vector: usize) -> bool {
        let Some(pba_offset) = self.pba_offset else {
            return false;
        };
        let Ok(word) = read_u64(&self.bar, pba_offset) else {
            return false;
        };
        let Some(vector_bit) = 1_u64.checked_shl(vector as u32) else {
            return false;
        };
        word & vector_bit != 0
    }

    fn set_pba(&mut self, vector: usize, pending: bool) -> Result<()> {
        let pba_offset = self.pba_offset.ok_or(Error::AccessDenied)?;
        let mut word = read_u64(&self.bar, pba_offset)?;
        let vector_bit = 1_u64
            .checked_shl(u32::try_from(vector).map_err(|_| Error::Overflow)?)
            .ok_or(Error::InvalidArgs)?;
        if pending {
            word |= vector_bit;
        } else {
            word &= !vector_bit;
        }
        write_u64(&mut self.bar, pba_offset, word)
    }

    fn complete_irq(&mut self, irq_line: VirtualIrqLine, target_vcpu: usize) -> bool {
        for vector in 0..self.delivery_pending.len() {
            if !self.delivery_pending[vector] {
                continue;
            }
            let expected_target = match self.family() {
                FrameVFunctionFamily::Sock if vector + 1 < self.delivery_pending.len() => vector,
                _ => 0,
            };
            if expected_target != target_vcpu {
                continue;
            }
            let Ok(message_data) = self
                .table_entry_offset(vector)
                .and_then(|entry| read_u32(&self.bar, entry + 8))
            else {
                continue;
            };
            if message_data == u32::from(irq_line.raw()) {
                self.delivery_pending[vector] = false;
                return true;
            }
        }
        false
    }

    fn rollback_delivery(&mut self, delivery: MsixDelivery) {
        if self.bdf != delivery.bdf
            || self.runtime.claimed_generation() != Some(delivery.generation)
            || usize::from(delivery.vector) >= self.delivery_pending.len()
        {
            return;
        }
        let vector = usize::from(delivery.vector);
        self.delivery_pending[vector] = false;
        let _ = self.set_pba(vector, true);
    }
}

fn prepare_pending_deliveries(
    functions: &mut [VirtualPciFunction],
    vm_id: vm::VmId,
) -> Vec<MsixDelivery> {
    let mut deliveries = Vec::new();
    for function in functions {
        let Some(generation) = function.runtime.claimed_generation() else {
            continue;
        };
        for vector in 0..function.delivery_pending.len() {
            if !function.pba_is_set(vector) || !function.vector_is_deliverable(vector) {
                continue;
            }
            if let Ok(PciRaiseOutcome::Deliver(delivery)) =
                function.prepare_raise(vector as u16, generation, vm_id)
            {
                deliveries.push(delivery);
            }
        }
    }
    deliveries
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset.checked_add(4).ok_or(Error::Overflow)?;
    let value = bytes.get(offset..end).ok_or(Error::InvalidArgs)?;
    let value = <[u8; 4]>::try_from(value).map_err(|_| Error::InvalidArgs)?;
    Ok(u32::from_le_bytes(value))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let end = offset.checked_add(8).ok_or(Error::Overflow)?;
    let value = bytes.get(offset..end).ok_or(Error::InvalidArgs)?;
    let value = <[u8; 8]>::try_from(value).map_err(|_| Error::InvalidArgs)?;
    Ok(u64::from_le_bytes(value))
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<()> {
    let end = offset.checked_add(8).ok_or(Error::Overflow)?;
    let destination = bytes.get_mut(offset..end).ok_or(Error::InvalidArgs)?;
    destination.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[derive(Clone)]
enum VirtualBarHandle {
    Synthetic {
        bdf: VirtualPciBdf,
        base: u64,
        len: usize,
    },
    Assigned {
        access: Arc<AssignedPciAccess>,
        bar_index: u8,
        offset: usize,
        len: usize,
    },
}

/// FrameVM's OSTD-shaped, FrameVisor-authorized virtual MMIO handle.
#[derive(Clone)]
pub struct IoMem {
    vm_id: vm::VmId,
    bar: VirtualBarHandle,
}

impl IoMem {
    /// Acquires a range only when it belongs to the current FrameVM's virtual BAR aperture.
    pub fn acquire(range: Range<usize>) -> host_ostd::Result<Self> {
        Self::acquire_inner(range).map_err(to_ostd_error)
    }

    fn acquire_inner(range: Range<usize>) -> Result<Self> {
        let current_vm = current_vm().ok_or(Error::AccessDenied)?;
        let bar = current_vm.devices().pci().acquire_bar(range)?;
        Ok(Self {
            vm_id: current_vm.id(),
            bar,
        })
    }

    fn with_vm<R>(&self, access_fn: impl FnOnce(&VirtualPciBus) -> Result<R>) -> Result<R> {
        let current_vm_id = task::current_frame_vcpu_id()
            .map(|id| id.vm_id())
            .ok_or(Error::AccessDenied)?;
        if current_vm_id != self.vm_id {
            return Err(Error::AccessDenied);
        }
        let current_vm = vm::get_vm_by_id(self.vm_id).ok_or(Error::AccessDenied)?;
        access_fn(current_vm.devices().pci())
    }
}

impl fmt::Debug for IoMem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IoMem")
            .field("vm_id", &self.vm_id)
            .field("bar", &self.bar)
            .finish_non_exhaustive()
    }
}

impl VmIoOnce for IoMem {
    fn read_once<T: PodOnce>(&self, offset: usize) -> host_ostd::Result<T> {
        match &self.bar {
            VirtualBarHandle::Synthetic { .. } => {
                let bytes = self
                    .with_vm(|pci| pci.read_bar(&self.bar, offset, size_of::<T>()))
                    .map_err(to_ostd_error)?;
                Ok(T::from_bytes(&bytes))
            }
            VirtualBarHandle::Assigned {
                access,
                bar_index,
                offset: base_offset,
                len,
            } => {
                self.with_vm(|_| Ok(())).map_err(to_ostd_error)?;
                validate_assigned_handle_access(*len, offset, size_of::<T>())?;
                let physical_offset = base_offset
                    .checked_add(offset)
                    .ok_or(host_ostd::Error::Overflow)?;
                access.read_bar(*bar_index, physical_offset)
            }
        }
    }

    fn write_once<T: PodOnce>(&self, offset: usize, new_val: &T) -> host_ostd::Result<()> {
        match &self.bar {
            VirtualBarHandle::Synthetic { .. } => self
                .with_vm(|pci| pci.write_bar(&self.bar, offset, new_val.as_bytes()))
                .map_err(to_ostd_error),
            VirtualBarHandle::Assigned {
                access,
                bar_index,
                offset: base_offset,
                len,
            } => {
                self.with_vm(|_| Ok(())).map_err(to_ostd_error)?;
                validate_assigned_handle_access(*len, offset, size_of::<T>())?;
                let physical_offset = base_offset
                    .checked_add(offset)
                    .ok_or(host_ostd::Error::Overflow)?;
                access.write_bar(*bar_index, physical_offset, new_val)
            }
        }
    }
}

impl fmt::Debug for VirtualBarHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Synthetic { bdf, len, .. } => formatter
                .debug_struct("SyntheticBar")
                .field("bdf", bdf)
                .field("len", len)
                .finish(),
            Self::Assigned { bar_index, len, .. } => formatter
                .debug_struct("AssignedBar")
                .field("index", bar_index)
                .field("len", len)
                .finish_non_exhaustive(),
        }
    }
}

#[inline(always)]
fn validate_assigned_handle_access(
    len: usize,
    offset: usize,
    width: usize,
) -> host_ostd::Result<()> {
    if width == 0 || !matches!(width, 1 | 2 | 4 | 8) || !offset.is_multiple_of(width) {
        return Err(host_ostd::Error::InvalidArgs);
    }
    let end = offset
        .checked_add(width)
        .ok_or(host_ostd::Error::Overflow)?;
    if end > len {
        return Err(host_ostd::Error::InvalidArgs);
    }
    Ok(())
}

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

fn family_config(
    family: FrameVFunctionFamily,
    guest_cid: u32,
    receive_queue_count: u16,
    block_config: Option<FrameVBlkConfig>,
    net_config: Option<FrameVNetConfig>,
) -> Result<Vec<u8>> {
    match family {
        FrameVFunctionFamily::Console => ConsoleConfig {
            max_input_chunk_bytes: MAX_INPUT_CHUNK_BYTES
                .try_into()
                .map_err(|_| Error::Overflow)?,
            queued_input_capacity_bytes: QUEUED_INPUT_CAPACITY_BYTES
                .try_into()
                .map_err(|_| Error::Overflow)?,
        }
        .encode()
        .map(Vec::from)
        .map_err(|_| Error::InvalidArgs),
        FrameVFunctionFamily::Rng => RngConfig {
            max_fill_bytes: MAX_FILL_BYTES.try_into().map_err(|_| Error::Overflow)?,
        }
        .encode()
        .map(Vec::from)
        .map_err(|_| Error::InvalidArgs),
        FrameVFunctionFamily::Block => {
            let config = block_config.ok_or(Error::InvalidArgs)?;
            BlockConfig {
                capacity_sectors: config.capacity_sectors(),
                sector_size_bytes: config.logical_block_size(),
                max_segments: MAX_BLOCK_SEGMENTS,
                flags: if config.flags().readonly() {
                    BlockConfigFlags::READ_ONLY
                } else {
                    BlockConfigFlags::EMPTY
                },
            }
            .encode()
            .map(Vec::from)
            .map_err(|_| Error::InvalidArgs)
        }
        FrameVFunctionFamily::Sock => SockConfig {
            guest_cid,
            receive_queue_count,
            state_vector_count: 1,
            max_packet_bytes: framev_sock_common::flow_control::MAX_PKT_BUF_SIZE,
            receive_queue_capacity: u32::try_from(
                framev_sock_common::flow_control::MAX_PENDING_PACKETS,
            )
            .map_err(|_| Error::Overflow)?,
        }
        .encode()
        .map(Vec::from)
        .map_err(|_| Error::InvalidArgs),
        FrameVFunctionFamily::Net => {
            let config = net_config.ok_or(Error::InvalidArgs)?;
            NetConfig {
                mac_address: config.mac_address(),
                mtu: config.mtu(),
                max_frame_bytes: config.maximum_frame_bytes(),
                max_posted_receive_buffers: config.maximum_posted_receive_buffers(),
            }
            .encode()
            .map(Vec::from)
            .map_err(|_| Error::InvalidArgs)
        }
    }
}

fn find_function(
    functions: &[VirtualPciFunction],
    bus: u8,
    device: u8,
    function: u8,
) -> Option<&VirtualPciFunction> {
    functions
        .iter()
        .find(|entry| entry.bdf_matches(bus, device, function))
}

fn find_function_by_bdf(
    functions: &[VirtualPciFunction],
    bdf: VirtualPciBdf,
) -> Option<&VirtualPciFunction> {
    functions.iter().find(|function| function.bdf == bdf)
}

fn find_function_by_bdf_mut(
    functions: &mut [VirtualPciFunction],
    bdf: VirtualPciBdf,
) -> Option<&mut VirtualPciFunction> {
    functions.iter_mut().find(|function| function.bdf == bdf)
}

fn checked_handle_range(
    handle: &VirtualBarHandle,
    offset: usize,
    len: usize,
) -> Result<Range<u64>> {
    let VirtualBarHandle::Synthetic {
        base,
        len: handle_len,
        ..
    } = handle
    else {
        return Err(Error::AccessDenied);
    };
    if len == 0 || !offset.is_multiple_of(len) {
        return Err(Error::InvalidArgs);
    }
    let end_offset = offset.checked_add(len).ok_or(Error::Overflow)?;
    if end_offset > *handle_len {
        return Err(Error::InvalidArgs);
    }
    let start = base
        .checked_add(u64::try_from(offset).map_err(|_| Error::Overflow)?)
        .ok_or(Error::Overflow)?;
    let end = start
        .checked_add(u64::try_from(len).map_err(|_| Error::Overflow)?)
        .ok_or(Error::Overflow)?;
    Ok(start..end)
}

fn validated_bar_offset(
    function: &VirtualPciFunction,
    handle: &VirtualBarHandle,
    range: Range<u64>,
) -> Result<usize> {
    let VirtualBarHandle::Synthetic {
        base,
        len: handle_len,
        ..
    } = handle
    else {
        return Err(Error::AccessDenied);
    };
    let handle_end = base
        .checked_add(u64::try_from(*handle_len).map_err(|_| Error::Overflow)?)
        .ok_or(Error::Overflow)?;
    let bar_end = function
        .bar_base
        .checked_add(function.bar_size())
        .ok_or(Error::Overflow)?;
    if *base < function.bar_base
        || handle_end > bar_end
        || range.start < *base
        || range.end > handle_end
    {
        return Err(Error::AccessDenied);
    }
    usize::try_from(range.start - function.bar_base).map_err(|_| Error::Overflow)
}

fn relocate_bar(functions: &mut [VirtualPciFunction], index: usize, offset: u32, value: u32) {
    if value == u32::MAX {
        if offset == BAR0_OFFSET {
            functions[index].probe_low = true;
        } else {
            functions[index].probe_high = true;
        }
        return;
    }

    let current_base = functions[index].bar_base;
    let candidate = if offset == BAR0_OFFSET {
        (current_base & !u64::from(u32::MAX)) | u64::from(value & !0xf)
    } else {
        (u64::from(value) << 32) | (current_base & u64::from(u32::MAX))
    };
    functions[index].probe_low = false;
    functions[index].probe_high = false;
    if !bar_location_is_valid(functions, index, candidate) {
        return;
    }
    functions[index].bar_base = candidate;
    functions[index].config[BAR0_OFFSET as usize / 4] = candidate as u32 | 0b100;
    functions[index].config[BAR1_OFFSET as usize / 4] = (candidate >> 32) as u32;
}

fn bar_location_is_valid(functions: &[VirtualPciFunction], index: usize, candidate: u64) -> bool {
    let size = functions[index].bar_size();
    let Some(end) = candidate.checked_add(size) else {
        return false;
    };
    if candidate < VIRTUAL_MMIO_BASE || end > VIRTUAL_MMIO_END || !candidate.is_multiple_of(size) {
        return false;
    }
    functions.iter().enumerate().all(|(other_index, other)| {
        if other_index == index {
            return true;
        }
        let other_end = other.bar_base + other.bar_size();
        end <= other.bar_base || candidate >= other_end
    })
}

fn current_vm() -> Option<Arc<vm::FrameVm>> {
    let vm_id = task::current_frame_vcpu_id()?.vm_id();
    vm::get_vm_by_id(vm_id)
}

/// Returns the current FrameVM's virtual PCI bus range.
pub fn current_bus_range() -> Option<core::ops::RangeInclusive<u8>> {
    Some(current_vm()?.devices().pci().bus_range())
}

/// Reads the current FrameVM's virtual PCI configuration space.
pub fn read_config32(bus: u8, device: u8, function: u8, offset: u32) -> u32 {
    current_vm()
        .map(|vm| vm.devices().pci().read32(bus, device, function, offset))
        .unwrap_or(u32::MAX)
}

/// Writes the current FrameVM's virtual PCI configuration space.
pub fn write_config32(bus: u8, device: u8, function: u8, offset: u32, value: u32) {
    let Some(vm) = current_vm() else {
        return;
    };
    vm.devices()
        .pci()
        .write32(bus, device, function, offset, value);
}

/// Claims one FrameV PCI function for the current device-claim generation.
pub fn claim_current_function(
    bus: u8,
    device: u8,
    function: u8,
    family: FrameVFunctionFamily,
) -> Result<FunctionClaim> {
    let frame_vm = current_vm().ok_or(Error::AccessDenied)?;
    frame_vm
        .devices()
        .pci()
        .claim(bus, device, function, family)
}

#[cfg(ktest)]
mod tests {
    use super::*;
    use crate::prelude::ktest;

    fn space(vm_id: vm::VmId) -> VirtualPciBus {
        let guest_cid = vm_id.guest_id().unwrap().checked_add(3).unwrap();
        VirtualPciBus::new(vm_id, 2, guest_cid, &[], None).unwrap()
    }

    #[ktest]
    fn multiple_block_functions_keep_stable_ids_and_distinct_configs() {
        let writable = FrameVBlkConfig::new(8, 512, FrameVBlkConfigFlags::EMPTY).unwrap();
        let readonly =
            FrameVBlkConfig::new(16, 512, framev_blk_common::FrameVBlkConfigFlags::READONLY)
                .unwrap();
        let space =
            VirtualPciBus::new(crate::vm::VmId::new(1), 1, 3, &[writable, readonly], None).unwrap();

        let first = space.runtime_at(FrameVFunctionFamily::Block, 0).unwrap();
        let second = space.runtime_at(FrameVFunctionFamily::Block, 1).unwrap();
        assert_ne!(first.bdf(), second.bdf());
        assert_eq!(first.bdf().device(), 3);
        assert_eq!(second.bdf().device(), 4);
    }

    #[ktest]
    fn topology_and_identity_are_deterministic() {
        let space = space(crate::vm::VmId::new(1));

        assert_eq!(space.read32(0, 0, 0, 0), u32::MAX);
        assert_eq!(space.read32(0, 1, 0, 0) & 0xffff, 0xa57e);
        assert_eq!(space.read32(0, 1, 0, 0) >> 16, 1);
        assert_eq!(space.read32(0, 2, 0, 0) >> 16, 3);
        assert_eq!(space.read32(0, 3, 0, 0) >> 16, 2);
        assert_eq!(space.read32(0, 4, 0, 0), u32::MAX);
    }

    #[ktest]
    fn bar_probe_reports_64_bit_aperture_without_leaking_host_addresses() {
        let space = space(crate::vm::VmId::new(1));
        let original_low = space.read32(0, 1, 0, BAR0_OFFSET);
        let original_high = space.read32(0, 1, 0, BAR1_OFFSET);

        space.write32(0, 1, 0, BAR0_OFFSET, u32::MAX);
        space.write32(0, 1, 0, BAR1_OFFSET, u32::MAX);
        assert_eq!(space.read32(0, 1, 0, BAR0_OFFSET) & 0b111, 0b100);
        assert_eq!(space.read32(0, 1, 0, BAR1_OFFSET), u32::MAX);

        space.write32(0, 1, 0, BAR0_OFFSET, original_low);
        space.write32(0, 1, 0, BAR1_OFFSET, original_high);
        assert_eq!(space.read32(0, 1, 0, BAR0_OFFSET), original_low);
        assert_eq!(space.read32(0, 1, 0, BAR1_OFFSET), original_high);
        assert!((original_low as u64) >= VIRTUAL_MMIO_BASE);
    }

    #[ktest]
    fn relocation_and_immutable_writes_are_vm_private() {
        let first = space(crate::vm::VmId::new(1));
        let second = space(crate::vm::VmId::new(2));
        let second_original = second.read32(0, 1, 0, BAR0_OFFSET);
        let relocated = (VIRTUAL_MMIO_BASE + 0x8000) as u32;

        first.write32(0, 1, 0, BAR0_OFFSET, relocated);
        first.write32(0, 1, 0, 0, 0);

        assert_eq!(first.read32(0, 1, 0, BAR0_OFFSET), relocated | 0b100);
        assert_eq!(second.read32(0, 1, 0, BAR0_OFFSET), second_original);
        assert_eq!(first.read32(0, 1, 0, 0) & 0xffff, 0xa57e);
    }

    #[ktest]
    fn invalid_accesses_have_standard_absent_or_no_effect_semantics() {
        let space = space(crate::vm::VmId::new(1));
        let identity = space.read32(0, 1, 0, 0);

        assert_eq!(space.read32(1, 1, 0, 0), u32::MAX);
        assert_eq!(space.read32(0, 1, 0, 3), u32::MAX);
        space.write32(0, 31, 7, BAR0_OFFSET, 0);
        space.write32(0, 1, 0, 3, 0);
        assert_eq!(space.read32(0, 1, 0, 0), identity);
    }

    #[ktest]
    fn assigned_bar_probe_reports_size_without_exposing_physical_address() {
        let bar = AssignedBar {
            index: 0,
            base: ASSIGNED_MMIO_BASE,
            size: 0x4000,
            is_64_bit: true,
            probe_low: true,
            probe_high: true,
        };

        assert_eq!(assigned_bar_probe_value(&bar, false), 0xffff_c004);
        assert_eq!(assigned_bar_probe_value(&bar, true), u32::MAX);
    }

    #[ktest]
    fn assigned_bar_handle_rejects_misaligned_and_out_of_range_accesses() {
        assert!(validate_assigned_handle_access(0x1000, 0xffc, 4).is_ok());
        assert_eq!(
            validate_assigned_handle_access(0x1000, 0xffd, 4),
            Err(host_ostd::Error::InvalidArgs)
        );
        assert_eq!(
            validate_assigned_handle_access(0x1000, 0x1000, 4),
            Err(host_ostd::Error::InvalidArgs)
        );
        assert_eq!(
            validate_assigned_handle_access(usize::MAX, usize::MAX - 3, 4),
            Err(host_ostd::Error::Overflow)
        );
    }

    #[ktest]
    fn claims_are_exclusive_family_checked_and_revoked_on_reset() {
        let space = space(crate::vm::VmId::new(1));
        space
            .runtime(FrameVFunctionFamily::Console)
            .unwrap()
            .start()
            .unwrap();

        let first_claim = space.claim(0, 1, 0, FrameVFunctionFamily::Console).unwrap();
        assert!(matches!(
            space.claim(0, 1, 0, FrameVFunctionFamily::Console),
            Err(Error::AccessDenied)
        ));
        assert!(matches!(
            space.claim(0, 2, 0, FrameVFunctionFamily::Console),
            Err(Error::AccessDenied)
        ));
        assert!(matches!(
            space.claim(0, 31, 0, FrameVFunctionFamily::Console),
            Err(Error::AccessDenied)
        ));

        space.revoke_claims();
        let replacement_claim = space.claim(0, 1, 0, FrameVFunctionFamily::Console).unwrap();
        drop(first_claim);
        assert_eq!(replacement_claim.family(), FrameVFunctionFamily::Console);
    }

    #[ktest]
    fn msix_routes_validate_generation_masks_pending_and_coalescing() {
        let space = space(crate::vm::VmId::new(1));
        let mut functions = space.functions.lock();
        let function = functions
            .iter_mut()
            .find(|function| function.family() == FrameVFunctionFamily::Console)
            .unwrap();
        function.runtime.start().unwrap();
        let _claim = function.claim(FrameVFunctionFamily::Console).unwrap();
        let generation = function.runtime.generation();
        function.write_msix_control(u32::from(MSIX_ENABLE) << 16);
        let table = function.msix_table.as_ref().unwrap().start;
        function.bar[table..table + 4]
            .copy_from_slice(&(MSIX_MESSAGE_ADDRESS as u32).to_le_bytes());
        function.bar[table + 4..table + 8].copy_from_slice(&0_u32.to_le_bytes());
        function.bar[table + 8..table + 12].copy_from_slice(&0x80_u32.to_le_bytes());
        function.bar[table + 12..table + 16].copy_from_slice(&0_u32.to_le_bytes());

        let PciRaiseOutcome::Deliver(delivery) = function
            .prepare_raise_with(0, generation, |irq_num| irq_num == 0x80)
            .unwrap()
        else {
            panic!("unmasked valid route must deliver");
        };
        assert_eq!(delivery.target_vcpu, 0);
        assert_eq!(
            function
                .prepare_raise_with(0, generation, |_| true)
                .unwrap(),
            PciRaiseOutcome::Coalesced
        );
        assert!(function.complete_irq(delivery.irq_line, 0));

        function.bar[table + 12..table + 16].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            function
                .prepare_raise_with(0, generation, |_| true)
                .unwrap(),
            PciRaiseOutcome::Masked
        );
        assert!(function.pba_is_set(0));
        assert!(matches!(
            function.prepare_raise_with(0, generation.saturating_sub(1), |_| true),
            Err(Error::AccessDenied)
        ));

        function.bar[table + 12..table + 16].copy_from_slice(&0_u32.to_le_bytes());
        let PciRaiseOutcome::Deliver(delivery) = function
            .prepare_raise_with(0, generation, |irq_num| irq_num == 0x80)
            .unwrap()
        else {
            panic!("unmasking a pending vector must deliver");
        };
        assert!(!function.pba_is_set(0));
        assert!(function.complete_irq(delivery.irq_line, 0));

        function.write_msix_control(u32::from(MSIX_ENABLE | MSIX_FUNCTION_MASK) << 16);
        assert_eq!(
            function
                .prepare_raise_with(0, generation, |_| true)
                .unwrap(),
            PciRaiseOutcome::Masked
        );
        assert!(function.pba_is_set(0));

        function.write_msix_control(u32::from(MSIX_ENABLE) << 16);
        function.bar[table + 8..table + 12].copy_from_slice(&0x81_u32.to_le_bytes());
        let PciRaiseOutcome::Deliver(retargeted) = function
            .prepare_raise_with(0, generation, |irq_num| irq_num == 0x81)
            .unwrap()
        else {
            panic!("an unmasked vector may be retargeted after completion");
        };
        assert_eq!(retargeted.irq_line.raw(), 0x81);
        assert!(function.complete_irq(retargeted.irq_line, 0));

        function.bar[table + 12..table + 16].copy_from_slice(&0_u32.to_le_bytes());
        function.bar[table..table + 4].copy_from_slice(&0_u32.to_le_bytes());
        assert!(matches!(
            function.prepare_raise_with(0, generation, |_| true),
            Err(Error::AccessDenied)
        ));
    }

    #[ktest]
    fn virtual_bar_revalidates_handles_and_only_allows_msix_table_writes() {
        let space = space(crate::vm::VmId::new(1));
        let original_base = u64::from(space.read32(0, 1, 0, BAR0_OFFSET) & !0xf);
        let handle = space
            .acquire_bar(original_base as usize..original_base as usize + 64)
            .unwrap();

        assert_eq!(
            u32::from_le_bytes(space.read_bar(&handle, 0, 4).unwrap().try_into().unwrap()),
            u32::try_from(MAX_INPUT_CHUNK_BYTES).unwrap()
        );
        assert!(matches!(
            space.write_bar(&handle, 0, &0_u32.to_le_bytes()),
            Err(Error::AccessDenied)
        ));
        assert!(matches!(
            space.write_bar(&handle, 16, &0_u16.to_le_bytes()),
            Err(Error::AccessDenied)
        ));
        space
            .write_bar(&handle, 16 + 12, &1_u32.to_le_bytes())
            .unwrap();

        space.write32(0, 1, 0, BAR0_OFFSET, (VIRTUAL_MMIO_BASE + 0x8000) as u32);
        assert!(matches!(
            space.read_bar(&handle, 0, 4),
            Err(Error::AccessDenied)
        ));
    }
}
