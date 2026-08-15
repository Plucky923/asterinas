// SPDX-License-Identifier: MPL-2.0

//! FrameV PCI discovery and binding for FrameVM frontends.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};

use aster_pci::{
    PciDeviceId, PciDeviceLocation,
    bus::{PciDevice, PciDriver},
    capability::msix::CapabilityMsixData,
    cfg_space::{AddrLen, Bar, BarAccess},
    common_device::{PciCommonDevice, PciDeviceType},
};
use component::{ComponentInitError, init_component};
use framev_blk_common::{FrameVBlkConfig, FrameVBlkStatus};
use framev_console_common::MAX_INPUT_CHUNK_BYTES;
use framev_net_common::{
    FrameVNetConfig, FrameVNetError, FrameVNetReceiveStatus, OwnedNetworkBuffer,
};
use framev_pci_common::{
    BlockConfig, ConsoleConfig, FrameVFunctionFamily, FrameVPciIdentity, FrameVPciLayout,
    NetConfig, RngConfig, SockConfig,
};
use framev_sock_common::{FrameVsockPacket, FrameVsockSendError};
pub use ostd::framev::blk::{BlockDestinations, BlockSources, MAX_BLOCK_EXTENTS};
use ostd::{
    bus::BusProbeError,
    irq::IrqLine as OstdIrqLine,
    mm::VmIoOnce,
    sync::{Mutex, Once},
};

type ConsoleInputCallback = fn(&[u8]);

/// A discovery or binding error raised by FrameV PCI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVPciError {
    NotInitialized,
    RuntimeUnavailable,
}

impl FrameVPciError {
    /// Returns a stable human-readable error message.
    pub const fn message(self) -> &'static str {
        match self {
            Self::NotInitialized => "FrameV devices are not initialized",
            Self::RuntimeUnavailable => "FrameV runtime is unavailable",
        }
    }
}

/// A bound default FrameV console frontend handle.
pub struct FrameVConsole {
    function: Arc<FrameVPciFunction>,
}

impl FrameVConsole {
    fn new(function: Arc<FrameVPciFunction>) -> Self {
        Self { function }
    }

    /// Returns the PCI location that identifies this function.
    pub fn id(&self) -> PciDeviceLocation {
        self.function.location()
    }

    /// Writes bytes through the bound console backend.
    pub fn write(&self, input: &[u8]) -> Result<usize, FrameVPciError> {
        ostd::framev::console::write_claimed(&self.function.claim, input)
            .map_err(|_| FrameVPciError::RuntimeUnavailable)
    }

    /// Registers a service-side input callback for the bound console backend.
    pub fn register_input_callback(
        &self,
        callback: ConsoleInputCallback,
    ) -> Result<(), FrameVPciError> {
        frontend_state()?.register_console_callback(&self.function, callback)
    }
}

/// A bound default FrameV RNG frontend handle.
pub struct FrameVRng {
    function: Arc<FrameVPciFunction>,
}

impl FrameVRng {
    fn new(function: Arc<FrameVPciFunction>) -> Self {
        Self { function }
    }

    /// Returns the PCI location that identifies this function.
    pub fn id(&self) -> PciDeviceLocation {
        self.function.location()
    }

    /// Fills `dst` through the bound RNG backend.
    pub fn fill_bytes(&self, dst: &mut [u8]) -> Result<(), FrameVPciError> {
        ostd::framev::rng::fill_bytes_claimed(&self.function.claim, dst)
            .map_err(|_| FrameVPciError::RuntimeUnavailable)
    }
}

/// A bound optional FrameV block frontend handle.
pub struct FrameVBlock {
    function: Arc<FrameVPciFunction>,
}

/// Failure returned by one claimed FrameV-net operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVNetOperationError {
    /// The PCI claim or FrameVisor runtime is unavailable.
    RuntimeUnavailable,
    /// The endpoint rejected an otherwise valid network operation.
    Transport(FrameVNetError),
}

/// A bound optional FrameV-net frontend handle.
pub struct FrameVNet {
    function: Arc<FrameVPciFunction>,
}

impl FrameVNet {
    fn new(function: Arc<FrameVPciFunction>) -> Self {
        Self { function }
    }

    /// Returns the PCI location that identifies this function.
    pub fn id(&self) -> PciDeviceLocation {
        self.function.location()
    }

    /// Returns the backend-authoritative immutable network configuration.
    pub fn config(&self) -> Result<FrameVNetConfig, FrameVPciError> {
        ostd::framev::net::current_net_config(&self.function.claim)
            .map_err(|_| FrameVPciError::RuntimeUnavailable)
    }

    /// Sends one borrowed Ethernet frame through the captured endpoint.
    pub fn send(&self, ethernet_frame: &[u8]) -> Result<(), FrameVNetOperationError> {
        ostd::framev::net::send_claimed(&self.function.claim, ethernet_frame)
            .map_err(|_| FrameVNetOperationError::RuntimeUnavailable)?
            .map_err(FrameVNetOperationError::Transport)
    }

    /// Allocates one Host-owned receive buffer for this endpoint.
    pub fn allocate_receive_buffer(&self) -> Result<OwnedNetworkBuffer, FrameVPciError> {
        ostd::framev::net::allocate_receive_buffer_claimed(&self.function.claim)
            .map_err(|_| FrameVPciError::RuntimeUnavailable)
    }

    /// Posts one owned receive buffer to the backend.
    pub fn post_receive_buffer(
        &self,
        receive_buffer: OwnedNetworkBuffer,
    ) -> Result<(), (FrameVNetOperationError, OwnedNetworkBuffer)> {
        match ostd::framev::net::post_receive_buffer_claimed(&self.function.claim, receive_buffer) {
            Ok(Ok(())) => Ok(()),
            Ok(Err((error, receive_buffer))) => {
                Err((FrameVNetOperationError::Transport(error), receive_buffer))
            }
            Err((_, receive_buffer)) => {
                Err((FrameVNetOperationError::RuntimeUnavailable, receive_buffer))
            }
        }
    }

    /// Polls the endpoint once and publishes at most one received frame.
    pub fn poll_receive(&self) -> Result<FrameVNetReceiveStatus, FrameVPciError> {
        ostd::framev::net::poll_receive_claimed(&self.function.claim)
            .map_err(|_| FrameVPciError::RuntimeUnavailable)
    }

    /// Returns whether a received Ethernet frame is ready for the network frontend.
    pub fn has_completed_buffer(&self) -> Result<bool, FrameVPciError> {
        ostd::framev::net::has_completed_buffer_claimed(&self.function.claim)
            .map_err(|_| FrameVPciError::RuntimeUnavailable)
    }

    /// Returns whether the captured endpoint is permanently unavailable.
    pub fn is_endpoint_lost(&self) -> Result<bool, FrameVPciError> {
        ostd::framev::net::is_endpoint_lost_claimed(&self.function.claim)
            .map_err(|_| FrameVPciError::RuntimeUnavailable)
    }

    /// Takes one published receive buffer with its Ethernet frame length.
    pub fn take_completed_buffer(
        &self,
    ) -> Result<Option<(OwnedNetworkBuffer, usize)>, FrameVPciError> {
        ostd::framev::net::take_completed_buffer_claimed(&self.function.claim)
            .map_err(|_| FrameVPciError::RuntimeUnavailable)
    }

    /// Takes one receive buffer reclaimed after endpoint loss.
    pub fn take_reclaimed_buffer(&self) -> Result<Option<OwnedNetworkBuffer>, FrameVPciError> {
        ostd::framev::net::take_reclaimed_buffer_claimed(&self.function.claim)
            .map_err(|_| FrameVPciError::RuntimeUnavailable)
    }

    /// Installs the receive notification callback for the bound network function.
    pub fn install_rx_callback(&self, callback: fn()) -> Result<(), FrameVPciError> {
        frontend_state()?.install_irq_callback(FrameVFunctionFamily::Net, callback)
    }
}

impl FrameVBlock {
    fn new(function: Arc<FrameVPciFunction>) -> Self {
        Self { function }
    }

    /// Returns the PCI location that identifies this function.
    pub fn id(&self) -> PciDeviceLocation {
        self.function.location()
    }

    /// Returns the backend-authoritative block configuration.
    pub fn config(&self) -> Result<FrameVBlkConfig, FrameVPciError> {
        ostd::framev::blk::current_block_config(&self.function.claim)
            .map_err(|_| FrameVPciError::RuntimeUnavailable)
    }

    /// Reads one sector-aligned SG range from the block backend.
    pub fn read(
        &self,
        sector: u64,
        destinations: &mut BlockDestinations<'_>,
    ) -> Result<FrameVBlkStatus, FrameVPciError> {
        ostd::framev::blk::read_current_block(&self.function.claim, sector, destinations)
            .map_err(|_| FrameVPciError::RuntimeUnavailable)
    }

    /// Writes one sector-aligned SG range to the block backend.
    pub fn write(
        &self,
        sector: u64,
        sources: &mut BlockSources<'_>,
    ) -> Result<FrameVBlkStatus, FrameVPciError> {
        ostd::framev::blk::write_current_block(&self.function.claim, sector, sources)
            .map_err(|_| FrameVPciError::RuntimeUnavailable)
    }

    /// Flushes durable block backend state.
    pub fn flush(&self) -> Result<FrameVBlkStatus, FrameVPciError> {
        ostd::framev::blk::flush_current_block(&self.function.claim)
            .map_err(|_| FrameVPciError::RuntimeUnavailable)
    }
}

/// A bound default FrameV Sock frontend handle.
pub struct FrameVSock {
    function: Arc<FrameVPciFunction>,
}

impl FrameVSock {
    fn new(function: Arc<FrameVPciFunction>) -> Self {
        Self { function }
    }

    /// Returns the PCI location that identifies this function.
    pub fn id(&self) -> PciDeviceLocation {
        self.function.location()
    }

    /// Marks this socket transport active in the FrameV runtime.
    pub fn activate(&self) -> Result<(), FrameVPciError> {
        ostd::framev::sock::activate_claimed(&self.function.claim)
            .map_err(|_| FrameVPciError::RuntimeUnavailable)
    }

    /// Installs the service-side RX notification callback for this socket transport.
    pub fn install_rx_callback(&self, callback: fn()) -> Result<(), FrameVPciError> {
        frontend_state()?.install_irq_callback(FrameVFunctionFamily::Sock, callback)
    }

    /// Returns whether the socket transport is active.
    pub fn is_active(&self) -> bool {
        ostd::framev::sock::is_active_claimed(&self.function.claim).unwrap_or(false)
    }

    /// Returns the number of socket queue pairs.
    pub fn queue_count(&self) -> usize {
        ostd::framev::sock::queue_count_claimed(&self.function.claim).unwrap_or(0)
    }

    /// Returns the current service vCPU index.
    pub fn current_vcpu_index(&self) -> Option<usize> {
        ostd::task::current_cpu_index()
    }

    /// Returns the service-visible guest CID.
    pub fn guest_cid(&self) -> Option<u64> {
        ostd::framev::sock::guest_cid_claimed(&self.function.claim)
            .ok()
            .flatten()
    }

    /// Submits one packet to the backend transport.
    pub fn submit_packet(
        &self,
        queue_id: usize,
        packet: FrameVsockPacket,
    ) -> Result<(), (FrameVsockSendError, FrameVsockPacket)> {
        match ostd::framev::sock::submit_packet_claimed(&self.function.claim, queue_id, &packet) {
            Ok(()) => Ok(()),
            Err(error) => Err((error, packet)),
        }
    }

    /// Receives one packet from the selected socket queue.
    pub fn recv_packet(&self, queue_id: usize) -> Option<FrameVsockPacket> {
        ostd::framev::sock::recv_packet_claimed(
            &self.function.claim,
            queue_id,
            copy_packet_to_service,
        )
    }

    /// Takes the current generation's pending transport-reset event.
    pub fn take_transport_reset(&self) -> Option<u64> {
        ostd::framev::sock::take_transport_reset_claimed(&self.function.claim)
            .ok()
            .flatten()
    }
}

fn copy_packet_to_service(packet: &FrameVsockPacket) -> Option<FrameVsockPacket> {
    packet.try_clone()
}

#[derive(Debug)]
struct FrameVPciFunction {
    common_device: PciCommonDevice,
    identity: FrameVPciIdentity,
    claim: ostd::pci::FunctionClaim,
    msix: Option<CapabilityMsixData>,
    irq_lines: Mutex<Vec<OstdIrqLine>>,
}

impl FrameVPciFunction {
    fn family(&self) -> FrameVFunctionFamily {
        self.identity.family()
    }

    fn location(&self) -> PciDeviceLocation {
        *self.common_device.location()
    }

    fn generation(&self) -> u64 {
        self.claim.generation()
    }

    fn msix(&self) -> Option<&CapabilityMsixData> {
        self.msix.as_ref()
    }

    fn install_irq_callback(&self, callback: fn()) -> Result<(), FrameVPciError> {
        let mut irq_lines = {
            let mut stored_lines = self.irq_lines.lock();
            core::mem::take(&mut *stored_lines)
        };
        if irq_lines.is_empty() || irq_lines.iter().any(|line| !line.is_empty()) {
            self.irq_lines.lock().extend(irq_lines);
            return Err(FrameVPciError::RuntimeUnavailable);
        }
        for irq_line in &mut irq_lines {
            irq_line.on_active(move |_| callback());
        }
        self.irq_lines.lock().extend(irq_lines);
        Ok(())
    }
}

impl PciDevice for FrameVPciFunction {
    fn device_id(&self) -> PciDeviceId {
        *self.common_device.device_id()
    }
}

#[derive(Debug)]
struct FrameVPciDriver {
    functions: Mutex<Vec<Arc<FrameVPciFunction>>>,
    initialization: Mutex<FrameVPciInitialization>,
    console_callback: Mutex<Option<ConsoleInputCallback>>,
}

impl FrameVPciDriver {
    fn new() -> Self {
        Self {
            functions: Mutex::new(Vec::new()),
            initialization: Mutex::new(FrameVPciInitialization::New),
            console_callback: Mutex::new(None),
        }
    }

    fn has_family(&self, family: FrameVFunctionFamily) -> bool {
        self.function(family).is_some()
    }

    fn function(&self, family: FrameVFunctionFamily) -> Option<Arc<FrameVPciFunction>> {
        self.functions
            .lock()
            .iter()
            .find(|function| function.family() == family)
            .cloned()
    }

    fn functions(&self, family: FrameVFunctionFamily) -> Vec<Arc<FrameVPciFunction>> {
        self.functions
            .lock()
            .iter()
            .filter(|function| function.family() == family)
            .cloned()
            .collect()
    }

    fn has_singleton(&self, family: FrameVFunctionFamily) -> bool {
        family != FrameVFunctionFamily::Block && self.has_family(family)
    }

    fn install_irq_callback(
        &self,
        family: FrameVFunctionFamily,
        callback: fn(),
    ) -> Result<(), FrameVPciError> {
        let function = self
            .function(family)
            .ok_or(FrameVPciError::NotInitialized)?;
        function.install_irq_callback(callback)
    }

    fn register_console_callback(
        &self,
        function: &FrameVPciFunction,
        callback: ConsoleInputCallback,
    ) -> Result<(), FrameVPciError> {
        {
            let mut stored_callback = self.console_callback.lock();
            if stored_callback.is_some() {
                return Err(FrameVPciError::RuntimeUnavailable);
            }
            *stored_callback = Some(callback);
        }
        // `on_active` may immediately dispatch a pending MSI-X edge. Publish
        // the callback first, but never hold its lock while installing the IRQ
        // handler because the handler reads the same slot.
        if function.family() != FrameVFunctionFamily::Console {
            *self.console_callback.lock() = None;
            return Err(FrameVPciError::RuntimeUnavailable);
        }
        if let Err(error) = function.install_irq_callback(dispatch_console_input) {
            *self.console_callback.lock() = None;
            return Err(error);
        }
        dispatch_console_input();
        Ok(())
    }
}

impl PciDriver for FrameVPciDriver {
    fn probe(
        &self,
        mut device: PciCommonDevice,
    ) -> Result<Arc<dyn PciDevice>, (BusProbeError, PciCommonDevice)> {
        let identity = match decode_identity(device.device_id()) {
            Ok(identity) => identity,
            Err(BusProbeError::DeviceNotMatch) => {
                return Err((BusProbeError::DeviceNotMatch, device));
            }
            Err(error) => return Err((error, device)),
        };
        if self.has_singleton(identity.family()) {
            return Err((BusProbeError::ConfigurationSpaceError, device));
        }

        let mut msix = match validate_function_layout(&mut device, identity.family()) {
            Ok(msix) => msix,
            Err(error) => return Err((error, device)),
        };
        let irq_lines = match configure_msix_vectors(msix.as_mut()) {
            Ok(irq_lines) => irq_lines,
            Err(error) => return Err((error, device)),
        };
        let location = *device.location();
        let claim = match ostd::pci::claim_current_function(
            location.bus,
            location.device,
            location.function,
            identity.family(),
        ) {
            Ok(claim) => claim,
            Err(_) => return Err((BusProbeError::ConfigurationSpaceError, device)),
        };
        let function = Arc::new(FrameVPciFunction {
            common_device: device,
            identity,
            claim,
            msix,
            irq_lines: Mutex::new(irq_lines),
        });
        self.functions.lock().push(function.clone());
        Ok(function)
    }
}

// The service image is loaded once per FrameVM.  Image-local statics therefore
// already have the required per-VM lifetime; retaining a second FrameVisor
// lookup table would duplicate ownership and teardown state.
static FRAMEV_PCI_DRIVER: Once<Arc<FrameVPciDriver>> = Once::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameVPciInitialization {
    New,
    DriverRegistered,
    Ready,
}

fn dispatch_console_input() {
    let Ok(state) = frontend_state() else {
        return;
    };
    let Some(callback) = *state.console_callback.lock() else {
        return;
    };
    let Some(function) = state.function(FrameVFunctionFamily::Console) else {
        return;
    };
    // This IRQ handler is the sole frontend consumer. Copy into service-owned
    // storage before invoking the callback; the Host queue's allocation must
    // never cross the relocated service allocator boundary.
    let mut input = [0u8; MAX_INPUT_CHUNK_BYTES];
    loop {
        let Ok(Some(input_len)) =
            ostd::framev::console::take_claimed_input(&function.claim, &mut input)
        else {
            return;
        };
        callback(&input[..input_len]);
    }
}

#[init_component]
fn init() -> Result<(), ComponentInitError> {
    init_for_framevm_component_profile()
}

/// Initializes FrameV PCI in the FrameVM component profile.
pub fn init_for_framevm_component_profile() -> Result<(), ComponentInitError> {
    let state = FRAMEV_PCI_DRIVER.call_once(|| Arc::new(FrameVPciDriver::new()));
    let mut initialization = state.initialization.lock();
    match *initialization {
        FrameVPciInitialization::Ready => return Ok(()),
        FrameVPciInitialization::New => {
            aster_pci::with_bus(|bus| bus.register_driver(state.clone()));
            *initialization = FrameVPciInitialization::DriverRegistered;
        }
        FrameVPciInitialization::DriverRegistered => {}
    }
    ensure_required_functions(&state).map_err(|_| ComponentInitError::Unknown)?;
    *initialization = FrameVPciInitialization::Ready;
    let functions = state
        .functions
        .lock()
        .iter()
        .map(|function| {
            (
                function.family(),
                function.location(),
                function.generation(),
                function.msix().map(CapabilityMsixData::table_size),
            )
        })
        .collect::<Vec<_>>();
    for (family, location, generation, vector_count) in functions {
        ostd::early_println!(
            "FrameV PCI {:?} at {:?}, generation={}, MSI-X={:?}",
            family,
            location,
            generation,
            vector_count
        );
    }
    Ok(())
}

/// Returns the bound default `framev-console` frontend.
pub fn console() -> Result<FrameVConsole, FrameVPciError> {
    Ok(FrameVConsole::new(require_function(
        FrameVFunctionFamily::Console,
    )?))
}

/// Returns the bound default `framev-rng` frontend.
pub fn rng() -> Result<FrameVRng, FrameVPciError> {
    Ok(FrameVRng::new(require_function(FrameVFunctionFamily::Rng)?))
}

/// Returns the bound default `framev-sock` frontend.
pub fn sock() -> Result<FrameVSock, FrameVPciError> {
    Ok(FrameVSock::new(require_function(
        FrameVFunctionFamily::Sock,
    )?))
}

/// Returns all bound `framev-blk` frontends in PCI topology order.
pub fn blocks() -> Result<Vec<FrameVBlock>, FrameVPciError> {
    Ok(frontend_state()?
        .functions(FrameVFunctionFamily::Block)
        .into_iter()
        .map(FrameVBlock::new)
        .collect())
}

/// Returns the bound optional `framev-net` frontend, if present.
pub fn net() -> Result<Option<FrameVNet>, FrameVPciError> {
    Ok(frontend_state()?
        .function(FrameVFunctionFamily::Net)
        .map(FrameVNet::new))
}

fn frontend_state() -> Result<Arc<FrameVPciDriver>, FrameVPciError> {
    FRAMEV_PCI_DRIVER
        .get()
        .cloned()
        .ok_or(FrameVPciError::RuntimeUnavailable)
}

fn require_function(
    family: FrameVFunctionFamily,
) -> Result<Arc<FrameVPciFunction>, FrameVPciError> {
    frontend_state()?
        .function(family)
        .ok_or(FrameVPciError::NotInitialized)
}

fn ensure_required_functions(driver: &FrameVPciDriver) -> Result<(), FrameVPciError> {
    for family in [
        FrameVFunctionFamily::Console,
        FrameVFunctionFamily::Rng,
        FrameVFunctionFamily::Sock,
    ] {
        if !driver.has_family(family) {
            return Err(FrameVPciError::NotInitialized);
        }
    }
    Ok(())
}

fn decode_identity(device_id: &PciDeviceId) -> Result<FrameVPciIdentity, BusProbeError> {
    FrameVPciIdentity::decode(
        device_id.vendor_id,
        device_id.device_id,
        device_id.revision_id,
        device_id.class,
        device_id.subclass,
        device_id.prog_if,
    )
    .map_err(|error| match error {
        framev_pci_common::IdentityError::UnknownVendor
        | framev_pci_common::IdentityError::UnknownDevice => BusProbeError::DeviceNotMatch,
        _ => BusProbeError::ConfigurationSpaceError,
    })
}

fn validate_function_layout(
    device: &mut PciCommonDevice,
    family: FrameVFunctionFamily,
) -> Result<Option<CapabilityMsixData>, BusProbeError> {
    if device.device_type() != PciDeviceType::GeneralDevice || device.has_multi_funcs() {
        return Err(BusProbeError::ConfigurationSpaceError);
    }
    let Some(Bar::Memory(memory_bar)) = device.bar_manager().bar(0) else {
        return Err(BusProbeError::ConfigurationSpaceError);
    };
    if memory_bar.address_length() != AddrLen::Bits64 || memory_bar.prefetchable() {
        return Err(BusProbeError::ConfigurationSpaceError);
    }
    if (1..6).any(|index| device.bar_manager().bar(index).is_some()) {
        return Err(BusProbeError::ConfigurationSpaceError);
    }

    let mut config = [0_u8; 0x20];
    let access = device
        .bar_manager_mut()
        .bar_mut(0)
        .ok_or(BusProbeError::ConfigurationSpaceError)?
        .acquire()
        .map_err(|_| BusProbeError::ConfigurationSpaceError)?;
    let BarAccess::Memory(io_memory) = access else {
        return Err(BusProbeError::ConfigurationSpaceError);
    };
    for offset in (0..family.config_size_bytes()).step_by(size_of::<u32>()) {
        let word = io_memory
            .read_once::<u32>(offset)
            .map_err(|_| BusProbeError::ConfigurationSpaceError)?;
        config[offset..offset + size_of::<u32>()].copy_from_slice(&word.to_le_bytes());
    }
    let vector_count = validate_family_config(family, config)?;
    let layout = FrameVPciLayout::new(family, vector_count)
        .map_err(|_| BusProbeError::ConfigurationSpaceError)?;
    let Some(Bar::Memory(memory_bar)) = device.bar_manager().bar(0) else {
        return Err(BusProbeError::ConfigurationSpaceError);
    };
    if memory_bar.size() != layout.bar_size_bytes() as u64 {
        return Err(BusProbeError::ConfigurationSpaceError);
    }

    let msix = device
        .acquire_msix_capability()
        .map_err(|_| BusProbeError::ConfigurationSpaceError)?;
    if msix.as_ref().map(CapabilityMsixData::table_size)
        != family.has_msix().then_some(vector_count)
    {
        return Err(BusProbeError::ConfigurationSpaceError);
    }
    Ok(msix)
}

fn validate_family_config(
    family: FrameVFunctionFamily,
    bytes: [u8; 0x20],
) -> Result<u16, BusProbeError> {
    let invalid = |_| BusProbeError::ConfigurationSpaceError;
    match family {
        FrameVFunctionFamily::Console => {
            ConsoleConfig::decode(bytes[..0x10].try_into().unwrap()).map_err(invalid)?;
            Ok(1)
        }
        FrameVFunctionFamily::Rng => {
            RngConfig::decode(bytes[..0x10].try_into().unwrap()).map_err(invalid)?;
            Ok(0)
        }
        FrameVFunctionFamily::Block => {
            BlockConfig::decode(bytes).map_err(invalid)?;
            Ok(0)
        }
        FrameVFunctionFamily::Sock => {
            let config = SockConfig::decode(bytes).map_err(invalid)?;
            config
                .receive_queue_count
                .checked_add(config.state_vector_count)
                .ok_or(BusProbeError::ConfigurationSpaceError)
        }
        FrameVFunctionFamily::Net => {
            NetConfig::decode(bytes[..0x10].try_into().unwrap()).map_err(invalid)?;
            Ok(1)
        }
    }
}

fn configure_msix_vectors(
    msix: Option<&mut CapabilityMsixData>,
) -> Result<Vec<OstdIrqLine>, BusProbeError> {
    let Some(msix) = msix else {
        return Ok(Vec::new());
    };
    let mut irq_lines = Vec::with_capacity(usize::from(msix.table_size()));
    for vector in 0..msix.table_size() {
        let irq_line =
            OstdIrqLine::alloc_virtual().map_err(|_| BusProbeError::ConfigurationSpaceError)?;
        msix.set_interrupt_vector(irq_line.clone(), vector);
        irq_lines.push(irq_line);
    }
    Ok(irq_lines)
}
