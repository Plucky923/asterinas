// SPDX-License-Identifier: MPL-2.0

//! FrameV devices owned by one `FrameVm`.

use alloc::{sync::Arc, vec::Vec};

use framev_pci_common::FrameVFunctionFamily;

#[cfg(target_arch = "x86_64")]
use crate::assigned_pci::AssignedPciDevice;
use crate::{
    Error, Result, pci::VirtualPciBus, sync::SpinLock, vm::VmId, vsock::SockConfiguration,
};

mod block;
mod console;
mod net;
mod rng;
mod sock;
mod state;

pub(crate) use self::{block::Block, net::Net, rng::Rng, sock::Sock, state::FunctionRuntime};
pub use self::{
    block::{BlockDestinations, BlockImage, BlockImageError, BlockSources, MAX_BLOCK_EXTENTS},
    console::Console,
    net::{NetworkConfiguration, NetworkEndpoint},
    state::FunctionClaim,
};

/// Host-side FrameV device subsystem for one `FrameVm`.
pub struct Devices {
    console: Console,
    sock: Sock,
    rng: Rng,
    blocks: Vec<Block>,
    net: Option<Arc<Net>>,
    pci: Arc<VirtualPciBus>,
    #[cfg(target_arch = "x86_64")]
    assigned_pci: SpinLock<Option<AssignedPciDevice>>,
}

impl Devices {
    /// Creates the FrameV device set with explicit optional block and network backends.
    pub(crate) fn new(
        vm_id: VmId,
        vcpu_count: usize,
        block_images: Vec<Arc<dyn BlockImage>>,
        sock_configuration: SockConfiguration,
        network_configuration: Option<NetworkConfiguration>,
        #[cfg(target_arch = "x86_64")] reserved_pci: Option<aster_pci::ReservedPciGroup>,
    ) -> Result<Self> {
        let block_configs = block_images
            .iter()
            .map(|image| Block::config_for_image(image.as_ref()))
            .collect::<Result<Vec<_>>>()?;
        let pci = Arc::new(VirtualPciBus::new(
            vm_id,
            vcpu_count,
            sock_configuration.guest_cid(),
            &block_configs,
            network_configuration
                .as_ref()
                .map(NetworkConfiguration::config),
        )?);
        let console = Console::new(pci.runtime(FrameVFunctionFamily::Console)?, pci.clone());
        let sock = Sock::new(
            pci.runtime(FrameVFunctionFamily::Sock)?,
            vm_id,
            vcpu_count,
            sock_configuration,
            pci.clone(),
        )?;
        let rng = Rng::new(pci.runtime(FrameVFunctionFamily::Rng)?);
        let blocks = block_images
            .into_iter()
            .zip(block_configs)
            .enumerate()
            .map(|(stable_id, (image, config))| {
                Ok(Block::new(
                    pci.runtime_at(FrameVFunctionFamily::Block, stable_id as u64)?,
                    image,
                    config,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let net = match network_configuration {
            Some(configuration) => {
                let runtime = pci.runtime(FrameVFunctionFamily::Net)?;
                Some(Net::new(runtime, configuration, pci.clone()))
            }
            None => None,
        };
        #[cfg(target_arch = "x86_64")]
        let assigned_pci = reserved_pci
            .map(|reserved| AssignedPciDevice::new(vm_id, reserved))
            .transpose()?;
        #[cfg(target_arch = "x86_64")]
        if let Some(assigned_pci) = &assigned_pci {
            pci.attach_assigned(assigned_pci.access())?;
        }
        let devices = Self {
            console,
            sock,
            rng,
            blocks,
            net,
            pci,
            #[cfg(target_arch = "x86_64")]
            assigned_pci: SpinLock::new(assigned_pci),
        };
        Ok(devices)
    }

    /// Returns the typed console backend handle.
    pub fn console(&self) -> &Console {
        &self.console
    }

    /// Returns the typed sock backend handle.
    pub(crate) fn sock(&self) -> &Sock {
        &self.sock
    }

    /// Returns the typed RNG backend handle.
    pub(crate) fn rng(&self) -> &Rng {
        &self.rng
    }

    /// Returns every typed block backend in stable device order.
    pub(crate) fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    /// Returns the optional typed network backend handle.
    pub(crate) fn net(&self) -> Option<&Net> {
        self.net.as_deref()
    }

    /// Returns this FrameVM's private virtual PCI configuration space.
    pub(crate) fn pci(&self) -> &VirtualPciBus {
        &self.pci
    }

    /// Returns the DMA domain owned by the assigned physical function.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn assigned_pci_dma_domain(&self) -> Option<Arc<host_ostd::mm::dma::PciDmaDomain>> {
        self.assigned_pci
            .lock()
            .as_ref()
            .map(AssignedPciDevice::dma_domain)
    }

    /// Returns the generation-scoped access authority for the assigned
    /// physical function.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn assigned_pci_access(
        &self,
    ) -> Option<Arc<crate::assigned_pci::AssignedPciAccess>> {
        self.assigned_pci
            .lock()
            .as_ref()
            .map(AssignedPciDevice::access)
    }

    /// Releases the assigned physical function, returning whether it had to
    /// be quarantined by the PCI layer.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn release_assigned_pci(&self) -> bool {
        let Some(mut assigned_pci) = self.assigned_pci.lock().take() else {
            return false;
        };
        assigned_pci.release().is_err()
    }

    /// Permanently quarantines the assigned physical function.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn quarantine_assigned_pci(&self) -> bool {
        let Some(mut assigned_pci) = self.assigned_pci.lock().take() else {
            return false;
        };
        assigned_pci.quarantine();
        true
    }

    /// Queues nonblocking console input and raises its MSI-X vector.
    pub fn inject_console_input(&self, bytes: &[u8]) -> Result<usize> {
        self.console.inject_host_input(bytes)
    }

    /// Queues blocking console input and raises its MSI-X vector.
    pub fn inject_console_input_blocking(&self, bytes: &[u8]) -> Result<usize> {
        self.console.inject_host_input_blocking(bytes)
    }

    /// Resets all device state before starting interrupt delivery.
    pub(crate) fn reset_for_start(&self) {
        self.pci.revoke_claims();
        self.console.reset();
        self.sock.reset();
        if let Some(net) = &self.net {
            net.reset();
        }
    }

    /// Marks the current default device set ready.
    pub(crate) fn mark_ready_all(&self) -> Result<()> {
        self.sock.validate_start()?;
        let start_result = (|| {
            self.console.runtime().start()?;
            self.sock.runtime().start()?;
            self.rng.runtime().start()?;
            for block in &self.blocks {
                block.runtime().start()?;
            }
            if let Some(net) = &self.net {
                net.runtime().start()?;
            }
            self.sock.publish_generation()?;
            Ok(())
        })();
        if start_result.is_err() {
            self.close_function_admission();
            self.wait_for_function_calls();
        }
        start_result
    }

    /// Stops all devices and clears delivery/runtime state.
    pub(crate) fn stop_all(&self) {
        self.pci.revoke_claims();
        self.close_function_admission();
        self.wait_for_function_calls();
        self.console.stop();
        self.sock.stop();
        if let Some(net) = &self.net {
            net.reset();
        }
    }

    fn close_function_admission(&self) {
        self.console.runtime().begin_stop();
        self.sock.runtime().begin_stop();
        self.rng.runtime().begin_stop();
        for block in &self.blocks {
            block.runtime().begin_stop();
        }
        if let Some(net) = &self.net {
            net.runtime().begin_stop();
        }
    }

    fn wait_for_function_calls(&self) {
        self.console.runtime().wait_until_stopped();
        self.sock.runtime().wait_until_stopped();
        self.rng.runtime().wait_until_stopped();
        for block in &self.blocks {
            block.runtime().wait_until_stopped();
        }
        if let Some(net) = &self.net {
            net.runtime().wait_until_stopped();
        }
    }
}

/// Returns the current service VM's optional FrameV-blk configuration.
pub fn current_block_config(claim: &FunctionClaim) -> Result<framev_blk_common::FrameVBlkConfig> {
    let _call = claim.enter(FrameVFunctionFamily::Block)?;
    with_current_block(claim, |block| Ok(block.config()))
}

/// Reads one SG operation from the current service VM's optional block backend.
///
/// This is a service-runnable data-path hook. Callers must invoke it from the
/// FrameVM service runtime, not from IRQ notification/control callbacks.
pub fn read_current_block(
    claim: &FunctionClaim,
    sector: u64,
    destinations: &mut BlockDestinations<'_>,
) -> Result<framev_blk_common::FrameVBlkStatus> {
    let _call = claim.enter(FrameVFunctionFamily::Block)?;
    with_current_block(claim, |block| Ok(block.read(sector, destinations)))
}

/// Writes one SG operation to the current service VM's optional block backend.
pub fn write_current_block(
    claim: &FunctionClaim,
    sector: u64,
    sources: &mut BlockSources<'_>,
) -> Result<framev_blk_common::FrameVBlkStatus> {
    let _call = claim.enter(FrameVFunctionFamily::Block)?;
    with_current_block(claim, |block| Ok(block.write(sector, sources)))
}

/// Flushes the current service VM's optional block backend.
pub fn flush_current_block(claim: &FunctionClaim) -> Result<framev_blk_common::FrameVBlkStatus> {
    let _call = claim.enter(FrameVFunctionFamily::Block)?;
    with_current_block(claim, |block| Ok(block.flush()))
}

fn with_current_block<T>(claim: &FunctionClaim, f: impl FnOnce(&Block) -> Result<T>) -> Result<T> {
    let vm = crate::vm::get_vm_by_id(claim.vm_id()).ok_or(Error::InvalidArgs)?;
    let block = vm
        .devices()
        .blocks()
        .iter()
        .find(|block| block.runtime().bdf() == claim.bdf())
        .ok_or(Error::InvalidArgs)?;
    f(block)
}

#[cfg(ktest)]
mod tests {
    use framev_net_common::{FrameVNetConfig, NetworkEndpointError, OwnedNetworkBuffer};
    use host_ostd::prelude::ktest;

    use super::*;
    use crate::{task::scheduler::DEFAULT_FRAMEVM_SHARE, vm::FrameVm};

    struct IdleNetworkEndpoint;

    impl NetworkEndpoint for IdleNetworkEndpoint {
        fn send(&self, _ethernet_frame: &[u8]) -> Result<(), NetworkEndpointError> {
            Ok(())
        }

        fn receive(
            &self,
            _receive_buffer: &mut OwnedNetworkBuffer,
        ) -> Result<Option<usize>, NetworkEndpointError> {
            Ok(None)
        }

        fn install_receive_callback(&self, _callback: Arc<dyn Fn() + Send + Sync>) {}
    }

    fn network_configuration() -> NetworkConfiguration {
        let config = FrameVNetConfig::new([0x02, 0, 0, 0, 0, 1], 1_500, 1_514, 16).unwrap();
        NetworkConfiguration::new(config, Arc::new(IdleNetworkEndpoint))
    }

    #[ktest]
    fn host_control_uses_typed_device_handles_without_device_ids() {
        let vm = FrameVm::new(
            crate::vm::VmId::new(17),
            crate::vm::FrameVmConfig::new(
                2,
                DEFAULT_FRAMEVM_SHARE,
                crate::mm::PAGE_SIZE * 16,
                Arc::from(&[][..]),
                None,
                Vec::new(),
                SockConfiguration::new(20).unwrap(),
                None,
                None,
            ),
        )
        .unwrap();
        let devices = vm.devices();

        assert_eq!(devices.console().inject_input(b"x").unwrap(), 1);
        assert!(devices.console().has_input());
        assert_eq!(devices.sock().queue_count(), 2);
        assert_eq!(devices.rng().runtime().generation(), 0);
        assert!(devices.net().is_none());
    }

    #[ktest]
    fn configured_network_gets_one_bdf_owned_function_runtime() {
        let devices = Devices::new(
            crate::vm::VmId::new(1),
            1,
            Vec::new(),
            SockConfiguration::new(3).unwrap(),
            Some(network_configuration()),
            #[cfg(target_arch = "x86_64")]
            None,
        )
        .unwrap();
        let net = devices.net().unwrap();

        assert_eq!(net.runtime().bdf().device(), 4);
        assert_eq!(net.config().mac_address(), [0x02, 0, 0, 0, 0, 1]);

        devices.mark_ready_all().unwrap();
        assert!(net.runtime().enter_host().is_ok());

        devices.stop_all();
        assert!(matches!(
            net.runtime().enter_host(),
            Err(Error::AccessDenied)
        ));
    }

    #[ktest]
    fn restart_cleans_typed_device_state_and_advances_generation() {
        let devices = Devices::new(
            crate::vm::VmId::new(0),
            1,
            Vec::new(),
            SockConfiguration::new(20).unwrap(),
            None,
            #[cfg(target_arch = "x86_64")]
            None,
        )
        .unwrap();
        devices.mark_ready_all().unwrap();
        let first_generation = devices.rng().runtime().generation();

        devices.stop_all();
        devices.reset_for_start();
        devices.mark_ready_all().unwrap();

        assert_eq!(devices.rng().runtime().generation(), first_generation + 1);
        assert!(devices.rng().runtime().enter_host().is_ok());
    }

    #[ktest]
    fn stop_stops_typed_devices() {
        let devices = Devices::new(
            crate::vm::VmId::new(0),
            1,
            Vec::new(),
            SockConfiguration::new(20).unwrap(),
            None,
            #[cfg(target_arch = "x86_64")]
            None,
        )
        .unwrap();
        devices.mark_ready_all().unwrap();

        devices.stop_all();

        assert!(matches!(
            devices.console().runtime().enter_host(),
            Err(Error::AccessDenied)
        ));
        assert!(matches!(
            devices.sock().runtime().enter_host(),
            Err(Error::AccessDenied)
        ));
        assert!(matches!(
            devices.rng().runtime().enter_host(),
            Err(Error::AccessDenied)
        ));
    }
}
