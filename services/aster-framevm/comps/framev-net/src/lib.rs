// SPDX-License-Identifier: MPL-2.0

//! FrameV-net frontend provider for the FrameVM service.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::{format, sync::Arc};
use core::{
    fmt,
    sync::atomic::{AtomicBool, Ordering},
};

use aster_bigtcp::device::{Checksum, DeviceCapabilities, Medium};
use aster_network::{
    AnyNetworkDevice, EthernetAddr, NetError, OwnedNetworkBuffer, OwnedNetworkBufferRecycler,
    RxBuffer,
};
use component::{ComponentInitError, init_component};
use framev_net_common::{FrameVNetConfig, FrameVNetError};
use framev_pci::{FrameVNet, FrameVNetOperationError};

const RECEIVE_BUFFER_HEADER_LEN: usize = 0;

/// The FrameV-net network device, identified by its private PCI BDF.
pub struct FrameVNetworkDevice {
    config: FrameVNetConfig,
    capabilities: DeviceCapabilities,
    net: Arc<FrameVNet>,
    receive_recycler: Arc<ReceiveRecycler>,
}

impl FrameVNetworkDevice {
    fn new(net: Arc<FrameVNet>, config: FrameVNetConfig) -> Self {
        let receive_recycler = Arc::new(ReceiveRecycler::new(net.clone()));
        Self {
            config,
            capabilities: network_capabilities(config),
            net,
            receive_recycler,
        }
    }

    fn post_initial_receive_buffers(&self) -> Result<(), ComponentInitError> {
        for _ in 0..self.config.maximum_posted_receive_buffers() {
            let receive_buffer = self
                .net
                .allocate_receive_buffer()
                .map_err(|_| ComponentInitError::Unknown)?;
            let receive_buffer = match self.net.post_receive_buffer(receive_buffer) {
                Ok(()) => continue,
                Err((FrameVNetOperationError::Transport(FrameVNetError::EndpointLost), buffer)) => {
                    self.receive_recycler.mark_endpoint_lost();
                    buffer
                }
                Err((_, _receive_buffer)) => return Err(ComponentInitError::Unknown),
            };
            drop(receive_buffer);
            self.receive_recycler.drain_reclaimed_buffers();
            return Ok(());
        }
        Ok(())
    }

    fn drain_reclaimed_buffers(&self) {
        self.receive_recycler.drain_reclaimed_buffers();
    }

    fn is_endpoint_unavailable(&self) -> bool {
        if self.receive_recycler.is_endpoint_lost() {
            return true;
        }

        match self.net.is_endpoint_lost() {
            Ok(false) => false,
            Ok(true) => {
                self.receive_recycler.mark_endpoint_lost();
                self.drain_reclaimed_buffers();
                true
            }
            Err(_) => true,
        }
    }
}

impl AnyNetworkDevice for FrameVNetworkDevice {
    fn mac_addr(&self) -> EthernetAddr {
        EthernetAddr(self.config.mac_address())
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities.clone()
    }

    fn can_receive(&self) -> bool {
        self.drain_reclaimed_buffers();
        !self.is_endpoint_unavailable() && self.net.has_completed_buffer().unwrap_or(false)
    }

    fn can_send(&self) -> bool {
        !self.is_endpoint_unavailable()
    }

    fn receive(&mut self) -> Result<RxBuffer, NetError> {
        self.drain_reclaimed_buffers();
        if self.is_endpoint_unavailable() {
            return Err(NetError::NotReady);
        }
        let Some((receive_buffer, frame_len)) = self
            .net
            .take_completed_buffer()
            .map_err(|_| NetError::NotReady)?
        else {
            return Err(NetError::NotReady);
        };
        assert!(frame_len <= receive_buffer.len());
        Ok(RxBuffer::from_owned_with_recycler(
            receive_buffer,
            RECEIVE_BUFFER_HEADER_LEN,
            frame_len,
            self.receive_recycler.clone(),
        ))
    }

    fn send(&mut self, packet: &[u8]) -> Result<(), NetError> {
        match self.net.send(packet) {
            Ok(()) => Ok(()),
            Err(FrameVNetOperationError::Transport(FrameVNetError::EndpointLost)) => {
                self.receive_recycler.mark_endpoint_lost();
                self.drain_reclaimed_buffers();
                Err(NetError::NotReady)
            }
            Err(FrameVNetOperationError::Transport(FrameVNetError::NotReady)) => {
                Err(NetError::NotReady)
            }
            Err(_) => Err(NetError::Busy),
        }
    }

    fn free_processed_tx_buffers(&mut self) {}

    fn notify_poll_end(&mut self) {}
}

impl fmt::Debug for FrameVNetworkDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FrameVNetworkDevice")
            .field("id", &self.net.id())
            .field("config", &self.config)
            .field("endpoint_lost", &self.receive_recycler.is_endpoint_lost())
            .finish()
    }
}

struct ReceiveRecycler {
    endpoint_lost: AtomicBool,
    net: Arc<FrameVNet>,
}

impl ReceiveRecycler {
    fn new(net: Arc<FrameVNet>) -> Self {
        Self {
            endpoint_lost: AtomicBool::new(false),
            net,
        }
    }

    fn is_endpoint_lost(&self) -> bool {
        self.endpoint_lost.load(Ordering::Acquire)
    }

    fn mark_endpoint_lost(&self) {
        self.endpoint_lost.store(true, Ordering::Release);
    }

    fn drain_reclaimed_buffers(&self) {
        while self.net.take_reclaimed_buffer().ok().flatten().is_some() {}
    }
}

impl OwnedNetworkBufferRecycler for ReceiveRecycler {
    fn recycle(&self, receive_buffer: OwnedNetworkBuffer) {
        if self.is_endpoint_lost() {
            return;
        }

        match self.net.post_receive_buffer(receive_buffer) {
            Ok(()) => {}
            Err((FrameVNetOperationError::Transport(FrameVNetError::EndpointLost), buffer)) => {
                self.mark_endpoint_lost();
                drop(buffer);
                self.drain_reclaimed_buffers();
            }
            Err((_, buffer)) => drop(buffer),
        }
    }
}

#[init_component(kthread)]
fn init() -> Result<(), ComponentInitError> {
    init_for_framevm_component_profile()
}

/// Initializes the optional FrameV-net device in the FrameVM component profile.
pub fn init_for_framevm_component_profile() -> Result<(), ComponentInitError> {
    let Some(net) = framev_pci::net().map_err(|_| ComponentInitError::Unknown)? else {
        return Ok(());
    };
    let net = Arc::new(net);
    let config = net.config().map_err(|_| ComponentInitError::Unknown)?;
    net.install_rx_callback(schedule_receive_poll)
        .map_err(|_| ComponentInitError::Unknown)?;
    let device = FrameVNetworkDevice::new(net.clone(), config);
    device.post_initial_receive_buffers()?;
    aster_network::register_device_instance(device_name(&net), device);
    aster_network::raise_receive_softirq();
    Ok(())
}

fn schedule_receive_poll() {
    aster_network::raise_receive_softirq();
}

/// Returns the service registry name for the optional FrameV-net PCI function.
pub fn network_device_name() -> Result<Option<alloc::string::String>, framev_pci::FrameVPciError> {
    Ok(framev_pci::net()?.map(|net| device_name(&net)))
}

fn device_name(net: &FrameVNet) -> alloc::string::String {
    let id = net.id();
    format!("framevnet-{:02x}:{:02x}.{}", id.bus, id.device, id.function)
}

fn network_capabilities(config: FrameVNetConfig) -> DeviceCapabilities {
    let mut capabilities = DeviceCapabilities::default();
    capabilities.max_burst_size = None;
    capabilities.medium = Medium::Ethernet;
    capabilities.max_transmission_unit = config.mtu() as usize;
    capabilities.checksum.tcp = Checksum::Both;
    capabilities.checksum.udp = Checksum::Both;
    capabilities.checksum.ipv4 = Checksum::Both;
    capabilities.checksum.icmpv4 = Checksum::Both;
    capabilities
}
