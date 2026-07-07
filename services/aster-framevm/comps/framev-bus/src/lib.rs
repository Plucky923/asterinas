// SPDX-License-Identifier: MPL-2.0

//! FrameV transport discovery for FrameVM frontends.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::{vec, vec::Vec};

use component::{ComponentInitError, init_component};
use framev_blk_common::{FrameVBlkConfig, FrameVBlkOp, FrameVBlkRequestHeader, FrameVBlkStatus};
use framev_device::{
    FrameVDeviceDescriptor, FrameVDeviceError, FrameVDeviceId, FrameVDeviceInfo, FrameVDeviceType,
    OwnedResource,
};
use framev_sock_common::FrameVsockPacket;
use ostd::sync::Once;

static DESCRIPTOR: Once<FrameVDeviceDescriptor> = Once::new();
static FRAMEV: Once<FrameV> = Once::new();

/// A descriptor or binding error raised by the FrameV bus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameVBusError {
    Device(FrameVDeviceError),
    MissingDescriptor,
    NotInitialized,
    RuntimeUnavailable,
}

impl FrameVBusError {
    /// Returns a stable human-readable error message.
    pub const fn message(self) -> &'static str {
        match self {
            Self::Device(FrameVDeviceError::DuplicateDeviceId(_)) => "duplicate FrameV device id",
            Self::Device(FrameVDeviceError::DuplicateIrqLine(_)) => "duplicate FrameV IRQ line",
            Self::Device(FrameVDeviceError::DuplicateRequiredDevice(_)) => {
                "duplicate required FrameV device"
            }
            Self::Device(FrameVDeviceError::InvalidDescriptorEncoding) => {
                "invalid FrameV descriptor encoding"
            }
            Self::Device(FrameVDeviceError::InvalidDeviceType) => "invalid FrameV device type",
            Self::Device(FrameVDeviceError::InvalidLifecycleTransition) => {
                "invalid FrameV lifecycle transition"
            }
            Self::Device(FrameVDeviceError::MissingRequiredDevice(_)) => {
                "missing required FrameV device"
            }
            Self::Device(FrameVDeviceError::ReservedIrqLine) => "reserved FrameV IRQ line",
            Self::Device(FrameVDeviceError::RequiredDeviceMismatch { .. }) => {
                "required FrameV device mismatch"
            }
            Self::Device(FrameVDeviceError::Stopped) => "FrameV device runtime is stopped",
            Self::Device(FrameVDeviceError::UnexpectedDeviceCount { .. }) => {
                "unexpected FrameV device count"
            }
            Self::MissingDescriptor => "missing FrameV descriptor",
            Self::NotInitialized => "FrameV devices are not initialized",
            Self::RuntimeUnavailable => "FrameV runtime is unavailable",
        }
    }
}

impl From<FrameVDeviceError> for FrameVBusError {
    fn from(error: FrameVDeviceError) -> Self {
        Self::Device(error)
    }
}

/// A bound default FrameV console frontend handle.
#[derive(Clone, Copy)]
pub struct FrameVConsole {
    info: FrameVDeviceInfo,
}

impl FrameVConsole {
    const fn new(info: FrameVDeviceInfo) -> Self {
        Self { info }
    }

    /// Returns the descriptor-owned device ID.
    pub const fn id(&self) -> FrameVDeviceId {
        self.info.id
    }

    /// Writes bytes through the bound console backend.
    pub fn write(&self, input: &[u8]) -> Result<usize, FrameVBusError> {
        ostd::framev::console::write(input).map_err(|_| FrameVBusError::RuntimeUnavailable)
    }

    /// Registers a service-side input callback for the bound console backend.
    pub fn register_input_callback(&self, callback: fn(&[u8])) -> Result<(), FrameVBusError> {
        ostd::framev::console::register_input_callback(callback)
            .map_err(|_| FrameVBusError::RuntimeUnavailable)
    }
}

/// A bound default FrameV RNG frontend handle.
#[derive(Clone, Copy)]
pub struct FrameVRng {
    info: FrameVDeviceInfo,
}

impl FrameVRng {
    const fn new(info: FrameVDeviceInfo) -> Self {
        Self { info }
    }

    /// Returns the descriptor-owned device ID.
    pub const fn id(&self) -> FrameVDeviceId {
        self.info.id
    }

    /// Fills `dst` through the bound RNG backend.
    pub fn fill_bytes(&self, dst: &mut [u8]) -> Result<(), FrameVBusError> {
        ostd::framev::rng::fill_bytes(dst).map_err(|_| FrameVBusError::RuntimeUnavailable)
    }
}

/// A bound optional FrameV block frontend handle.
#[derive(Clone, Copy)]
pub struct FrameVBlock {
    info: FrameVDeviceInfo,
}

impl FrameVBlock {
    const fn new(info: FrameVDeviceInfo) -> Self {
        Self { info }
    }

    /// Returns the descriptor-owned device ID.
    pub const fn id(&self) -> FrameVDeviceId {
        self.info.id
    }

    /// Returns the backend-authoritative block configuration.
    pub fn config(&self) -> Result<FrameVBlkConfig, FrameVBusError> {
        ostd::framev::blk::current_block_config().map_err(|_| FrameVBusError::RuntimeUnavailable)
    }

    /// Reads one sector-aligned range from the block backend.
    pub fn read(&self, sector: u64, dst: &mut [u8]) -> Result<FrameVBlkStatus, FrameVBusError> {
        let header = FrameVBlkRequestHeader::new(FrameVBlkOp::Read, sector, dst.len() as u64);
        let resource = ostd::framev::blk::BlockRequestResource::ReadBuffer(
            OwnedResource::new(vec![0; dst.len()]).submit(),
        );
        let completion = ostd::framev::blk::submit_current_block_request(header, resource)
            .map_err(|_| FrameVBusError::RuntimeUnavailable)?;
        let status = *completion.info().payload();
        if status == FrameVBlkStatus::Ok {
            let Some(ostd::framev::blk::BlockReturnedResource::ReadBuffer(buffer)) =
                completion.into_resource()
            else {
                return Err(FrameVBusError::RuntimeUnavailable);
            };
            dst.copy_from_slice(&buffer.into_inner());
        }
        Ok(status)
    }

    /// Writes one sector-aligned range to the block backend.
    pub fn write(&self, sector: u64, src: &[u8]) -> Result<FrameVBlkStatus, FrameVBusError> {
        let header = FrameVBlkRequestHeader::new(FrameVBlkOp::Write, sector, src.len() as u64);
        let resource = ostd::framev::blk::BlockRequestResource::WriteBuffer(
            OwnedResource::new(src.to_vec()).submit(),
        );
        let completion = ostd::framev::blk::submit_current_block_request(header, resource)
            .map_err(|_| FrameVBusError::RuntimeUnavailable)?;
        Ok(*completion.info().payload())
    }

    /// Flushes durable block backend state.
    pub fn flush(&self) -> Result<FrameVBlkStatus, FrameVBusError> {
        let header = FrameVBlkRequestHeader::new(FrameVBlkOp::Flush, 0, 0);
        let completion = ostd::framev::blk::submit_current_block_request(
            header,
            ostd::framev::blk::BlockRequestResource::None,
        )
        .map_err(|_| FrameVBusError::RuntimeUnavailable)?;
        Ok(*completion.info().payload())
    }
}

/// A bound default FrameV Sock frontend handle.
#[derive(Clone, Copy)]
pub struct FrameVSock {
    info: FrameVDeviceInfo,
}

impl FrameVSock {
    const fn new(info: FrameVDeviceInfo) -> Self {
        Self { info }
    }

    /// Returns the descriptor-owned device ID.
    pub const fn id(&self) -> FrameVDeviceId {
        self.info.id
    }

    /// Marks this socket transport active in the FrameV runtime.
    pub fn activate(&self) {
        ostd::framev::sock::activate();
    }

    /// Installs the service-side RX notification callback for this socket transport.
    pub fn install_rx_callback(&self, callback: fn()) -> Result<(), FrameVBusError> {
        ostd::framev::sock::install_rx_callback(callback)
            .map_err(|_| FrameVBusError::RuntimeUnavailable)
    }

    /// Returns whether the socket transport is active.
    pub fn is_active(&self) -> bool {
        ostd::framev::sock::is_active()
    }

    /// Returns the number of socket queue pairs.
    pub fn queue_count(&self) -> usize {
        ostd::framev::sock::queue_count()
    }

    /// Returns the current service vCPU index.
    pub fn current_vcpu_index(&self) -> Option<usize> {
        ostd::framev::sock::current_vcpu_index()
    }

    /// Returns the service-visible guest CID.
    pub fn guest_cid(&self) -> Option<u64> {
        ostd::framev::sock::guest_cid()
    }

    /// Submits one packet to the backend transport.
    pub fn submit_packet(
        &self,
        queue_id: usize,
        packet: FrameVsockPacket,
    ) -> Result<(), FrameVsockPacket> {
        ostd::framev::sock::submit_packet(queue_id, packet)
    }

    /// Receives one packet from the selected socket queue.
    pub fn recv_packet(&self, queue_id: usize) -> Option<FrameVsockPacket> {
        ostd::framev::sock::recv_packet(queue_id)
    }
}

#[derive(Clone, Copy)]
struct FrameV {
    console: FrameVConsole,
    sock: FrameVSock,
    rng: FrameVRng,
    block: Option<FrameVBlock>,
}

impl FrameV {
    fn bind(descriptor: &FrameVDeviceDescriptor) -> Result<Self, FrameVBusError> {
        Ok(Self {
            console: FrameVConsole::new(default_device(descriptor, FrameVDeviceType::Console)?),
            sock: FrameVSock::new(default_device(descriptor, FrameVDeviceType::Sock)?),
            rng: FrameVRng::new(default_device(descriptor, FrameVDeviceType::Rng)?),
            block: optional_device(descriptor, FrameVDeviceType::Block)?.map(FrameVBlock::new),
        })
    }

    const fn console(&self) -> FrameVConsole {
        self.console
    }

    const fn rng(&self) -> FrameVRng {
        self.rng
    }

    const fn sock(&self) -> FrameVSock {
        self.sock
    }

    const fn block(&self) -> Option<FrameVBlock> {
        self.block
    }
}

#[init_component]
fn init() -> Result<(), ComponentInitError> {
    init_for_framevm_component_profile()
}

/// Initializes the FrameV bus component in the FrameVM component profile.
pub fn init_for_framevm_component_profile() -> Result<(), ComponentInitError> {
    init_descriptor().map_err(|_| ComponentInitError::Unknown)?;
    init_devices().map_err(|_| ComponentInitError::Unknown)?;

    Ok(())
}

/// Initializes the owned FrameV descriptor transferred by the backend.
pub fn init_descriptor() -> Result<(), FrameVBusError> {
    let value = ostd::framev::devices_boot_arg().ok_or(FrameVBusError::MissingDescriptor)?;
    let descriptor = FrameVDeviceDescriptor::decode_boot_arg(value).map_err(|err| {
        ostd::early_println!(
            "[kernel] critical error: invalid FrameV descriptor encoding: {}",
            err
        );
        FrameVBusError::from(err)
    })?;
    validate_default_descriptor(&descriptor, "descriptor initialization")?;

    DESCRIPTOR.call_once(|| descriptor);
    Ok(())
}

/// Binds all default FrameV frontend devices.
pub fn init_devices() -> Result<(), FrameVBusError> {
    let descriptor = descriptor()?;
    validate_default_descriptor(descriptor, "frontend device binding")?;
    let framev = FrameV::bind(descriptor)?;

    FRAMEV.call_once(|| framev);
    ostd::early_println!(
        "FrameV devices ready: console={:?}, rng={:?}, sock={:?}, block={:?}",
        framev.console.id(),
        framev.rng.id(),
        framev.sock.id(),
        framev.block.map(|block| block.id())
    );
    Ok(())
}

/// Returns the owned boot descriptor.
pub fn descriptor() -> Result<&'static FrameVDeviceDescriptor, FrameVBusError> {
    DESCRIPTOR.get().ok_or(FrameVBusError::NotInitialized)
}

/// Returns the bound default `framev-console` frontend.
pub fn console() -> Result<FrameVConsole, FrameVBusError> {
    Ok(framev()?.console())
}

/// Returns the bound default `framev-rng` frontend.
pub fn rng() -> Result<FrameVRng, FrameVBusError> {
    Ok(framev()?.rng())
}

/// Returns the bound default `framev-sock` frontend.
pub fn sock() -> Result<FrameVSock, FrameVBusError> {
    Ok(framev()?.sock())
}

/// Returns the bound optional `framev-blk` frontend, if present.
pub fn block() -> Result<Option<FrameVBlock>, FrameVBusError> {
    Ok(framev()?.block())
}

fn framev() -> Result<&'static FrameV, FrameVBusError> {
    FRAMEV.get().ok_or(FrameVBusError::NotInitialized)
}

fn default_devices() -> Vec<FrameVDeviceInfo> {
    Vec::from([
        framev_console_common::default_device_info(),
        framev_sock_common::default_device_info(),
        framev_rng_common::default_device_info(),
    ])
}

fn default_device(
    descriptor: &FrameVDeviceDescriptor,
    device_type: FrameVDeviceType,
) -> Result<FrameVDeviceInfo, FrameVBusError> {
    descriptor
        .devices()
        .iter()
        .copied()
        .find(|device| device.device_type == device_type)
        .ok_or(FrameVBusError::Device(
            FrameVDeviceError::MissingRequiredDevice(device_type),
        ))
}

fn optional_device(
    descriptor: &FrameVDeviceDescriptor,
    device_type: FrameVDeviceType,
) -> Result<Option<FrameVDeviceInfo>, FrameVBusError> {
    let mut matches = descriptor
        .devices()
        .iter()
        .copied()
        .filter(|device| device.device_type == device_type);
    let first = matches.next();
    if matches.next().is_some() {
        return Err(FrameVBusError::Device(
            FrameVDeviceError::UnexpectedDeviceCount {
                expected: default_devices().len() + 1,
                actual: descriptor.devices().len(),
            },
        ));
    }
    Ok(first)
}

fn validate_default_descriptor(
    descriptor: &FrameVDeviceDescriptor,
    context: &'static str,
) -> Result<(), FrameVBusError> {
    validate_default_descriptor_shape(descriptor).map_err(|err| {
        ostd::early_println!(
            "[kernel] critical error: invalid default FrameV devices during {}: {}",
            context,
            err
        );
        FrameVBusError::from(err)
    })
}

fn validate_default_descriptor_shape(
    descriptor: &FrameVDeviceDescriptor,
) -> Result<(), FrameVDeviceError> {
    for required_device in default_devices() {
        let Some(actual_device) = descriptor
            .devices()
            .iter()
            .copied()
            .find(|device| device.id == required_device.id)
        else {
            return Err(FrameVDeviceError::MissingRequiredDevice(
                required_device.device_type,
            ));
        };
        if actual_device != required_device {
            return Err(FrameVDeviceError::RequiredDeviceMismatch {
                expected: required_device,
                actual: actual_device,
            });
        }
        if descriptor
            .devices()
            .iter()
            .filter(|device| device.device_type == required_device.device_type)
            .count()
            > 1
        {
            return Err(FrameVDeviceError::DuplicateRequiredDevice(
                required_device.device_type,
            ));
        }
    }

    let mut block_count = 0;
    for device in descriptor.devices() {
        match device.device_type {
            FrameVDeviceType::Console | FrameVDeviceType::Sock | FrameVDeviceType::Rng => {}
            FrameVDeviceType::Block => block_count += 1,
            _ => {
                return Err(FrameVDeviceError::UnexpectedDeviceCount {
                    expected: default_devices().len() + block_count,
                    actual: descriptor.devices().len(),
                });
            }
        }
    }
    if block_count > 1 {
        return Err(FrameVDeviceError::UnexpectedDeviceCount {
            expected: default_devices().len() + 1,
            actual: descriptor.devices().len(),
        });
    }
    let expected = default_devices().len() + block_count;
    if descriptor.devices().len() != expected {
        return Err(FrameVDeviceError::UnexpectedDeviceCount {
            expected,
            actual: descriptor.devices().len(),
        });
    }
    Ok(())
}
