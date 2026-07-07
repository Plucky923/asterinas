//! FrameV device descriptor metadata.
//!
//! This module defines device IDs, device types, IRQ lines, boot descriptor
//! encoding, and fixed well-known device identities.

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::fmt::Write;

use crate::error::{FrameVDeviceError, Result};

/// A FrameV device ID local to one FrameVM.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FrameVDeviceId(u64);

impl FrameVDeviceId {
    /// Creates a FrameV device ID.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the raw FrameV device ID.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// A FrameV device type.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FrameVDeviceType {
    Block,
    Console,
    Net,
    Rng,
    Sock,
}

impl FrameVDeviceType {
    /// Returns the fixed well-known device ID for this device type.
    pub const fn well_known_id(self) -> FrameVDeviceId {
        match self {
            Self::Console => well_known::DEFAULT_CONSOLE_DEVICE_ID,
            Self::Sock => well_known::DEFAULT_SOCK_DEVICE_ID,
            Self::Rng => well_known::DEFAULT_RNG_DEVICE_ID,
            Self::Block => well_known::DEFAULT_BLOCK_DEVICE_ID,
            Self::Net => well_known::DEFAULT_NET_DEVICE_ID,
        }
    }
}

impl FrameVDeviceType {
    /// Returns the stable boot metadata name.
    pub const fn boot_name(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Console => "console",
            Self::Net => "net",
            Self::Rng => "rng",
            Self::Sock => "sock",
        }
    }

    /// Parses a stable boot metadata name.
    pub fn parse_boot_name(name: &str) -> Result<Self> {
        match name {
            "block" => Ok(Self::Block),
            "console" => Ok(Self::Console),
            "net" => Ok(Self::Net),
            "rng" => Ok(Self::Rng),
            "sock" => Ok(Self::Sock),
            _ => Err(FrameVDeviceError::InvalidDeviceType),
        }
    }
}

/// A FrameV software IRQ line local to one FrameVM.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IrqLine(u16);

impl IrqLine {
    /// The reserved raw IRQ line number.
    pub const RESERVED_RAW: u16 = 0;

    /// Creates an IRQ line for well-known constants.
    pub const fn new(line: u16) -> Self {
        Self(line)
    }

    /// Parses a runtime-provided IRQ line.
    pub fn parse(raw: u16) -> core::result::Result<Self, InvalidIrqLine> {
        if raw == Self::RESERVED_RAW {
            return Err(InvalidIrqLine);
        }
        Ok(Self(raw))
    }

    /// Returns the raw IRQ line number.
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Returns whether the IRQ line is reserved.
    pub const fn is_reserved(self) -> bool {
        self.0 == Self::RESERVED_RAW
    }
}

/// An error returned when parsing an IRQ line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidIrqLine;

/// Metadata for one FrameV device instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameVDeviceInfo {
    pub id: FrameVDeviceId,
    pub device_type: FrameVDeviceType,
    pub irq_line: IrqLine,
}

impl FrameVDeviceInfo {
    /// Creates FrameV device metadata.
    pub const fn new(id: FrameVDeviceId, device_type: FrameVDeviceType, irq_line: IrqLine) -> Self {
        Self {
            id,
            device_type,
            irq_line,
        }
    }

    /// Validates FrameV device metadata.
    pub fn validate(self) -> Result<()> {
        if self.irq_line.is_reserved() {
            return Err(FrameVDeviceError::ReservedIrqLine);
        }
        Ok(())
    }
}

/// A boot-time snapshot of FrameV device metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrameVDeviceDescriptor {
    devices: Vec<FrameVDeviceInfo>,
}

impl FrameVDeviceDescriptor {
    /// Creates a validated FrameV device descriptor.
    pub fn new(devices: Vec<FrameVDeviceInfo>) -> Result<Self> {
        for (index, device) in devices.iter().copied().enumerate() {
            device.validate()?;

            for existing in &devices[..index] {
                if existing.id == device.id {
                    return Err(FrameVDeviceError::DuplicateDeviceId(device.id));
                }
                if existing.irq_line == device.irq_line {
                    return Err(FrameVDeviceError::DuplicateIrqLine(device.irq_line));
                }
            }
        }

        Ok(Self { devices })
    }

    /// Returns the FrameV devices in stable descriptor order.
    pub fn devices(&self) -> &[FrameVDeviceInfo] {
        &self.devices
    }

    /// Finds a FrameV device by ID.
    pub fn find_by_id(&self, id: FrameVDeviceId) -> Option<&FrameVDeviceInfo> {
        self.devices.iter().find(|device| device.id == id)
    }

    /// Encodes this descriptor as a boot metadata value.
    pub fn encode_boot_arg(&self) -> String {
        let mut output = String::new();
        for (index, device) in self.devices.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }

            let _ = write!(
                output,
                "{}:{}:{}",
                device.id.raw(),
                device.device_type.boot_name(),
                device.irq_line.raw()
            );
        }
        output
    }

    /// Decodes a descriptor from a boot metadata value.
    pub fn decode_boot_arg(value: &str) -> Result<Self> {
        if value.is_empty() {
            return Err(FrameVDeviceError::InvalidDescriptorEncoding);
        }

        let mut devices = Vec::new();
        for entry in value.split(',') {
            devices.push(parse_boot_device_entry(entry)?);
        }
        Self::new(devices)
    }

    /// Validates that this descriptor exactly matches a required device set.
    pub fn validate_required_exact(&self, required: &[FrameVDeviceInfo]) -> Result<()> {
        if self.devices.len() != required.len() {
            return Err(FrameVDeviceError::UnexpectedDeviceCount {
                expected: required.len(),
                actual: self.devices.len(),
            });
        }

        for required_device in required {
            debug_assert_eq!(
                required_device.id,
                required_device.device_type.well_known_id()
            );

            let Some(actual_device) = self.find_by_id(required_device.id).copied() else {
                return Err(FrameVDeviceError::MissingRequiredDevice(
                    required_device.device_type,
                ));
            };
            if self
                .devices
                .iter()
                .filter(|device| device.device_type == required_device.device_type)
                .count()
                > 1
            {
                return Err(FrameVDeviceError::DuplicateRequiredDevice(
                    required_device.device_type,
                ));
            }
            if actual_device != *required_device {
                return Err(FrameVDeviceError::RequiredDeviceMismatch {
                    expected: *required_device,
                    actual: actual_device,
                });
            }
        }

        Ok(())
    }
}

fn parse_boot_device_entry(entry: &str) -> Result<FrameVDeviceInfo> {
    let mut parts = entry.split(':');
    let id = parse_u64(parts.next())?;
    let device_type = FrameVDeviceType::parse_boot_name(
        parts
            .next()
            .ok_or(FrameVDeviceError::InvalidDescriptorEncoding)?,
    )?;
    let irq_line = parse_u16(parts.next())?;
    if parts.next().is_some() {
        return Err(FrameVDeviceError::InvalidDescriptorEncoding);
    }

    Ok(FrameVDeviceInfo::new(
        FrameVDeviceId::new(id),
        device_type,
        IrqLine::parse(irq_line).map_err(|_| FrameVDeviceError::InvalidDescriptorEncoding)?,
    ))
}

fn parse_u16(value: Option<&str>) -> Result<u16> {
    let value = parse_u64(value)?;
    u16::try_from(value).map_err(|_| FrameVDeviceError::InvalidDescriptorEncoding)
}

fn parse_u64(value: Option<&str>) -> Result<u64> {
    value
        .ok_or(FrameVDeviceError::InvalidDescriptorEncoding)?
        .parse()
        .map_err(|_| FrameVDeviceError::InvalidDescriptorEncoding)
}

/// Well-known FrameV device identities.
pub mod well_known {
    use super::FrameVDeviceId;

    /// The default `framev-console` device ID.
    pub const DEFAULT_CONSOLE_DEVICE_ID: FrameVDeviceId = FrameVDeviceId::new(1);

    /// The default `framev-sock` device ID.
    pub const DEFAULT_SOCK_DEVICE_ID: FrameVDeviceId = FrameVDeviceId::new(2);

    /// The default `framev-rng` device ID.
    pub const DEFAULT_RNG_DEVICE_ID: FrameVDeviceId = FrameVDeviceId::new(3);

    /// The default `framev-block` device ID.
    pub const DEFAULT_BLOCK_DEVICE_ID: FrameVDeviceId = FrameVDeviceId::new(4);

    /// The default `framev-net` device ID.
    pub const DEFAULT_NET_DEVICE_ID: FrameVDeviceId = FrameVDeviceId::new(5);
}
