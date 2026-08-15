// SPDX-License-Identifier: MPL-2.0

//! FrameV PCI function identity.

/// Prototype-only FrameV PCI vendor ID.
pub const FRAMEV_PCI_VENDOR_ID: u16 = 0xa57e;

/// Exact FrameV PCI layout revision.
pub const FRAMEV_PCI_REVISION: u8 = 1;

/// Vendor-specific PCI class code.
pub const FRAMEV_PCI_CLASS: u8 = 0xff;

/// FrameV PCI subclass code.
pub const FRAMEV_PCI_SUBCLASS: u8 = 0;

/// FrameV PCI programming interface.
pub const FRAMEV_PCI_PROGRAMMING_INTERFACE: u8 = 0;

/// A closed FrameV PCI function family.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum FrameVFunctionFamily {
    /// Console function.
    Console = 0x0001,
    /// Socket function.
    Sock = 0x0002,
    /// Entropy function.
    Rng = 0x0003,
    /// Block function.
    Block = 0x0004,
    /// Ethernet function.
    Net = 0x0005,
}

/// A mismatch in the exact FrameV PCI function identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// The vendor ID does not identify the private FrameV family.
    UnknownVendor,
    /// The device ID does not identify a known FrameV family.
    UnknownDevice,
    /// The frontend and backend layout revisions differ.
    UnsupportedRevision,
    /// The PCI class tuple does not match revision 1.
    InvalidClass,
}

/// A validated revision-1 FrameV PCI identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameVPciIdentity {
    family: FrameVFunctionFamily,
}

impl FrameVPciIdentity {
    /// Decodes and validates an exact revision-1 PCI identity tuple.
    pub const fn decode(
        vendor_id: u16,
        device_id: u16,
        revision: u8,
        class: u8,
        subclass: u8,
        programming_interface: u8,
    ) -> Result<Self, IdentityError> {
        if vendor_id != FRAMEV_PCI_VENDOR_ID {
            return Err(IdentityError::UnknownVendor);
        }
        let Some(family) = FrameVFunctionFamily::from_device_id(device_id) else {
            return Err(IdentityError::UnknownDevice);
        };
        if revision != FRAMEV_PCI_REVISION {
            return Err(IdentityError::UnsupportedRevision);
        }
        if class != FRAMEV_PCI_CLASS
            || subclass != FRAMEV_PCI_SUBCLASS
            || programming_interface != FRAMEV_PCI_PROGRAMMING_INTERFACE
        {
            return Err(IdentityError::InvalidClass);
        }
        Ok(Self { family })
    }

    /// Returns the validated function family.
    pub const fn family(self) -> FrameVFunctionFamily {
        self.family
    }
}

impl FrameVFunctionFamily {
    /// Decodes a FrameV PCI device ID.
    pub const fn from_device_id(device_id: u16) -> Option<Self> {
        match device_id {
            0x0001 => Some(Self::Console),
            0x0002 => Some(Self::Sock),
            0x0003 => Some(Self::Rng),
            0x0004 => Some(Self::Block),
            0x0005 => Some(Self::Net),
            _ => None,
        }
    }

    /// Returns the exact PCI device ID.
    pub const fn device_id(self) -> u16 {
        self as u16
    }

    /// Returns the immutable family configuration size in bytes.
    pub const fn config_size_bytes(self) -> usize {
        match self {
            Self::Console | Self::Rng | Self::Net => 0x10,
            Self::Sock | Self::Block => 0x20,
        }
    }

    /// Returns whether this family exposes Host-initiated events.
    pub const fn has_msix(self) -> bool {
        matches!(self, Self::Console | Self::Sock | Self::Net)
    }

    /// Returns the deterministic topology family order.
    pub const fn topology_order(self) -> u8 {
        match self {
            Self::Console => 0,
            Self::Rng => 1,
            Self::Block => 2,
            Self::Sock => 3,
            Self::Net => 4,
        }
    }
}
