// SPDX-License-Identifier: MPL-2.0

//! Deterministic FrameV virtual PCI topology allocation.

use alloc::vec::Vec;

use crate::FrameVFunctionFamily;

/// One validated PCI bus/device/function address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VirtualPciBdf {
    bus: u8,
    device: u8,
    function: u8,
}

impl VirtualPciBdf {
    /// Creates a validated PCI BDF.
    pub const fn new(bus: u8, device: u8, function: u8) -> Result<Self, TopologyError> {
        if device > 31 || function > 7 {
            return Err(TopologyError::InvalidBdf);
        }
        Ok(Self {
            bus,
            device,
            function,
        })
    }

    /// Returns the bus number.
    pub const fn bus(self) -> u8 {
        self.bus
    }

    /// Returns the device number.
    pub const fn device(self) -> u8 {
        self.device
    }

    /// Returns the function number.
    pub const fn function(self) -> u8 {
        self.function
    }
}

/// One synthetic function before virtual BDF allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticFunction {
    /// FrameV family identity.
    pub family: FrameVFunctionFamily,
    /// Stable identity within one family.
    pub stable_id: u64,
}

/// One assigned physical function before virtual BDF allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssignedFunction {
    /// Private physical BDF used only for deterministic ordering.
    pub physical_bdf: VirtualPciBdf,
}

/// A function participating in deterministic topology allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TopologyFunction {
    /// A synthetic FrameV function.
    Synthetic(SyntheticFunction),
    /// An assigned physical function.
    Assigned(AssignedFunction),
}

/// A virtual PCI topology allocation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TopologyError {
    /// A BDF exceeds the PCI field width.
    InvalidBdf,
    /// Revision 1 has no free single-function slot.
    TooManyFunctions,
    /// Two synthetic functions have the same family-local stable identity.
    DuplicateSyntheticIdentity,
    /// One physical BDF was assigned more than once.
    DuplicatePhysicalBdf,
}

/// Allocates revision-1 virtual BDFs in deterministic ABI order.
pub fn allocate_topology(
    functions: &mut [TopologyFunction],
) -> Result<Vec<(VirtualPciBdf, TopologyFunction)>, TopologyError> {
    if functions.len() > 31 {
        return Err(TopologyError::TooManyFunctions);
    }
    validate_unique(functions)?;
    functions.sort_unstable_by_key(ordering_key);

    functions
        .iter()
        .copied()
        .enumerate()
        .map(|(index, function)| {
            let device = u8::try_from(index + 1).map_err(|_| TopologyError::TooManyFunctions)?;
            Ok((VirtualPciBdf::new(0, device, 0)?, function))
        })
        .collect()
}

fn ordering_key(function: &TopologyFunction) -> (u8, u64, u32) {
    match function {
        TopologyFunction::Synthetic(function) => {
            (function.family.topology_order(), function.stable_id, 0)
        }
        TopologyFunction::Assigned(function) => (5, 0, encode_bdf(function.physical_bdf)),
    }
}

fn validate_unique(functions: &[TopologyFunction]) -> Result<(), TopologyError> {
    for (index, function) in functions.iter().enumerate() {
        for existing in &functions[..index] {
            match (function, existing) {
                (TopologyFunction::Synthetic(left), TopologyFunction::Synthetic(right))
                    if left.family == right.family && left.stable_id == right.stable_id =>
                {
                    return Err(TopologyError::DuplicateSyntheticIdentity);
                }
                (TopologyFunction::Assigned(left), TopologyFunction::Assigned(right))
                    if left.physical_bdf == right.physical_bdf =>
                {
                    return Err(TopologyError::DuplicatePhysicalBdf);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn encode_bdf(bdf: VirtualPciBdf) -> u32 {
    (u32::from(bdf.bus()) << 8) | (u32::from(bdf.device()) << 3) | u32::from(bdf.function())
}
