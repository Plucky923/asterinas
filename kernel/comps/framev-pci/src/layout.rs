// SPDX-License-Identifier: MPL-2.0

//! Checked FrameV PCI BAR and MSI-X layout.

use crate::FrameVFunctionFamily;

/// An invalid FrameV PCI BAR layout request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutError {
    /// The vector count does not match the family contract.
    InvalidVectorCount,
    /// Layout arithmetic overflowed.
    Overflow,
}

/// The exact revision-1 BAR0 layout for one FrameV function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameVPciLayout {
    vector_count: u16,
    table_offset_bytes: Option<usize>,
    pba_offset_bytes: Option<usize>,
    bar_size_bytes: usize,
}

impl FrameVPciLayout {
    /// Creates a checked layout for `family` and its immutable vector count.
    pub fn new(family: FrameVFunctionFamily, vector_count: u16) -> Result<Self, LayoutError> {
        validate_vector_count(family, vector_count)?;

        let family_config_size = family.config_size_bytes();
        if vector_count == 0 {
            return Ok(Self {
                vector_count,
                table_offset_bytes: None,
                pba_offset_bytes: None,
                bar_size_bytes: family_config_size,
            });
        }

        let table_offset = align_up(family_config_size, 16)?;
        let table_size = usize::from(vector_count)
            .checked_mul(16)
            .ok_or(LayoutError::Overflow)?;
        let table_end = table_offset
            .checked_add(table_size)
            .ok_or(LayoutError::Overflow)?;
        let pba_offset = align_up(table_end, 8)?;
        let pba_words = usize::from(vector_count)
            .checked_add(63)
            .ok_or(LayoutError::Overflow)?
            / 64;
        let pba_size = pba_words.checked_mul(8).ok_or(LayoutError::Overflow)?;
        let used_size = pba_offset
            .checked_add(pba_size)
            .ok_or(LayoutError::Overflow)?;
        let bar_size = used_size
            .checked_next_power_of_two()
            .ok_or(LayoutError::Overflow)?
            .max(16);

        Ok(Self {
            vector_count,
            table_offset_bytes: Some(table_offset),
            pba_offset_bytes: Some(pba_offset),
            bar_size_bytes: bar_size,
        })
    }

    /// Returns the MSI-X vector count.
    pub const fn vector_count(self) -> u16 {
        self.vector_count
    }

    /// Returns the MSI-X table offset in bytes when present.
    pub const fn table_offset_bytes(self) -> Option<usize> {
        self.table_offset_bytes
    }

    /// Returns the MSI-X PBA offset in bytes when present.
    pub const fn pba_offset_bytes(self) -> Option<usize> {
        self.pba_offset_bytes
    }

    /// Returns the required BAR aperture size in bytes.
    pub const fn bar_size_bytes(self) -> usize {
        self.bar_size_bytes
    }
}

fn validate_vector_count(
    family: FrameVFunctionFamily,
    vector_count: u16,
) -> Result<(), LayoutError> {
    let is_valid = match family {
        FrameVFunctionFamily::Console | FrameVFunctionFamily::Net => vector_count == 1,
        FrameVFunctionFamily::Sock => (2..=5).contains(&vector_count),
        FrameVFunctionFamily::Rng | FrameVFunctionFamily::Block => vector_count == 0,
    };
    if !is_valid {
        return Err(LayoutError::InvalidVectorCount);
    }
    Ok(())
}

fn align_up(value: usize, alignment: usize) -> Result<usize, LayoutError> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(LayoutError::Overflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alignment_overflow_is_rejected() {
        assert_eq!(align_up(usize::MAX, 16), Err(LayoutError::Overflow));
    }
}
