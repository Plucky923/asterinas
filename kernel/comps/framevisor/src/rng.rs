// SPDX-License-Identifier: MPL-2.0

//! FrameV RNG backend.

use framev_pci_common::FrameVFunctionFamily;

use crate::{Error, Result, task};

/// Fills `dst` through the current FrameVM's required RNG backend.
#[inline(never)]
pub fn fill_bytes(dst: &mut [u8]) -> Result<()> {
    task::current_frame_vm()
        .ok_or(Error::InvalidArgs)?
        .devices()
        .rng()
        .fill_bytes(dst)
}

/// Fills `dst` through one claimed RNG PCI function.
#[inline(never)]
pub fn fill_bytes_claimed(claim: &crate::device::FunctionClaim, dst: &mut [u8]) -> Result<()> {
    let _call = claim.enter(FrameVFunctionFamily::Rng)?;
    task::current_frame_vm()
        .ok_or(Error::InvalidArgs)?
        .devices()
        .rng()
        .fill_bytes(dst)
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn service_shim_fails_without_current_vm_context() {
        let mut bytes = [0u8; 8];

        assert_eq!(fill_bytes(&mut bytes), Err(Error::InvalidArgs));
    }
}
