// SPDX-License-Identifier: MPL-2.0

//! FrameVM scheduler share policy.

use crate::{error::Error, prelude::Result};

/// Default CPU share for a FrameVM scheduling group.
pub const DEFAULT_FRAMEVM_SHARE: u32 = 1024;

/// Minimum accepted FrameVM scheduling group share.
pub const MIN_FRAMEVM_SHARE: u32 = 2;

/// Maximum accepted FrameVM scheduling group share.
pub const MAX_FRAMEVM_SHARE: u32 = 262_144;

/// Validates a FrameVM scheduling group CPU share.
pub fn validate_framevm_share(share: u32) -> Result<()> {
    if (MIN_FRAMEVM_SHARE..=MAX_FRAMEVM_SHARE).contains(&share) {
        Ok(())
    } else {
        Err(Error::InvalidArgs)
    }
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn share_validation_rejects_out_of_range_values() {
        assert!(validate_framevm_share(MIN_FRAMEVM_SHARE).is_ok());
        assert!(validate_framevm_share(MAX_FRAMEVM_SHARE).is_ok());
        assert!(validate_framevm_share(MIN_FRAMEVM_SHARE - 1).is_err());
        assert!(validate_framevm_share(MAX_FRAMEVM_SHARE + 1).is_err());
    }
}
