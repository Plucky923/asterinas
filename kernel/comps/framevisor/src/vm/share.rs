// SPDX-License-Identifier: MPL-2.0

//! FrameVM scheduler share helpers.

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

/// Converts a CFS-style share into the closest host `nice` hint.
pub fn share_to_nice_hint(share: u32) -> i8 {
    let share = share.clamp(MIN_FRAMEVM_SHARE, MAX_FRAMEVM_SHARE);

    if share == DEFAULT_FRAMEVM_SHARE {
        return 0;
    }

    if share > DEFAULT_FRAMEVM_SHARE {
        share_to_negative_nice_hint(share)
    } else {
        share_to_positive_nice_hint(share)
    }
}

fn share_to_negative_nice_hint(share: u32) -> i8 {
    let mut nice = 0i8;
    let mut threshold = DEFAULT_FRAMEVM_SHARE;
    while nice > -20 && threshold < share {
        threshold = threshold.saturating_mul(5).saturating_add(3) / 4;
        nice -= 1;
    }
    nice
}

fn share_to_positive_nice_hint(share: u32) -> i8 {
    let mut nice = 0i8;
    let mut threshold = DEFAULT_FRAMEVM_SHARE;
    while nice < 19 && share < threshold {
        threshold = threshold.saturating_mul(4) / 5;
        nice += 1;
    }
    nice
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn default_share_maps_to_default_nice() {
        assert_eq!(share_to_nice_hint(DEFAULT_FRAMEVM_SHARE), 0);
    }

    #[ktest]
    fn share_mapping_preserves_priority_direction() {
        assert!(share_to_nice_hint(DEFAULT_FRAMEVM_SHARE * 2) < 0);
        assert!(share_to_nice_hint(DEFAULT_FRAMEVM_SHARE / 2) > 0);
    }

    #[ktest]
    fn share_validation_rejects_out_of_range_values() {
        assert!(validate_framevm_share(MIN_FRAMEVM_SHARE).is_ok());
        assert!(validate_framevm_share(MAX_FRAMEVM_SHARE).is_ok());
        assert!(validate_framevm_share(MIN_FRAMEVM_SHARE - 1).is_err());
        assert!(validate_framevm_share(MAX_FRAMEVM_SHARE + 1).is_err());
    }
}
