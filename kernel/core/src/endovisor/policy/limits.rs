// SPDX-License-Identifier: MPL-2.0

//! Operator-selected per-user memory reservation limit.

use core::str::FromStr;

use aster_cmdline::parse::ParamError;
use spin::Once;

// The default remains 1 GiB, including Guest ceilings and Host storage.
const GRAIN_MIB: u32 = (ostd::kernelet::abi::GRAIN_SIZE / (1024 * 1024)) as u32;
const DEFAULT_GRAINS: u32 = 1024 / GRAIN_MIB;
static USER_MEMORY_LIMIT: Once<UserMemoryLimit> = Once::new();
aster_cmdline::define_kv_param!("kernelet_user_memory_mib", USER_MEMORY_LIMIT);

struct UserMemoryLimit(u32);

impl FromStr for UserMemoryLimit {
    type Err = ParamError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mib: u32 = value.parse().map_err(|_| ParamError::InvalidValue)?;
        if mib < GRAIN_MIB || !mib.is_multiple_of(GRAIN_MIB) {
            return Err(ParamError::InvalidValue);
        }
        Ok(Self(mib / GRAIN_MIB))
    }
}

pub(super) fn max_grains_per_user() -> u32 {
    USER_MEMORY_LIMIT
        .get()
        .map_or(DEFAULT_GRAINS, |limit| limit.0)
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn user_memory_limit_covers_large_guest_and_execution_reservations() {
        let limit: UserMemoryLimit = "4096".parse().ok().unwrap();
        let host = ostd::kernelet::control::execution_reservation_bytes(4096, 1).unwrap();
        let host_grains = host.div_ceil(ostd::kernelet::abi::GRAIN_SIZE);
        assert!(1024 + host_grains < limit.0 as usize);
        assert_eq!(
            "1024".parse::<UserMemoryLimit>().ok().unwrap().0,
            DEFAULT_GRAINS
        );
    }

    #[ktest]
    fn user_memory_limit_rejects_partial_grains_and_invalid_values() {
        for value in ["0", "1", "4095", "-2", "4294967296", "4G", ""] {
            assert!(value.parse::<UserMemoryLimit>().is_err());
        }
    }
}
