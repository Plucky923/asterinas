// SPDX-License-Identifier: MPL-2.0

//! Local TSC conversion using an immutable Host-boot clock calibration.
//!
//! Host service deadlines and image time readers use the same origin. Each
//! side owns its monotonic watermark; neither needs a periodically written page.

use core::sync::atomic::{AtomicU64, Ordering};

/// Converts a TSC sample and retains the largest value observed by this clock.
///
/// The caller supplies a validated nonzero frequency. The watermark prevents
/// regressions across CPU migration; elapsed-time accuracy still requires a
/// stable frequency and synchronized TSCs on the configured Host CPUs.
#[cfg_attr(not(feature = "kernelet"), allow(dead_code))]
pub(super) fn monotonic_ns_at(
    tsc: u64,
    origin_tsc: u64,
    tsc_freq_hz: u64,
    latest: &AtomicU64,
) -> u64 {
    debug_assert_ne!(tsc_freq_hz, 0);
    let cycles = tsc.saturating_sub(origin_tsc);
    let nanos = (u128::from(cycles) * 1_000_000_000 / u128::from(tsc_freq_hz))
        .min(u128::from(u64::MAX)) as u64;
    latest.fetch_max(nanos, Ordering::Relaxed).max(nanos)
}

#[cfg(ktest)]
mod test {
    use super::*;
    use crate::prelude::*;

    #[ktest]
    fn local_clock_advances_without_publication_and_never_regresses() {
        let latest = AtomicU64::new(0);
        assert_eq!(monotonic_ns_at(90, 100, 1_000_000_000, &latest), 0);
        assert_eq!(monotonic_ns_at(110, 100, 1_000_000_000, &latest), 10);
        assert_eq!(monotonic_ns_at(105, 100, 1_000_000_000, &latest), 10);
        assert_eq!(monotonic_ns_at(130, 100, 1_000_000_000, &latest), 30);
    }

    #[ktest]
    fn local_clock_rounds_fractional_cycles_and_saturates() {
        let latest = AtomicU64::new(0);
        assert_eq!(monotonic_ns_at(101, 100, 3_000_000_000, &latest), 0);
        assert_eq!(monotonic_ns_at(103, 100, 3_000_000_000, &latest), 1);
        assert_eq!(monotonic_ns_at(u64::MAX, 0, 1, &latest), u64::MAX);
        assert_eq!(monotonic_ns_at(0, 0, 1, &latest), u64::MAX);
    }
}
