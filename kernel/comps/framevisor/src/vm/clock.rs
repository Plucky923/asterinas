// SPDX-License-Identifier: MPL-2.0

//! VM-local virtual clock.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::timer::TIMER_FREQ;

/// A VM-wide clocksource fed by virtual timer accounting.
pub(crate) struct VmClock {
    base_tsc: AtomicU64,
    latest_tsc: AtomicU64,
    frequency_hz: u64,
}

impl VmClock {
    /// Creates a clock anchored to the current architecture counter.
    pub(crate) fn new() -> Self {
        Self::new_at(crate::arch::read_tsc(), crate::arch::tsc_freq())
    }

    pub(crate) fn new_at(base_tsc: u64, frequency_hz: u64) -> Self {
        Self {
            base_tsc: AtomicU64::new(base_tsc),
            latest_tsc: AtomicU64::new(base_tsc),
            frequency_hz,
        }
    }

    /// Records a virtual timer deadline observed for this VM.
    pub(crate) fn record_deadline(&self, deadline_tsc: u64) {
        self.latest_tsc.fetch_max(deadline_tsc, Ordering::AcqRel);
    }

    /// Returns elapsed jiffies from the VM-wide virtual timer timebase.
    pub(crate) fn elapsed_jiffies(&self) -> u64 {
        if self.frequency_hz == 0 {
            return 0;
        }

        let base_tsc = self.base_tsc.load(Ordering::Acquire);
        let latest_tsc = self.latest_tsc.load(Ordering::Acquire);
        cycles_to_jiffies(latest_tsc.saturating_sub(base_tsc), self.frequency_hz)
    }

    /// Re-anchors the clock to the current architecture counter.
    pub(crate) fn reset(&self) {
        let base_tsc = crate::arch::read_tsc();
        self.base_tsc.store(base_tsc, Ordering::Release);
        self.latest_tsc.store(base_tsc, Ordering::Release);
    }
}

fn cycles_to_jiffies(cycles: u64, frequency_hz: u64) -> u64 {
    if frequency_hz == 0 {
        return 0;
    }

    let jiffies = (cycles as u128).saturating_mul(TIMER_FREQ as u128) / frequency_hz as u128;
    jiffies.min(u64::MAX as u128) as u64
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn converts_cycles_to_timer_freq_jiffies() {
        assert_eq!(cycles_to_jiffies(1_500_000, 1_000_000), 1_500);
    }

    #[ktest]
    fn clocks_advance_independently() {
        let first = VmClock::new_at(10_000, 1_000);
        let second = VmClock::new_at(20_000, 1_000);

        first.record_deadline(11_000);
        second.record_deadline(23_000);
        assert_eq!(first.elapsed_jiffies(), 1_000);
        assert_eq!(second.elapsed_jiffies(), 3_000);

        first.record_deadline(12_000);
        assert_eq!(first.elapsed_jiffies(), 2_000);
        assert_eq!(second.elapsed_jiffies(), 3_000);
    }

    #[ktest]
    fn zero_frequency_returns_zero() {
        assert_eq!(cycles_to_jiffies(1_500_000, 0), 0);
    }

    #[ktest]
    fn conversion_saturates() {
        assert_eq!(cycles_to_jiffies(u64::MAX, 1), u64::MAX);
    }

    #[ktest]
    fn latest_deadline_wins() {
        let clock = VmClock::new_at(1_000, 1_000);

        clock.record_deadline(2_500);
        assert_eq!(clock.elapsed_jiffies(), 1_500);

        clock.record_deadline(1_500);
        assert_eq!(clock.elapsed_jiffies(), 1_500);
    }
}
