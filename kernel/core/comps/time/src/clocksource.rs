// SPDX-License-Identifier: MPL-2.0

//! Monotonic counter conversion used by the Host time component and vDSO.

use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use aster_util::coeff::Coeff;
use ostd::{
    arch::read_tsc,
    sync::{LocalIrqDisabled, RwLock},
};

const NANOS_PER_SECOND: u32 = 1_000_000_000;
const MAX_DELAY_SECS: u64 = 100;

/// Converts the TSC counter into monotonic [`Duration`] values.
///
/// The recorded point is refreshed by the timer path. A bounded conversion
/// keeps a delayed refresh from overflowing the conversion coefficient.
pub struct ClockSource {
    max_cycles: u64,
    coeff: Coeff,
    /// A calibration point and the corresponding TSC value.
    last_record: RwLock<(Duration, u64), LocalIrqDisabled>,
    unreliable_warning_reported: AtomicBool,
}

impl ClockSource {
    /// Creates the TSC clock source.
    pub(crate) fn new(freq: u64) -> Self {
        let max_cycles = MAX_DELAY_SECS.saturating_mul(freq);
        // Too big `max_delay_secs` will lead to a low resolution `Coeff`.
        debug_assert!(MAX_DELAY_SECS < 600);
        let coeff = Coeff::new(NANOS_PER_SECOND as u64, freq, max_cycles);
        Self {
            max_cycles,
            coeff,
            last_record: RwLock::new((Duration::ZERO, 0)),
            unreliable_warning_reported: AtomicBool::new(false),
        }
    }

    /// Calculates a duration and the TSC value used for it.
    fn calculate_instant(&self) -> (Duration, u64) {
        let (instant_cycles, last_instant, last_cycles) = {
            let last_record = self.last_record.read();
            let (last_instant, last_cycles) = *last_record;
            (read_tsc(), last_instant, last_cycles)
        };

        let delta_nanos = match instant_cycles.checked_sub(last_cycles) {
            Some(delta) => self.cycles_to_nanos_lossy(delta),
            None => {
                ostd::warn!(
                    "The clock source becomes not reliable since TSC \
                    has moved backwards from {} to {}",
                    last_cycles,
                    instant_cycles
                );
                0
            }
        };
        let duration = Duration::from_nanos(delta_nanos);
        (last_instant.saturating_add(duration), instant_cycles)
    }

    fn cycles_to_nanos_lossy(&self, cycles: u64) -> u64 {
        if cycles <= self.max_cycles {
            self.coeff * cycles
        } else {
            if !self
                .unreliable_warning_reported
                .swap(true, Ordering::Relaxed)
            {
                ostd::warn!(
                    "The clock source becomes not reliable since an \
                    interval of {} cycles exceeds the maximum delay {} cycles",
                    cycles,
                    self.max_cycles
                );
            }
            self.coeff * self.max_cycles
        }
    }

    /// Stores the next vDSO calibration point.
    fn update_last_record(&self, record: (Duration, u64)) {
        *self.last_record.write() = record;
    }

    /// Returns the last calibration point.
    pub fn last_record(&self) -> (Duration, u64) {
        *self.last_record.read()
    }

    /// Returns the counter-to-nanoseconds coefficient used by vDSO.
    pub fn coeff(&self) -> &Coeff {
        &self.coeff
    }

    /// Calibrates the source at boot.
    pub(crate) fn calibrate(&self) {
        self.update_last_record((Duration::ZERO, read_tsc()));
    }

    /// Refreshes the recorded point.
    pub(crate) fn update(&self) {
        let (instant, instant_cycles) = self.calculate_instant();
        self.update_last_record((instant, instant_cycles));
    }

    /// Reads the current monotonic duration.
    pub(crate) fn read_instant(&self) -> Duration {
        self.calculate_instant().0
    }
}
