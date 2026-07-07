// SPDX-License-Identifier: MPL-2.0

//! A fast and scalable per-CPU counter.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicIsize, Ordering};

use ostd::cpu::{CpuId, all_cpus, num_cpus};

/// A fast, SMP-friendly, dynamically allocated, per-CPU counter.
///
/// Updating it is fast and scalable, but reading is slow and inaccurate.
pub struct PerCpuCounter {
    per_cpu_counter: Vec<AtomicIsize>,
}

impl PerCpuCounter {
    /// Creates a new, zero-valued per-CPU counter.
    pub fn new() -> Self {
        let per_cpu_counter = (0..num_cpus()).map(|_| AtomicIsize::new(0)).collect();
        Self { per_cpu_counter }
    }

    /// Adds `increment` to the counter on the given CPU.
    pub fn add_on_cpu(&self, on_cpu: CpuId, increment: isize) {
        self.per_cpu_counter[on_cpu.as_usize()].fetch_add(increment, Ordering::Relaxed);
    }

    /// Gets the total counter value.
    ///
    /// This function may be inaccurate since other CPUs may be
    /// updating the counter.
    pub fn sum_all_cpus(&self) -> usize {
        let mut total: isize = 0;
        for cpu in all_cpus() {
            total =
                total.wrapping_add(self.per_cpu_counter[cpu.as_usize()].load(Ordering::Relaxed));
        }
        if total < 0 {
            // The counter is unsigned. But an observer may see a negative
            // value due to race conditions. We return zero if it happens.
            0
        } else {
            total as usize
        }
    }

    /// Gets the counter value on a specific CPU.
    pub fn get_on_cpu(&self, cpu: CpuId) -> usize {
        let val = self.per_cpu_counter[cpu.as_usize()].load(Ordering::Relaxed);
        if val < 0 {
            // See explanation in `sum_all_cpus`.
            0
        } else {
            val as usize
        }
    }
}

impl Default for PerCpuCounter {
    fn default() -> Self {
        Self::new()
    }
}
