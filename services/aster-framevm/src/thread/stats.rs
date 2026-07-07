// SPDX-License-Identifier: MPL-2.0

use spin::Once;

use crate::util::per_cpu_counter::PerCpuCounter;
pub(super) static CONTEXT_SWITCH_COUNTER: Once<PerCpuCounter> = Once::new();

/// Counts the number of context switches ever happened across all CPUs.
pub fn collect_context_switch_count() -> usize {
    CONTEXT_SWITCH_COUNTER.get().unwrap().sum_all_cpus()
}
