// SPDX-License-Identifier: MPL-2.0

use aster_util::per_cpu_counter::PerCpuCounter;
use spin::Once;

use crate::prelude::*;

pub(super) static PROCESS_CREATION_COUNTER: Once<PerCpuCounter> = Once::new();

/// Counts the number of processes ever created across all CPUs.
///
/// Returns `None` until process statistics have been initialized.
pub fn collect_process_creation_count() -> Option<usize> {
    PROCESS_CREATION_COUNTER
        .get()
        .map(PerCpuCounter::sum_all_cpus)
}

pub(super) fn init() -> Result<()> {
    let counter = PerCpuCounter::new()?;
    PROCESS_CREATION_COUNTER.call_once(|| counter);
    Ok(())
}
