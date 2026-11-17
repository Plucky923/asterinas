// SPDX-License-Identifier: MPL-2.0

//! Execution clock for kernelet virtual CPUs.

use core::sync::atomic::Ordering;

/// Returns the kernelet vCPU execution clock with Host off-CPU intervals removed.
pub(super) fn runtime_ticks() -> u64 {
    let offset = &crate::kernelet::entry::vcpu_record().nonrunning_tsc;
    loop {
        let before = offset.load(Ordering::Acquire);
        let now = crate::arch::read_tsc_ordered();
        let after = offset.load(Ordering::Acquire);
        if before == after {
            return now.saturating_sub(after);
        }
    }
}
