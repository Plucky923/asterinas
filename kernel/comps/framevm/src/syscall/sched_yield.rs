// SPDX-License-Identifier: MPL-2.0

use super::Result;
use crate::{scheduler, task::current_scheduler_identity};

/// Yields the current task's remaining time slice.
pub(super) fn sys_sched_yield() -> Result<isize> {
    if let Some((cpu_id, tid)) = current_scheduler_identity() {
        scheduler::yield_current_task(cpu_id, tid);
    }
    Ok(0)
}
