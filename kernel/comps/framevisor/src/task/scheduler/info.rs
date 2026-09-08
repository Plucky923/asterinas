// SPDX-License-Identifier: MPL-2.0

//! Scheduling information associated with a task.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::{cpu::CpuId, task::Task};

/// Fields managed by the task scheduler.
#[derive(Debug)]
pub struct TaskScheduleInfo {
    /// The CPU that the task most recently ran on or wants to run on.
    pub cpu: AtomicCpuId,
}

/// An atomic CPU ID container.
#[derive(Debug)]
pub struct AtomicCpuId(AtomicU32);

impl AtomicCpuId {
    const NONE: u32 = u32::MAX;

    /// Sets the CPU ID if the container is empty.
    pub fn set_if_is_none(&self, cpu_id: CpuId) -> Result<(), CpuId> {
        self.0
            .compare_exchange(
                Self::NONE,
                cpu_id.into(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .map(|_| ())
            .map_err(CpuId::from_raw)
    }

    /// Sets the CPU ID unconditionally.
    pub fn set_anyway(&self, cpu_id: CpuId) {
        self.0.store(cpu_id.into(), Ordering::Relaxed);
    }

    /// Clears the CPU ID.
    pub fn set_to_none(&self) {
        self.0.store(Self::NONE, Ordering::Relaxed);
    }

    /// Gets the CPU ID.
    pub fn get(&self) -> Option<CpuId> {
        self.get_for_cpu_count(crate::cpu::num_cpus())
    }

    /// Gets the CPU ID against an explicit owning CPU count.
    ///
    /// FrameVM bootstrap runs on a Host worker before there is a current
    /// FrameVM execution context. Callers that already own a VM must use its
    /// vCPU count rather than deriving the count from that Host worker.
    pub(crate) fn get_for_cpu_count(&self, cpu_count: usize) -> Option<CpuId> {
        let value = self.0.load(Ordering::Relaxed);
        if value == Self::NONE {
            None
        } else {
            ((value as usize) < cpu_count).then_some(CpuId::from_raw(value))
        }
    }
}

impl Default for AtomicCpuId {
    fn default() -> Self {
        Self(AtomicU32::new(Self::NONE))
    }
}

impl CommonSchedInfo for Task {
    fn cpu(&self) -> &AtomicCpuId {
        &self.schedule_info().cpu
    }
}

/// Trait for fetching common scheduling information.
pub trait CommonSchedInfo {
    /// Gets the CPU that the task is running on or most recently ran on.
    fn cpu(&self) -> &AtomicCpuId;
}

#[cfg(test)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::AtomicCpuId;
    use crate::cpu::CpuId;

    #[ktest]
    fn explicit_cpu_count_resolves_bootstrap_placement_without_current_vm() {
        let cpu = AtomicCpuId::default();
        cpu.set_anyway(CpuId::from_raw(0));

        assert_eq!(cpu.get_for_cpu_count(1), Some(CpuId::from_raw(0)));
        assert_eq!(cpu.get_for_cpu_count(0), None);
    }
}
