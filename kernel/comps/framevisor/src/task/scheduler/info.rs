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
            .map_err(|previous| (previous as usize).try_into().unwrap())
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
        let value = self.0.load(Ordering::Relaxed);
        if value == Self::NONE {
            None
        } else {
            Some((value as usize).try_into().ok()?)
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
