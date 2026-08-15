// SPDX-License-Identifier: MPL-2.0

//! FrameVM-vCPU counter storage.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicIsize, Ordering};

/// A relaxed counter with one slot for each vCPU in the current FrameVM.
pub struct PerCpuCounter {
    values: Vec<AtomicIsize>,
}

/// Reasons why a per-vCPU counter cannot be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PerCpuCounterError {
    /// The caller is not running in a task bound to a FrameVM vCPU.
    NoCurrentFrameVcpu,
    /// The current vCPU refers to a VM that is no longer registered.
    FrameVmNotFound,
    /// A FrameVM with no vCPUs cannot own a per-vCPU counter.
    NoVcpus,
}

impl PerCpuCounter {
    /// Creates a zero-valued counter for the current FrameVM's vCPUs.
    ///
    /// The counter is scoped to the FrameVM that owns the current vCPU.  It
    /// therefore cannot be constructed from bootstrap code or from a task
    /// that is not bound to a FrameVM; callers must propagate the error from
    /// those paths instead of falling back to Host-global CPU state.
    pub fn new() -> Result<Self, PerCpuCounterError> {
        let Some(frame_vcpu_id) = aster_framevisor::current_frame_vcpu_id() else {
            return Err(PerCpuCounterError::NoCurrentFrameVcpu);
        };
        let Some(frame_vm) = aster_framevisor::get_framevm(frame_vcpu_id.vm_id()) else {
            return Err(PerCpuCounterError::FrameVmNotFound);
        };

        Self::with_vcpu_count(frame_vm.vcpu_count())
    }

    /// Adds `increment` to the selected FrameVM vCPU slot.
    ///
    /// Returns `None` when the index does not belong to this counter.  A
    /// counter has no safe recovery policy for an invalid index, so callers
    /// decide whether to drop best-effort accounting or return an error.
    pub fn add_on_cpu(&self, vcpu_index: usize, increment: isize) -> Option<()> {
        self.values.get(vcpu_index).map(|value| {
            value.fetch_add(increment, Ordering::Relaxed);
        })
    }

    /// Returns the approximate sum across this FrameVM's vCPUs.
    pub fn sum_all_cpus(&self) -> usize {
        let total = self.values.iter().fold(0isize, |total, value| {
            total.wrapping_add(value.load(Ordering::Relaxed))
        });
        total.max(0) as usize
    }

    /// Returns the selected FrameVM vCPU slot.
    pub fn get_on_cpu(&self, vcpu_index: usize) -> Option<usize> {
        self.values
            .get(vcpu_index)
            .map(|value| value.load(Ordering::Relaxed).max(0) as usize)
    }

    fn with_vcpu_count(vcpu_count: usize) -> Result<Self, PerCpuCounterError> {
        if vcpu_count == 0 {
            return Err(PerCpuCounterError::NoVcpus);
        }

        Ok(Self {
            values: (0..vcpu_count).map(|_| AtomicIsize::new(0)).collect(),
        })
    }
}
