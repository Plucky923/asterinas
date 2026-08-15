// SPDX-License-Identifier: MPL-2.0

//! CPU-related definitions.

mod id;
pub mod local;

pub use host_ostd::cpu::PrivilegeLevel;
pub use id::{AtomicCpuSet, CpuId, CpuIdFromIntError, CpuSet, PinCurrentCpu, all_cpus};

/// Returns the number of CPUs visible to the current service runtime.
pub fn num_cpus() -> usize {
    crate::task::current_frame_vm()
        .map(|frame_vm| frame_vm.vcpu_count())
        .unwrap_or(0)
}
