// SPDX-License-Identifier: MPL-2.0

//! CPU-related definitions.

mod id;
pub mod local;

pub use host_ostd::cpu::PrivilegeLevel;
use id::init_cpu_id;
pub use id::{AtomicCpuSet, CpuId, CpuIdFromIntError, CpuSet, PinCurrentCpu, all_cpus};

/// Returns the number of CPUs visible to the current service runtime.
pub fn num_cpus() -> usize {
    crate::visible_cpu_count()
}

/// Tries to return the current FrameVM CPU.
#[inline(never)]
pub fn try_current_cpu() -> Option<CpuId> {
    crate::task::scheduler::try_current_cpu()
}

/// Returns the current FrameVM CPU.
#[inline(never)]
pub fn current_cpu() -> CpuId {
    crate::task::scheduler::current_cpu()
}

/// Initialize the CPU subsystem.
pub(crate) fn init_cpu() {
    init_cpu_id();
}
