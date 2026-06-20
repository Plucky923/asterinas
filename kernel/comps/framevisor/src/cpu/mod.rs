// SPDX-License-Identifier: MPL-2.0

//! CPU-related definitions.

mod id;

pub use host_ostd::cpu::PrivilegeLevel;
use id::init_cpu_id;
pub use id::{AtomicCpuSet, CpuId, CpuIdFromIntError, CpuSet, PinCurrentCpu, all_cpus};

/// Returns the number of CPUs.
#[cfg(feature = "host-api")]
pub fn num_cpus() -> usize {
    crate::vm::get_vcpu_count().max(1)
}

/// Returns the number of CPUs visible to service-payload code.
#[cfg(not(feature = "host-api"))]
pub fn num_cpus() -> usize {
    crate::service_domain::get_vcpu_count()
}

/// Initialize the CPU subsystem.
pub(crate) fn init_cpu() {
    init_cpu_id();
}
