// SPDX-License-Identifier: MPL-2.0

//! Scoped FrameVM CPU identity.

use crate::{cpu::CpuId, task};

const NO_SCOPED_CPU: u32 = u32::MAX;

host_ostd::cpu_local_cell! {
    static SCOPED_FRAMEVM_CPU: u32 = NO_SCOPED_CPU;
}

/// Scoped FrameVM CPU identity for host-to-FrameVM scheduler boundaries.
pub(crate) struct FrameCpuScope {
    previous_raw_cpu: u32,
}

impl Drop for FrameCpuScope {
    fn drop(&mut self) {
        SCOPED_FRAMEVM_CPU.store(self.previous_raw_cpu);
    }
}

/// Enters a scoped FrameVM CPU identity boundary.
pub(crate) fn enter_frame_cpu_scope(cpu_id: CpuId) -> FrameCpuScope {
    let previous_raw_cpu = SCOPED_FRAMEVM_CPU.load();
    SCOPED_FRAMEVM_CPU.store(u32::from(cpu_id));
    FrameCpuScope { previous_raw_cpu }
}

/// Tries to return the current virtual CPU.
pub(crate) fn try_current_cpu() -> Option<CpuId> {
    let scoped_raw_cpu = SCOPED_FRAMEVM_CPU.load();
    if scoped_raw_cpu != NO_SCOPED_CPU {
        return Some(CpuId::from_raw(scoped_raw_cpu));
    }

    let frame_vcpu_id = task::current_frame_vcpu_id()?;
    Some(CpuId::from_raw(frame_vcpu_id.vcpu_index() as u32))
}

/// Returns the current virtual CPU.
pub(crate) fn current_cpu() -> CpuId {
    try_current_cpu().expect("FrameVM CPU identity is missing")
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn frame_cpu_scope_restores_previous_identity() {
        let previous_cpu = try_current_cpu();

        {
            let _scope = enter_frame_cpu_scope(CpuId::bsp());
            assert_eq!(try_current_cpu(), Some(CpuId::bsp()));
        }

        assert_eq!(try_current_cpu(), previous_cpu);
    }
}
