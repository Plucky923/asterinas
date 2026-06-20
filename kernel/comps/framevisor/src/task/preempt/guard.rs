//! Guard type for disabled preemption sections.

use host_ostd::{
    sync::GuardTransfer as OstdGuardTransfer,
    task::{
        DisabledPreemptGuard as OstdDisabledPreemptGuard,
        atomic_mode::{
            AsAtomicModeGuard as OstdAsAtomicModeGuard, InAtomicMode as OstdInAtomicMode,
        },
        disable_preempt as ostd_disable_preempt,
    },
};

use crate::{cpu::CpuId, sync::GuardTransfer, task::atomic_mode::AsAtomicModeGuard};

#[derive(Debug)]
pub struct DisabledPreemptGuard {
    inner: OstdDisabledPreemptGuard,
}

impl DisabledPreemptGuard {
    fn inner(&self) -> &OstdDisabledPreemptGuard {
        &self.inner
    }

    /// Returns the pinned current CPU.
    pub fn current_cpu(&self) -> CpuId {
        CpuId::current_racy()
    }
}

pub fn disable_preempt() -> DisabledPreemptGuard {
    DisabledPreemptGuard {
        inner: ostd_disable_preempt(),
    }
}

impl AsAtomicModeGuard for DisabledPreemptGuard {
    type Inner = OstdDisabledPreemptGuard;

    fn get_inner(&self) -> &Self::Inner {
        self.inner()
    }
}

impl OstdAsAtomicModeGuard for DisabledPreemptGuard {
    fn as_atomic_mode_guard(&self) -> &dyn OstdInAtomicMode {
        self.inner.as_atomic_mode_guard()
    }
}

impl OstdGuardTransfer for DisabledPreemptGuard {
    fn transfer_to(&mut self) -> Self {
        Self {
            inner: self.inner.transfer_to(),
        }
    }
}

impl GuardTransfer for DisabledPreemptGuard {
    fn transfer_to(&mut self) -> Self {
        <Self as OstdGuardTransfer>::transfer_to(self)
    }
}

pub(super) fn init_preempt() {
    disable_preempt();
}
