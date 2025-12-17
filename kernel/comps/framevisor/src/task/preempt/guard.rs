use ostd::task::{
    atomic_mode::{AsAtomicModeGuard as OstdAsAtomicModeGuard, InAtomicMode as OstdInAtomicMode},
    disable_preempt as ostd_disable_preempt, DisabledPreemptGuard as OstdDisabledPreemptGuard,
};

use crate::task::atomic_mode::{AsAtomicModeGuard, InAtomicMode};

#[derive(Debug)]
pub struct DisabledPreemptGuard(OstdDisabledPreemptGuard);

impl DisabledPreemptGuard {
    fn inner(&self) -> &OstdDisabledPreemptGuard {
        &self.0
    }
}

pub fn disable_preempt() -> DisabledPreemptGuard {
    DisabledPreemptGuard(ostd_disable_preempt())
}

impl AsAtomicModeGuard for DisabledPreemptGuard {
    type Inner = OstdDisabledPreemptGuard;

    fn get_inner(&self) -> &Self::Inner {
        self.inner()
    }
}

pub fn init_preempt() {
    disable_preempt();
}
