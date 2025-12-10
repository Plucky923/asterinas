use ostd::task::{
    atomic_mode::AsAtomicModeGuard as OstdAsAtomicModeGuard,
    DisabledPreemptGuard as OstdDisabledPreemptGuard,
};

pub trait InAtomicMode: core::fmt::Debug {
    fn get_inner(&self) -> &OstdDisabledPreemptGuard;
}

pub trait AsAtomicModeGuard {
    fn inner(&self) -> &OstdDisabledPreemptGuard;
    fn as_atomic_mode_guard(&self) -> &dyn InAtomicMode;
}

impl<G: InAtomicMode> AsAtomicModeGuard for G {
    fn inner(&self) -> &OstdDisabledPreemptGuard {
        self.get_inner()
    }
    fn as_atomic_mode_guard(&self) -> &dyn InAtomicMode {
        self
    }
}

impl AsAtomicModeGuard for dyn InAtomicMode + '_ {
    fn inner(&self) -> &OstdDisabledPreemptGuard {
        self.get_inner()
    }
    fn as_atomic_mode_guard(&self) -> &dyn InAtomicMode {
        self
    }
}
