use ostd::task::{
    atomic_mode::AsAtomicModeGuard as OstdAsAtomicModeGuard,
    DisabledPreemptGuard as OstdDisabledPreemptGuard,
};

pub trait InAtomicMode: core::fmt::Debug {}

pub trait AsAtomicModeGuard {
    type Inner: OstdAsAtomicModeGuard;
    fn get_inner(&self) -> &Self::Inner;
}
