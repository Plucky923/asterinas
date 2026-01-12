//! Traits for interoperating with atomic-mode execution guards.

use ostd::task::{
    DisabledPreemptGuard as OstdDisabledPreemptGuard,
    atomic_mode::AsAtomicModeGuard as OstdAsAtomicModeGuard,
};

pub trait InAtomicMode: core::fmt::Debug {}

pub trait AsAtomicModeGuard {
    type Inner: OstdAsAtomicModeGuard;
    fn get_inner(&self) -> &Self::Inner;
}
