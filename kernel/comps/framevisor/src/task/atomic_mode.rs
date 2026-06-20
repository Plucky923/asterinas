//! Traits for interoperating with atomic-mode execution guards.

use host_ostd::task::atomic_mode::AsAtomicModeGuard as OstdAsAtomicModeGuard;

pub trait InAtomicMode: core::fmt::Debug {}

pub trait AsAtomicModeGuard {
    type Inner: OstdAsAtomicModeGuard;
    fn get_inner(&self) -> &Self::Inner;
}
