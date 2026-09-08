// SPDX-License-Identifier: MPL-2.0

//! Service entry points owned by one FrameVM image.

#[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
use host_ostd::arch::cpu::context::CpuException;
#[cfg(target_arch = "loongarch64")]
use host_ostd::arch::cpu::context::CpuExceptionInfo as CpuException;
use host_ostd::sync::{LocalIrqDisabled as HostLocalIrqDisabled, SpinLock};

use crate::{irq::DisabledLocalIrqGuard, prelude::Result};

type PostScheduleEntryPoint = fn();
type PreScheduleEntryPoint = fn(&DisabledLocalIrqGuard);
type PhysicalPostScheduleEntryPoint = fn();
type ShutdownEntryPoint = fn();
pub(crate) type UserPageFaultEntryPoint = fn(&CpuException) -> Result<(), ()>;

/// Stores the fixed runtime entry points of one FrameVM service image.
pub(crate) struct ServiceEntryPoints {
    // Trap and scheduling dispatch can run in physical interrupt context. The
    // lock also closes the admission window between loading an entry point
    // and calling it while teardown clears the service image.
    state: SpinLock<EntryPointState, HostLocalIrqDisabled>,
}

struct EntryPointState {
    accepting: bool,
    active_calls: usize,
    entry_points: EntryPointSet,
}

impl Default for EntryPointState {
    fn default() -> Self {
        Self {
            accepting: true,
            active_calls: 0,
            entry_points: EntryPointSet::default(),
        }
    }
}

pub(crate) struct EntryPointCall<'a, T: Copy> {
    owner: &'a ServiceEntryPoints,
    handler: T,
}

impl<T: Copy> EntryPointCall<'_, T> {
    pub(crate) fn handler(&self) -> T {
        self.handler
    }
}

impl<T: Copy> Drop for EntryPointCall<'_, T> {
    fn drop(&mut self) {
        let mut state = self.owner.state.lock();
        state.active_calls = state.active_calls.saturating_sub(1);
    }
}

impl ServiceEntryPoints {
    /// Creates an empty set of service entry points.
    pub(crate) fn new() -> Self {
        Self {
            state: SpinLock::new(EntryPointState::default()),
        }
    }

    /// Installs the pre-schedule entry point.
    pub(crate) fn install_pre_schedule(&self, entrypoint: PreScheduleEntryPoint) {
        self.state.lock().entry_points.pre_schedule = Some(entrypoint);
    }

    /// Installs the post-schedule entry point.
    pub(crate) fn install_post_schedule(&self, entrypoint: PostScheduleEntryPoint) {
        self.state.lock().entry_points.post_schedule = Some(entrypoint);
    }

    pub(crate) fn install_physical_pre_schedule(&self, entrypoint: PreScheduleEntryPoint) {
        self.state.lock().entry_points.physical_pre_schedule = Some(entrypoint);
    }

    pub(crate) fn install_physical_post_schedule(
        &self,
        entrypoint: PhysicalPostScheduleEntryPoint,
    ) {
        self.state.lock().entry_points.physical_post_schedule = Some(entrypoint);
    }

    /// Installs the pre-user-run entry point.
    pub(crate) fn install_pre_user_run(&self, entrypoint: PreScheduleEntryPoint) {
        self.state.lock().entry_points.pre_user_run = Some(entrypoint);
    }

    /// Installs the service shutdown entry point.
    pub(crate) fn install_shutdown(&self, entrypoint: ShutdownEntryPoint) {
        self.state.lock().entry_points.shutdown = Some(entrypoint);
    }

    /// Installs the user page-fault entry point.
    pub(crate) fn install_user_page_fault(&self, entrypoint: UserPageFaultEntryPoint) {
        self.state.lock().entry_points.user_page_fault = Some(entrypoint);
    }

    /// Admits one pre-schedule call while the service image remains mapped.
    pub(crate) fn enter_pre_schedule(&self) -> Option<EntryPointCall<'_, PreScheduleEntryPoint>> {
        self.enter(|entry_points| entry_points.pre_schedule)
    }

    /// Admits one post-schedule call while the service image remains mapped.
    pub(crate) fn enter_post_schedule(&self) -> Option<EntryPointCall<'_, PostScheduleEntryPoint>> {
        self.enter(|entry_points| entry_points.post_schedule)
    }

    pub(crate) fn enter_physical_pre_schedule(
        &self,
    ) -> Option<EntryPointCall<'_, PreScheduleEntryPoint>> {
        self.enter(|entry_points| entry_points.physical_pre_schedule)
    }

    pub(crate) fn enter_physical_post_schedule(
        &self,
    ) -> Option<EntryPointCall<'_, PhysicalPostScheduleEntryPoint>> {
        self.enter(|entry_points| entry_points.physical_post_schedule)
    }

    /// Admits one pre-user-run call while the service image remains mapped.
    pub(crate) fn enter_pre_user_run(&self) -> Option<EntryPointCall<'_, PreScheduleEntryPoint>> {
        self.enter(|entry_points| entry_points.pre_user_run)
    }

    /// Admits one shutdown call while the service image remains mapped.
    pub(crate) fn enter_shutdown(&self) -> Option<EntryPointCall<'_, ShutdownEntryPoint>> {
        let mut state = self.state.lock();
        if !state.accepting {
            return None;
        }
        let handler = state.entry_points.shutdown.take()?;
        state.active_calls = state.active_calls.saturating_add(1);
        Some(EntryPointCall {
            owner: self,
            handler,
        })
    }

    /// Admits one user page-fault call while the service image remains mapped.
    pub(crate) fn enter_user_page_fault(
        &self,
    ) -> Option<EntryPointCall<'_, UserPageFaultEntryPoint>> {
        self.enter(|entry_points| entry_points.user_page_fault)
    }

    fn enter<T: Copy>(
        &self,
        select_fn: impl FnOnce(&EntryPointSet) -> Option<T>,
    ) -> Option<EntryPointCall<'_, T>> {
        let mut state = self.state.lock();
        if !state.accepting {
            return None;
        }
        let handler = select_fn(&state.entry_points)?;
        state.active_calls = state.active_calls.saturating_add(1);
        Some(EntryPointCall {
            owner: self,
            handler,
        })
    }

    /// Clears all entry points and waits for admitted calls to finish.
    pub(crate) fn clear(&self) {
        {
            let mut state = self.state.lock();
            state.accepting = false;
            state.entry_points = EntryPointSet::default();
        }

        while self.state.lock().active_calls != 0 {
            core::hint::spin_loop();
        }
    }
}

#[derive(Default)]
struct EntryPointSet {
    pre_schedule: Option<PreScheduleEntryPoint>,
    post_schedule: Option<PostScheduleEntryPoint>,
    physical_pre_schedule: Option<PreScheduleEntryPoint>,
    physical_post_schedule: Option<PhysicalPostScheduleEntryPoint>,
    pre_user_run: Option<PreScheduleEntryPoint>,
    shutdown: Option<ShutdownEntryPoint>,
    user_page_fault: Option<UserPageFaultEntryPoint>,
}
