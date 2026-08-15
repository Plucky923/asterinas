// SPDX-License-Identifier: MPL-2.0

use alloc::sync::Arc;
use core::fmt;

use framev_pci_common::{FrameVFunctionFamily, VirtualPciBdf};
use host_ostd::sync::WaitQueue;

use crate::{Error, Result, sync::SpinLock, task, vm::VmId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FunctionStatus {
    Stopped,
    Running,
    Stopping,
    Failed,
}

struct FunctionState {
    status: FunctionStatus,
    generation: u64,
    active_calls: u64,
    next_claim_id: u64,
    current_claim_id: Option<u64>,
}

impl FunctionState {
    const fn new() -> Self {
        Self {
            status: FunctionStatus::Stopped,
            generation: 0,
            active_calls: 0,
            next_claim_id: 1,
            current_claim_id: None,
        }
    }
}

/// Admission and generation authority for one virtual PCI function.
pub(crate) struct FunctionRuntime {
    vm_id: VmId,
    bdf: VirtualPciBdf,
    family: FrameVFunctionFamily,
    state: SpinLock<FunctionState>,
    idle_wait: WaitQueue,
}

impl FunctionRuntime {
    pub(crate) fn new(vm_id: VmId, bdf: VirtualPciBdf, family: FrameVFunctionFamily) -> Self {
        Self {
            vm_id,
            bdf,
            family,
            state: SpinLock::new(FunctionState::new()),
            idle_wait: WaitQueue::new(),
        }
    }

    pub(crate) const fn family(&self) -> FrameVFunctionFamily {
        self.family
    }

    pub(crate) const fn bdf(&self) -> VirtualPciBdf {
        self.bdf
    }

    pub(crate) fn generation(&self) -> u64 {
        self.state.lock().generation
    }

    pub(crate) fn claimed_generation(&self) -> Option<u64> {
        let state = self.state.lock();
        (state.status == FunctionStatus::Running && state.current_claim_id.is_some())
            .then_some(state.generation)
    }

    pub(crate) fn start(&self) -> Result<()> {
        let mut state = self.state.lock();
        if state.status != FunctionStatus::Stopped || state.active_calls != 0 {
            return Err(Error::AccessDenied);
        }
        let Some(generation) = state.generation.checked_add(1) else {
            state.status = FunctionStatus::Failed;
            state.current_claim_id = None;
            return Err(Error::Overflow);
        };
        state.generation = generation;
        state.status = FunctionStatus::Running;
        Ok(())
    }

    pub(crate) fn claim(self: &Arc<Self>) -> Result<FunctionClaim> {
        let mut state = self.state.lock();
        if state.status != FunctionStatus::Running || state.current_claim_id.is_some() {
            return Err(Error::AccessDenied);
        }
        let claim_id = state.next_claim_id;
        state.next_claim_id = state.next_claim_id.checked_add(1).ok_or(Error::Overflow)?;
        state.current_claim_id = Some(claim_id);
        Ok(FunctionClaim {
            runtime: self.clone(),
            claim_id,
            generation: state.generation,
        })
    }

    pub(crate) fn enter_host(&self) -> Result<FunctionCall<'_>> {
        self.enter(None)
    }

    fn enter(&self, claim_id: Option<u64>) -> Result<FunctionCall<'_>> {
        let mut state = self.state.lock();
        if state.status != FunctionStatus::Running {
            return Err(Error::AccessDenied);
        }
        if claim_id.is_some() && state.current_claim_id != claim_id {
            return Err(Error::AccessDenied);
        }
        state.active_calls = state.active_calls.checked_add(1).ok_or(Error::Overflow)?;
        Ok(FunctionCall { runtime: self })
    }

    pub(crate) fn begin_stop(&self) {
        let mut state = self.state.lock();
        if state.status == FunctionStatus::Running {
            state.status = FunctionStatus::Stopping;
        }
    }

    pub(crate) fn wait_until_stopped(&self) {
        self.idle_wait.wait_until(|| {
            let mut state = self.state.lock();
            if matches!(
                state.status,
                FunctionStatus::Stopped | FunctionStatus::Failed
            ) {
                return Some(());
            }
            if state.status != FunctionStatus::Stopping || state.active_calls != 0 {
                return None;
            }
            state.status = FunctionStatus::Stopped;
            Some(())
        });
    }

    fn release_call(&self) {
        let mut state = self.state.lock();
        state.active_calls = state.active_calls.saturating_sub(1);
        let should_wake = state.active_calls == 0 && state.status == FunctionStatus::Stopping;
        drop(state);
        if should_wake {
            self.idle_wait.wake_all();
        }
    }

    fn release_claim(&self, claim_id: u64) {
        let mut state = self.state.lock();
        if state.current_claim_id == Some(claim_id) {
            state.current_claim_id = None;
        }
    }

    pub(crate) fn revoke_claim(&self) {
        self.state.lock().current_claim_id = None;
    }
}

/// An unforgeable claim to one FrameV PCI function.
pub struct FunctionClaim {
    runtime: Arc<FunctionRuntime>,
    claim_id: u64,
    generation: u64,
}

impl FunctionClaim {
    /// Returns the claimed function family.
    pub fn family(&self) -> FrameVFunctionFamily {
        self.runtime.family()
    }

    /// Returns the generation captured by the claimed function runtime.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn bdf(&self) -> VirtualPciBdf {
        self.runtime.bdf()
    }

    pub(crate) fn vm_id(&self) -> VmId {
        self.runtime.vm_id
    }

    pub(crate) fn enter(&self, expected_family: FrameVFunctionFamily) -> Result<FunctionCall<'_>> {
        let frame_vcpu_id = task::current_frame_vcpu_id().ok_or(Error::AccessDenied)?;
        if frame_vcpu_id.vm_id() != self.runtime.vm_id || self.runtime.family != expected_family {
            return Err(Error::AccessDenied);
        }
        self.runtime.enter(Some(self.claim_id))
    }
}

impl fmt::Debug for FunctionClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FunctionClaim")
            .field("bdf", &self.runtime.bdf())
            .field("family", &self.runtime.family())
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl Drop for FunctionClaim {
    fn drop(&mut self) {
        self.runtime.release_claim(self.claim_id);
    }
}

/// Releases one admitted function call when it leaves the direct-call path.
pub(crate) struct FunctionCall<'a> {
    runtime: &'a FunctionRuntime,
}

impl Drop for FunctionCall<'_> {
    fn drop(&mut self) {
        self.runtime.release_call();
    }
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    fn runtime() -> Arc<FunctionRuntime> {
        Arc::new(FunctionRuntime::new(
            crate::vm::VmId::new(7),
            VirtualPciBdf::new(0, 1, 0).unwrap(),
            FrameVFunctionFamily::Console,
        ))
    }

    #[ktest]
    fn stop_closes_admission_and_restart_advances_generation() {
        let runtime = runtime();
        runtime.start().unwrap();
        let first_generation = runtime.generation();
        let call = runtime.enter_host().unwrap();

        runtime.begin_stop();
        assert!(matches!(runtime.enter_host(), Err(Error::AccessDenied)));
        drop(call);
        runtime.wait_until_stopped();

        runtime.start().unwrap();
        assert_eq!(runtime.generation(), first_generation + 1);
    }

    #[ktest]
    fn revoked_claim_cannot_reenter_or_revoke_its_replacement() {
        let runtime = runtime();
        runtime.start().unwrap();
        let first = runtime.claim().unwrap();
        assert!(runtime.enter(Some(first.claim_id)).is_ok());

        runtime.revoke_claim();
        let replacement = runtime.claim().unwrap();
        assert!(matches!(
            runtime.enter(Some(first.claim_id)),
            Err(Error::AccessDenied)
        ));
        drop(first);
        assert!(runtime.enter(Some(replacement.claim_id)).is_ok());
    }

    #[ktest]
    fn generation_exhaustion_is_terminal() {
        let runtime = runtime();
        runtime.state.lock().generation = u64::MAX;

        assert_eq!(runtime.start(), Err(Error::Overflow));
        assert_eq!(runtime.start(), Err(Error::AccessDenied));
        runtime.begin_stop();
        runtime.wait_until_stopped();
    }
}
