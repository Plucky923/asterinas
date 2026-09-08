// SPDX-License-Identifier: MPL-2.0

//! FrameVM host scheduling domains.

use alloc::{
    collections::BTreeSet,
    sync::{Arc, Weak},
};
use core::sync::atomic::{AtomicBool, Ordering};

use host_ostd::{
    cpu::{CpuId as HostCpuId, PinCurrentCpu},
    sync::{
        LocalIrqDisabled as HostLocalIrqDisabled, SpinLock as HostSpinLock, Waker as HostWaker,
    },
    task::disable_preempt,
    timer,
};

use super::VmId;
use crate::{
    irq::InterruptHandler,
    task::{Task, scheduler::UpdateFlags},
};

/// Identifies the host scheduling domain for one FrameVM vCPU.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FrameVcpuId {
    vm_id: VmId,
    vcpu_index: usize,
}

impl FrameVcpuId {
    /// Creates an identifier for one FrameVM vCPU scheduling domain.
    pub const fn new(vm_id: VmId, vcpu_index: usize) -> Self {
        Self { vm_id, vcpu_index }
    }

    /// Returns the owning VM ID.
    pub const fn vm_id(&self) -> VmId {
        self.vm_id
    }

    /// Returns the vCPU index within the owning VM.
    pub const fn vcpu_index(&self) -> usize {
        self.vcpu_index
    }
}

/// Host scheduling domain for one FrameVM vCPU.
pub struct FrameSchedGroup {
    id: FrameVcpuId,
    share: u32,
    host_cpu: HostSpinLock<HostCpuId, HostLocalIrqDisabled>,
    interrupt_handler: Arc<InterruptHandler>,
    state: HostSpinLock<RunState, HostLocalIrqDisabled>,
    continuation: HostSpinLock<ContinuationState<Task>, HostLocalIrqDisabled>,
    /// The Host wake edge published only while the current continuation is
    /// parking this opaque vCPU through virtual `halt_cpu`.
    outer_halt_waker: HostSpinLock<Option<Arc<HostWaker>>, HostLocalIrqDisabled>,
    inner_preempt_pending: AtomicBool,
    timer_host_cpus: HostSpinLock<BTreeSet<usize>, HostLocalIrqDisabled>,
}

impl FrameSchedGroup {
    /// Creates a FrameVM host scheduling domain.
    pub fn new(
        id: FrameVcpuId,
        share: u32,
        host_cpu: HostCpuId,
        interrupt_handler: Arc<InterruptHandler>,
    ) -> Self {
        Self {
            id,
            share,
            host_cpu: HostSpinLock::new(host_cpu),
            interrupt_handler,
            state: HostSpinLock::new(RunState::new()),
            continuation: HostSpinLock::new(ContinuationState::new()),
            outer_halt_waker: HostSpinLock::new(None),
            inner_preempt_pending: AtomicBool::new(false),
            timer_host_cpus: HostSpinLock::new(BTreeSet::new()),
        }
    }

    /// Returns this scheduling domain's identity.
    pub const fn id(&self) -> FrameVcpuId {
        self.id
    }

    /// Returns this group's configured CPU share.
    pub const fn share(&self) -> u32 {
        self.share
    }

    /// Returns the owning VM ID.
    pub(crate) const fn vm_id(&self) -> VmId {
        self.id.vm_id()
    }

    /// Returns the vCPU index within the owning VM.
    pub(crate) const fn vcpu_index(&self) -> usize {
        self.id.vcpu_index()
    }

    /// Returns the bound host CPU.
    pub fn host_cpu(&self) -> HostCpuId {
        *self.host_cpu.lock()
    }

    /// Binds this group to one physical host CPU.
    pub fn bind_host_cpu(&self, host_cpu: HostCpuId) {
        *self.host_cpu.lock() = host_cpu;
    }

    /// Returns the FrameVM task whose Host carrier is committed as this
    /// group's outer continuation.
    ///
    /// This is intentionally a committed value: staging an A -> B processor
    /// switch does not make B observable here until the processor has
    /// switched to B and the outer scheduler commits that exact pair.
    #[doc(hidden)]
    pub fn continuation(&self) -> Option<Arc<Task>> {
        self.continuation.lock().continuation()
    }

    /// Installs the one initial continuation owned by this group.
    ///
    /// Bootstrap construction is the sole caller in the converged scheduler;
    /// an already committed continuation cannot be replaced through this
    /// path.
    pub(crate) fn install_initial_continuation(
        &self,
        task: Arc<Task>,
    ) -> Result<(), ContinuationTransitionError> {
        self.continuation.lock().install_initial(task)
    }

    /// Stages one exact A -> B switch without changing the committed
    /// continuation.
    ///
    /// The slot is deliberately single-entry. A second inner selection cannot
    /// overwrite the pair that the processor is about to switch, and the
    /// outer scheduler later commits by pointer identity rather than by an
    /// epoch or a task ID.
    pub(crate) fn stage_continuation_switch(
        &self,
        from: &Arc<Task>,
        to: Arc<Task>,
    ) -> Result<(), ContinuationTransitionError> {
        self.continuation.lock().stage(from, to)
    }

    /// Commits the staged A -> B switch after the processor has reached B.
    ///
    /// Both arguments are checked against the staged pair. In particular, an
    /// old post-switch callback cannot commit a newer transition, nor can it
    /// commit after the slot has already been consumed.
    #[doc(hidden)]
    pub fn commit_continuation_switch(
        &self,
        from: &Arc<Task>,
        to: &Arc<Task>,
    ) -> Result<(), ContinuationTransitionError> {
        self.continuation.lock().commit(from, to)
    }

    /// Releases this group's committed continuation during final teardown.
    ///
    /// The caller must first remove the group from Host scheduler visibility
    /// and ensure that no execution can remain in the group. This method
    /// enforces the local half of that protocol by requiring the exact
    /// committed task and by rejecting a transition that is still pending.
    pub(crate) fn release_committed_continuation(
        &self,
        expected: &Arc<Task>,
    ) -> Result<Arc<Task>, ContinuationTransitionError> {
        self.continuation.lock().release(expected)
    }

    /// Records that this virtual CPU must consume an exact-inner preemption
    /// request at its next service preemption point.
    ///
    /// This is virtual processor state, not a Host scheduler request.  A
    /// producer may set it for a vCPU that is not physically running; only
    /// that vCPU's continuation may consume it.
    pub(crate) fn request_inner_preempt(&self) {
        self.inner_preempt_pending.store(true, Ordering::Release);
        self.ring_outer_halt();
    }

    /// Consumes one pending exact-inner preemption request.
    pub(crate) fn take_inner_preempt(&self) -> bool {
        self.inner_preempt_pending.swap(false, Ordering::AcqRel)
    }

    /// Returns whether work published before an outer halt must keep the
    /// current continuation running.
    pub(crate) fn has_virtual_halt_work(&self) -> bool {
        self.inner_preempt_pending.load(Ordering::Acquire)
            || self.interrupt_handler.has_deliverable_work()
            || !self.state.lock().admits_work
    }

    /// Publishes the one Host Waker that can restore this opaque group.
    pub(crate) fn register_outer_halt(
        &self,
        carrier: &Arc<host_ostd::task::Task>,
        waker: Arc<HostWaker>,
    ) {
        let continuation = self
            .continuation()
            .expect("an outer halt requires a committed continuation");
        assert!(
            Arc::ptr_eq(continuation.ostd_task(), carrier),
            "only the committed Frame continuation may halt its outer group"
        );

        let mut registered = self.outer_halt_waker.lock();
        assert!(
            registered.is_none(),
            "one Frame vCPU may publish only one outer-halt Waker"
        );
        *registered = Some(waker);
    }

    /// Removes the exact outer-halt registration after its waiter returns or
    /// the final pre-park work check cancels the halt.
    pub(crate) fn unregister_outer_halt(&self, expected: &Arc<HostWaker>) {
        let mut registered = self.outer_halt_waker.lock();
        let current = registered
            .as_ref()
            .expect("an outer-halt Waker must remain registered until its waiter returns");
        assert!(
            Arc::ptr_eq(current, expected),
            "a stale waiter cannot remove a newer outer-halt registration"
        );
        *registered = None;
    }

    /// Returns whether a Host wake names the exact continuation currently
    /// parked by virtual `halt_cpu`.
    pub fn accepts_outer_halt_wake(&self, carrier: &Arc<host_ostd::task::Task>) -> bool {
        let Some(continuation) = self.continuation() else {
            return false;
        };
        Arc::ptr_eq(continuation.ostd_task(), carrier) && self.outer_halt_waker.lock().is_some()
    }

    fn is_outer_halted(&self) -> bool {
        self.outer_halt_waker.lock().is_some()
    }

    fn ring_outer_halt(&self) {
        let waker = self.outer_halt_waker.lock().clone();
        if let Some(waker) = waker {
            let _ = waker.wake_up();
        }
    }

    pub(crate) fn enable_timer_on_current_cpu(self: &Arc<Self>) {
        let host_cpu = disable_preempt().current_cpu();
        if host_cpu != self.host_cpu() {
            return;
        }
        if !self
            .timer_host_cpus
            .lock()
            .insert(u32::from(host_cpu) as usize)
        {
            return;
        }

        let group = Arc::downgrade(self);
        timer::register_callback_on_cpu(move || {
            let Some(group) = group.upgrade() else {
                return;
            };
            if group.host_cpu() == host_cpu {
                super::get_vm_by_id(group.vm_id()).map(|vm| vm.record_timer_tick(group.id()));
            }
        });
    }

    fn has_interrupt_work(&self) -> bool {
        self.interrupt_handler.has_deliverable_work()
    }

    fn has_service_work_inner(&self) -> bool {
        // The Host may observe only the committed continuation.  Looking into
        // an inner runqueue here would make outer policy choose an inner task
        // and would expose a staged B before its processor switch commits.
        self.continuation().is_some()
    }

    /// Returns whether service work can keep this group runnable.
    pub fn has_service_work_for_outer(&self) -> bool {
        if self.is_outer_halted() {
            return false;
        }
        let admits_work = self.state.lock().admits_work;
        admits_work && self.has_service_work_inner()
    }

    /// Returns whether this group has work for the Host scheduler.
    pub fn has_runnable_work(&self) -> bool {
        if self.is_outer_halted() {
            return false;
        }
        if !self.state.lock().admits_work {
            return self.interrupt_handler.has_deliverable_work() || self.has_service_work_inner();
        }
        self.has_interrupt_work() || self.has_service_work_inner()
    }

    /// Allows service and interrupt work to re-enter the Host scheduler.
    pub(crate) fn open_admission(&self) {
        let mut state = self.state.lock();
        state.admits_work = true;
    }

    /// Closes admission for new service and interrupt work.
    pub(crate) fn close_admission(&self) {
        {
            let mut state = self.state.lock();
            state.admits_work = false;
        }
        // A halted idle continuation must resume once to observe closure and
        // retire the virtual CPU. The durable closed state is published
        // before the optional Host wake edge is rung.
        self.request_inner_preempt();
    }

    /// Accounts an outer scheduling event without interpreting it as an
    /// inner task transition.
    ///
    /// Direct Frame task switches never call this method: they replace only
    /// the concrete continuation in the already-current outer pair at the
    /// processor boundary.  Consequently, an outer `Yield`, `Wait`, or
    /// `Exit` must not be forwarded to the injected inner scheduler.
    pub fn update_current(
        &self,
        _task: &Arc<host_ostd::task::Task>,
        _state: &Arc<crate::task::FrameTaskState>,
        flags: UpdateFlags,
    ) -> bool {
        match flags {
            UpdateFlags::Tick => self.has_interrupt_work(),
            UpdateFlags::Yield | UpdateFlags::Wait | UpdateFlags::Exit => self.has_runnable_work(),
        }
    }

    /// Returns the Host context of the committed continuation.
    ///
    /// This is deliberately not an inner scheduler pick. A staged target
    /// remains private until the physical processor has switched to it and
    /// the post-switch path commits that exact pair.
    pub fn pick_task(&self) -> Option<Arc<host_ostd::task::Task>> {
        self.continuation().map(|task| task.ostd_task().clone())
    }
}

/// The committed continuation and the one processor switch awaiting commit.
///
/// `T` is generic only so the identity protocol can be unit-tested without a
/// live FrameVM. `FrameSchedGroup` always instantiates it as `Task`.
enum ContinuationState<T: ?Sized> {
    Vacant,
    Active {
        continuation: Arc<T>,
        pending: Option<PendingSwitch<T>>,
    },
    Released,
}

impl<T: ?Sized> ContinuationState<T> {
    const fn new() -> Self {
        Self::Vacant
    }

    fn continuation(&self) -> Option<Arc<T>> {
        match self {
            Self::Active { continuation, .. } => Some(continuation.clone()),
            Self::Vacant | Self::Released => None,
        }
    }

    fn install_initial(&mut self, task: Arc<T>) -> Result<(), ContinuationTransitionError> {
        match self {
            Self::Vacant => {
                *self = Self::Active {
                    continuation: task,
                    pending: None,
                };
                Ok(())
            }
            Self::Active { .. } => {
                Err(ContinuationTransitionError::InitialContinuationAlreadyInstalled)
            }
            Self::Released => Err(ContinuationTransitionError::ContinuationAlreadyReleased),
        }
    }

    fn stage(&mut self, from: &Arc<T>, to: Arc<T>) -> Result<(), ContinuationTransitionError> {
        let Self::Active {
            continuation,
            pending,
        } = self
        else {
            return Err(ContinuationTransitionError::CommittedContinuationMismatch);
        };
        if !Arc::ptr_eq(continuation, from) {
            return Err(ContinuationTransitionError::CommittedContinuationMismatch);
        }
        if pending.is_some() {
            return Err(ContinuationTransitionError::PendingSwitchOccupied);
        }
        if Arc::ptr_eq(from, &to) {
            return Err(ContinuationTransitionError::NoContinuationChange);
        }

        *pending = Some(PendingSwitch {
            from: Arc::downgrade(from),
            to,
        });
        Ok(())
    }

    fn commit(&mut self, from: &Arc<T>, to: &Arc<T>) -> Result<(), ContinuationTransitionError> {
        let Self::Active {
            continuation,
            pending,
        } = self
        else {
            return Err(ContinuationTransitionError::CommittedContinuationMismatch);
        };
        if !Arc::ptr_eq(continuation, from) {
            return Err(ContinuationTransitionError::CommittedContinuationMismatch);
        }

        let Some(pending_switch) = pending.as_ref() else {
            return Err(ContinuationTransitionError::PendingSwitchMissing);
        };
        if !pending_switch
            .from
            .upgrade()
            .is_some_and(|pending_from| Arc::ptr_eq(&pending_from, from))
        {
            return Err(ContinuationTransitionError::PendingSourceMismatch);
        }
        if !Arc::ptr_eq(&pending_switch.to, to) {
            return Err(ContinuationTransitionError::PendingTargetMismatch);
        }

        let pending_switch = pending
            .take()
            .expect("a checked pending continuation switch must still exist");
        *continuation = pending_switch.to;
        Ok(())
    }

    fn release(&mut self, expected: &Arc<T>) -> Result<Arc<T>, ContinuationTransitionError> {
        let Self::Active {
            continuation,
            pending,
        } = self
        else {
            return Err(ContinuationTransitionError::CommittedContinuationMismatch);
        };
        if !Arc::ptr_eq(continuation, expected) {
            return Err(ContinuationTransitionError::CommittedContinuationMismatch);
        }
        if pending.is_some() {
            return Err(ContinuationTransitionError::PendingSwitchOccupied);
        }

        let Self::Active { continuation, .. } = core::mem::replace(self, Self::Released) else {
            unreachable!("a checked active continuation state must remain active");
        };
        Ok(continuation)
    }
}

/// The one exact processor handoff waiting to arrive on its target stack.
struct PendingSwitch<T: ?Sized> {
    from: Weak<T>,
    to: Arc<T>,
}

/// Why an exact continuation transition was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum ContinuationTransitionError {
    /// Bootstrap attempted to replace the group's already-installed initial continuation.
    InitialContinuationAlreadyInstalled,
    /// Teardown has released the group's continuation permanently.
    ContinuationAlreadyReleased,
    /// The caller's source task is not the committed continuation.
    CommittedContinuationMismatch,
    /// A different staged switch is already awaiting commit.
    PendingSwitchOccupied,
    /// The staged switch has already committed or was never staged.
    PendingSwitchMissing,
    /// The staged source no longer names the caller's exact continuation.
    PendingSourceMismatch,
    /// The processor reported a target different from the staged target.
    PendingTargetMismatch,
    /// The virtual scheduler tried to stage a switch to the already-current task.
    NoContinuationChange,
}

struct RunState {
    admits_work: bool,
}

impl RunState {
    const fn new() -> Self {
        Self { admits_work: false }
    }
}

#[cfg(ktest)]
mod tests {
    use alloc::sync::Arc;

    use host_ostd::prelude::ktest;

    use super::{ContinuationState, ContinuationTransitionError};

    #[ktest]
    fn continuation_switch_rejects_pointer_mismatch() {
        let committed = Arc::new(());
        let staged_target = Arc::new(());
        let distinct_same_value = Arc::new(());
        let mut state = ContinuationState::new();

        state.install_initial(committed.clone()).unwrap();

        assert_eq!(
            state.stage(&distinct_same_value, staged_target.clone()),
            Err(ContinuationTransitionError::CommittedContinuationMismatch)
        );
        state.stage(&committed, staged_target.clone()).unwrap();
        assert_eq!(
            state.commit(&committed, &distinct_same_value),
            Err(ContinuationTransitionError::PendingTargetMismatch)
        );

        assert!(Arc::ptr_eq(&state.continuation().unwrap(), &committed));
    }

    #[ktest]
    fn continuation_switch_rejects_stale_commit() {
        let first = Arc::new(());
        let second = Arc::new(());
        let mut state = ContinuationState::new();

        state.install_initial(first.clone()).unwrap();
        state.stage(&first, second.clone()).unwrap();
        state.commit(&first, &second).unwrap();

        assert_eq!(
            state.commit(&first, &second),
            Err(ContinuationTransitionError::CommittedContinuationMismatch)
        );
        assert_eq!(
            state.commit(&second, &first),
            Err(ContinuationTransitionError::PendingSwitchMissing)
        );
        assert!(Arc::ptr_eq(&state.continuation().unwrap(), &second));
    }

    #[ktest]
    fn continuation_switch_has_one_pending_slot() {
        let first = Arc::new(());
        let second = Arc::new(());
        let third = Arc::new(());
        let mut state = ContinuationState::new();

        state.install_initial(first.clone()).unwrap();
        state.stage(&first, second.clone()).unwrap();

        assert_eq!(
            state.stage(&first, third),
            Err(ContinuationTransitionError::PendingSwitchOccupied)
        );
        assert!(Arc::ptr_eq(&state.continuation().unwrap(), &first));

        state.commit(&first, &second).unwrap();
        assert!(Arc::ptr_eq(&state.continuation().unwrap(), &second));
    }

    #[ktest]
    fn continuation_release_rejects_wrong_expected_task() {
        let committed = Arc::new(());
        let wrong = Arc::new(());
        let mut state = ContinuationState::new();

        state.install_initial(committed.clone()).unwrap();

        assert_eq!(
            state.release(&wrong),
            Err(ContinuationTransitionError::CommittedContinuationMismatch)
        );
        assert!(Arc::ptr_eq(&state.continuation().unwrap(), &committed));
    }

    #[ktest]
    fn continuation_release_rejects_pending_switch() {
        let committed = Arc::new(());
        let pending = Arc::new(());
        let mut state = ContinuationState::new();

        state.install_initial(committed.clone()).unwrap();
        state.stage(&committed, pending).unwrap();

        assert_eq!(
            state.release(&committed),
            Err(ContinuationTransitionError::PendingSwitchOccupied)
        );
        assert!(Arc::ptr_eq(&state.continuation().unwrap(), &committed));
    }

    #[ktest]
    fn continuation_release_returns_exact_task_and_empties_state() {
        let committed = Arc::new(());
        let mut state = ContinuationState::new();

        state.install_initial(committed.clone()).unwrap();

        let released = state.release(&committed).unwrap();

        assert!(Arc::ptr_eq(&released, &committed));
        assert!(state.continuation().is_none());
    }

    #[ktest]
    fn continuation_release_is_terminal() {
        let initial = Arc::new(());
        let replacement = Arc::new(());
        let mut state = ContinuationState::new();

        state.install_initial(initial.clone()).unwrap();
        state.release(&initial).unwrap();

        assert_eq!(
            state.install_initial(replacement),
            Err(ContinuationTransitionError::ContinuationAlreadyReleased)
        );
        assert!(state.continuation().is_none());
    }
}
