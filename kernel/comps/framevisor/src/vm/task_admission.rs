// SPDX-License-Identifier: MPL-2.0

//! FrameVM task admission and completion.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use host_ostd::sync::{
    LocalIrqDisabled as HostLocalIrqDisabled, SpinLock as HostSpinLock, WaitQueue as HostWaitQueue,
};

use crate::sync::WaitQueue;

const ORDERLY_STOP_BIT: usize = 1 << (usize::BITS - 2);
const FORCED_STOP_BIT: usize = 1 << (usize::BITS - 1);
const STOP_BITS: usize = ORDERLY_STOP_BIT | FORCED_STOP_BIT;
const RESETTING_BIT: usize = 1 << (usize::BITS - 3);
const ADMISSION_COUNT_MASK: usize = !(STOP_BITS | RESETTING_BIT);

/// Coordinates admission work owned by one FrameVM service image.
pub struct TaskAdmission {
    request_admission: AtomicUsize,
    completion: HostSpinLock<AdmissionCompletion, HostLocalIrqDisabled>,
    service_wait_queue: Arc<WaitQueue>,
    completion_wait_queue: HostWaitQueue,
}

impl TaskAdmission {
    pub(crate) fn new() -> Self {
        Self {
            request_admission: AtomicUsize::new(0),
            completion: HostSpinLock::new(AdmissionCompletion::new()),
            service_wait_queue: Arc::new(WaitQueue::new()),
            completion_wait_queue: HostWaitQueue::new(),
        }
    }

    /// Returns the wait queue shared by service-owned request workers.
    pub fn wait_queue(&self) -> Arc<WaitQueue> {
        self.service_wait_queue.clone()
    }

    /// Registers one startup worker that must finish before orderly admission completes.
    ///
    /// Registration remains open only while the owning [`TaskStartup`] exists.
    pub fn register_participant(self: &Arc<Self>) -> Option<TaskWorker> {
        let mut completion = self.completion.lock();
        if self.is_forced() || !completion.registration_open {
            return None;
        }

        completion.participants = completion.participants.checked_add(1)?;
        Some(TaskWorker {
            admission: self.clone(),
            is_active: true,
        })
    }

    /// Begins service startup and permits its workers to register for admission.
    pub(crate) fn begin_startup(self: &Arc<Self>) -> Option<TaskStartup> {
        let mut completion = self.completion.lock();
        if self.stop_bits() != 0 || completion.registration_open || completion.startup_active {
            return None;
        }

        let participants = completion.participants.checked_add(1)?;
        completion.registration_open = true;
        completion.startup_active = true;
        completion.participants = participants;
        Some(TaskStartup {
            admission: self.clone(),
            participant: Some(TaskWorker {
                admission: self.clone(),
                is_active: true,
            }),
        })
    }

    /// Begins one request that may be accepted before service admission.
    pub fn try_enter_request(&self) -> bool {
        loop {
            let state = self.request_admission.load(Ordering::Acquire);
            if state & (STOP_BITS | RESETTING_BIT) != 0
                || state & ADMISSION_COUNT_MASK == ADMISSION_COUNT_MASK
            {
                return false;
            }

            if self
                .request_admission
                .compare_exchange_weak(state, state + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Completes one request that was admitted before service admission.
    pub fn leave_request(&self) {
        loop {
            let state = self.request_admission.load(Ordering::Acquire);
            let count = state & ADMISSION_COUNT_MASK;
            if count == 0 {
                debug_assert_ne!(count, 0, "service request admission underflow");
                return;
            }

            let next = state - 1;
            if self
                .request_admission
                .compare_exchange_weak(state, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                if state & STOP_BITS != 0 && count == 1 {
                    self.service_wait_queue.wake_all();
                }
                return;
            }
        }
    }

    /// Returns whether orderly admission was requested for this service.
    pub fn is_orderly_requested(&self) -> bool {
        self.stop_bits() == ORDERLY_STOP_BIT
    }

    /// Returns whether forced admission was requested for this service.
    pub fn is_forced(&self) -> bool {
        self.stop_bits() == FORCED_STOP_BIT
    }

    /// Returns whether a request worker may stop after draining its queue.
    pub fn is_closed(&self) -> bool {
        let state = self.request_admission.load(Ordering::Acquire);
        state & FORCED_STOP_BIT != 0
            || (state & ORDERLY_STOP_BIT != 0 && state & ADMISSION_COUNT_MASK == 0)
    }

    /// Records an error that prevents an orderly service admission.
    pub fn report_failure(&self) {
        let should_wake_completion = {
            let mut completion = self.completion.lock();
            completion.failed = true;
            completion.phase == AdmissionPhase::Orderly && completion.participants == 0
        };
        if should_wake_completion {
            self.completion_wait_queue.wake_all();
        }
    }

    pub(crate) fn request_orderly(&self) -> bool {
        if !self.set_stop_bit(ORDERLY_STOP_BIT) {
            return false;
        }

        let should_wake_completion = {
            let mut completion = self.completion.lock();
            if completion.phase == AdmissionPhase::Forced {
                false
            } else {
                completion.phase = AdmissionPhase::Orderly;
                completion.participants == 0
            }
        };
        self.service_wait_queue.wake_all();
        if should_wake_completion {
            self.completion_wait_queue.wake_all();
        }
        true
    }

    pub(crate) fn request_forced(&self) {
        loop {
            let state = self.request_admission.load(Ordering::Acquire);
            if state & FORCED_STOP_BIT != 0 {
                break;
            }

            let next = state & ADMISSION_COUNT_MASK | FORCED_STOP_BIT;
            if self
                .request_admission
                .compare_exchange_weak(state, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }

        {
            let mut completion = self.completion.lock();
            completion.phase = AdmissionPhase::Forced;
            completion.registration_open = false;
        }
        self.service_wait_queue.wake_all();
        self.completion_wait_queue.wake_all();
    }

    pub(crate) fn wait_for_orderly_completion(&self) -> TaskAdmissionOutcome {
        self.completion_wait_queue.wait_until(|| {
            let completion = self.completion.lock();
            match completion.phase {
                AdmissionPhase::Active => None,
                AdmissionPhase::Orderly if completion.participants != 0 => None,
                AdmissionPhase::Orderly if completion.failed => Some(TaskAdmissionOutcome::Failed),
                AdmissionPhase::Orderly => Some(TaskAdmissionOutcome::Completed),
                AdmissionPhase::Forced => Some(TaskAdmissionOutcome::Forced),
            }
        })
    }

    pub(crate) fn reset(&self) -> bool {
        let prior_state = loop {
            let state = self.request_admission.load(Ordering::Acquire);
            if state & (ADMISSION_COUNT_MASK | RESETTING_BIT) != 0 {
                return false;
            }

            if self
                .request_admission
                .compare_exchange_weak(state, RESETTING_BIT, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break state;
            }
        };

        let mut completion = self.completion.lock();
        if completion.participants != 0 {
            let _ = self.request_admission.compare_exchange(
                RESETTING_BIT,
                prior_state,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return false;
        }

        // Clear the claim before replacing completion state. A concurrent stop
        // that wins this compare-exchange must retain its completion phase;
        // a later stop waits on this lock and observes the reopened admission.
        if self
            .request_admission
            .compare_exchange(RESETTING_BIT, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        *completion = AdmissionCompletion::new();
        true
    }

    fn set_stop_bit(&self, stop_bit: usize) -> bool {
        loop {
            let state = self.request_admission.load(Ordering::Acquire);
            if state & STOP_BITS != 0 {
                return false;
            }

            if self
                .request_admission
                .compare_exchange_weak(state, state | stop_bit, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    fn stop_bits(&self) -> usize {
        self.request_admission.load(Ordering::Acquire) & STOP_BITS
    }

    fn complete_participant(&self, succeeded: bool) {
        let should_wake_completion = {
            let mut completion = self.completion.lock();
            if completion.participants == 0 {
                debug_assert_ne!(
                    completion.participants, 0,
                    "service admission participant underflow"
                );
                return;
            }

            completion.participants -= 1;
            completion.failed |= !succeeded;
            completion.phase == AdmissionPhase::Orderly && completion.participants == 0
        };
        if should_wake_completion {
            self.completion_wait_queue.wake_all();
        }
    }

    fn seal_startup(&self) {
        let mut completion = self.completion.lock();
        completion.registration_open = false;
        completion.startup_active = false;
    }
}

/// Keeps service startup visible to orderly admission until initialization finishes.
pub struct TaskStartup {
    admission: Arc<TaskAdmission>,
    participant: Option<TaskWorker>,
}

impl TaskStartup {
    /// Marks service startup as complete.
    pub fn complete(mut self) {
        self.finish(true);
    }

    /// Marks service startup as failed.
    pub fn fail(mut self) {
        self.finish(false);
    }

    fn finish(&mut self, succeeded: bool) {
        let Some(mut participant) = self.participant.take() else {
            return;
        };

        self.admission.seal_startup();
        participant.finish(succeeded);
    }
}

impl Drop for TaskStartup {
    fn drop(&mut self) {
        self.finish(false);
    }
}

/// Represents one service worker participating in orderly admission.
pub struct TaskWorker {
    admission: Arc<TaskAdmission>,
    is_active: bool,
}

impl TaskWorker {
    /// Marks this participant's orderly admission work as complete.
    pub fn complete(mut self) {
        self.finish(true);
    }

    /// Marks this participant as unable to complete orderly admission work.
    pub fn fail(mut self) {
        self.finish(false);
    }

    fn finish(&mut self, succeeded: bool) {
        if !self.is_active {
            return;
        }

        self.is_active = false;
        self.admission.complete_participant(succeeded);
    }
}

impl Drop for TaskWorker {
    fn drop(&mut self) {
        self.finish(false);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TaskAdmissionOutcome {
    Completed,
    Failed,
    Forced,
}

struct AdmissionCompletion {
    phase: AdmissionPhase,
    participants: usize,
    failed: bool,
    registration_open: bool,
    startup_active: bool,
}

impl AdmissionCompletion {
    const fn new() -> Self {
        Self {
            phase: AdmissionPhase::Active,
            participants: 0,
            failed: false,
            registration_open: false,
            startup_active: false,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AdmissionPhase {
    Active,
    Orderly,
    Forced,
}

#[cfg(ktest)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::Ordering;

    use host_ostd::prelude::ktest;

    use super::{RESETTING_BIT, TaskAdmission, TaskAdmissionOutcome};

    #[ktest]
    fn orderly_admission_waits_for_previously_admitted_request() {
        let admission = TaskAdmission::new();

        assert!(admission.try_enter_request());
        assert!(admission.request_orderly());
        assert!(!admission.is_closed());

        admission.leave_request();
        assert!(admission.is_closed());
        assert_eq!(
            admission.wait_for_orderly_completion(),
            TaskAdmissionOutcome::Completed
        );
    }

    #[ktest]
    fn failed_participant_prevents_orderly_completion() {
        let admission = Arc::new(TaskAdmission::new());
        let startup = admission.begin_startup().unwrap();
        let participant = admission.register_participant().unwrap();

        assert!(admission.request_orderly());
        startup.complete();
        participant.fail();

        assert_eq!(
            admission.wait_for_orderly_completion(),
            TaskAdmissionOutcome::Failed
        );
    }

    #[ktest]
    fn startup_allows_worker_registration_after_orderly_stop() {
        let admission = Arc::new(TaskAdmission::new());
        let startup = admission.begin_startup().unwrap();

        assert!(admission.request_orderly());
        let worker = admission.register_participant().unwrap();
        startup.complete();
        worker.complete();

        assert_eq!(
            admission.wait_for_orderly_completion(),
            TaskAdmissionOutcome::Completed
        );
        assert!(admission.register_participant().is_none());
    }

    #[ktest]
    fn reported_failure_prevents_orderly_completion() {
        let admission = Arc::new(TaskAdmission::new());
        let startup = admission.begin_startup().unwrap();

        admission.report_failure();
        assert!(admission.request_orderly());
        startup.complete();

        assert_eq!(
            admission.wait_for_orderly_completion(),
            TaskAdmissionOutcome::Failed
        );
    }

    #[ktest]
    fn forced_admission_refuses_late_request_admission() {
        let admission = TaskAdmission::new();

        assert!(admission.try_enter_request());
        admission.request_forced();

        assert!(admission.is_closed());
        assert!(!admission.try_enter_request());
        admission.leave_request();
    }

    #[ktest]
    fn forced_admission_outcome_overrides_orderly_admission() {
        let admission = TaskAdmission::new();

        assert!(admission.request_orderly());
        admission.request_forced();

        assert_eq!(
            admission.wait_for_orderly_completion(),
            TaskAdmissionOutcome::Forced
        );
    }

    #[ktest]
    fn reset_reopens_admission_after_forced_stop() {
        let admission = TaskAdmission::new();

        admission.request_forced();
        assert!(admission.reset());
        assert!(admission.try_enter_request());
        admission.leave_request();
    }

    #[ktest]
    fn forced_admission_overrides_an_in_progress_reset() {
        let admission = TaskAdmission::new();
        admission
            .request_admission
            .store(RESETTING_BIT, Ordering::Release);

        admission.request_forced();

        assert!(admission.is_forced());
        assert_ne!(
            admission.request_admission.load(Ordering::Acquire),
            RESETTING_BIT
        );
        assert!(!admission.try_enter_request());
    }

    #[ktest]
    fn orderly_admission_claims_an_in_progress_reset() {
        let admission = TaskAdmission::new();
        admission
            .request_admission
            .store(RESETTING_BIT, Ordering::Release);

        assert!(admission.request_orderly());
        assert_eq!(
            admission.wait_for_orderly_completion(),
            TaskAdmissionOutcome::Completed
        );
    }
}
