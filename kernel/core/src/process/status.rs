// SPDX-License-Identifier: MPL-2.0

//! The process status.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use ostd::sync::SpinLock;

use super::ExitCode;
use crate::process::{WaitOptions, signal::sig_num::SigNum};

/// The status of a process.
///
/// This maintains:
/// 1. Whether the process is running, a zombie, or has been reaped;
/// 2. Whether the process is the vfork child, which shares the user-space virtual memory
///    with its parent process;
/// 3. The exit code of the process;
/// 4. Whether the process is stopped by a signal.
#[derive(Debug)]
pub(crate) struct ProcessStatus {
    exit_state: AtomicU8,
    is_vfork_child: AtomicBool,
    exit_code: AtomicU32,
    stop_status: StopStatus,
}

#[repr(u8)]
enum ExitState {
    Running,
    Zombie,
    Reaped,
}

impl Default for ProcessStatus {
    fn default() -> Self {
        Self {
            exit_state: AtomicU8::new(ExitState::Running as u8),
            is_vfork_child: AtomicBool::new(false),
            exit_code: AtomicU32::new(0),
            stop_status: StopStatus::new(),
        }
    }
}

impl ProcessStatus {
    /// Returns whether all threads of the process have exited.
    pub(crate) fn is_zombie(&self) -> bool {
        // Use the `Acquire` memory order to make the exit code visible.
        self.exit_state.load(Ordering::Acquire) != ExitState::Running as u8
    }

    /// Sets the process to be a zombie process.
    ///
    /// This method should be called when the process completes its exit. The current thread must
    /// be the last thread in the process, so that no threads belonging to the process can run
    /// after it.
    pub(super) fn set_zombie(&self) {
        // Use the `Release` memory order to make the exit code visible.
        self.exit_state
            .store(ExitState::Zombie as u8, Ordering::Release);
    }

    /// Returns whether the parent has reaped the zombie process.
    pub(crate) fn is_reaped(&self) -> bool {
        self.exit_state.load(Ordering::Acquire) == ExitState::Reaped as u8
    }

    /// Marks the process reaped after detaching its PID and main task.
    pub(super) fn set_reaped(&self) {
        debug_assert_eq!(
            self.exit_state.load(Ordering::Relaxed),
            ExitState::Zombie as u8
        );
        self.exit_state
            .store(ExitState::Reaped as u8, Ordering::Release);
    }
}

impl ProcessStatus {
    /// Returns whether the process is the vfork child.
    pub(crate) fn is_vfork_child(&self) -> bool {
        self.is_vfork_child.load(Ordering::Acquire)
    }

    /// Sets whether the process is the vfork child.
    pub(crate) fn set_vfork_child(&self, is_vfork_child: bool) {
        self.is_vfork_child.store(is_vfork_child, Ordering::Release);
    }
}

impl ProcessStatus {
    /// Returns the exit code.
    pub(crate) fn exit_code(&self) -> ExitCode {
        self.exit_code.load(Ordering::Relaxed)
    }

    /// Sets the exit code.
    pub(super) fn set_exit_code(&self, exit_code: ExitCode) {
        self.exit_code.store(exit_code, Ordering::Relaxed);
    }
}

impl ProcessStatus {
    pub(super) fn stop_status(&self) -> &StopStatus {
        &self.stop_status
    }
}

#[derive(Debug)]
pub(super) struct StopStatus {
    /// Indicates whether the process is stopped.
    is_stopped: AtomicBool,

    /// Indicates whether the process's status has changed and has not yet been waited on.
    ///
    /// User programs may use the wait* syscalls to check for changes in
    /// the process's status. This field will be set to `Some(_)` once the
    /// process's status changes and will be set to `None` if the process
    /// has already been waited on.
    wait_status: SpinLock<Option<StopWaitStatus>>,
}

impl StopStatus {
    pub(self) const fn new() -> Self {
        Self {
            is_stopped: AtomicBool::new(false),
            wait_status: SpinLock::new(None),
        }
    }

    /// Stops the process by some signal.
    ///
    /// The return value indicates whether the stop status has changed.
    pub(super) fn stop(&self, signum: SigNum) -> bool {
        // Hold the lock first to avoid race conditions
        let mut wait_status = self.wait_status.lock();

        if self.is_stopped.load(Ordering::Relaxed) {
            false
        } else {
            self.is_stopped.store(true, Ordering::Relaxed);
            *wait_status = Some(StopWaitStatus::Stopped(signum));
            true
        }
    }

    /// Resumes the process.
    ///
    /// The return value indicates whether the stop status has changed.
    pub(super) fn resume(&self) -> bool {
        // Hold the lock first to avoid race conditions
        let mut wait_status = self.wait_status.lock();

        if self.is_stopped.load(Ordering::Relaxed) {
            self.is_stopped.store(false, Ordering::Relaxed);
            *wait_status = Some(StopWaitStatus::Continue);
            true
        } else {
            false
        }
    }

    /// Returns whether the process is stopped.
    pub(super) fn is_stopped(&self) -> bool {
        self.is_stopped.load(Ordering::Relaxed)
    }

    /// Returns the stop status changes for the `wait` syscall.
    pub(super) fn wait(&self, options: WaitOptions) -> Option<StopWaitStatus> {
        let mut wait_status = self.wait_status.lock();

        if options.contains(WaitOptions::WSTOPPED)
            && let Some(StopWaitStatus::Stopped(_)) = wait_status.as_ref()
        {
            return if options.contains(WaitOptions::WNOWAIT) {
                wait_status.as_ref().cloned()
            } else {
                wait_status.take()
            };
        }

        if options.contains(WaitOptions::WCONTINUED)
            && let Some(StopWaitStatus::Continue) = wait_status.as_ref()
        {
            return if options.contains(WaitOptions::WNOWAIT) {
                wait_status.as_ref().cloned()
            } else {
                wait_status.take()
            };
        }

        None
    }
}

#[derive(Clone, Debug)]
pub(super) enum StopWaitStatus {
    Stopped(SigNum),
    Continue,
}
