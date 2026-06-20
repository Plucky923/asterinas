// SPDX-License-Identifier: MPL-2.0

//! Kernel-local signal disposition and mask state.

use ostd::sync::SpinLock as Mutex;

use crate::error::{Errno, Error, Result};

const MIN_SIGNAL: u8 = 1;
const MAX_SIGNAL: u8 = 64;
const SIGNAL_COUNT: usize = MAX_SIGNAL as usize;
const SIGKILL: u8 = 9;
const SIGSTOP: u8 = 19;
const SIG_DFL: usize = 0;
const SIG_IGN: usize = 1;
const SA_RESTORER: u32 = 0x0400_0000;
const VALID_SIGNAL_ACTION_FLAGS: u32 =
    0x1 | 0x2 | 0x4 | SA_RESTORER | 0x0800_0000 | 0x1000_0000 | 0x4000_0000 | 0x8000_0000;

/// Linux `struct sigaction` fields used by the x86-64 syscall ABI.
#[derive(Clone, Copy, Debug, Default)]
pub struct RawSignalAction {
    /// Signal handler pointer.
    pub handler_ptr: usize,
    /// Signal action flags.
    pub flags: u32,
    /// Signal restorer trampoline pointer.
    pub restorer_ptr: usize,
    /// Signal mask installed while the handler runs.
    pub mask: u64,
}

impl RawSignalAction {
    fn is_user_handler(self) -> bool {
        self.handler_ptr != SIG_DFL && self.handler_ptr != SIG_IGN
    }
}

/// Process-level signal dispositions.
pub struct SignalActions {
    actions: Mutex<[RawSignalAction; SIGNAL_COUNT]>,
}

impl SignalActions {
    /// Creates signal dispositions with all signals set to default action.
    pub fn new() -> Self {
        Self {
            actions: Mutex::new([RawSignalAction::default(); SIGNAL_COUNT]),
        }
    }

    /// Creates an independent copy of the current dispositions.
    pub fn snapshot(&self) -> Self {
        Self {
            actions: Mutex::new(*self.actions.lock()),
        }
    }

    /// Returns the current action for `signal`.
    pub fn get(&self, signal: u8) -> Result<RawSignalAction> {
        let index = signal_index(signal)?;
        Ok(self.actions.lock()[index])
    }

    /// Sets the action for `signal` and returns the previous action.
    pub fn set(&self, signal: u8, action: RawSignalAction) -> Result<RawSignalAction> {
        let index = signal_index(signal)?;
        if matches!(signal, SIGKILL | SIGSTOP) {
            return Err(Error::new(Errno::EINVAL));
        }
        validate_signal_action(action)?;

        let mut actions = self.actions.lock();
        let old_action = actions[index];
        actions[index] = action;
        Ok(old_action)
    }

    /// Resets user handlers during `execve`, preserving ignored/default signals.
    pub fn reset_user_handlers_for_exec(&self) {
        let mut actions = self.actions.lock();
        for action in actions.iter_mut() {
            if action.is_user_handler() {
                *action = RawSignalAction::default();
            }
        }
    }
}

/// Removes signals that Linux does not allow user space to block.
pub fn sanitize_signal_mask(mask: u64) -> u64 {
    mask & !signal_bit_unchecked(SIGKILL) & !signal_bit_unchecked(SIGSTOP)
}

/// Removes signal action flags that the kernel would not preserve.
pub fn sanitize_signal_action_flags(flags: u32) -> u32 {
    flags & VALID_SIGNAL_ACTION_FLAGS
}

fn signal_index(signal: u8) -> Result<usize> {
    if !(MIN_SIGNAL..=MAX_SIGNAL).contains(&signal) {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok((signal - MIN_SIGNAL) as usize)
}

fn signal_bit_unchecked(signal: u8) -> u64 {
    1_u64 << (signal - MIN_SIGNAL)
}

fn validate_signal_action(action: RawSignalAction) -> Result<()> {
    if !action.is_user_handler() {
        return Ok(());
    }
    validate_user_signal_action(action)
}

#[cfg(target_arch = "x86_64")]
fn validate_user_signal_action(action: RawSignalAction) -> Result<()> {
    if action.flags & SA_RESTORER != 0 && action.restorer_ptr != 0 {
        return Ok(());
    }
    Err(Error::new(Errno::EINVAL))
}

#[cfg(target_arch = "riscv64")]
fn validate_user_signal_action(_action: RawSignalAction) -> Result<()> {
    Ok(())
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
fn validate_user_signal_action(_action: RawSignalAction) -> Result<()> {
    Err(Error::new(Errno::EINVAL))
}

#[cfg(ktest)]
mod tests {
    use ostd::prelude::ktest;

    use super::*;

    const SIGUSR1: u8 = 10;

    #[ktest]
    fn user_signal_action_with_restorer_is_accepted() {
        let actions = SignalActions::new();
        let action = RawSignalAction {
            handler_ptr: 0x1000,
            flags: SA_RESTORER,
            restorer_ptr: 0x2000,
            mask: 0,
        };

        let old_action = actions.set(SIGUSR1, action).unwrap();

        assert_eq!(old_action.handler_ptr, SIG_DFL);
        assert_eq!(
            actions.get(SIGUSR1).unwrap().handler_ptr,
            action.handler_ptr
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[ktest]
    fn x86_user_signal_action_requires_restorer() {
        let actions = SignalActions::new();
        let action = RawSignalAction {
            handler_ptr: 0x1000,
            flags: 0,
            restorer_ptr: 0,
            mask: 0,
        };

        assert_eq!(
            actions.set(SIGUSR1, action).unwrap_err().errno(),
            Errno::EINVAL
        );
    }

    #[ktest]
    fn sigkill_and_sigstop_actions_are_rejected() {
        let actions = SignalActions::new();
        let action = RawSignalAction {
            handler_ptr: SIG_IGN,
            flags: 0,
            restorer_ptr: 0,
            mask: 0,
        };

        assert_eq!(
            actions.set(SIGKILL, action).unwrap_err().errno(),
            Errno::EINVAL
        );
        assert_eq!(
            actions.set(SIGSTOP, action).unwrap_err().errno(),
            Errno::EINVAL
        );
    }

    #[ktest]
    fn unknown_signal_action_flags_are_discarded() {
        let unknown_flags = 0x0200_0000 | 0x2000_0000;
        let known_flags = 0x0400_0000 | 0x1000_0000;

        assert_eq!(
            sanitize_signal_action_flags(unknown_flags | known_flags),
            known_flags
        );
    }
}
