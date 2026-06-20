// SPDX-License-Identifier: MPL-2.0

//! Panic support.

/// Aborts the system.
pub fn abort() -> ! {
    crate::power::poweroff(crate::power::ExitCode::Failure)
}
