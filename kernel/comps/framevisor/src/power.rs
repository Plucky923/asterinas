// SPDX-License-Identifier: MPL-2.0

//! Power-management APIs exposed through the OSTD-compatible surface.

use crate::sync::Once;

/// An exit code that denotes the reason for restarting or powering off.
pub enum ExitCode {
    /// The code that indicates a successful exit.
    Success,
    /// The code that indicates a failed exit.
    Failure,
}

type PowerHandler = fn(ExitCode);

static RESTART_HANDLER: Once<PowerHandler> = Once::new();
static POWEROFF_HANDLER: Once<PowerHandler> = Once::new();

/// Injects a handler that can restart the system.
pub fn inject_restart_handler(handler: fn(ExitCode)) {
    RESTART_HANDLER.call_once(|| handler);
}

/// Restarts the system.
pub fn restart(code: ExitCode) -> ! {
    if let Some(handler) = RESTART_HANDLER.get() {
        handler(code);
    }

    halt_system()
}

/// Injects a handler that can power off the system.
pub fn inject_poweroff_handler(handler: fn(ExitCode)) {
    POWEROFF_HANDLER.call_once(|| handler);
}

/// Powers off the system.
pub fn poweroff(code: ExitCode) -> ! {
    if let Some(handler) = POWEROFF_HANDLER.get() {
        handler(code);
    }

    halt_system()
}

fn halt_system() -> ! {
    loop {
        crate::task::Task::yield_now();
    }
}

#[cfg(feature = "host-api")]
pub(crate) fn init_power() {
    inject_restart_handler(shutdown_current_service);
    inject_poweroff_handler(shutdown_current_service);
}

#[cfg(feature = "host-api")]
fn shutdown_current_service(_code: ExitCode) {
    let _ = crate::boot::shutdown_current_service();
}
