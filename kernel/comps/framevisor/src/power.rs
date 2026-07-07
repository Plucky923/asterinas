// SPDX-License-Identifier: MPL-2.0

//! Power-management APIs exposed through the OSTD-compatible surface.

use crate::{
    boot,
    sync::{Once, WaitQueue},
    vm::VmId,
};

/// An exit code that denotes the reason for restarting or powering off.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitCode {
    /// The code that indicates a successful exit.
    Success,
    /// The code that indicates a failed exit.
    Failure,
    /// The concrete guest status code that indicates a failed exit.
    FailureStatus(i32),
}

/// A service-originated power request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PowerAction {
    /// The service requested poweroff.
    Poweroff,
    /// The service requested restart.
    Restart,
}

type PowerHandler = fn(ExitCode);
type ServicePowerEventHandler = fn(VmId, PowerAction, i32);

static RESTART_HANDLER: Once<PowerHandler> = Once::new();
static POWEROFF_HANDLER: Once<PowerHandler> = Once::new();
static SERVICE_POWER_EVENT_HANDLER: Once<ServicePowerEventHandler> = Once::new();

/// Injects a handler for service-originated terminal power events.
pub fn inject_service_power_event_handler(handler: ServicePowerEventHandler) {
    SERVICE_POWER_EVENT_HANDLER.call_once(|| handler);
}

/// Injects a handler that can restart the system.
pub fn inject_restart_handler(handler: fn(ExitCode)) {
    RESTART_HANDLER.call_once(|| handler);
}

/// Restarts the system.
pub fn restart(code: ExitCode) -> ! {
    notify_service_power_event(PowerAction::Restart, status_code_from_exit_code(code));
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
    notify_service_power_event(PowerAction::Poweroff, status_code_from_exit_code(code));
    if let Some(handler) = POWEROFF_HANDLER.get() {
        handler(code);
    }
    halt_system()
}

fn halt_system() -> ! {
    let wait_queue = WaitQueue::new();
    loop {
        wait_queue.wait_until(|| None::<()>);
    }
}

pub(crate) fn init_power() {
    inject_restart_handler(shutdown_current_service);
    inject_poweroff_handler(shutdown_current_service);
}

fn shutdown_current_service(_code: ExitCode) {
    let _ = boot::shutdown_current_service();
}

fn notify_service_power_event(action: PowerAction, status_code: i32) {
    let Some(handler) = SERVICE_POWER_EVENT_HANDLER.get() else {
        crate::early_println!(
            "[framevisor] service power event dropped: handler missing action={:?} status={}",
            action,
            status_code
        );
        return;
    };
    let Some(vm_id) = boot::current_service_vm_id() else {
        crate::early_println!(
            "[framevisor] service power event dropped: vm missing action={:?} status={}",
            action,
            status_code
        );
        return;
    };

    handler(vm_id, action, status_code);
}

const fn status_code_from_exit_code(code: ExitCode) -> i32 {
    match code {
        ExitCode::Success => 0,
        ExitCode::Failure => 1,
        ExitCode::FailureStatus(status_code) => status_code,
    }
}
