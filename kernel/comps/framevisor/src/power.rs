// SPDX-License-Identifier: MPL-2.0

//! Power-management APIs exposed through the OSTD-compatible surface.

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

/// Restarts the system.
pub fn restart(code: ExitCode) -> ! {
    let Some(frame_vm) = crate::task::current_frame_vm() else {
        crate::early_println!(
            "[framevisor] service power event dropped: vm missing action={:?} status={}",
            PowerAction::Restart,
            status_code_from_exit_code(code)
        );
        halt_system();
    };
    if let Some(shutdown) = frame_vm.service_entry_points().enter_shutdown() {
        (shutdown.handler())();
    }
    frame_vm.devices().console().clear_input();
    frame_vm.notify_power_event(PowerAction::Restart, status_code_from_exit_code(code));
    halt_system()
}

/// Powers off the system.
pub fn poweroff(code: ExitCode) -> ! {
    let Some(frame_vm) = crate::task::current_frame_vm() else {
        crate::early_println!(
            "[framevisor] service power event dropped: vm missing action={:?} status={}",
            PowerAction::Poweroff,
            status_code_from_exit_code(code)
        );
        halt_system();
    };
    if let Some(shutdown) = frame_vm.service_entry_points().enter_shutdown() {
        (shutdown.handler())();
    }
    frame_vm.devices().console().clear_input();
    crate::early_println!(
        "[FrameVM] poweroff requested: action={:?}, code={}",
        PowerAction::Poweroff,
        status_code_from_exit_code(code)
    );
    frame_vm.notify_power_event(PowerAction::Poweroff, status_code_from_exit_code(code));
    halt_system()
}

fn halt_system() -> ! {
    // Mark the VM as stopping before the final service carrier leaves its
    // inner runqueue. That lets the scheduler retire a vCPU with no successor
    // into the Host scheduler instead of waiting forever for new service work.
    if let Some(frame_vm) = crate::task::current_frame_vm() {
        frame_vm.request_stop();
    }
    crate::task::scheduler::exit_current_task();
}

const fn status_code_from_exit_code(code: ExitCode) -> i32 {
    match code {
        ExitCode::Success => 0,
        ExitCode::Failure => 1,
        ExitCode::FailureStatus(status_code) => status_code,
    }
}
