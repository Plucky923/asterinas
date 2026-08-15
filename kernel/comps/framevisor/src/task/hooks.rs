// SPDX-License-Identifier: MPL-2.0

//! Host and service callback boundaries for FrameVisor tasks.

#[cfg(target_arch = "x86_64")]
use host_ostd::arch::cpu::context::CpuException;
#[cfg(target_arch = "riscv64")]
use host_ostd::arch::cpu::context::CpuException;
#[cfg(target_arch = "loongarch64")]
use host_ostd::arch::cpu::context::CpuExceptionInfo as CpuException;
use host_ostd::irq::{DisabledLocalIrqGuard as OstdDisabledLocalIrqGuard, InterruptLevel};

use super::binding::current_frame_vm;
use crate::{irq::DisabledLocalIrqGuard, prelude::Result, vm};

/// Installs the post-schedule entry point for the current FrameVM.
pub fn inject_post_schedule_handler(handler: fn() -> bool) {
    let Some(frame_vm) = current_frame_vm() else {
        return;
    };

    frame_vm
        .service_entry_points()
        .install_post_schedule(handler);
}

/// Installs the pre-schedule entry point for the current FrameVM.
pub fn inject_pre_schedule_handler(handler: fn(&DisabledLocalIrqGuard)) {
    let Some(frame_vm) = current_frame_vm() else {
        return;
    };

    frame_vm
        .service_entry_points()
        .install_pre_schedule(handler);
}

/// Installs the pre-user-run entry point for the current FrameVM.
pub fn inject_pre_user_run_handler(handler: fn(&DisabledLocalIrqGuard)) {
    let Some(frame_vm) = current_frame_vm() else {
        return;
    };

    frame_vm
        .service_entry_points()
        .install_pre_user_run(handler);
}

/// Installs the shutdown entry point for the current FrameVM service.
pub fn inject_shutdown_handler(handler: fn()) {
    let Some(frame_vm) = current_frame_vm() else {
        return;
    };

    frame_vm.service_entry_points().install_shutdown(handler);
}

pub(crate) fn inject_user_page_fault_handler(handler: vm::UserPageFaultEntryPoint) {
    let Some(frame_vm) = current_frame_vm() else {
        return;
    };

    frame_vm
        .service_entry_points()
        .install_user_page_fault(handler);
}

/// Dispatches pre-schedule accounting for service backing tasks.
pub fn dispatch_pre_schedule(_guard: &OstdDisabledLocalIrqGuard) -> bool {
    let Some(frame_vm) = current_frame_vm() else {
        return false;
    };

    if let Some(handler) = frame_vm.service_entry_points().enter_pre_schedule() {
        let service_guard = crate::irq::disable_local();
        (handler.handler())(&service_guard);
    }

    true
}

/// Dispatches a post-schedule handler for managed tasks.
/// Returns true if handler was dispatched.
pub fn dispatch_post_schedule() -> bool {
    let Some(frame_vm) = current_frame_vm() else {
        return false;
    };

    super::scheduler::enable_preemption_on_cpu();
    if let Some(handler) = frame_vm.service_entry_points().enter_post_schedule() {
        (handler.handler())();
    }
    true
}

/// Dispatches a pre-user-run handler for managed tasks.
pub fn dispatch_pre_user_run(_guard: &OstdDisabledLocalIrqGuard) -> bool {
    let Some(frame_vm) = current_frame_vm() else {
        return false;
    };

    if let Some(handler) = frame_vm.service_entry_points().enter_pre_user_run() {
        let service_guard = crate::irq::disable_local();
        (handler.handler())(&service_guard);
    }
    true
}

/// Dispatches a user page fault handler for managed tasks.
pub fn dispatch_user_page_fault(info: &CpuException) -> Option<Result<(), ()>> {
    // OSTD's `CurrentTask` local-data access is task-context-only. A fault
    // raised while an interrupt callback touches a user buffer must be
    // recovered by the exception table without entering the kernel VMAR path.
    if !InterruptLevel::current().is_task_context() {
        return Some(Err(()));
    }
    let frame_vm = current_frame_vm()?;
    let handler = frame_vm.service_entry_points().enter_user_page_fault();
    Some(handler.map_or(Err(()), |handler| (handler.handler())(info)))
}
