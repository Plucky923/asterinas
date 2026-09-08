// SPDX-License-Identifier: MPL-2.0

//! Host and service callback boundaries for FrameVisor tasks.

#[cfg(target_arch = "x86_64")]
use host_ostd::arch::cpu::context::CpuException;
#[cfg(target_arch = "riscv64")]
use host_ostd::arch::cpu::context::CpuException;
#[cfg(target_arch = "loongarch64")]
use host_ostd::arch::cpu::context::CpuExceptionInfo as CpuException;
use host_ostd::irq::{DisabledLocalIrqGuard as OstdDisabledLocalIrqGuard, InterruptLevel};

use super::current::current_frame_vm;
use crate::{irq::DisabledLocalIrqGuard, prelude::Result, vm};

/// Installs the post-schedule entry point for the current FrameVM.
pub fn inject_post_schedule_handler(handler: fn()) {
    let Some(frame_vm) = current_frame_vm() else {
        return;
    };

    frame_vm
        .service_entry_points()
        .install_post_schedule(handler);
}

/// Installs a private physical-suspend handler for outer Frame group switches.
#[doc(hidden)]
pub fn inject_physical_pre_schedule_handler(handler: fn(&DisabledLocalIrqGuard)) {
    let Some(frame_vm) = current_frame_vm() else {
        return;
    };
    frame_vm
        .service_entry_points()
        .install_physical_pre_schedule(handler);
}

/// Installs a private physical-resume handler for outer Frame group switches.
#[doc(hidden)]
pub fn inject_physical_post_schedule_handler(handler: fn()) {
    let Some(frame_vm) = current_frame_vm() else {
        return;
    };
    frame_vm
        .service_entry_points()
        .install_physical_post_schedule(handler);
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

/// Performs the private physical-suspend half of an outer Frame group switch.
///
/// This intentionally does not invoke the service-visible logical PRE hook:
/// an outer pause may resume the exact same continuation.  Architecture-
/// specific supplemental-state save hooks attach here as the Frame runtime
/// grows, separately from the logical task-switch callback.
#[doc(hidden)]
pub fn dispatch_physical_pre_schedule(_guard: &OstdDisabledLocalIrqGuard) {
    let Some(frame_vm) = current_frame_vm() else {
        return;
    };
    if let Some(handler) = frame_vm
        .service_entry_points()
        .enter_physical_pre_schedule()
    {
        let service_guard = crate::irq::disable_local();
        (handler.handler())(&service_guard);
    }
}

/// Dispatches a post-schedule handler for managed tasks.
/// Returns true if handler was dispatched.
pub fn dispatch_post_schedule() -> bool {
    let Some(frame_vm) = current_frame_vm() else {
        return false;
    };

    dispatch_pending_vcpu_events(&frame_vm);
    super::scheduler::enable_preemption_on_cpu();
    if let Some(handler) = frame_vm.service_entry_points().enter_post_schedule() {
        (handler.handler())();
    }
    true
}

/// Performs the private physical-resume half of an outer Frame group switch.
///
/// Logical POST is deliberately excluded and is dispatched only after a
/// pointer-checked pending A -> B continuation handoff commits.
#[doc(hidden)]
pub fn dispatch_physical_post_schedule() {
    let Some(frame_vm) = current_frame_vm() else {
        return;
    };
    dispatch_pending_vcpu_events(&frame_vm);
    super::scheduler::enable_preemption_on_cpu();
    if let Some(handler) = frame_vm
        .service_entry_points()
        .enter_physical_post_schedule()
    {
        (handler.handler())();
    }
}

fn dispatch_pending_vcpu_events(frame_vm: &crate::vm::FrameVm) {
    let Some(vcpu_id) = super::current_frame_vcpu_id() else {
        return;
    };
    if vcpu_id.vm_id() == frame_vm.id()
        && let Some(handler) = frame_vm.interrupt_handler(vcpu_id.vcpu_index())
    {
        handler.deliver_pending_on_current_vcpu();
    }
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
