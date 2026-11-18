// SPDX-License-Identifier: MPL-2.0

//! Virtual local-interrupt state for a kernelet vCPU.

use core::sync::atomic::Ordering;

use crate::kernelet::entry;

pub(crate) fn enable_local() {
    let pending: u64;
    // SAFETY: Unmasking and the pending read share one protected lookup.
    // The memory-clobbering asm implements the original Release store and
    // Acquire load with x86's ordinary scalar instructions.
    unsafe {
        crate::arch::cpu::local::record_asm!(
            "mov dword ptr [{record_base} + {irq_offset}], 0",
            "mov {pending}, qword ptr [{record_base} + {pending_offset}]";
            pending = out(reg) pending,
            irq_offset = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, irq_off),
            pending_offset = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, pending),
            options(nostack),
        );
    }
    // A local wake can request preemption without publishing a pending IRQ.
    // When neither action is needed, avoid all Task/context gate lookups.
    if pending == 0 && !crate::task::scheduler::should_preempt() {
        return;
    }
    finish_enable_local_slow();
}

/// Slow continuation after unmasking virtual IRQs when `pending != 0` or a
/// scheduler preemption may be due.
#[cold]
#[inline(never)]
pub(crate) fn finish_enable_local_slow() {
    if !can_receive_virtual_interrupts() {
        // Bootstrap must finish installing its idle Task. A scheduling
        // transition or upcall epilogue must finish before another upcall.
        return;
    }
    crate::task::scheduler::might_preempt();
    if entry::vcpu_record().pending.load(Ordering::Acquire) == 0
        || entry::copy_fault_record().pending.load(Ordering::Acquire) != 0
    {
        return;
    }
    let _ = entry::deliver_pending();
}

#[inline]
fn can_receive_virtual_interrupts() -> bool {
    entry::vcpu_record().guards.load(Ordering::Acquire) == 0
        && entry::vcpu_record().irq_off.load(Ordering::Acquire) == 0
        && crate::irq::InterruptLevel::current().is_task_context()
        && !crate::task::virq_delivery_deferred()
        && crate::task::Task::current().is_some()
}

pub(crate) fn disable_local() {
    set_local_mask(true);
}

/// Saves the current mask and disables virtual IRQs in one protected access.
pub(crate) fn disable_local_save() -> bool {
    let mask: u32;
    // SAFETY: The mask read and conditional Release store cannot be separated
    // by an image upcall. Native carrier preemption preserves the selected vCPU.
    unsafe {
        crate::arch::cpu::local::record_asm!(
            "mov {mask:e}, dword ptr [{record_base} + {irq_offset}]",
            "test {mask:e}, {mask:e}",
            "jnz 4f",
            "mov dword ptr [{record_base} + {irq_offset}], 1",
            "4:";
            mask = out(reg) mask,
            irq_offset = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, irq_off),
            options(nostack),
        );
    }
    mask == 0
}

/// Disables virtual IRQs and reads the guard count in one
/// nonredirectable `.text.kernelet_cpu_access` sequence.
fn disable_local_with_guards() -> u32 {
    let guards: u32;
    // SAFETY: Reading `guards` and masking `irq_off = 1` cannot be separated
    // by an image upcall.
    unsafe {
        crate::arch::cpu::local::record_asm!(
            "mov {guards:e}, dword ptr [{record_base} + {guards_offset}]",
            "mov dword ptr [{record_base} + {irq_offset}], 1";
            guards = out(reg) guards,
            irq_offset = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, irq_off),
            guards_offset = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, guards),
            options(nostack),
        );
    }
    guards
}

// A nonnegative result is the vCPU's guard count.
const PREEMPTION_PENDING: i64 = -1;

/// Masks virtual IRQs after handling any pending preemption and checks for open guards.
#[inline(always)]
pub(crate) fn disable_local_for_user_return(current_task: &crate::task::CurrentTask) {
    let status: i64;
    // SAFETY: Every switch-in refreshes the current task's record pointer
    // before it resumes. Loading that pointer, checking `PREEMPT_INFO`, and
    // masking IRQs execute together inside `.text.kernelet_cpu_access`, so
    // migration cannot leave a stale pointer between the load and its uses.
    // Host preemption preserves the vCPU and its pinned shared record.
    unsafe {
        core::arch::asm!(
            "jmp 2f",
            ".pushsection .text.kernelet_cpu_access, \"ax\", @progbits",
            "2:",
            "mov {vrec}, qword ptr [{record_ptr}]",
            "mov {status}, qword ptr [{vrec} + {local_base_off}]",
            "cmp dword ptr [{status} + {preempt_info_off}], 0",
            "jz 4f",
            "mov {status:e}, dword ptr [{vrec} + {guards_off}]",
            "mov dword ptr [{vrec} + {irq_off}], 1",
            "jmp 3f",
            "4:",
            "mov {status}, {preemption_pending}",
            "jmp 3f",
            ".popsection",
            "3:",
            record_ptr = in(reg) current_task.active_vcpu_record_ptr(),
            vrec = out(reg) _,
            status = out(reg) status,
            preempt_info_off = in(reg) crate::task::Task::preempt_info_offset(),
            preemption_pending = const PREEMPTION_PENDING,
            local_base_off = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, cpu_local_base),
            irq_off = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, irq_off),
            guards_off = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, guards),
            options(nostack),
        );
    }
    if status != 0 {
        finish_disable_for_user_return(status);
    }
}

#[cold]
#[inline(never)]
fn finish_disable_for_user_return(status: i64) {
    let guards = if status == PREEMPTION_PENDING {
        crate::task::scheduler::might_preempt();
        disable_local_with_guards()
    } else {
        status as u32
    };
    assert_eq!(
        guards, 0,
        "returning to user mode with active preemption guard (guards={guards})"
    );
}

pub(crate) fn is_local_enabled() -> bool {
    let mask: u32;
    // SAFETY: The record selection and state read cannot be separated by a
    // virtual upcall. The Host pins this validated cooperation mapping.
    unsafe {
        crate::arch::cpu::local::record_asm!(
            "mov {mask:e}, dword ptr [{record_base} + {irq_offset}]";
            mask = out(reg) mask,
            irq_offset = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, irq_off),
            options(nostack, readonly),
        );
    }
    mask == 0
}

#[inline]
fn set_local_mask(disabled: bool) {
    // SAFETY: The complete selection and store are nonredirectable. The
    // memory-clobbering asm plus x86 store ordering implements Release.
    unsafe {
        crate::arch::cpu::local::record_asm!(
            "mov dword ptr [{record_base} + {irq_offset}], {mask:e}";
            mask = in(reg) u32::from(disabled),
            irq_offset = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, irq_off),
            options(nostack),
        );
    }
}
