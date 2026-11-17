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

/// Disables virtual IRQs and reads `(was_enabled, guards)` in one
/// nonredirectable `.text.kernelet_cpu_access` sequence.
pub(crate) fn disable_local_save_with_guards() -> (bool, u32) {
    let mask: u32;
    let guards: u32;
    // SAFETY: Reading `irq_off`, reading `guards`, and masking `irq_off = 1`
    // cannot be separated by an image upcall.
    unsafe {
        crate::arch::cpu::local::record_asm!(
            "mov {mask:e}, dword ptr [{record_base} + {irq_offset}]",
            "mov {guards:e}, dword ptr [{record_base} + {guards_offset}]",
            "mov dword ptr [{record_base} + {irq_offset}], 1";
            mask = out(reg) mask,
            guards = out(reg) guards,
            irq_offset = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, irq_off),
            guards_offset = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, guards),
            options(nostack),
        );
    }
    (mask == 0, guards)
}

/// Fast user-return exit check: reads `PREEMPT_INFO` and, when no preemption
/// is needed (`preempt_info != 0`), masks virtual IRQs and reads `(was_enabled, guards)`
/// in a single `.text.kernelet_cpu_access` sequence.
#[inline(always)]
pub(crate) fn try_disable_with_guards_if_no_preempt(
    preempt_info_off: usize,
) -> Option<(bool, u32)> {
    let mut preempt = preempt_info_off;
    let mask: u32;
    let guards: usize;
    // SAFETY: Checking `PREEMPT_INFO != 0`, reading `irq_off`/`guards`, and
    // writing `irq_off = 1` execute together inside `.text.kernelet_cpu_access`.
    unsafe {
        core::arch::asm!(
            "jmp 2f",
            ".pushsection .text.kernelet_cpu_access, \"ax\", @progbits",
            "2:",
            "lea {vrec}, [rip + {fast_cpu}]",
            "mov {slot}, qword ptr [{vrec} + {slot_gs_off}]",
            "movzx {slot:e}, word ptr gs:[{slot} + 2]",
            "mov {guards}, qword ptr [{vrec} + {slot} * 8 + {local_bases_off}]",
            "mov {preempt:e}, dword ptr [{guards} + {preempt}]",
            "test {preempt:e}, {preempt:e}",
            "jz 4f",
            "mov {vrec}, qword ptr [{vrec} + {slot} * 8 + {record_ptrs_off}]",
            "mov {mask:e}, dword ptr [{vrec} + {irq_off}]",
            "mov {guards:e}, dword ptr [{vrec} + {guards_off}]",
            "mov dword ptr [{vrec} + {irq_off}], 1",
            "4:",
            "jmp 3f",
            ".popsection",
            "3:",
            vrec = out(reg) _,
            slot = out(reg) _,
            preempt = inout(reg) preempt,
            mask = out(reg) mask,
            guards = out(reg) guards,
            fast_cpu = sym entry::KERNELET_FAST_CPU,
            slot_gs_off = const core::mem::offset_of!(entry::FastCpuTable, slot_gs_offset),
            local_bases_off = const core::mem::offset_of!(entry::FastCpuTable, local_bases),
            record_ptrs_off = const core::mem::offset_of!(entry::FastCpuTable, record_ptrs),
            irq_off = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, irq_off),
            guards_off = const core::mem::offset_of!(crate::kernelet::abi::VcpuRecord, guards),
            options(nostack),
        );
    }
    if preempt as u32 != 0 {
        Some((mask == 0, guards as u32))
    } else {
        None
    }
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
