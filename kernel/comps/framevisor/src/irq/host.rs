// SPDX-License-Identifier: MPL-2.0

//! Host interrupt context and FrameVM lock critical sections.

use host_ostd::{
    arch::trap::TrapFrame,
    sync::GuardTransfer as OstdGuardTransfer,
    task::atomic_mode::{
        AsAtomicModeGuard as OstdAsAtomicModeGuard, InAtomicMode as OstdInAtomicMode,
    },
};

use crate::{
    cpu::{CpuId, PrivilegeLevel},
    sync::GuardTransfer,
    task::{self, DisabledPreemptGuard, atomic_mode::AsAtomicModeGuard, disable_preempt},
};

const LEVEL_VALUE_SHIFT: u8 = 1;
const LEVEL_CPU_PRIVILEGE_MASK: u8 = 1;

host_ostd::cpu_local_cell! {
    static INTERRUPT_LEVEL: u8 = 0;
}

/// The interrupt nesting level of the current Host CPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptLevel {
    /// Task context.
    L0,
    /// First-level interrupt context.
    L1(PrivilegeLevel),
    /// Nested interrupt context.
    L2,
}

impl InterruptLevel {
    /// Returns the current Host interrupt level.
    pub fn current() -> Self {
        decode_level(INTERRUPT_LEVEL.load())
    }

    /// Returns the numeric nesting level.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::L0 => 0,
            Self::L1(_) => 1,
            Self::L2 => 2,
        }
    }

    /// Returns whether execution is in task context.
    pub fn is_task_context(self) -> bool {
        self == Self::L0
    }

    /// Returns whether execution is in interrupt context.
    pub fn is_interrupt_context(self) -> bool {
        matches!(self, Self::L1(_) | Self::L2)
    }
}

/// Disables Host preemption and the current FrameVM vCPU's virtual IRQs.
pub fn disable_local() -> DisabledLocalIrqGuard {
    let guard = disable_preempt();
    let handler = host_ostd::task::Task::current()
        .and_then(|current| {
            let data = current.extension().downcast_ref::<task::FrameTaskData>()?;
            (data.kind() != task::FrameTaskKind::Interrupt).then(|| data.frame_vcpu_id())
        })
        .and_then(|id| {
            let frame_vm = crate::vm::get_vm_by_id(id.vm_id())?;
            let handler = frame_vm.interrupt_handler(id.vcpu_index())?;
            handler.disable_virtual_interrupts();
            Some(handler)
        });

    DisabledLocalIrqGuard { guard, handler }
}

/// Guard held while Host preemption and one vCPU's virtual IRQs are disabled.
#[must_use]
pub struct DisabledLocalIrqGuard {
    guard: DisabledPreemptGuard,
    handler: Option<alloc::sync::Arc<super::InterruptHandler>>,
}

impl DisabledLocalIrqGuard {
    /// Returns the pinned Host CPU.
    pub fn current_cpu(&self) -> CpuId {
        self.guard.current_cpu()
    }
}

impl OstdAsAtomicModeGuard for DisabledLocalIrqGuard {
    fn as_atomic_mode_guard(&self) -> &dyn OstdInAtomicMode {
        self.guard.as_atomic_mode_guard()
    }
}

impl AsAtomicModeGuard for DisabledLocalIrqGuard {
    type Inner = <DisabledPreemptGuard as AsAtomicModeGuard>::Inner;

    fn get_inner(&self) -> &Self::Inner {
        self.guard.get_inner()
    }
}

impl OstdGuardTransfer for DisabledLocalIrqGuard {
    fn transfer_to(&mut self) -> Self {
        Self {
            guard: <DisabledPreemptGuard as OstdGuardTransfer>::transfer_to(&mut self.guard),
            handler: self.handler.take(),
        }
    }
}

impl GuardTransfer for DisabledLocalIrqGuard {
    fn transfer_to(&mut self) -> Self {
        <Self as OstdGuardTransfer>::transfer_to(self)
    }
}

impl Drop for DisabledLocalIrqGuard {
    fn drop(&mut self) {
        if let Some(handler) = self.handler.take() {
            handler.enable_virtual_interrupts();
        }
    }
}

/// Executes a callback at Host timer-interrupt nesting level.
pub(crate) fn enter_timer_interrupt(callback: impl FnOnce()) {
    enter_interrupt(PrivilegeLevel::Kernel, callback);
}

pub(crate) fn enter_interrupt(privilege: PrivilegeLevel, callback: impl FnOnce()) {
    let previous = decode_level(INTERRUPT_LEVEL.load());
    let next = match previous {
        InterruptLevel::L0 => InterruptLevel::L1(privilege),
        InterruptLevel::L1(_) | InterruptLevel::L2 => InterruptLevel::L2,
    };
    INTERRUPT_LEVEL.store(encode_level(next));
    callback();
    INTERRUPT_LEVEL.store(encode_level(previous));
}

/// Creates a synthetic Host trap frame for virtual IRQ callback delivery.
#[cfg(target_arch = "x86_64")]
pub fn make_synthetic_trapframe(irq_num: u8) -> TrapFrame {
    TrapFrame {
        trap_num: irq_num as usize,
        error_code: 0,
        ..Default::default()
    }
}

#[cfg(target_arch = "riscv64")]
pub fn make_synthetic_trapframe(_irq_num: u8) -> TrapFrame {
    TrapFrame {
        general: Default::default(),
        sstatus: 0,
        sepc: 0,
    }
}

#[cfg(target_arch = "loongarch64")]
pub fn make_synthetic_trapframe(_irq_num: u8) -> TrapFrame {
    TrapFrame::default()
}

fn decode_level(raw: u8) -> InterruptLevel {
    match raw >> LEVEL_VALUE_SHIFT {
        0 => InterruptLevel::L0,
        1 => {
            let privilege = if raw & LEVEL_CPU_PRIVILEGE_MASK == 0 {
                PrivilegeLevel::Kernel
            } else {
                PrivilegeLevel::User
            };
            InterruptLevel::L1(privilege)
        }
        _ => InterruptLevel::L2,
    }
}

fn encode_level(level: InterruptLevel) -> u8 {
    match level {
        InterruptLevel::L0 => 0,
        InterruptLevel::L1(PrivilegeLevel::Kernel) => 1 << LEVEL_VALUE_SHIFT,
        InterruptLevel::L1(PrivilegeLevel::User) => {
            (1 << LEVEL_VALUE_SHIFT) | LEVEL_CPU_PRIVILEGE_MASK
        }
        InterruptLevel::L2 => 2 << LEVEL_VALUE_SHIFT,
    }
}
