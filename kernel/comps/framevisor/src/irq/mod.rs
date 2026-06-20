// SPDX-License-Identifier: MPL-2.0

//! IRQ handling.

use alloc::{boxed::Box, vec::Vec};
#[cfg(feature = "host-api")]
use core::sync::atomic::{AtomicBool, AtomicU64};
use core::sync::atomic::{AtomicU8, Ordering};

use host_ostd::{
    arch::trap::TrapFrame,
    sync::GuardTransfer as OstdGuardTransfer,
    task::atomic_mode::{
        AsAtomicModeGuard as OstdAsAtomicModeGuard, InAtomicMode as OstdInAtomicMode,
    },
};

use crate::{
    cpu::{CpuId, PrivilegeLevel},
    prelude::*,
    sync::{GuardTransfer, Once, RwLock},
    task::{
        self, DisabledPreemptGuard, atomic_mode::AsAtomicModeGuard, disable_preempt, scheduler,
    },
};
#[cfg(feature = "host-api")]
use crate::{
    iht,
    vm::{self, VmId},
};

#[cfg(feature = "host-api")]
const FRAMEVSOCK_IRQ_NUM: u8 = 0x80;

/// IRQ number range for the IRQ allocator.
const IRQ_NUM_MIN: u8 = 0x80;
const IRQ_NUM_MAX: u8 = 0x8F;
const NUMBER_OF_IRQS: usize = (IRQ_NUM_MAX - IRQ_NUM_MIN + 1) as usize;
const MAX_IRQ_LEVEL_CPUS: usize = 256;
const IRQ_LEVEL_VAL_OFFSET: u8 = 1;
const IRQ_LEVEL_CPU_PRIV_MASK: u8 = 1 << 0;

static INTERRUPT_LEVELS: [AtomicU8; MAX_IRQ_LEVEL_CPUS] =
    [const { AtomicU8::new(0) }; MAX_IRQ_LEVEL_CPUS];
static BOTTOM_HALF_HANDLER_L1: Once<fn(DisabledLocalIrqGuard, u8) -> DisabledLocalIrqGuard> =
    Once::new();
static BOTTOM_HALF_HANDLER_L2: Once<fn(u8)> = Once::new();

/// Disables local IRQ delivery for the current task.
pub fn disable_local() -> DisabledLocalIrqGuard {
    let guard = disable_preempt();
    let virtual_interrupt_task_group_id = scheduler::enter_virtual_interrupt_disabled_section();
    let priority_boost_task_key =
        virtual_interrupt_task_group_id.and_then(|_| task::enter_virtual_irq_priority_boost());

    DisabledLocalIrqGuard {
        guard,
        virtual_interrupt_token: virtual_interrupt_task_group_id,
        priority_boost_task_key,
    }
}

/// A guard for disabled local IRQs.
#[derive(Debug)]
#[must_use]
pub struct DisabledLocalIrqGuard {
    guard: DisabledPreemptGuard,
    virtual_interrupt_token: Option<scheduler::VirtualInterruptToken>,
    priority_boost_task_key: Option<usize>,
}

impl DisabledLocalIrqGuard {
    /// Returns the pinned current CPU.
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
            virtual_interrupt_token: self.virtual_interrupt_token.take(),
            priority_boost_task_key: self.priority_boost_task_key.take(),
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
        if let Some(task_key) = self.priority_boost_task_key.take() {
            task::exit_virtual_irq_priority_boost(task_key);
        }
        if let Some(token) = self.virtual_interrupt_token.take() {
            scheduler::exit_virtual_interrupt_disabled_section(token);
        }
    }
}

/// The current interrupt level on a CPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptLevel {
    /// Level 0 (the task context).
    L0,
    /// Level 1 (the interrupt context).
    L1(PrivilegeLevel),
    /// Level 2 (the interrupt context due to nested interrupts).
    L2,
}

impl InterruptLevel {
    /// Returns the current interrupt level of this CPU.
    pub fn current() -> Self {
        decode_interrupt_level(current_interrupt_level_slot().load(Ordering::Acquire))
    }

    /// Returns the interrupt level as an integer between 0 and 2.
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::L0 => 0,
            Self::L1(_) => 1,
            Self::L2 => 2,
        }
    }

    /// Checks if the CPU is currently in task context.
    pub fn is_task_context(&self) -> bool {
        *self == Self::L0
    }

    /// Checks if the CPU is currently in interrupt context.
    pub fn is_interrupt_context(&self) -> bool {
        matches!(self, Self::L1(_) | Self::L2)
    }
}

/// Registers a bottom-half callback to be executed at interrupt level 1.
pub fn register_bottom_half_handler_l1(
    func: fn(DisabledLocalIrqGuard, u8) -> DisabledLocalIrqGuard,
) {
    BOTTOM_HALF_HANDLER_L1.call_once(|| func);
}

/// Registers a bottom-half callback to be executed at interrupt level 2.
pub fn register_bottom_half_handler_l2(func: fn(u8)) {
    BOTTOM_HALF_HANDLER_L2.call_once(|| func);
}

/// Type alias for IRQ callback function.
/// Signature matches `host_ostd::irq::IrqCallbackFunction`.
pub type IrqCallbackFunction = dyn Fn(&TrapFrame) + Sync + Send + 'static;

/// Inner state for a single IRQ line
struct IrqInner {
    callbacks: RwLock<Vec<Box<IrqCallbackFunction>>>,
}

impl IrqInner {
    const fn new() -> Self {
        Self {
            callbacks: RwLock::new(Vec::new()),
        }
    }
}

/// Global IRQ table.
static FRAMEVISOR_IRQS: [IrqInner; NUMBER_OF_IRQS] = [const { IrqInner::new() }; NUMBER_OF_IRQS];

/// IRQ line handle.
///
/// This structure provides the same API shape as `host_ostd::irq::IrqLine`.
#[derive(Debug)]
#[must_use]
pub struct IrqLine {
    index: u8,
    callbacks: Vec<CallbackHandle>,
}

#[derive(Debug)]
struct CallbackHandle {
    irq_index: u8,
    callback_addr: usize,
}

impl Drop for CallbackHandle {
    #[inline]
    fn drop(&mut self) {
        unregister_irq_callback(self.irq_index, self.callback_addr);
    }
}

impl IrqLine {
    /// Allocates an available IRQ line.
    ///
    /// Signature matches `host_ostd::irq::IrqLine::alloc()`.
    pub fn alloc() -> Result<Self> {
        // Keep the allocator deterministic until a service-visible allocator is
        // needed by copied kernel drivers.
        Self::alloc_specific(IRQ_NUM_MIN)
    }

    /// Allocates a specific IRQ line.
    ///
    /// Signature matches `host_ostd::irq::IrqLine::alloc_specific()`.
    pub fn alloc_specific(irq_num: u8) -> Result<Self> {
        if irq_num < IRQ_NUM_MIN || irq_num > IRQ_NUM_MAX {
            return Err(error::Error::InvalidArgs);
        }
        Ok(Self::new(irq_num - IRQ_NUM_MIN))
    }

    fn new(index: u8) -> Self {
        Self {
            index,
            callbacks: Vec::new(),
        }
    }

    /// Gets the IRQ number.
    ///
    /// Signature matches `host_ostd::irq::IrqLine::num()`.
    pub fn num(&self) -> u8 {
        self.index + IRQ_NUM_MIN
    }

    /// Registers a callback that will be invoked when the IRQ is active.
    ///
    /// Signature matches `host_ostd::irq::IrqLine::on_active()`.
    pub fn on_active<F>(&mut self, callback: F)
    where
        F: Fn(&TrapFrame) + Sync + Send + 'static,
    {
        let callback_box: Box<IrqCallbackFunction> = Box::new(callback);
        let callback_handle = register_irq_callback(self.index, callback_box);
        self.callbacks.push(callback_handle);
    }

    /// Checks if there are no registered callbacks.
    ///
    /// Signature matches `host_ostd::irq::IrqLine::is_empty()`.
    pub fn is_empty(&self) -> bool {
        self.callbacks.is_empty()
    }

    /// Gets the remapping index of the IRQ line.
    pub fn remapping_index(&self) -> Option<u16> {
        None
    }
}

impl Clone for IrqLine {
    fn clone(&self) -> Self {
        Self {
            index: self.index,
            callbacks: Vec::new(),
        }
    }
}

#[inline(never)]
fn register_irq_callback(irq_index: u8, callback: Box<IrqCallbackFunction>) -> CallbackHandle {
    let callback_addr = core::ptr::from_ref(&*callback).addr();
    FRAMEVISOR_IRQS[irq_index as usize]
        .callbacks
        .write()
        .push(callback);

    CallbackHandle {
        irq_index,
        callback_addr,
    }
}

#[inline(never)]
fn unregister_irq_callback(irq_index: u8, callback_addr: usize) {
    let mut callbacks = FRAMEVISOR_IRQS[irq_index as usize].callbacks.write();
    if let Some(pos) = callbacks
        .iter()
        .position(|cb| core::ptr::from_ref(&**cb).addr() == callback_addr)
    {
        let _ = callbacks.swap_remove(pos);
    }
}

#[cfg(feature = "host-api")]
#[used]
static PRESERVE_IRQ_CALLBACK_REGISTRY_SYMBOLS: (
    fn(u8, Box<IrqCallbackFunction>) -> CallbackHandle,
    fn(u8, usize),
) = (register_irq_callback, unregister_irq_callback);

fn call_irq_callbacks(trap_frame: &TrapFrame, irq_num: u8) {
    if irq_num < IRQ_NUM_MIN || irq_num > IRQ_NUM_MAX {
        return;
    }

    enter_interrupt_level(PrivilegeLevel::Kernel, || {
        let index = (irq_num - IRQ_NUM_MIN) as usize;
        let callbacks = FRAMEVISOR_IRQS[index].callbacks.read();

        for callback in callbacks.iter() {
            callback(trap_frame);
        }

        process_bottom_half(irq_num);
    });
}

/// Injects a virtual interrupt from the host control plane.
#[cfg(feature = "host-api")]
pub fn inject_irq(irq_num: u8, trap_frame: &TrapFrame) {
    call_irq_callbacks(trap_frame, irq_num);
}

/// Creates a synthetic TrapFrame for kernel-mode interrupt injection.
///
/// When injecting interrupts in kernel mode, we don't have real register state.
/// Virtual-device callbacks typically don't need these values.
#[cfg(all(feature = "host-api", target_arch = "x86_64"))]
pub fn make_synthetic_trapframe(irq_num: u8) -> TrapFrame {
    TrapFrame {
        trap_num: irq_num as usize,
        error_code: 0,
        ..Default::default()
    }
}

#[cfg(all(feature = "host-api", target_arch = "riscv64"))]
pub fn make_synthetic_trapframe(_irq_num: u8) -> TrapFrame {
    TrapFrame {
        general: Default::default(),
        sstatus: 0,
        sepc: 0,
    }
}

#[cfg(all(feature = "host-api", target_arch = "loongarch64"))]
pub fn make_synthetic_trapframe(_irq_num: u8) -> TrapFrame {
    TrapFrame::default()
}

/// Per-vCPU vsock IRQ dedup flag.
///
/// When set, a vsock IRQ callback is already pending in the internal IRQ log.
/// Subsequent injections skip the push to avoid duplicate callbacks that
/// contend on the IRQ queue lock without doing useful work.
/// Cleared by the callback itself after execution.
#[cfg(feature = "host-api")]
const MAX_VCPUS: usize = 16;
#[cfg(feature = "host-api")]
static VSOCK_IRQ_PENDING: [AtomicBool; MAX_VCPUS] = [const { AtomicBool::new(false) }; MAX_VCPUS];

/// Debug counters for vsock IRQ injection path.
#[cfg(feature = "host-api")]
#[derive(Debug, Clone, Copy, Default)]
pub struct VsockIrqDebugStats {
    pub inject_attempts: u64,
    pub dedup_skips: u64,
    pub enqueue_success: u64,
    pub enqueue_fail_no_vm: u64,
    pub enqueue_fail_no_ctx: u64,
    pub callback_runs: u64,
    pub callback_vcpu_unknown: u64,
}

#[cfg(feature = "host-api")]
static VSOCK_IRQ_INJECT_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "host-api")]
static VSOCK_IRQ_DEDUP_SKIPS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "host-api")]
static VSOCK_IRQ_ENQUEUE_SUCCESS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "host-api")]
static VSOCK_IRQ_ENQUEUE_FAIL_NO_VM: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "host-api")]
static VSOCK_IRQ_ENQUEUE_FAIL_NO_CTX: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "host-api")]
static VSOCK_IRQ_CALLBACK_RUNS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "host-api")]
static VSOCK_IRQ_CALLBACK_VCPU_UNKNOWN: AtomicU64 = AtomicU64::new(0);

/// Snapshot vsock IRQ debug counters.
#[cfg(feature = "host-api")]
pub fn vsock_irq_debug_stats() -> VsockIrqDebugStats {
    VsockIrqDebugStats {
        inject_attempts: VSOCK_IRQ_INJECT_ATTEMPTS.load(Ordering::Relaxed),
        dedup_skips: VSOCK_IRQ_DEDUP_SKIPS.load(Ordering::Relaxed),
        enqueue_success: VSOCK_IRQ_ENQUEUE_SUCCESS.load(Ordering::Relaxed),
        enqueue_fail_no_vm: VSOCK_IRQ_ENQUEUE_FAIL_NO_VM.load(Ordering::Relaxed),
        enqueue_fail_no_ctx: VSOCK_IRQ_ENQUEUE_FAIL_NO_CTX.load(Ordering::Relaxed),
        callback_runs: VSOCK_IRQ_CALLBACK_RUNS.load(Ordering::Relaxed),
        callback_vcpu_unknown: VSOCK_IRQ_CALLBACK_VCPU_UNKNOWN.load(Ordering::Relaxed),
    }
}

/// Reset vsock IRQ debug counters.
#[cfg(feature = "host-api")]
pub fn reset_vsock_irq_debug_stats() {
    VSOCK_IRQ_INJECT_ATTEMPTS.store(0, Ordering::Relaxed);
    VSOCK_IRQ_DEDUP_SKIPS.store(0, Ordering::Relaxed);
    VSOCK_IRQ_ENQUEUE_SUCCESS.store(0, Ordering::Relaxed);
    VSOCK_IRQ_ENQUEUE_FAIL_NO_VM.store(0, Ordering::Relaxed);
    VSOCK_IRQ_ENQUEUE_FAIL_NO_CTX.store(0, Ordering::Relaxed);
    VSOCK_IRQ_CALLBACK_RUNS.store(0, Ordering::Relaxed);
    VSOCK_IRQ_CALLBACK_VCPU_UNKNOWN.store(0, Ordering::Relaxed);
}

/// Injects a vsock RX ready interrupt for a specific VM.
#[cfg(feature = "host-api")]
#[host_ostd::ensure_stack(4096)]
pub fn inject_vsock_rx_interrupt_for_vm(vm_id: VmId, vcpu_id: usize) {
    VSOCK_IRQ_INJECT_ATTEMPTS.fetch_add(1, Ordering::Relaxed);

    // Dedup: skip if a callback is already pending for this vCPU
    if vcpu_id < MAX_VCPUS && VSOCK_IRQ_PENDING[vcpu_id].swap(true, Ordering::AcqRel) {
        VSOCK_IRQ_DEDUP_SKIPS.fetch_add(1, Ordering::Relaxed);
        return;
    }

    let vm = match vm::get_vm_by_id(vm_id) {
        Some(v) => v,
        None => {
            if vcpu_id < MAX_VCPUS {
                VSOCK_IRQ_PENDING[vcpu_id].store(false, Ordering::Release);
            }
            VSOCK_IRQ_ENQUEUE_FAIL_NO_VM.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    if let Some(ctx) = vm.iht_context(vcpu_id) {
        iht::log_irq_fn_to_context(&ctx, vsock_rx_irq_callback);
        VSOCK_IRQ_ENQUEUE_SUCCESS.fetch_add(1, Ordering::Relaxed);
    } else {
        // Important: clear pending flag on enqueue failure path,
        // otherwise this vCPU can get permanently "dedup blocked".
        if vcpu_id < MAX_VCPUS {
            VSOCK_IRQ_PENDING[vcpu_id].store(false, Ordering::Release);
        }
        VSOCK_IRQ_ENQUEUE_FAIL_NO_CTX.fetch_add(1, Ordering::Relaxed);
    }
}

/// Injects a vsock RX ready interrupt (backward compatible, uses first VM).
#[cfg(feature = "host-api")]
#[host_ostd::ensure_stack(4096)]
pub fn inject_vsock_rx_interrupt(vcpu_id: usize) {
    VSOCK_IRQ_INJECT_ATTEMPTS.fetch_add(1, Ordering::Relaxed);

    // Dedup: skip if a callback is already pending for this vCPU
    if vcpu_id < MAX_VCPUS && VSOCK_IRQ_PENDING[vcpu_id].swap(true, Ordering::AcqRel) {
        VSOCK_IRQ_DEDUP_SKIPS.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Schedule the interrupt handler on the IHT for the given vCPU.
    // If no VM/context exists, clear dedup flag to avoid permanent blockage.
    let Some(vm) = vm::get_vm() else {
        if vcpu_id < MAX_VCPUS {
            VSOCK_IRQ_PENDING[vcpu_id].store(false, Ordering::Release);
        }
        VSOCK_IRQ_ENQUEUE_FAIL_NO_VM.fetch_add(1, Ordering::Relaxed);
        return;
    };

    let Some(ctx) = vm.iht_context(vcpu_id) else {
        if vcpu_id < MAX_VCPUS {
            VSOCK_IRQ_PENDING[vcpu_id].store(false, Ordering::Release);
        }
        VSOCK_IRQ_ENQUEUE_FAIL_NO_CTX.fetch_add(1, Ordering::Relaxed);
        return;
    };

    iht::log_irq_fn_to_context(&ctx, vsock_rx_irq_callback);
    VSOCK_IRQ_ENQUEUE_SUCCESS.fetch_add(1, Ordering::Relaxed);
}

#[inline]
#[cfg(feature = "host-api")]
fn vsock_rx_irq_callback() {
    VSOCK_IRQ_CALLBACK_RUNS.fetch_add(1, Ordering::Relaxed);
    let trap_frame = make_synthetic_trapframe(FRAMEVSOCK_IRQ_NUM);
    inject_irq(FRAMEVSOCK_IRQ_NUM, &trap_frame);
    // Clear dedup flag AFTER drain completes so packets arriving during
    // drain don't get lost — they will trigger a new callback after this one.
    if let Some(vcpu_id) = iht::current_vcpu_id() {
        if vcpu_id < MAX_VCPUS {
            VSOCK_IRQ_PENDING[vcpu_id].store(false, Ordering::Release);
        }
    } else {
        VSOCK_IRQ_CALLBACK_VCPU_UNKNOWN.fetch_add(1, Ordering::Relaxed);
    }
}

/// Initialize the IRQ subsystem.
pub(crate) fn init() {
    // Virtual IRQ table is statically initialized, no runtime setup needed.
}

fn current_interrupt_level_slot() -> &'static AtomicU8 {
    let cpu_id = CpuId::current_racy().as_usize();
    &INTERRUPT_LEVELS[cpu_id.min(MAX_IRQ_LEVEL_CPUS - 1)]
}

fn decode_interrupt_level(raw_level: u8) -> InterruptLevel {
    match raw_level >> IRQ_LEVEL_VAL_OFFSET {
        0 => InterruptLevel::L0,
        1 => {
            let cpu_privilege = if raw_level & IRQ_LEVEL_CPU_PRIV_MASK == 0 {
                PrivilegeLevel::Kernel
            } else {
                PrivilegeLevel::User
            };
            InterruptLevel::L1(cpu_privilege)
        }
        _ => InterruptLevel::L2,
    }
}

fn encode_interrupt_level(level: InterruptLevel) -> u8 {
    match level {
        InterruptLevel::L0 => 0,
        InterruptLevel::L1(PrivilegeLevel::Kernel) => 1 << IRQ_LEVEL_VAL_OFFSET,
        InterruptLevel::L1(PrivilegeLevel::User) => {
            (1 << IRQ_LEVEL_VAL_OFFSET) | IRQ_LEVEL_CPU_PRIV_MASK
        }
        InterruptLevel::L2 => 2 << IRQ_LEVEL_VAL_OFFSET,
    }
}

fn enter_interrupt_level(faulting_privilege: PrivilegeLevel, f: impl FnOnce()) {
    let level_slot = current_interrupt_level_slot();
    let previous = decode_interrupt_level(level_slot.load(Ordering::Acquire));
    let next = match previous {
        InterruptLevel::L0 => InterruptLevel::L1(faulting_privilege),
        InterruptLevel::L1(_) | InterruptLevel::L2 => InterruptLevel::L2,
    };
    level_slot.store(encode_interrupt_level(next), Ordering::Release);
    f();
    level_slot.store(encode_interrupt_level(previous), Ordering::Release);
}

fn process_bottom_half(irq_num: u8) {
    match InterruptLevel::current() {
        InterruptLevel::L1(_) => {
            if let Some(handler) = BOTTOM_HALF_HANDLER_L1.get() {
                let guard = disable_local();
                let _guard = handler(guard, irq_num);
            }
        }
        InterruptLevel::L2 => {
            if let Some(handler) = BOTTOM_HALF_HANDLER_L2.get() {
                handler(irq_num);
            }
        }
        InterruptLevel::L0 => {}
    }
}
