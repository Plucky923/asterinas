// SPDX-License-Identifier: MPL-2.0

//! IRQ handling.

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec::Vec};
use core::{
    fmt, hint, mem,
    sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
};

use framev_device::IrqLine as FrameVIrqLine;
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
    sync::{GuardTransfer, Once, RwLock, SpinLock},
    task::{
        self, DisabledPreemptGuard, atomic_mode::AsAtomicModeGuard, disable_preempt, scheduler,
    },
    vm::{self, VmId},
};

/// IRQ number range for the IRQ allocator.
const IRQ_NUM_MIN: u8 = 0x80;
const IRQ_NUM_MAX: u8 = 0x8F;
const NUMBER_OF_IRQS: usize = (IRQ_NUM_MAX - IRQ_NUM_MIN + 1) as usize;
const MAX_IRQ_LEVEL_CPUS: usize = 256;
const IRQ_LEVEL_VAL_OFFSET: u8 = 1;
const IRQ_LEVEL_CPU_PRIV_MASK: u8 = 1 << 0;

static INTERRUPT_LEVELS: [AtomicU8; MAX_IRQ_LEVEL_CPUS] =
    [const { AtomicU8::new(0) }; MAX_IRQ_LEVEL_CPUS];
/// Disables local IRQ delivery for the current task.
pub fn disable_local() -> DisabledLocalIrqGuard {
    let guard = disable_preempt();
    let virtual_interrupt_frame_vcpu_id = scheduler::enter_virtual_interrupt_disabled_section();
    let priority_boost_task_key =
        virtual_interrupt_frame_vcpu_id.and_then(|_| task::enter_virtual_irq_priority_boost());

    DisabledLocalIrqGuard {
        guard,
        virtual_interrupt_token: virtual_interrupt_frame_vcpu_id,
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
    if let Ok(runtime) = current_virtual_irq_runtime() {
        runtime.register_bottom_half_handler_l1(func);
    }
}

/// Registers a bottom-half callback to be executed at interrupt level 2.
pub fn register_bottom_half_handler_l2(func: fn(u8)) {
    if let Ok(runtime) = current_virtual_irq_runtime() {
        runtime.register_bottom_half_handler_l2(func);
    }
}

/// Executes a virtual timer callback with OSTD-shaped interrupt-level semantics.
pub(crate) fn enter_timer_interrupt(f: impl FnOnce()) {
    enter_interrupt_level(PrivilegeLevel::Kernel, f);
}

/// Type alias for IRQ callback function.
/// Signature matches `host_ostd::irq::IrqCallbackFunction`.
pub type IrqCallbackFunction = dyn Fn(&TrapFrame) + Sync + Send + 'static;
/// Type alias for a FrameV software IRQ handler.
pub type FrameVIrqHandler = dyn Fn() + Sync + Send + 'static;

/// Per-runtime state for one OSTD-shaped IRQ line.
struct OstdIrqInner {
    allocated: AtomicBool,
    callbacks: RwLock<Vec<Arc<IrqCallbackEntry>>>,
}

impl OstdIrqInner {
    const fn new() -> Self {
        Self {
            allocated: AtomicBool::new(false),
            callbacks: RwLock::new(Vec::new()),
        }
    }

    fn try_allocate(&self) -> bool {
        self.allocated
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

struct IrqCallbackEntry {
    registration_id: u64,
    active: AtomicBool,
    running: AtomicU64,
    callback: Box<IrqCallbackFunction>,
}

impl IrqCallbackEntry {
    fn new(registration_id: u64, callback: Box<IrqCallbackFunction>) -> Self {
        Self {
            registration_id,
            active: AtomicBool::new(true),
            running: AtomicU64::new(0),
            callback,
        }
    }

    fn invoke(&self, trap_frame: &TrapFrame) {
        if !self.active.load(Ordering::Acquire) {
            return;
        }

        self.running.fetch_add(1, Ordering::AcqRel);
        if self.active.load(Ordering::Acquire) {
            (self.callback)(trap_frame);
        }
        self.running.fetch_sub(1, Ordering::AcqRel);
    }

    fn deactivate(&self) {
        self.active.store(false, Ordering::Release);
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire) != 0
    }

    fn wait_until_idle(&self) {
        while self.is_running() {
            hint::spin_loop();
        }
    }
}

struct FrameVIrqHandlerEntry {
    registration_id: u64,
    handler: Arc<FrameVIrqHandler>,
    state: SpinLock<FrameVIrqHandlerState>,
}

struct FrameVIrqHandlerState {
    active: bool,
    running: bool,
    rerun_requested: bool,
}

impl FrameVIrqHandlerEntry {
    fn new(registration_id: u64, handler: Arc<FrameVIrqHandler>) -> Self {
        Self {
            registration_id,
            handler,
            state: SpinLock::new(FrameVIrqHandlerState {
                active: true,
                running: false,
                rerun_requested: false,
            }),
        }
    }

    fn try_begin(&self) -> bool {
        let mut state = self.state.lock();
        if !state.active {
            return false;
        }
        if state.running {
            state.rerun_requested = true;
            return false;
        }
        state.running = true;
        state.rerun_requested = false;
        true
    }

    fn finish(&self) -> bool {
        let mut state = self.state.lock();
        state.running = false;
        let should_rerun = state.active && state.rerun_requested;
        state.rerun_requested = false;
        should_rerun
    }

    fn deactivate(&self) {
        let mut state = self.state.lock();
        state.active = false;
        state.rerun_requested = false;
    }

    fn is_running(&self) -> bool {
        self.state.lock().running
    }

    fn wait_until_idle(&self) {
        while self.is_running() {
            hint::spin_loop();
        }
    }
}

/// Per-runtime software IRQ handler state.
pub(crate) struct FrameVVirtualIrqState {
    ostd_irqs: [OstdIrqInner; NUMBER_OF_IRQS],
    next_callback_registration_id: AtomicU64,
    bottom_half_handler_l1: Once<fn(DisabledLocalIrqGuard, u8) -> DisabledLocalIrqGuard>,
    bottom_half_handler_l2: Once<fn(u8)>,
    handlers: RwLock<BTreeMap<FrameVIrqLine, Arc<FrameVIrqHandlerEntry>>>,
    next_registration_id: AtomicU64,
}

impl FrameVVirtualIrqState {
    /// Creates an empty virtual IRQ runtime.
    pub(crate) fn new() -> Self {
        Self {
            ostd_irqs: [const { OstdIrqInner::new() }; NUMBER_OF_IRQS],
            next_callback_registration_id: AtomicU64::new(1),
            bottom_half_handler_l1: Once::new(),
            bottom_half_handler_l2: Once::new(),
            handlers: RwLock::new(BTreeMap::new()),
            next_registration_id: AtomicU64::new(1),
        }
    }

    fn alloc_ostd_irq(self: &Arc<Self>) -> Result<IrqLine> {
        for index in 0..NUMBER_OF_IRQS {
            if self.ostd_irqs[index].try_allocate() {
                return Ok(IrqLine::new(self.clone(), index as u8));
            }
        }

        Err(error::Error::NotEnoughResources)
    }

    fn alloc_specific_ostd_irq(self: &Arc<Self>, irq_num: u8) -> Result<IrqLine> {
        if !(IRQ_NUM_MIN..=IRQ_NUM_MAX).contains(&irq_num) {
            return Err(error::Error::InvalidArgs);
        }

        let index = irq_num - IRQ_NUM_MIN;
        if !self.ostd_irqs[index as usize].try_allocate() {
            return Err(error::Error::InvalidArgs);
        }

        Ok(IrqLine::new(self.clone(), index))
    }

    fn register_ostd_callback(
        self: &Arc<Self>,
        irq_index: u8,
        callback: Box<IrqCallbackFunction>,
    ) -> CallbackHandle {
        let registration_id = self
            .next_callback_registration_id
            .fetch_add(1, Ordering::AcqRel);
        let entry = Arc::new(IrqCallbackEntry::new(registration_id, callback));
        self.ostd_irqs[irq_index as usize]
            .callbacks
            .write()
            .push(entry);

        CallbackHandle {
            runtime: self.clone(),
            irq_index,
            registration_id,
        }
    }

    fn unregister_ostd_callback(&self, irq_index: u8, registration_id: u64) {
        let entry = {
            let mut callbacks = self.ostd_irqs[irq_index as usize].callbacks.write();
            let Some(pos) = callbacks
                .iter()
                .position(|entry| entry.registration_id == registration_id)
            else {
                return;
            };
            let entry = callbacks.swap_remove(pos);
            entry.deactivate();
            entry
        };

        entry.wait_until_idle();
    }

    fn release_ostd_irq(&self, irq_index: u8) {
        let callbacks = {
            let irq = &self.ostd_irqs[irq_index as usize];
            let mut callbacks = irq.callbacks.write();
            for entry in callbacks.iter() {
                entry.deactivate();
            }
            mem::take(&mut *callbacks)
        };

        for entry in callbacks {
            entry.wait_until_idle();
        }

        self.ostd_irqs[irq_index as usize]
            .allocated
            .store(false, Ordering::Release);
    }

    fn dispatch_ostd_irq(&self, trap_frame: &TrapFrame, irq_num: u8) {
        if !(IRQ_NUM_MIN..=IRQ_NUM_MAX).contains(&irq_num) {
            return;
        }

        enter_interrupt_level(PrivilegeLevel::Kernel, || {
            let index = (irq_num - IRQ_NUM_MIN) as usize;
            let callbacks = self.ostd_irqs[index].callbacks.read().clone();
            for callback in callbacks {
                callback.invoke(trap_frame);
            }

            self.process_bottom_half(irq_num);
        });
    }

    fn register_bottom_half_handler_l1(
        &self,
        func: fn(DisabledLocalIrqGuard, u8) -> DisabledLocalIrqGuard,
    ) {
        self.bottom_half_handler_l1.call_once(|| func);
    }

    fn register_bottom_half_handler_l2(&self, func: fn(u8)) {
        self.bottom_half_handler_l2.call_once(|| func);
    }

    fn process_bottom_half(&self, irq_num: u8) {
        match InterruptLevel::current() {
            InterruptLevel::L1(_) => {
                if let Some(handler) = self.bottom_half_handler_l1.get() {
                    let guard = disable_local();
                    let _guard = handler(guard, irq_num);
                }
            }
            InterruptLevel::L2 => {
                if let Some(handler) = self.bottom_half_handler_l2.get() {
                    handler(irq_num);
                }
            }
            InterruptLevel::L0 => {}
        }
    }

    fn register(
        self: &Arc<Self>,
        irq_line: FrameVIrqLine,
        handler: Arc<FrameVIrqHandler>,
    ) -> Result<IrqHandlerRegistration> {
        let registration_id = self.register_handler_entry(irq_line, handler)?;

        Ok(IrqHandlerRegistration {
            runtime: self.clone(),
            irq_line,
            registration_id,
        })
    }

    fn register_persistent(
        self: &Arc<Self>,
        irq_line: FrameVIrqLine,
        handler: Arc<FrameVIrqHandler>,
    ) -> Result<()> {
        self.register_handler_entry(irq_line, handler).map(|_| ())
    }

    fn register_handler_entry(
        self: &Arc<Self>,
        irq_line: FrameVIrqLine,
        handler: Arc<FrameVIrqHandler>,
    ) -> Result<u64> {
        if irq_line.is_reserved() {
            return Err(error::Error::InvalidArgs);
        }

        let registration_id = self.next_registration_id.fetch_add(1, Ordering::AcqRel);
        let mut handlers = self.handlers.write();
        if handlers.contains_key(&irq_line) {
            return Err(error::Error::InvalidArgs);
        }

        handlers.insert(
            irq_line,
            Arc::new(FrameVIrqHandlerEntry::new(registration_id, handler)),
        );

        Ok(registration_id)
    }

    fn unregister(&self, irq_line: FrameVIrqLine, registration_id: u64) {
        let entry = {
            let mut handlers = self.handlers.write();
            let Some(entry) = handlers.get(&irq_line) else {
                return;
            };
            if entry.registration_id != registration_id {
                return;
            }
            let Some(entry) = handlers.remove(&irq_line) else {
                return;
            };
            entry
        };

        entry.deactivate();
        entry.wait_until_idle();
    }

    pub(crate) fn dispatch(&self, irq_line: FrameVIrqLine) {
        enter_interrupt_level(PrivilegeLevel::Kernel, || {
            let irq_num = framev_irq_num(irq_line);
            loop {
                let entry = {
                    let handlers = self.handlers.read();
                    let Some(entry) = handlers.get(&irq_line) else {
                        return;
                    };
                    entry.clone()
                };

                if !entry.try_begin() {
                    return;
                }

                (entry.handler)();

                let should_rerun = entry.finish();
                // Mirrors OSTD IRQ delivery: FrameV device IRQ handlers are
                // notification-only top halves, and service-side softirqs own
                // deferred data-path work after the top half returns.
                self.process_bottom_half(irq_num);
                if !should_rerun {
                    return;
                }
            }
        });
    }

    pub(crate) fn clear(&self) {
        self.clear_ostd_irqs();
        let entries = {
            let mut handlers = self.handlers.write();
            mem::take(&mut *handlers).into_values().collect::<Vec<_>>()
        };
        for entry in entries {
            entry.deactivate();
            entry.wait_until_idle();
        }
    }

    fn clear_ostd_irqs(&self) {
        for irq_index in 0..NUMBER_OF_IRQS {
            self.release_ostd_irq(irq_index as u8);
        }
    }
}

/// A RAII registration for one FrameV software IRQ handler.
#[must_use]
pub struct IrqHandlerRegistration {
    runtime: Arc<FrameVVirtualIrqState>,
    irq_line: FrameVIrqLine,
    registration_id: u64,
}

impl Drop for IrqHandlerRegistration {
    fn drop(&mut self) {
        self.runtime.unregister(self.irq_line, self.registration_id);
    }
}

/// Registers a handler for a software IRQ line in the current service domain.
///
/// Each `IrqLine` supports exactly one handler in one service domain.
pub fn register_handler<F>(irq_line: FrameVIrqLine, handler: F) -> Result<IrqHandlerRegistration>
where
    F: Fn() + Sync + Send + 'static,
{
    let frame_vcpu_id = task::current_frame_vcpu_id().ok_or(error::Error::InvalidArgs)?;
    let vm = vm::get_vm_by_id(frame_vcpu_id.vm_id()).ok_or(error::Error::InvalidArgs)?;
    vm.devices()
        .irq_runtime()
        .register(irq_line, Arc::new(handler))
}

/// Registers a handler owned by the current VM's virtual IRQ runtime.
///
/// The handler is cleared with the VM runtime during stop/reset. This is used by
/// service boot shims whose lifetime is the loaded FrameVM service itself rather
/// than a Rust value returned to service code.
pub(crate) fn register_persistent_handler<F>(irq_line: FrameVIrqLine, handler: F) -> Result<()>
where
    F: Fn() + Sync + Send + 'static,
{
    let frame_vcpu_id = task::current_frame_vcpu_id().ok_or(error::Error::InvalidArgs)?;
    let vm = vm::get_vm_by_id(frame_vcpu_id.vm_id()).ok_or(error::Error::InvalidArgs)?;
    vm.devices()
        .irq_runtime()
        .register_persistent(irq_line, Arc::new(handler))
}

/// IRQ line handle.
///
/// This structure provides the same API shape as `host_ostd::irq::IrqLine`.
#[must_use]
pub struct IrqLine {
    allocation: Arc<IrqAllocation>,
    callbacks: Vec<CallbackHandle>,
}

struct IrqAllocation {
    runtime: Arc<FrameVVirtualIrqState>,
    index: u8,
}

impl IrqAllocation {
    fn new(runtime: Arc<FrameVVirtualIrqState>, index: u8) -> Self {
        Self { runtime, index }
    }
}

impl Drop for IrqAllocation {
    fn drop(&mut self) {
        self.runtime.release_ostd_irq(self.index);
    }
}

struct CallbackHandle {
    runtime: Arc<FrameVVirtualIrqState>,
    irq_index: u8,
    registration_id: u64,
}

impl Drop for CallbackHandle {
    #[inline]
    fn drop(&mut self) {
        self.runtime
            .unregister_ostd_callback(self.irq_index, self.registration_id);
    }
}

impl fmt::Debug for IrqLine {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IrqLine")
            .field("num", &self.num())
            .field("callback_count", &self.callbacks.len())
            .finish()
    }
}

impl fmt::Debug for CallbackHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallbackHandle")
            .field("irq_index", &self.irq_index)
            .field("registration_id", &self.registration_id)
            .finish()
    }
}

impl IrqLine {
    /// Allocates an available IRQ line.
    ///
    /// Signature matches `host_ostd::irq::IrqLine::alloc()`.
    pub fn alloc() -> Result<Self> {
        current_virtual_irq_runtime()?.alloc_ostd_irq()
    }

    /// Allocates a specific IRQ line.
    ///
    /// Signature matches `host_ostd::irq::IrqLine::alloc_specific()`.
    pub fn alloc_specific(irq_num: u8) -> Result<Self> {
        current_virtual_irq_runtime()?.alloc_specific_ostd_irq(irq_num)
    }

    fn new(runtime: Arc<FrameVVirtualIrqState>, index: u8) -> Self {
        Self {
            allocation: Arc::new(IrqAllocation::new(runtime, index)),
            callbacks: Vec::new(),
        }
    }

    fn index(&self) -> u8 {
        self.allocation.index
    }

    /// Gets the IRQ number.
    ///
    /// Signature matches `host_ostd::irq::IrqLine::num()`.
    pub fn num(&self) -> u8 {
        self.index() + IRQ_NUM_MIN
    }

    /// Registers a callback that will be invoked when the IRQ is active.
    ///
    /// Signature matches `host_ostd::irq::IrqLine::on_active()`.
    pub fn on_active<F>(&mut self, callback: F)
    where
        F: Fn(&TrapFrame) + Sync + Send + 'static,
    {
        let callback_box: Box<IrqCallbackFunction> = Box::new(callback);
        let callback_handle = self
            .allocation
            .runtime
            .register_ostd_callback(self.index(), callback_box);
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
            allocation: self.allocation.clone(),
            callbacks: Vec::new(),
        }
    }
}

fn current_virtual_irq_runtime() -> Result<Arc<FrameVVirtualIrqState>> {
    let frame_vcpu_id = task::current_frame_vcpu_id().ok_or(error::Error::InvalidArgs)?;
    let vm = vm::get_vm_by_id(frame_vcpu_id.vm_id()).ok_or(error::Error::InvalidArgs)?;
    Ok(vm.devices().irq_runtime().clone())
}

/// Injects a virtual interrupt from the host control plane.
pub fn inject_irq(irq_num: u8, trap_frame: &TrapFrame) {
    if let Ok(runtime) = current_virtual_irq_runtime() {
        runtime.dispatch_ostd_irq(trap_frame, irq_num);
    }
}

/// Dispatches one FrameV software IRQ line after routing has selected a vCPU.
pub(crate) fn dispatch_framev_irq_line(vm_id: VmId, irq_line: FrameVIrqLine, target_vcpu: usize) {
    // This dispatch is the IHT-side notification/control handoff. Device-class
    // protocol work and upper-subsystem callbacks must be scheduled into the
    // FrameVM service runtime unless a future change adds a bounded,
    // nonblocking IHT fast path with starvation tests.
    let Some(vm) = vm::get_vm_by_id(vm_id) else {
        return;
    };

    vm.devices().dispatch_irq(irq_line, target_vcpu);
}

/// Creates a synthetic TrapFrame for kernel-mode interrupt injection.
///
/// When injecting interrupts in kernel mode, we don't have real register state.
/// Virtual-device callbacks typically don't need these values.
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

fn framev_irq_num(irq_line: FrameVIrqLine) -> u8 {
    irq_line.raw().min(u16::from(u8::MAX)) as u8
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;

    #[ktest]
    fn framev_irq_handlers_are_scoped_to_one_runtime() {
        let irq_line = FrameVIrqLine::new(1);
        let first_runtime = Arc::new(FrameVVirtualIrqState::new());
        let second_runtime = Arc::new(FrameVVirtualIrqState::new());
        let calls = Arc::new(AtomicU64::new(0));
        let recorded_calls = calls.clone();
        let _registration = first_runtime
            .register(
                irq_line,
                Arc::new(move || {
                    recorded_calls.fetch_add(1, Ordering::Relaxed);
                }),
            )
            .unwrap();

        first_runtime.dispatch(irq_line);
        second_runtime.dispatch(irq_line);

        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[ktest]
    fn ostd_irq_allocations_are_scoped_to_one_runtime() {
        let irq_num = IRQ_NUM_MIN;
        let first_runtime = Arc::new(FrameVVirtualIrqState::new());
        let second_runtime = Arc::new(FrameVVirtualIrqState::new());
        let first_irq = first_runtime.alloc_specific_ostd_irq(irq_num).unwrap();

        assert!(first_runtime.alloc_specific_ostd_irq(irq_num).is_err());

        let second_irq = second_runtime.alloc_specific_ostd_irq(irq_num).unwrap();
        assert_eq!(first_irq.num(), irq_num);
        assert_eq!(second_irq.num(), irq_num);
    }

    #[ktest]
    fn timer_interrupt_scope_enters_l1_from_task_context() {
        let level_slot = current_interrupt_level_slot();
        let previous = level_slot.load(Ordering::Acquire);
        level_slot.store(
            encode_interrupt_level(InterruptLevel::L0),
            Ordering::Release,
        );

        enter_timer_interrupt(|| {
            assert_eq!(
                InterruptLevel::current(),
                InterruptLevel::L1(PrivilegeLevel::Kernel)
            );
        });
        assert_eq!(InterruptLevel::current(), InterruptLevel::L0);

        level_slot.store(previous, Ordering::Release);
    }

    #[ktest]
    fn timer_interrupt_scope_nests_as_l2() {
        let level_slot = current_interrupt_level_slot();
        let previous = level_slot.load(Ordering::Acquire);
        level_slot.store(
            encode_interrupt_level(InterruptLevel::L1(PrivilegeLevel::User)),
            Ordering::Release,
        );

        enter_timer_interrupt(|| {
            assert_eq!(InterruptLevel::current(), InterruptLevel::L2);
        });
        assert_eq!(
            InterruptLevel::current(),
            InterruptLevel::L1(PrivilegeLevel::User)
        );

        level_slot.store(previous, Ordering::Release);
    }

    #[ktest]
    fn dropping_ostd_irq_handle_prevents_later_callbacks() {
        let runtime = Arc::new(FrameVVirtualIrqState::new());
        let mut irq_line = runtime.alloc_specific_ostd_irq(IRQ_NUM_MIN).unwrap();
        let irq_num = irq_line.num();
        let trap_frame = make_synthetic_trapframe(irq_num);
        let calls = Arc::new(AtomicU64::new(0));
        let recorded_calls = calls.clone();
        irq_line.on_active(move |_| {
            recorded_calls.fetch_add(1, Ordering::Relaxed);
        });

        runtime.dispatch_ostd_irq(&trap_frame, irq_num);
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        drop(irq_line);
        runtime.dispatch_ostd_irq(&trap_frame, irq_num);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[ktest]
    fn framev_irq_rejects_duplicate_and_ignores_stale_dispatch() {
        let irq_line = FrameVIrqLine::new(1);
        let runtime = Arc::new(FrameVVirtualIrqState::new());
        let _registration = runtime.register(irq_line, Arc::new(|| {})).unwrap();

        assert!(runtime.register(irq_line, Arc::new(|| {})).is_err());

        drop(_registration);
        runtime.dispatch(irq_line);
    }

    #[ktest]
    fn service_irq_shims_fail_without_current_vm_context() {
        assert!(register_handler(framev_sock_common::DEFAULT_IRQ_LINE, || {}).is_err());
        assert!(register_persistent_handler(framev_sock_common::DEFAULT_IRQ_LINE, || {}).is_err());
        assert!(IrqLine::alloc().is_err());
        assert!(IrqLine::alloc_specific(IRQ_NUM_MIN).is_err());
    }
}
