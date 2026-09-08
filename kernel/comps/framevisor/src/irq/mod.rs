// SPDX-License-Identifier: MPL-2.0

//! IRQ handling.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    fmt, hint, mem,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use host_ostd::arch::trap::TrapFrame;

#[cfg(target_arch = "x86_64")]
use crate::assigned_pci::AssignedPciIrqRoute;
use crate::{
    Error,
    prelude::*,
    sync::{Once, RwLock},
    task,
    vm::{self, VmId},
};

mod handler;
mod host;

pub use handler::InterruptHandler;
pub(crate) use handler::{enqueue_physical_irq, enqueue_virtual_irq};
pub use host::{DisabledLocalIrqGuard, InterruptLevel, disable_local, make_synthetic_trapframe};

/// IRQ number range for the IRQ allocator.
const IRQ_NUM_MIN: u8 = 0x80;
const IRQ_NUM_MAX: u8 = 0xBF;
const NUMBER_OF_IRQS: usize = (IRQ_NUM_MAX - IRQ_NUM_MIN + 1) as usize;

/// Identifies one virtual PCI requester presented to FrameVM service code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciIrqRequester {
    bus: u8,
    device: u8,
    function: u8,
}

impl PciIrqRequester {
    /// Creates a requester identifier from a virtual PCI bus/device/function tuple.
    #[inline(always)]
    pub fn new(bus: u8, device: u8, function: u8) -> Result<Self> {
        if device >= 32 || function >= 8 {
            return Err(Error::InvalidArgs);
        }
        Ok(Self {
            bus,
            device,
            function,
        })
    }

    #[inline(always)]
    pub(crate) const fn tuple(self) -> (u8, u8, u8) {
        (self.bus, self.device, self.function)
    }
}

/// FrameVisor-private virtual interrupt selected by a programmed MSI-X entry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct VirtualIrqLine(u16);

impl VirtualIrqLine {
    const RESERVED_RAW: u16 = 0;

    pub(crate) fn parse(raw: u16) -> Result<Self> {
        (raw != Self::RESERVED_RAW)
            .then_some(Self(raw))
            .ok_or(Error::InvalidArgs)
    }

    pub(crate) const fn raw(self) -> u16 {
        self.0
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
    host::enter_timer_interrupt(f);
}

/// Type alias for IRQ callback function.
/// Signature matches `host_ostd::irq::IrqCallbackFunction`.
pub type IrqCallbackFunction = dyn Fn(&TrapFrame) + Sync + Send + 'static;

/// Per-runtime state for one OSTD-shaped IRQ line.
struct OstdIrqInner {
    allocated: AtomicBool,
    generation: AtomicU64,
    callbacks: RwLock<Vec<Arc<IrqCallbackEntry>>>,
}

impl OstdIrqInner {
    const fn new() -> Self {
        Self {
            allocated: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            callbacks: RwLock::new(Vec::new()),
        }
    }

    fn try_allocate(&self) -> Option<u64> {
        if self
            .allocated
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }
        let generation =
            self.generation
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_add(1)
                });
        match generation {
            Ok(previous) => Some(previous + 1),
            Err(_) => {
                self.allocated.store(false, Ordering::Release);
                None
            }
        }
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
        // Count the invocation before observing `active`.  Unregistration
        // deactivates the entry and waits for this counter to reach zero
        // before dropping the callback.  Checking `active` first would leave
        // a window in which teardown could observe zero, unload the service
        // image, and then this invocation could enter its callback.
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

/// Per-runtime software IRQ handler state.
pub(crate) struct Irq {
    ostd_irqs: [OstdIrqInner; NUMBER_OF_IRQS],
    next_callback_registration_id: AtomicU64,
    bottom_half_handler_l1: Once<fn(DisabledLocalIrqGuard, u8) -> DisabledLocalIrqGuard>,
    bottom_half_handler_l2: Once<fn(u8)>,
}

impl Irq {
    /// Creates an empty virtual IRQ runtime.
    pub(crate) fn new() -> Self {
        Self {
            ostd_irqs: [const { OstdIrqInner::new() }; NUMBER_OF_IRQS],
            next_callback_registration_id: AtomicU64::new(1),
            bottom_half_handler_l1: Once::new(),
            bottom_half_handler_l2: Once::new(),
        }
    }

    #[inline(always)]
    fn alloc_ostd_irq(self: &Arc<Self>) -> Result<IrqLine> {
        for index in 0..NUMBER_OF_IRQS {
            if let Some(generation) = self.ostd_irqs[index].try_allocate() {
                return Ok(IrqLine::new(self.clone(), index as u8, generation));
            }
        }

        Err(Error::NotEnoughResources)
    }

    fn alloc_specific_ostd_irq(self: &Arc<Self>, irq_num: u8) -> Result<IrqLine> {
        if !(IRQ_NUM_MIN..=IRQ_NUM_MAX).contains(&irq_num) {
            return Err(Error::InvalidArgs);
        }

        let index = irq_num - IRQ_NUM_MIN;
        let Some(generation) = self.ostd_irqs[index as usize].try_allocate() else {
            return Err(Error::InvalidArgs);
        };

        Ok(IrqLine::new(self.clone(), index, generation))
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

        host::enter_interrupt(crate::cpu::PrivilegeLevel::Kernel, || {
            let index = (irq_num - IRQ_NUM_MIN) as usize;
            let callbacks = self.ostd_irqs[index].callbacks.read().clone();
            for callback in callbacks {
                callback.invoke(trap_frame);
            }

            self.process_bottom_half(irq_num);
        });
    }

    pub(crate) fn is_ostd_irq_allocated(&self, irq_num: u8) -> bool {
        if !(IRQ_NUM_MIN..=IRQ_NUM_MAX).contains(&irq_num) {
            return false;
        }
        self.ostd_irqs[(irq_num - IRQ_NUM_MIN) as usize]
            .allocated
            .load(Ordering::Acquire)
    }

    pub(crate) fn owns_ostd_irq(&self, irq_num: u8, generation: u64) -> bool {
        if !self.is_ostd_irq_allocated(irq_num) {
            return false;
        }
        self.ostd_irqs[(irq_num - IRQ_NUM_MIN) as usize]
            .generation
            .load(Ordering::Acquire)
            == generation
    }

    pub(crate) fn dispatch_ostd_irq_from_handler(&self, irq_num: u8) {
        self.dispatch_ostd_irq(&make_synthetic_trapframe(irq_num), irq_num);
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

    pub(crate) fn clear(&self) {
        self.clear_ostd_irqs();
    }

    fn clear_ostd_irqs(&self) {
        for irq_index in 0..NUMBER_OF_IRQS {
            self.release_ostd_irq(irq_index as u8);
        }
    }
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
    runtime: Arc<Irq>,
    index: u8,
    generation: u64,
    #[cfg(target_arch = "x86_64")]
    assigned_route: Option<Arc<AssignedPciIrqRoute>>,
}

impl IrqAllocation {
    fn new(runtime: Arc<Irq>, index: u8, generation: u64) -> Self {
        Self {
            runtime,
            index,
            generation,
            #[cfg(target_arch = "x86_64")]
            assigned_route: None,
        }
    }
}

impl Drop for IrqAllocation {
    fn drop(&mut self) {
        self.runtime.release_ostd_irq(self.index);
    }
}

struct CallbackHandle {
    runtime: Arc<Irq>,
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
    /// Allocates a software-only IRQ line for a FrameV virtual PCI function.
    ///
    /// FrameV drivers use this explicit constructor so that a FrameVM which also owns a
    /// physical PCI function does not consume an interrupt-remapping entry for virtual devices.
    #[inline(always)]
    pub fn alloc_virtual() -> Result<Self> {
        current_virtual_irq_runtime()?.alloc_ostd_irq()
    }

    /// Allocates an available IRQ line.
    ///
    /// Signature matches `host_ostd::irq::IrqLine::alloc()`.
    pub fn alloc() -> Result<Self> {
        let vm = current_vm()?;
        let mut irq_line = vm.irq().alloc_ostd_irq()?;
        irq_line.attach_assigned_route(&vm)?;
        Ok(irq_line)
    }

    /// Allocates a specific IRQ line.
    ///
    /// Signature matches `host_ostd::irq::IrqLine::alloc_specific()`.
    pub fn alloc_specific(irq_num: u8) -> Result<Self> {
        let vm = current_vm()?;
        let mut irq_line = vm.irq().alloc_specific_ostd_irq(irq_num)?;
        irq_line.attach_assigned_route(&vm)?;
        Ok(irq_line)
    }

    fn new(runtime: Arc<Irq>, index: u8, generation: u64) -> Self {
        Self {
            allocation: Arc::new(IrqAllocation::new(runtime, index, generation)),
            callbacks: Vec::new(),
        }
    }

    fn index(&self) -> u8 {
        self.allocation.index
    }

    fn attach_assigned_route(&mut self, vm: &vm::FrameVm) -> Result<()> {
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = vm;
            return Ok(());
        }
        #[cfg(target_arch = "x86_64")]
        {
            let Some(access) = vm.assigned_pci_access() else {
                return Ok(());
            };
            let route =
                access.allocate_irq_route(vm.id(), self.num(), self.allocation.generation)?;
            let allocation = Arc::get_mut(&mut self.allocation)
                .expect("a newly allocated IRQ line has unique allocation authority");
            allocation.assigned_route = Some(route);
            Ok(())
        }
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
        #[cfg(not(target_arch = "x86_64"))]
        {
            return None;
        }
        #[cfg(target_arch = "x86_64")]
        self.allocation
            .assigned_route
            .as_ref()
            .map(|route| route.remapping_index())
    }

    /// Signature matches `host_ostd::irq::IrqLine::bind_pci_requester()`.
    #[inline(always)]
    pub fn bind_pci_requester(&self, requester: PciIrqRequester) -> Result<()> {
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = requester;
            return Err(Error::AccessDenied);
        }
        #[cfg(target_arch = "x86_64")]
        {
            let vm = current_vm()?;
            if !Arc::ptr_eq(&self.allocation.runtime, vm.irq()) {
                return Err(Error::AccessDenied);
            }
            let route = self
                .allocation
                .assigned_route
                .as_ref()
                .ok_or(Error::AccessDenied)?;
            let location = vm.devices().pci().resolve_assigned_requester(requester)?;
            route.bind_requester(location)
        }
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

#[inline(always)]
fn current_virtual_irq_runtime() -> Result<Arc<Irq>> {
    let vm = current_vm()?;
    Ok(vm.irq().clone())
}

#[inline(always)]
fn current_vm() -> Result<Arc<vm::FrameVm>> {
    let frame_vcpu_id = task::current_frame_vcpu_id().ok_or(Error::InvalidArgs)?;
    vm::get_vm_by_id(frame_vcpu_id.vm_id()).ok_or(Error::InvalidArgs)
}

/// Injects a virtual interrupt from the host control plane.
pub fn inject_irq(irq_num: u8, trap_frame: &TrapFrame) {
    if let Ok(runtime) = current_virtual_irq_runtime() {
        runtime.dispatch_ostd_irq(trap_frame, irq_num);
    }
}

/// Dispatches one FrameV software IRQ line after routing has selected a vCPU.
pub(crate) fn dispatch_framev_irq_line(vm_id: VmId, irq_line: VirtualIrqLine, target_vcpu: usize) {
    // This dispatch is the IRQ-side notification/control handoff. Device-class
    // protocol work and upper-subsystem callbacks must be scheduled into the
    // FrameVM service runtime unless a future change adds a bounded,
    // nonblocking IRQ fast path with starvation tests.
    let Some(vm) = vm::get_vm_by_id(vm_id) else {
        return;
    };

    vm.dispatch_framev_irq(irq_line, target_vcpu);
}

/// Dispatches one source-bound physical IRQ through the owning FrameVM's interrupt handler.
pub(crate) fn dispatch_physical_irq(vm_id: VmId, irq_num: u8, generation: u64, target_vcpu: usize) {
    let Some(vm) = vm::get_vm_by_id(vm_id) else {
        return;
    };
    if target_vcpu >= vm.vcpu_count() || !vm.irq().owns_ostd_irq(irq_num, generation) {
        return;
    }
    vm.irq().dispatch_ostd_irq_from_handler(irq_num);
}

/// Records one timer tick for a FrameVM vCPU.
pub fn inject_timer_tick(frame_vcpu_id: vm::FrameVcpuId) {
    let Some(frame_vm) = vm::get_vm_by_id(frame_vcpu_id.vm_id()) else {
        return;
    };
    frame_vm.record_timer_tick(frame_vcpu_id);
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    use super::*;
    use crate::cpu::PrivilegeLevel;
    #[ktest]
    fn ostd_irq_allocations_are_scoped_to_one_runtime() {
        let irq_num = IRQ_NUM_MIN;
        let first_runtime = Arc::new(Irq::new());
        let second_runtime = Arc::new(Irq::new());
        let first_irq = first_runtime.alloc_specific_ostd_irq(irq_num).unwrap();

        assert!(first_runtime.alloc_specific_ostd_irq(irq_num).is_err());

        let second_irq = second_runtime.alloc_specific_ostd_irq(irq_num).unwrap();
        assert_eq!(first_irq.num(), irq_num);
        assert_eq!(second_irq.num(), irq_num);
    }

    #[ktest]
    fn reused_irq_number_rejects_stale_allocation_generation() {
        let runtime = Arc::new(Irq::new());
        let irq_num = IRQ_NUM_MIN;
        let first = runtime.alloc_specific_ostd_irq(irq_num).unwrap();
        let first_generation = first.allocation.generation;
        assert!(runtime.owns_ostd_irq(irq_num, first_generation));

        drop(first);
        let second = runtime.alloc_specific_ostd_irq(irq_num).unwrap();
        let second_generation = second.allocation.generation;

        assert_ne!(first_generation, second_generation);
        assert!(!runtime.owns_ostd_irq(irq_num, first_generation));
        assert!(runtime.owns_ostd_irq(irq_num, second_generation));
    }

    #[ktest]
    fn pci_requester_rejects_invalid_virtual_bdf() {
        assert!(PciIrqRequester::new(0, 31, 7).is_ok());
        assert!(PciIrqRequester::new(0, 32, 0).is_err());
        assert!(PciIrqRequester::new(0, 0, 8).is_err());
    }

    #[ktest]
    fn timer_interrupt_scope_enters_l1_from_task_context() {
        enter_timer_interrupt(|| {
            assert_eq!(
                InterruptLevel::current(),
                InterruptLevel::L1(PrivilegeLevel::Kernel)
            );
        });
        assert_eq!(InterruptLevel::current(), InterruptLevel::L0);
    }

    #[ktest]
    fn timer_interrupt_scope_nests_as_l2() {
        host::enter_interrupt(crate::cpu::PrivilegeLevel::User, || {
            enter_timer_interrupt(|| {
                assert_eq!(InterruptLevel::current(), InterruptLevel::L2);
            });
        });
        assert_eq!(InterruptLevel::current(), InterruptLevel::L0);
    }

    #[ktest]
    fn dropping_ostd_irq_handle_prevents_later_callbacks() {
        let runtime = Arc::new(Irq::new());
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
    fn service_irq_allocation_fails_without_current_vm_context() {
        assert!(IrqLine::alloc().is_err());
        assert!(IrqLine::alloc_specific(IRQ_NUM_MIN).is_err());
    }
}
