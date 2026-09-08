// SPDX-License-Identifier: MPL-2.0

//! FrameVM instance implementation.

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    alloc::Layout,
    sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};

use host_ostd::sync::{RwLock, WaitQueue};

use super::{
    FrameSchedGroup, FrameVcpuId, FrameVmAllocator, MemoryCharge, MemoryDomain, MemoryStats,
    ServiceEntryPoints, TaskAdmission, TaskAdmissionOutcome, TaskStartup, Vcpu, VmClock, VmId,
};
use crate::{
    cpu::local::CpuLocalDomain,
    device::{BlockImage, Devices},
    error::Error,
    irq::{self, InterruptHandler, Irq, VirtualIrqLine},
    mm::ownership,
    prelude::Result,
    sync::{Once, SpinLock},
    task::{
        Task,
        scheduler::{self, Scheduler},
    },
    vsock::SockConfiguration,
};

/// Maximum supported vCPU count.
pub const MAX_VCPU_COUNT: usize = 4;

const MIN_VCPU_COUNT: usize = 1;

// Host-owned per-VM records and queue metadata are not reusable physical
// extents, but they still consume capacity created specifically for one VM.
// Reserve a conservative page-granular budget before task admission.  The
// actual stack backing and all Frame/Segment payloads are charged separately
// at the point where they are created.
const CONTROL_MEMORY_BASE_PAGES: usize = 8;
const CONTROL_MEMORY_PER_VCPU_PAGES: usize = 2;
const CONTROL_MEMORY_PER_BLOCK_PAGES: usize = 2;
const CONTROL_MEMORY_NETWORK_PAGES: usize = 2;
const CONTROL_MEMORY_PCI_PAGES: usize = 2;

/// FrameVM running status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VmStatus {
    Stopped = 0,
    Starting = 1,
    Running = 2,
    Stopping = 3,
}

/// Host-owned observer for one FrameVM's terminal events.
///
/// The observer is installed on the VM instance itself. This keeps service
/// events tied to the VM that emitted them and avoids a process-global
/// VmId-to-callback registry.
pub trait FrameVmEventSink: Send + Sync {
    /// Records a service-originated power request.
    fn on_power_event(&self, action: crate::power::PowerAction, status_code: i32);

    /// Records an assigned-device containment result.
    fn on_assigned_device_failure(&self);
}

#[cfg(target_arch = "x86_64")]
enum AssignedPciStop {
    Release,
    Quarantine,
}

/// Serializes one VM start or teardown transition.
///
/// The claim covers the complete stop path, not only the final status store:
/// a waiter must not release the service image or devices while the owner is
/// still waiting for task, IRQ, or reservation quiescence. The owner publishes
/// completion only after it has published `VmStatus::Stopped`, so waiters can
/// safely return without repeating the teardown.
struct StopCleanup {
    in_progress: AtomicBool,
    completion: WaitQueue,
    #[cfg(target_arch = "x86_64")]
    pci_teardown_state: AtomicU8,
}

#[cfg(target_arch = "x86_64")]
const PCI_TEARDOWN_NOT_STARTED: u8 = 0;
#[cfg(target_arch = "x86_64")]
const PCI_QUARANTINE_REQUESTED: u8 = 1;
#[cfg(target_arch = "x86_64")]
const PCI_TEARDOWN_STARTED: u8 = 2;

impl StopCleanup {
    const fn new() -> Self {
        Self {
            in_progress: AtomicBool::new(false),
            completion: WaitQueue::new(),
            #[cfg(target_arch = "x86_64")]
            pci_teardown_state: AtomicU8::new(PCI_TEARDOWN_NOT_STARTED),
        }
    }

    fn try_claim(&self) -> Option<StopCleanupGuard<'_>> {
        self.in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then_some(StopCleanupGuard { cleanup: self })
    }

    fn wait_for_completion(&self) {
        self.completion
            .wait_until(|| (!self.in_progress.load(Ordering::Acquire)).then_some(()));
    }

    #[cfg(target_arch = "x86_64")]
    fn request_pci_quarantine(&self) -> bool {
        loop {
            match self.pci_teardown_state.load(Ordering::Acquire) {
                PCI_TEARDOWN_NOT_STARTED => {
                    if self
                        .pci_teardown_state
                        .compare_exchange(
                            PCI_TEARDOWN_NOT_STARTED,
                            PCI_QUARANTINE_REQUESTED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return true;
                    }
                }
                PCI_QUARANTINE_REQUESTED => return true,
                PCI_TEARDOWN_STARTED => return false,
                _ => return false,
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn begin_pci_teardown(&self, requested_policy: AssignedPciStop) -> AssignedPciStop {
        let quarantine_requested = loop {
            match self.pci_teardown_state.load(Ordering::Acquire) {
                PCI_TEARDOWN_NOT_STARTED => {
                    if self
                        .pci_teardown_state
                        .compare_exchange(
                            PCI_TEARDOWN_NOT_STARTED,
                            PCI_TEARDOWN_STARTED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break false;
                    }
                }
                PCI_QUARANTINE_REQUESTED => {
                    if self
                        .pci_teardown_state
                        .compare_exchange(
                            PCI_QUARANTINE_REQUESTED,
                            PCI_TEARDOWN_STARTED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break true;
                    }
                }
                // The cleanup claim prevents this path from being entered
                // twice. Treat an already-started phase as a defensive
                // release-policy fallback rather than reopening the request.
                PCI_TEARDOWN_STARTED => break false,
                _ => break false,
            }
        };

        if quarantine_requested || matches!(requested_policy, AssignedPciStop::Quarantine) {
            AssignedPciStop::Quarantine
        } else {
            AssignedPciStop::Release
        }
    }

    fn complete(&self) {
        self.in_progress.store(false, Ordering::Release);
        self.completion.wake_all();
    }
}

/// Owns the VM transition until startup or complete teardown has published.
struct StopCleanupGuard<'a> {
    cleanup: &'a StopCleanup,
}

impl Drop for StopCleanupGuard<'_> {
    fn drop(&mut self) {
        self.cleanup.complete();
    }
}

/// Immutable Host-side configuration consumed when a FrameVM is created.
///
/// The configuration is deliberately moved into the VM constructor as one
/// value. This keeps memory admission, device construction, and optional
/// assignment on one validation path instead of multiplying creation helpers
/// for every device combination.
pub struct FrameVmConfig {
    pub vcpu_count: usize,
    pub share: u32,
    pub memory_limit_bytes: usize,
    pub program_image: Arc<[u8]>,
    pub cmdline_append: Option<alloc::string::String>,
    pub block_images: Vec<Arc<dyn BlockImage>>,
    pub sock_configuration: SockConfiguration,
    pub network_configuration: Option<crate::device::NetworkConfiguration>,
    pub reserved_pci: Option<aster_pci::ReservedPciGroup>,
}

impl FrameVmConfig {
    /// Creates one complete immutable FrameVM configuration.
    #[expect(
        clippy::too_many_arguments,
        reason = "This constructor mirrors the complete device configuration boundary."
    )]
    pub fn new(
        vcpu_count: usize,
        share: u32,
        memory_limit_bytes: usize,
        program_image: Arc<[u8]>,
        cmdline_append: Option<alloc::string::String>,
        block_images: Vec<Arc<dyn BlockImage>>,
        sock_configuration: SockConfiguration,
        network_configuration: Option<crate::device::NetworkConfiguration>,
        reserved_pci: Option<aster_pci::ReservedPciGroup>,
    ) -> Self {
        Self {
            vcpu_count,
            share,
            memory_limit_bytes,
            program_image,
            cmdline_append,
            block_images,
            sock_configuration,
            network_configuration,
            reserved_pci,
        }
    }
}

impl From<u8> for VmStatus {
    fn from(val: u8) -> Self {
        match val {
            1 => VmStatus::Starting,
            2 => VmStatus::Running,
            3 => VmStatus::Stopping,
            _ => VmStatus::Stopped,
        }
    }
}

/// FrameVM instance.
///
/// This structure aggregates all resources for a FrameVM instance:
/// - VM identifier for multi-VM support
/// - vCPU set with one interrupt handler per vCPU
/// - VM status tracking
pub struct FrameVm {
    /// VM identifier
    id: VmId,
    /// Running status
    status: AtomicU8,
    /// Coordinates exactly-once teardown while a stop request drains.
    stop_cleanup: StopCleanup,
    /// Per-VM physical-memory accounting and ownership admission.
    memory: MemoryDomain,
    /// FrameV device subsystem.
    devices: Devices,
    /// Per-VM virtual IRQ allocation and callback state.
    irq: Arc<Irq>,
    /// Host observer for service-originated lifecycle events.
    event_sink: SpinLock<Option<Arc<dyn FrameVmEventSink>>>,
    /// Blocks Host teardown until another service carrier has left its image.
    ///
    /// Teardown must sleep here rather than repeatedly yield: a freshly
    /// spawned cleanup task otherwise competes with the FrameSchedGroup that
    /// owns the service carriers it is waiting for.
    service_task_exit_wait: WaitQueue,
    /// Number of task states whose service-defined values may still execute
    /// destructors from this VM image.
    service_image_task_count: AtomicUsize,
    /// Immutable boot information installed for this VM image.
    boot_info: SpinLock<Option<&'static crate::boot::BootInfo>>,
    /// VM-owned CPU-local state for FrameVM service code.
    cpu_local: CpuLocalDomain,
    /// Admission state shared by all FrameVM service tasks.
    task_admission: Arc<TaskAdmission>,
    /// Exact service scheduler selected for this FrameVM.
    ///
    /// Host policy has no companion scheduler view: it schedules only opaque
    /// vCPU groups and crosses the processor boundary after an inner choice.
    scheduler: RwLock<Option<&'static dyn Scheduler<Task>>>,
    /// Service entry points installed for this service image.
    service_entry_points: ServiceEntryPoints,
    /// Startup image waiting for the bootstrap task to load it.
    ///
    /// The bootstrap task takes this exactly once, then drops its copy before
    /// entering the non-returning service entry point. Keeping it in the VM
    /// rather than in that task's closure prevents a stopped carrier from
    /// retaining a complete ELF image until Host task reclamation.
    service_image: SpinLock<Option<Arc<[u8]>>>,
    /// Loaded service program used by this VM's tasks.
    program: SpinLock<Option<Arc<host_ostd::loader::Program>>>,
    /// OSTD provider cells relocated into this VM's service image.
    pub(super) allocator: Once<Box<FrameVmAllocator>>,
    /// Page-granular Host charge for control resources created for this VM.
    control_memory_charge_bytes: usize,
    /// Charge held while this VM is executing.
    control_memory_charge: SpinLock<Option<MemoryCharge>>,
    /// VM-wide timebase for jiffies accounting.
    clock: Arc<VmClock>,
    /// Static scheduler share configured at VM creation.
    share: u32,
    /// vCPU set
    vcpus: Vec<Vcpu>,
}

impl FrameVm {
    /// Creates a FrameVM instance from one complete immutable configuration.
    pub(crate) fn new(id: VmId, config: FrameVmConfig) -> Result<Self> {
        if !id.is_guest() {
            return Err(Error::InvalidArgs);
        }

        let FrameVmConfig {
            vcpu_count,
            share,
            memory_limit_bytes,
            program_image,
            cmdline_append,
            block_images,
            sock_configuration,
            network_configuration,
            reserved_pci,
        } = config;
        let control_memory_charge_bytes = control_memory_charge_bytes(
            vcpu_count,
            block_images.len(),
            network_configuration.is_some(),
            #[cfg(target_arch = "x86_64")]
            reserved_pci.is_some(),
            #[cfg(not(target_arch = "x86_64"))]
            false,
        )?;
        // The bootstrap task consumes the image exactly once. Keep it only in
        // the private startup slot rather than duplicating it in the loader or
        // a non-returning service-carrier closure.
        drop(cmdline_append);
        validate_create_args(vcpu_count, share)?;
        let memory =
            MemoryDomain::new_with_minimum(memory_limit_bytes, control_memory_charge_bytes)?;
        // Device queues, vCPU metadata, and provider control state are
        // allocated while the instance is constructed. Charge their
        // conservative Host-owned budget before publishing those resources,
        // so a too-small `MEM` fails creation rather than leaving an
        // uncharged stopped instance behind.
        let control_memory_charge = memory.charge_host(control_memory_charge_bytes)?;
        #[cfg(not(target_arch = "x86_64"))]
        if reserved_pci.is_some() {
            return Err(Error::InvalidArgs);
        }
        let devices = Devices::new(
            id,
            vcpu_count,
            block_images,
            sock_configuration,
            network_configuration,
            #[cfg(target_arch = "x86_64")]
            reserved_pci,
        )?;
        let irq = Arc::new(Irq::new());
        let clock = Arc::new(VmClock::new());
        let vcpus = (0..vcpu_count)
            .map(|vcpu_id| Vcpu::new(FrameVcpuId::new(id, vcpu_id), share))
            .collect();

        Ok(Self {
            id,
            status: AtomicU8::new(VmStatus::Stopped as u8),
            stop_cleanup: StopCleanup::new(),
            memory,
            devices,
            irq,
            event_sink: SpinLock::new(None),
            service_task_exit_wait: WaitQueue::new(),
            service_image_task_count: AtomicUsize::new(0),
            boot_info: SpinLock::new(None),
            cpu_local: CpuLocalDomain::new(vcpu_count),
            task_admission: Arc::new(TaskAdmission::new()),
            scheduler: RwLock::new(None),
            service_entry_points: ServiceEntryPoints::new(),
            service_image: SpinLock::new(Some(program_image)),
            program: SpinLock::new(None),
            allocator: Once::new(),
            control_memory_charge_bytes,
            control_memory_charge: SpinLock::new(Some(control_memory_charge)),
            clock,
            share,
            vcpus,
        })
    }

    /// Get VM ID.
    pub fn id(&self) -> VmId {
        self.id
    }

    /// Returns this VM's memory accounting snapshot.
    pub fn memory_stats(&self) -> MemoryStats {
        self.memory.stats()
    }

    /// Returns the private memory domain used by FrameVisor allocation paths.
    pub(crate) fn memory(&self) -> &MemoryDomain {
        &self.memory
    }

    /// Get CID for this VM.
    pub fn cid(&self) -> u64 {
        self.devices.sock().guest_cid() as u64
    }

    /// Get vCPU count.
    pub fn vcpu_count(&self) -> usize {
        self.vcpus.len()
    }

    /// Returns this VM's static scheduler share.
    pub const fn share(&self) -> u32 {
        self.share
    }

    /// Gets this VM's FrameV device subsystem.
    pub fn devices(&self) -> &Devices {
        &self.devices
    }

    /// Returns this VM's virtual IRQ state.
    pub(crate) fn irq(&self) -> &Arc<Irq> {
        &self.irq
    }

    /// Installs the Host observer for this VM.
    pub fn install_event_sink(&self, sink: Arc<dyn FrameVmEventSink>) -> Result<()> {
        let mut event_sink = self.event_sink.lock();
        if event_sink.is_some() {
            return Err(Error::InvalidArgs);
        }
        *event_sink = Some(sink);
        Ok(())
    }

    /// Delivers a service power request to this VM's Host observer.
    pub(crate) fn notify_power_event(&self, action: crate::power::PowerAction, status_code: i32) {
        if let Some(sink) = self.event_sink.lock().as_ref().cloned() {
            sink.on_power_event(action, status_code);
        }
    }

    /// Delivers the final service-carrier exit boundary to the Host observer.
    pub(crate) fn notify_service_task_exit(&self) {
        // Publish the image-membership change before waking a Host cleanup
        // task that may be waiting to release this VM.
        self.service_task_exit_wait.wake_all();
    }

    pub(crate) fn acquire_service_image_task_lease(&self) {
        self.service_image_task_count.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn release_service_image_task_lease(&self) {
        let previous = self.service_image_task_count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(
            previous != 0,
            "service image task leases must not underflow"
        );
        self.service_task_exit_wait.wake_all();
    }

    /// Quiesces service allocator state after every service task has exited.
    ///
    /// A non-co-designed service may retain opaque OSTD frame metadata whose
    /// destruction requires its own execution context. The Host may stop new
    /// allocation and release allocator-owned cache state, but it must not
    /// destroy those guest-owned frames on the service's behalf.
    pub(crate) fn quiesce_service_memory(&self) {
        if let Some(allocator) = self.allocator.get() {
            allocator.quiesce();
        }
    }

    /// Delivers assigned-device containment to the Host observer.
    pub fn notify_assigned_device_failure(&self) -> bool {
        let Some(sink) = self.event_sink.lock().as_ref().cloned() else {
            return false;
        };
        sink.on_assigned_device_failure();
        true
    }

    /// Completes one virtual PCI IRQ delivery after interrupt routing.
    pub(crate) fn dispatch_framev_irq(&self, irq_line: VirtualIrqLine, target_vcpu: usize) {
        if self.devices.pci().complete_irq(irq_line, target_vcpu)
            && let Ok(irq_num) = u8::try_from(irq_line.raw())
        {
            self.irq.dispatch_ostd_irq_from_handler(irq_num);
        }
    }

    /// Returns this VM's isolated PCI DMA domain, if assigned.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn pci_dma_domain(&self) -> Option<Arc<host_ostd::mm::dma::PciDmaDomain>> {
        self.devices.assigned_pci_dma_domain()
    }

    /// Returns this VM's current physical PCI access authority.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn assigned_pci_access(
        &self,
    ) -> Option<Arc<crate::assigned_pci::AssignedPciAccess>> {
        self.devices.assigned_pci_access()
    }

    /// Installs immutable boot information for this VM image.
    pub(crate) fn set_boot_info(&self, boot_info: &'static crate::boot::BootInfo) {
        *self.boot_info.lock() = Some(boot_info);
    }

    /// Returns the boot information installed for this VM image.
    pub(crate) fn boot_info(&self) -> Option<&'static crate::boot::BootInfo> {
        *self.boot_info.lock()
    }

    /// Releases boot information after the service image has stopped.
    pub(crate) fn clear_boot_info(&self) {
        *self.boot_info.lock() = None;
    }

    /// Gets this VM's CPU-local domain.
    #[inline]
    pub(crate) fn cpu_local_domain(&self) -> &CpuLocalDomain {
        &self.cpu_local
    }

    /// Returns this VM's service-task admission state.
    pub(crate) fn task_admission(&self) -> &Arc<TaskAdmission> {
        &self.task_admission
    }

    /// Begins the one service startup sequence for this VM.
    pub fn begin_task_startup(&self) -> Option<TaskStartup> {
        if !matches!(self.status(), VmStatus::Starting | VmStatus::Running) {
            return None;
        }

        self.task_admission.begin_startup()
    }

    /// Returns VM-wide elapsed jiffies.
    pub(crate) fn elapsed_jiffies(&self) -> u64 {
        self.clock.elapsed_jiffies()
    }

    /// Registers a timer callback for one owned vCPU.
    pub(crate) fn register_timer_callback(
        &self,
        frame_vcpu_id: FrameVcpuId,
        callback: fn(),
    ) -> Result<()> {
        if frame_vcpu_id.vm_id() != self.id {
            return Err(Error::InvalidArgs);
        }

        let vcpu = self
            .vcpu(frame_vcpu_id.vcpu_index())
            .ok_or(Error::InvalidArgs)?;
        vcpu.register_timer_callback(callback);
        Ok(())
    }

    /// Dispatches timer callbacks through one owned vCPU's interrupt context.
    pub(crate) fn dispatch_timer_callbacks(&self, frame_vcpu_id: FrameVcpuId, ticks: u64) {
        if frame_vcpu_id.vm_id() != self.id {
            return;
        }

        if let Some(vcpu) = self.vcpu(frame_vcpu_id.vcpu_index()) {
            vcpu.dispatch_timer_callbacks(ticks);
        }
    }

    /// Installs the OSTD-shaped service scheduler for this VM.
    pub(crate) fn install_scheduler(&self, scheduler: &'static dyn Scheduler<Task>) -> bool {
        let mut scheduler_slot = self.scheduler.write();
        if scheduler_slot.is_some() {
            return false;
        }
        *scheduler_slot = Some(scheduler);
        true
    }

    /// Returns this VM's exact service scheduler.
    pub(crate) fn scheduler(&self) -> Option<&'static dyn Scheduler<Task>> {
        *self.scheduler.read()
    }

    /// Clears the service scheduler for this VM.
    pub(crate) fn clear_scheduler(&self) {
        *self.scheduler.write() = None;
    }

    /// Returns this VM service image's runtime entry points.
    pub(crate) fn service_entry_points(&self) -> &ServiceEntryPoints {
        &self.service_entry_points
    }

    /// Returns the OSTD provider cells for this VM's service image.
    pub(crate) fn allocator(&self) -> &FrameVmAllocator {
        self.allocator
            .call_once(|| Box::new(FrameVmAllocator::new(self.memory.clone(), self.id)))
    }

    pub(super) fn release_control_memory(&self) {
        drop(self.control_memory_charge.lock().take());
    }

    fn acquire_control_memory(&self) -> Result<()> {
        let mut charge = self.control_memory_charge.lock();
        if charge.is_some() {
            return Ok(());
        }
        *charge = Some(self.memory.charge_host(self.control_memory_charge_bytes)?);
        Ok(())
    }

    /// Resolves a VM-local service provider symbol for Host loading.
    pub fn resolve_service_symbol(&self, name: &[u8]) -> Option<usize> {
        self.allocator().resolve_symbol(name)
    }

    /// Returns whether service relocation must wait for provider discovery.
    pub fn should_defer_service_symbol(name: &[u8]) -> bool {
        FrameVmAllocator::should_defer_symbol(name)
    }

    /// Records one provider cell discovered while loading this VM image.
    pub fn observe_service_symbol(
        &self,
        symbol: &host_ostd::loader::DefinedSymbol<'_>,
    ) -> Result<()> {
        self.allocator().observe_symbol(symbol)
    }

    /// Allocates a service heap block through this VM's OSTD-shaped provider.
    pub(crate) fn alloc_service_heap(&self, layout: Layout, zeroed: bool) -> *mut u8 {
        self.allocator().alloc_heap(layout, zeroed)
    }

    /// Deallocates a service heap block through this VM's provider.
    pub(crate) fn dealloc_service_heap(&self, ptr: *mut u8, layout: Layout) -> bool {
        self.allocator().dealloc_heap(ptr, layout)
    }

    /// Reallocates a service heap block through this VM's provider.
    pub(crate) fn realloc_service_heap(
        &self,
        ptr: *mut u8,
        old_layout: Layout,
        new_layout: Layout,
    ) -> *mut u8 {
        self.allocator().realloc_heap(ptr, old_layout, new_layout)
    }

    /// Installs this VM's loaded service program.
    pub fn install_program(&self, program: host_ostd::loader::Program) -> Result<()> {
        let mut installed = self.program.lock();
        if installed.is_some() {
            return Err(Error::InvalidArgs);
        }
        *installed = Some(Arc::new(program));
        Ok(())
    }

    /// Rolls back a service image that failed before execution started.
    ///
    /// The loader observes image-defined allocator cells after relocation and
    /// before program installation completes. If a later metadata
    /// check fails, those cells would otherwise point into an image that is no
    /// longer reachable. No service code has started at this point, so
    /// deactivate the cells and release the installed program together at
    /// this rollback boundary.
    pub fn abort_service_load(&self) {
        if let Some(allocator) = self.allocator.get() {
            allocator.deactivate();
        }
        drop(self.service_image.lock().take());
        drop(self.program.lock().take());
    }

    /// Starts the program installed for this VM.
    pub fn start_program(&self) -> Result<()> {
        // Keep the image alive for the duration of the call, but do not hold
        // the VM's program lock while service code is running.  A dynamic
        // entry may return, and the normal stop path must be able to take the
        // program slot and drop its mappings afterwards.
        let installed = self
            .program
            .lock()
            .as_ref()
            .cloned()
            .ok_or(Error::InvalidArgs)?;
        installed.start().map_err(Error::from)
    }

    /// Unloads the service program after all service tasks have stopped.
    pub(crate) fn unload_program(&self) {
        if let Some(allocator) = self.allocator.get() {
            allocator.deactivate();
        }
        drop(self.service_image.lock().take());
        drop(self.program.lock().take());
    }

    /// Takes the image to be loaded by this VM's bootstrap task.
    ///
    /// This is a one-shot startup handoff, not a reload facility. Once taken,
    /// the image must be dropped before the task enters service code.
    pub fn take_service_image(&self) -> Option<Arc<[u8]>> {
        self.service_image.lock().take()
    }

    /// Clears task entry points and scheduler state after image teardown.
    pub(crate) fn clear_task_state(&self) {
        self.service_entry_points.clear();
        self.clear_scheduler();
    }

    /// Clears VM-owned timer runtime state.
    pub(crate) fn clear_timer_runtime(&self) {
        self.clock.reset();
        for vcpu in &self.vcpus {
            vcpu.clear_timer_callbacks();
            vcpu.interrupt_handler().clear_pending();
        }
    }

    /// Get vCPU by ID.
    pub fn vcpu(&self, id: usize) -> Option<&Vcpu> {
        self.vcpus.get(id)
    }

    /// Returns the interrupt handler for a vCPU.
    pub(crate) fn interrupt_handler(&self, vcpu_id: usize) -> Option<Arc<InterruptHandler>> {
        self.vcpus
            .get(vcpu_id)
            .map(|vcpu| vcpu.interrupt_handler().clone())
    }

    /// Records one timer tick for an owned vCPU.
    pub(crate) fn record_timer_tick(&self, frame_vcpu_id: FrameVcpuId) {
        if frame_vcpu_id.vm_id() != self.id {
            return;
        }
        self.clock.record_deadline(crate::arch::read_tsc());
        if let Some(handler) = self.interrupt_handler(frame_vcpu_id.vcpu_index()) {
            handler.record_timer_tick();
            handler.wake();
        }
    }

    /// Gets the scheduler group for one vCPU.
    pub fn sched_group(&self, vcpu_id: usize) -> Option<&Arc<FrameSchedGroup>> {
        self.vcpus.get(vcpu_id).map(|v| v.sched_group())
    }

    /// Returns all scheduler groups owned by this VM.
    pub(crate) fn sched_groups(&self) -> Vec<Arc<FrameSchedGroup>> {
        self.vcpus
            .iter()
            .map(|vcpu| vcpu.sched_group().clone())
            .collect()
    }

    /// Get current status.
    pub fn status(&self) -> VmStatus {
        VmStatus::from(self.status.load(Ordering::Acquire))
    }

    /// Check if VM is running.
    pub fn is_running(&self) -> bool {
        self.status() == VmStatus::Running
    }

    /// Starts all vCPU event owners.
    pub fn start(&self) -> Result<()> {
        let cleanup = self.claim_stop_cleanup();
        if self
            .status
            .compare_exchange(
                VmStatus::Stopped as u8,
                VmStatus::Starting as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            drop(cleanup);
            return Err(Error::InvalidArgs);
        }
        if let Err(error) = self.memory.resume() {
            self.status
                .store(VmStatus::Stopped as u8, Ordering::Release);
            drop(cleanup);
            return Err(error);
        }
        if let Err(error) = self.acquire_control_memory() {
            self.status
                .store(VmStatus::Stopped as u8, Ordering::Release);
            drop(cleanup);
            return Err(error);
        }
        if let Some(allocator) = self.allocator.get() {
            allocator.activate();
        }
        if !self.task_admission.reset() {
            self.release_control_memory();
            self.status
                .store(VmStatus::Stopped as u8, Ordering::Release);
            drop(cleanup);
            return Err(Error::InvalidArgs);
        }
        self.cpu_local.activate();
        self.devices.reset_for_start();
        for vcpu in &self.vcpus {
            vcpu.sched_group().open_admission();
        }

        if let Err(error) = self.devices.mark_ready_all() {
            self.rollback_start(cleanup);
            return Err(error);
        }

        if self
            .status
            .compare_exchange(
                VmStatus::Starting as u8,
                VmStatus::Running as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            self.rollback_start(cleanup);
            return Err(Error::InvalidArgs);
        }
        Ok(())
    }

    fn rollback_start(&self, cleanup: StopCleanupGuard<'_>) {
        self.request_stop();
        self.finish_stop(
            cleanup,
            #[cfg(target_arch = "x86_64")]
            AssignedPciStop::Release,
        );
    }

    /// Waits until every tracked service task has left the loaded image.
    pub fn wait_for_service_task_exit(&self) {
        let mut reported_wait = false;
        self.service_task_exit_wait.wait_until(|| {
            let active_tasks = self.service_image_task_count.load(Ordering::Acquire);
            if active_tasks == 0 {
                return Some(());
            }
            if !reported_wait {
                crate::early_println!(
                    "[FrameVM] waiting for service task exit: vm={}, active_tasks={}",
                    self.id,
                    active_tasks
                );
                reported_wait = true;
            }
            None
        });
    }

    /// Stops a VM after its service completes orderly shutdown work.
    pub fn stop(&self) -> bool {
        let cleanup = self.claim_stop_cleanup();
        if self.status() == VmStatus::Stopped {
            return false;
        }

        #[cfg(target_arch = "x86_64")]
        let assigned_pci_stop = match self.begin_orderly_stop() {
            TaskAdmissionOutcome::Completed => AssignedPciStop::Release,
            TaskAdmissionOutcome::Failed | TaskAdmissionOutcome::Forced => {
                AssignedPciStop::Quarantine
            }
        };
        #[cfg(not(target_arch = "x86_64"))]
        self.begin_orderly_stop();
        self.request_execution_stop();

        self.finish_stop(
            cleanup,
            #[cfg(target_arch = "x86_64")]
            assigned_pci_stop,
        )
    }

    /// Forces a VM stop without waiting for service persistence work.
    pub fn force_stop(&self) -> bool {
        let cleanup = self.claim_stop_cleanup();
        if self.status() == VmStatus::Stopped {
            return false;
        }

        if self.status() != VmStatus::Stopping {
            self.request_stop();
        }
        self.finish_stop(
            cleanup,
            #[cfg(target_arch = "x86_64")]
            AssignedPciStop::Release,
        )
    }

    /// Stops the VM and permanently quarantines its assigned PCI group.
    #[cfg(target_arch = "x86_64")]
    pub fn stop_for_assigned_pci_failure(&self) -> bool {
        self.stop_cleanup.request_pci_quarantine();
        let cleanup = self.claim_stop_cleanup();
        self.request_stop();
        self.finish_stop(cleanup, AssignedPciStop::Quarantine)
    }

    fn finish_stop(
        &self,
        _cleanup: StopCleanupGuard<'_>,
        #[cfg(target_arch = "x86_64")] assigned_pci_stop: AssignedPciStop,
    ) -> bool {
        // Every service task can hold image-defined callbacks and allocator
        // state. The service image must stay mapped until each task has
        // exited, regardless of whether the stop was orderly or forced.
        self.wait_for_service_task_exit();
        self.devices.stop_all();
        // Service callbacks carry vtables and function pointers into the
        // loaded image.  Drain every callback registry before dropping the
        // image mappings; otherwise callback destruction can dereference a
        // service vtable after its backing pages have been unmapped.
        self.irq.clear();
        self.clear_timer_runtime();
        // Pending owner-scoped events are no longer deliverable after
        // admission closes. Clear them while the service image and callback
        // registries are still valid; there is no interrupt task to join or
        // reset.
        for vcpu in &self.vcpus {
            vcpu.interrupt_handler().clear_pending();
        }
        self.clear_task_state();
        self.cpu_local.start_teardown();
        // CPU-local values may carry service-defined destructors or allocator
        // callbacks.  Drop them while the service image is still mapped;
        // otherwise destroying the FrameVM after `unload_program` can jump
        // through a vtable or function pointer into unmapped service code.
        self.cpu_local.clear();
        // Drop FrameVisor-owned heap state while provider cells are still
        // usable.  A custom provider may retain opaque grants or OSTD handles;
        // in that case `deactivate_if_quiescent` deliberately keeps the image
        // mapped for a later teardown retry.
        self.quiesce_service_memory();
        // Service-owned metadata may contain vtables or destructors in the
        // loaded image. Release hidden-owner-only entries after allocator
        // caches have drained, while the image is still mapped; opaque
        // provider caches with extra references remain retained for an
        // explicit teardown attempt.
        if let Err(error) = ownership::release_service_owned_for_vm(self.id) {
            ::log::error!(
                "[framevisor] failed to release post-quiesce memory for VM {}: {:?}",
                self.id,
                error
            );
        }
        self.memory.begin_stopping();
        self.memory.wait_for_reservations();
        #[cfg(target_arch = "x86_64")]
        let assigned_pci_failed = {
            // Entering this phase is the cutoff for quarantine requests. A
            // request that arrives after it is intentionally stale: PCI
            // teardown has already committed the policy for this stop request.
            let assigned_pci_stop = self.stop_cleanup.begin_pci_teardown(assigned_pci_stop);
            match assigned_pci_stop {
                AssignedPciStop::Quarantine => self.devices.quarantine_assigned_pci(),
                AssignedPciStop::Release => self.devices.release_assigned_pci(),
            }
        };
        #[cfg(not(target_arch = "x86_64"))]
        let assigned_pci_failed = false;

        self.release_stopped_memory_inner();
        assigned_pci_failed
    }

    /// Releases memory that became reclaimable after service execution stops.
    ///
    /// The first release attempt runs as part of normal stop. Host lifecycle
    /// code may call this again after an explicit scheduler boundary because
    /// loader mappings defer their frame drops until then. A terminal VM may
    /// still retain service-owned pages: the terminal status means no service
    /// code can execute, while destruction remains gated on the memory domain
    /// becoming empty.
    pub fn release_stopped_memory(&self) -> bool {
        let _cleanup = self.claim_stop_cleanup();
        self.release_stopped_memory_inner()
    }

    fn release_stopped_memory_inner(&self) -> bool {
        if !matches!(self.status(), VmStatus::Stopping | VmStatus::Stopped) {
            return false;
        }

        // Loader/RCU references may have drained after the first stop pass.
        // Retry service-owned cleanup while the program is still retained;
        // this is the last safe point for typed metadata destructors.
        self.quiesce_service_memory();
        if let Err(error) = ownership::release_service_owned_for_vm(self.id) {
            ::log::error!(
                "[framevisor] failed to retry service-owned memory release for VM {}: {:?}",
                self.id,
                error
            );
        }
        if let Err(error) = ownership::release_quiesced_for_vm(self.id) {
            ::log::error!(
                "[framevisor] failed to release cached memory for VM {}: {:?}",
                self.id,
                error
            );
        }

        // All ordinary owner records must be released while service metadata
        // vtables are still mapped. Provider-managed records and any public
        // service references remain protected by the image-retention checks.
        let image_can_unload = !ownership::has_service_owned_for_vm(self.id)
            && self
                .allocator
                .get()
                .is_none_or(|allocator| allocator.deactivate_if_quiescent());
        if image_can_unload {
            self.unload_program();
        } else {
            ::log::debug!(
                "[framevisor] allocator image for VM {} still has opaque state",
                self.id
            );
        }

        self.release_control_memory();
        // A non-co-designed service can retain opaque OSTD metadata after all
        // of its tasks have exited. This must not keep the VM in `Stopping`:
        // callers need a terminal execution state, while `destroy_vm` still
        // refuses to remove the instance until `MemoryDomain::close` proves
        // every retained frame has drained.
        self.status
            .store(VmStatus::Stopped as u8, Ordering::Release);
        true
    }

    fn claim_stop_cleanup(&self) -> StopCleanupGuard<'_> {
        loop {
            if let Some(cleanup) = self.stop_cleanup.try_claim() {
                return cleanup;
            }
            // The current owner may be waiting for service tasks, device
            // calls, IRQ state, or memory reservations. Never spin or hold a
            // VM spin lock while joining that owner.
            self.stop_cleanup.wait_for_completion();
        }
    }

    /// Requests all vCPUs to stop without waiting for interrupt teardown.
    pub fn request_stop(&self) {
        self.status
            .store(VmStatus::Stopping as u8, Ordering::Release);
        // Close memory admission before waking workers. A worker that observes
        // the stop request may still finish an already-admitted operation, but
        // it cannot create a new VM-owned backing extent.
        self.memory.begin_stopping();
        self.task_admission.request_forced();
        self.request_execution_stop();
    }

    fn begin_orderly_stop(&self) -> TaskAdmissionOutcome {
        self.status
            .store(VmStatus::Stopping as u8, Ordering::Release);
        self.memory.begin_stopping();
        self.task_admission.request_orderly();
        self.task_admission.wait_for_orderly_completion()
    }

    fn request_execution_stop(&self) {
        for vcpu in &self.vcpus {
            vcpu.sched_group().close_admission();
        }
    }
}

fn validate_vcpu_count(vcpu_count: usize) -> Result<()> {
    if (MIN_VCPU_COUNT..=MAX_VCPU_COUNT).contains(&vcpu_count) {
        return Ok(());
    }

    Err(Error::InvalidArgs)
}

pub(super) fn validate_create_args(vcpu_count: usize, share: u32) -> Result<()> {
    validate_vcpu_count(vcpu_count)?;
    scheduler::validate_framevm_share(share)
}

pub(super) fn control_memory_charge_bytes(
    vcpu_count: usize,
    block_count: usize,
    has_network: bool,
    has_assigned_pci: bool,
) -> Result<usize> {
    let mut pages = CONTROL_MEMORY_BASE_PAGES;
    pages = pages
        .checked_add(
            vcpu_count
                .checked_mul(CONTROL_MEMORY_PER_VCPU_PAGES)
                .ok_or(Error::Overflow)?,
        )
        .ok_or(Error::Overflow)?;
    pages = pages
        .checked_add(
            block_count
                .checked_mul(CONTROL_MEMORY_PER_BLOCK_PAGES)
                .ok_or(Error::Overflow)?,
        )
        .ok_or(Error::Overflow)?;
    if has_network {
        pages = pages
            .checked_add(CONTROL_MEMORY_NETWORK_PAGES)
            .ok_or(Error::Overflow)?;
    }
    if has_assigned_pci {
        pages = pages
            .checked_add(CONTROL_MEMORY_PCI_PAGES)
            .ok_or(Error::Overflow)?;
    }
    pages
        .checked_mul(crate::mm::PAGE_SIZE)
        .ok_or(Error::Overflow)
}

#[cfg(ktest)]
mod tests {
    use host_ostd::prelude::ktest;

    #[cfg(target_arch = "x86_64")]
    use super::AssignedPciStop;
    use super::StopCleanup;

    #[ktest]
    fn stop_cleanup_has_one_owner_until_completion() {
        let cleanup = StopCleanup::new();
        let owner = cleanup
            .try_claim()
            .expect("the first stop cleanup caller must claim ownership");

        assert!(cleanup.try_claim().is_none());

        drop(owner);
        assert!(cleanup.try_claim().is_some());
    }

    #[cfg(target_arch = "x86_64")]
    #[ktest]
    fn pci_quarantine_request_has_a_teardown_cutoff() {
        let cleanup = StopCleanup::new();
        assert!(cleanup.request_pci_quarantine());
        assert!(matches!(
            cleanup.begin_pci_teardown(AssignedPciStop::Release),
            AssignedPciStop::Quarantine
        ));

        let cleanup = StopCleanup::new();
        assert!(matches!(
            cleanup.begin_pci_teardown(AssignedPciStop::Release),
            AssignedPciStop::Release
        ));
        assert!(!cleanup.request_pci_quarantine());
    }
}
