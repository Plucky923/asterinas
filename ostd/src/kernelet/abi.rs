// SPDX-License-Identifier: MPL-2.0

//! Defines the C-compatible data exchanged by the host and a kernelet image.
//!
//! The first version of this ABI is x86-64 only. A service table is passed to
//! the image entry point; image code never resolves a host symbol by name.

use core::{
    mem::offset_of,
    sync::atomic::{AtomicU32, AtomicU64, Ordering},
};

/// Device entry with the existing VirtIO MMIO transport.
pub const DEVICE_KIND_VIRTIO: u16 = 1;

/// First kernel-half slot in the x86-64 PML4.
pub(crate) const KERNEL_HALF_START: usize = 256;
/// Number of kernel-half slots in the 512-entry x86-64 PML4.
pub(crate) const KERNEL_HALF_ENTRIES: usize = 512 - KERNEL_HALF_START;

/// Host-written identity of the carrier currently running on a physical CPU.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuSlot {
    /// Instance registry slot, or `u16::MAX` outside a carrier.
    pub kernelet: u16,
    /// Virtual CPU within that instance.
    pub vcpu: u16,
    /// Registry generation that rejects a previously occupied instance slot.
    pub generation: u32,
    /// Reserved and always zero.
    pub _reserved: u64,
}

impl CpuSlot {
    /// Identity published while no carrier runs on the Host CPU.
    pub const NONE: Self = Self {
        kernelet: u16::MAX,
        vcpu: u16::MAX,
        generation: 0,
        _reserved: 0,
    };
}

/// Records the image-relative targets and template bounds validated at registration.
#[repr(C)]
pub struct EntryTable {
    /// Size of this table in bytes.
    pub size: u64,
    /// Image-relative entry for a secondary virtual CPU.
    pub vcpu_entry_offset: u64,
    /// Image-relative entry for a virtual interrupt.
    pub virq_entry_offset: u64,
    /// Image-relative start of the CPU-local template.
    pub cpu_local_start_offset: u64,
    /// Image-relative end of the CPU-local template.
    pub cpu_local_end_offset: u64,
    /// Hash of the OSTD source and toolchain shared with the host build.
    pub source_hash: [u8; 32],
    /// Image-relative start of the exception table.
    pub ex_table_start_offset: u64,
    /// Image-relative end of the exception table.
    pub ex_table_end_offset: u64,
    /// Image-relative entry for a Host-requested carrier yield.
    pub yield_entry_offset: u64,
    /// Image-relative entry for termination at a trap return.
    pub exit_entry_offset: u64,
    /// Image-relative start of the fixed nonredirectable trap-return stubs.
    pub stub_range_start_offset: u64,
    /// Image-relative exclusive end of the fixed trap-return stubs.
    pub stub_range_end_offset: u64,
    /// Image-relative start of CPU-local selection and access sequences.
    pub cpu_access_start_offset: u64,
    /// Image-relative exclusive end of the CPU-local access sequences.
    pub cpu_access_end_offset: u64,
    /// Image-relative entry for user-mode returns (syscalls, exceptions, kernel events).
    pub user_event_entry_offset: u64,
}

/// Bootstrap version of the read-only boot page shared by the Host and image.
///
/// The scheduling fields follow the common image ABI. Grant and device fields
/// will extend this structure as their services become available.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootArgs {
    /// Size of this ABI version in bytes.
    pub size: u32,
    /// Generation of this instance.
    pub generation: u32,
    /// Hash of the common OSTD source and toolchain.
    pub source_hash: [u8; 32],
    /// Timestamp-counter frequency published by the Host.
    pub tsc_freq_hz: u64,
    /// TSC origin of the Host-boot monotonic clock, shared by all instances.
    pub clock_origin_tsc: u64,
    /// Host-assigned kernelet identifier.
    pub kernelet: u16,
    /// Number of virtual CPUs in this instance.
    pub num_vcpus: u16,
    /// Physical CPU assigned to each virtual CPU.
    pub vcpu_host_cpu: [u16; MAX_VCPUS],
    /// GS offset of the Host-written 16-byte [`CpuSlot`].
    /// The Host publishes [`CpuSlot::NONE`] outside a carrier.
    pub cpu_slot_gs_offset: u32,
    /// Size of one CPU-local replica in bytes.
    pub cpu_local_replica_bytes: u32,
    /// Base of the Host linear map shared by the kernelet.
    pub linear_map_base: u64,
    /// The stable kernel-half entries copied into every tenant user root.
    pub kernel_half_entries: [u64; KERNEL_HALF_ENTRIES],
    /// Base of this instance's sparse frame-metadata window.
    pub meta_base: u64,
    /// Offset from this boot page to the Host-written run table.
    pub grant_table: u32,
    /// Offset from this boot page to the physical-section index.
    pub meta_section_index: u32,
    /// Offset from this boot page to the compact-block reverse index.
    pub meta_block_sections: u32,
    /// Offset from this boot page to one read-only grain bitmap per metadata block.
    pub meta_grain_bitmap: u32,
    /// Maximum number of compact metadata blocks in this instance.
    pub max_meta_sections: u32,
    /// Offset from this boot page to the shared info page.
    pub info_page: u32,
    /// Offset from this boot page to the first writable virtual-CPU record.
    pub vcpu_records: u32,
    /// Maximum number of live internal Task stacks.
    pub max_tasks: u32,
    /// Size of the tenant floating-point save area.
    pub fpu_area_bytes: u32,
    /// Offset from this boot page to the read-only kernel command line.
    pub cmdline_offset: u32,
    /// Number of command-line bytes, without a trailing NUL.
    pub cmdline_len: u32,
    /// Offset from this boot page to the virtual-device table.
    pub devices_offset: u32,
    /// Number of virtual devices in the table.
    pub num_devices: u32,
    /// Nonzero if the Host kernel enables page table isolation (PTI).
    pub pti_enabled: u8,
    /// Nonzero if the Host CPU and page tables support the NX bit.
    pub nx_supported: u8,
    /// Number of hardware page-table levels on the Host (`4` or `5`).
    pub pgtable_levels: u8,
    /// User page-table mode: `0` for direct PTEs in OSTD, `1` for VMA services.
    pub pt_mode: u8,
    /// Host realtime nanoseconds since the Unix epoch at the clock snapshot.
    pub realtime_base_ns: u64,
    /// Host monotonic nanoseconds at the same clock snapshot.
    pub monotonic_base_ns: u64,
    /// Host kernel VA of the read-only initramfs CPIO archive, or `0`.
    pub initramfs_base: u64,
    /// Byte length of the initramfs CPIO archive, or `0`.
    pub initramfs_len: u64,
}

/// One virtual device and its reserved address and interrupt resources.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DeviceEntry {
    /// Host-assigned identifier used by the MMIO service calls.
    pub id: u16,
    /// Device kind: 1 for VirtIO MMIO, 2 for a shared-buffer device.
    pub kind: u16,
    /// Virtual interrupt line.
    pub irq: u8,
    /// Reserved and always zero.
    pub reserved: u8,
    /// Virtual CPU receiving this device's interrupt.
    pub vcpu: u16,
    /// Size of the register window in bytes.
    pub reg_bytes: u32,
    /// Virtio device type.
    pub device_type: u32,
    /// Pseudo-physical base of the register window.
    pub mmio_base: u64,
}

/// Maximum number of virtual CPUs supported by the common image ABI.
pub const MAX_VCPUS: usize = 64;

/// A physically contiguous run of 2 MiB grains published by the Host.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RunDesc {
    /// First physical byte of the run.
    pub paddr: u64,
    /// Number of grains in the run.
    pub grains: u32,
    /// Reserved and always zero.
    pub reserved: u32,
}

/// Host-published memory and lifecycle information.
#[repr(C)]
pub struct InfoPage {
    /// Published length of the grant table.
    pub runs: AtomicU32,
    /// Published number of compact frame-metadata blocks.
    pub meta_blocks: AtomicU32,
    /// End of the highest published grant run.
    pub max_paddr: AtomicU64,
    /// Nonzero when the Host has requested termination.
    pub dying: AtomicU32,
    /// Reserved and always zero.
    pub reserved: u32,
}

/// Size of the Host's physical-memory grant unit.
pub const GRAIN_SIZE: usize = 2 * 1024 * 1024;
/// Physical-memory span represented by one compact metadata block.
pub const META_SECTION_BYTES: usize = 128 * 1024 * 1024;
/// Metadata value for a physical section not granted to this kernelet.
pub const NO_META_BLOCK: u32 = u32::MAX;

/// Mapped bytes in a Host-owned internal Task stack slot.
pub(crate) const KSTACK_MAPPING_BYTES: usize = 64 * 4096;

/// Bytes usable by stack frames in a Host-owned slot.
pub(crate) const KSTACK_USABLE_BYTES: usize = KSTACK_MAPPING_BYTES;

/// Per-vCPU execution samples awaiting Image-side Task accounting.
///
/// Both privilege counts share one atomic word so taking a batch also defines
/// a single logical Task handoff boundary. User ticks occupy the low 32 bits;
/// kernel ticks occupy the high 32 bits. Overflow stops the Image rather than
/// wrapping into the other privilege count. This record contains no Task
/// identity and is independent of the virtual timer delivery counters.
#[repr(transparent)]
#[derive(Default)]
pub(crate) struct PendingTaskTicks(AtomicU64);

impl PendingTaskTicks {
    #[cfg(ktest)]
    pub(crate) fn record(&self, user: bool) -> bool {
        let shift = if user { 0 } else { 32 };
        let mut old = self.0.load(Ordering::Relaxed);
        loop {
            if (old >> shift) as u32 == u32::MAX {
                return false;
            }
            match self.0.compare_exchange_weak(
                old,
                old + (1 << shift),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(next) => old = next,
            }
        }
    }

    /// Atomically transfers this batch to the current Image-side consumer.
    pub(crate) fn take(&self) -> u64 {
        self.0.swap(0, Ordering::AcqRel)
    }

    pub(crate) fn split(batch: u64) -> (u64, u64) {
        (batch as u32 as u64, batch >> 32)
    }
}

#[cfg(ktest)]
mod pending_task_tick_tests {
    use super::*;
    use crate::prelude::*;

    #[ktest]
    fn handoff_separates_outgoing_and_incoming_execution_samples() {
        let ticks = PendingTaskTicks::default();
        assert!(ticks.record(true));
        assert!(ticks.record(false));
        let outgoing = ticks.take();
        // A physical producer after the logical handoff belongs to the new
        // owner, even while Image is still cleaning up the previous Task.
        assert!(ticks.record(false));
        assert_eq!(PendingTaskTicks::split(outgoing), (1, 1));
        assert_eq!(PendingTaskTicks::split(ticks.take()), (0, 1));
        assert_eq!(PendingTaskTicks::split(ticks.take()), (0, 0));
    }

    #[ktest]
    fn privilege_counts_do_not_wrap_into_each_other() {
        let ticks = PendingTaskTicks::default();
        ticks.0.store(u32::MAX as u64, Ordering::Relaxed);
        assert!(!ticks.record(true));
        assert!(ticks.record(false));
        assert_eq!(PendingTaskTicks::split(ticks.take()), (u32::MAX as u64, 1));
        ticks.0.store((u32::MAX as u64) << 32, Ordering::Relaxed);
        assert!(!ticks.record(false));
        assert!(ticks.record(true));
        assert_eq!(PendingTaskTicks::split(ticks.take()), (1, u32::MAX as u64));
    }
}

/// Communicates pending work and time for one virtual CPU.
///
/// This record is never authoritative for identity, ownership, or termination.
#[repr(C, align(64))]
#[derive(Default)]
pub(crate) struct VcpuRecord {
    /// Level-triggered summary of pending virtual interrupts.
    pub pending: AtomicU64,
    /// Pending device lines; lines below 32 are reserved.
    pub pending_lines: [AtomicU64; 4],
    /// User-mode execution ticks awaiting delivery.
    pub tick_user: AtomicU64,
    /// Kernel-mode execution ticks awaiting delivery.
    pub tick_kernel: AtomicU64,
    /// Bottom-half execution ticks awaiting delivery.
    pub tick_l2: AtomicU64,
    /// Host-published time runnable but not executing, in nanoseconds.
    pub stolen_ns: AtomicU64,
    /// Host-published offset excluded from the inner scheduler clock.
    pub nonrunning_tsc: AtomicU64,
    /// Inner preemption-guard depth, written by the current virtual CPU.
    pub guards: AtomicU32,
    /// Whether virtual interrupts are disabled on this virtual CPU.
    pub irq_off: AtomicU32,
    /// Immutable virtual CPU number, published before image entry.
    pub vcpu: u32,
    /// Virtual interrupt nesting level.
    pub irq_level: AtomicU32,
    /// Current internal Task's lower stack bound, retained as shared ABI metadata.
    pub stack_limit: AtomicU64,
    /// Immutable address of this virtual CPU's CPU-local replica.
    pub cpu_local_base: u64,
    /// Host-published time spent asleep in `vcpu_idle`, in nanoseconds.
    pub parked_ns: AtomicU64,
    /// Execution samples consumed at Image upcalls and logical Task handoffs.
    pub task_ticks: PendingTaskTicks,
}

/// Recoverable user-copy fault state for one virtual CPU.
///
/// These records follow the complete `VcpuRecord` array in the Host-pinned
/// shared pages. Keeping them separate preserves the two-cache-line virtual
/// interrupt ABI even when the user-copy protocol changes.
#[repr(C, align(64))]
#[derive(Default)]
pub struct CopyFaultRecord {
    /// Address of the most recent validated image-side copy fault.
    pub addr: AtomicU64,
    /// Hardware page-fault error code.
    pub error: AtomicU64,
    /// One after the Host publishes `addr` and `error`.
    pub pending: AtomicU32,
}

/// User-mode event and stack-handoff record for one virtual CPU.
///
/// These records follow the complete `CopyFaultRecord` array in the
/// Host-pinned shared pages.
#[repr(C, align(64))]
#[derive(Default)]
pub struct UserEventRecord {
    /// Host address of the carrier's live `struct pt_regs`.
    pub pt_regs: AtomicU64,
    /// Current user task's save-area-below event RSP (16-byte aligned).
    pub event_rsp: AtomicU64,
    /// Current user task's kernel stack lower bound.
    pub event_stack_limit: AtomicU64,
    /// Returned trap number for `UserEvent::Exception`.
    pub trap_num: AtomicU64,
    /// Returned trap error code for `UserEvent::Exception`.
    pub error_code: AtomicU64,
    /// Fault address (`CR2` on `#PF`) for `UserEvent::Exception`.
    pub fault_addr: AtomicU64,
    /// Reserved and always zero.
    pub _pad: [u64; 2],
}

/// Byte offset of the fault-record array from the first `VcpuRecord`.
pub const fn copy_fault_records_offset(vcpus: usize) -> usize {
    vcpus * size_of::<VcpuRecord>()
}

/// Byte offset of the user-event record array from the first `VcpuRecord`.
pub const fn user_event_records_offset(vcpus: usize) -> usize {
    copy_fault_records_offset(vcpus) + vcpus * size_of::<CopyFaultRecord>()
}

/// Number of bytes mapped for all per-vCPU shared arrays.
pub const fn vcpu_shared_bytes(vcpus: usize) -> usize {
    user_event_records_offset(vcpus) + vcpus * size_of::<UserEventRecord>()
}

/// The x86-64 register file borrowed in place by the `user_run` service.
///
/// Both the image's `UserContext` and Host entry assembly use this type.
/// The first twenty machine words keep the native syscall/trap stack layout;
/// the remaining fields are filled before interrupts can be enabled.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KletUserContext {
    /// General-purpose registers in the native entry assembly's order.
    pub general: crate::arch::cpu::context::GeneralRegs,
    /// Processor flags in the native entry assembly's order.
    pub rflags: usize,
    /// Returned trap number.
    pub trap_num: usize,
    /// Returned trap error code.
    pub error_code: usize,
    /// Page-fault address captured before interrupts are enabled.
    pub fault_addr: usize,
}

/// Returns the result of a virtual MMIO register read.
#[repr(C)]
pub struct MmioResult {
    /// Zero on success or a negative ABI error.
    pub status: i64,
    /// Register value on success.
    pub value: u64,
}

/// Supplies the fixed first-version services to an image.
#[repr(C)]
pub struct ServiceTable {
    /// Size of this table in bytes.
    pub size: u64,
    /// Requests more 2 MiB grains from the Host.
    pub grains_request: extern "C" fn(count: u32, contiguous: u32) -> i64,
    /// Registers a page-table root owned by the instance.
    pub pt_root_register: extern "C" fn(root_paddr: u64) -> i64,
    /// Unregisters an inactive page-table root.
    pub pt_root_unregister: extern "C" fn(root_paddr: u64) -> i64,
    /// Activates a registered page-table root.
    pub pt_activate: extern "C" fn(root_paddr: u64) -> i64,
    /// Invalidates translations belonging to a registered root.
    /// With root zero, only (start=0, len=u64::MAX) is valid: this invalidates
    /// all local carrier translations, including global entries, and retains
    /// its selected root. It does not initiate a remote shootdown.
    pub tlb_shootdown: extern "C" fn(root_paddr: u64, start: u64, len: u64) -> i64,
    /// Allocates one guarded internal Task stack.
    pub kstack_alloc: extern "C" fn() -> u64,
    /// Releases one inactive internal Task stack.
    pub kstack_free: extern "C" fn(vaddr: u64) -> i64,
    /// Starts a prepared secondary virtual CPU.
    pub vcpu_boot: extern "C" fn(vcpu: u32) -> i64,
    /// Parks the current virtual CPU until work, deadline, or stop.
    pub vcpu_idle: extern "C" fn(deadline_ns: u64) -> i64,
    /// Publishes work for another virtual CPU.
    pub vcpu_kick: extern "C" fn(vcpu: u32) -> i64,
    /// Yields the current carrier to the Host scheduler.
    pub vcpu_yield: extern "C" fn(),
    /// Hints that the current carrier is spinning on another carrier.
    pub vcpu_on_spin: extern "C" fn(),
    /// Executes user mode and returns the reason for re-entering the image.
    pub user_run: extern "C" fn(ctx: *mut KletUserContext) -> i32,
    /// Reads a virtual device register.
    pub mmio_read: extern "C" fn(dev: u32, offset: u32, width: u32) -> MmioResult,
    /// Writes a virtual device register.
    pub mmio_write: extern "C" fn(dev: u32, offset: u32, width: u32, value: u64) -> i64,
    /// Writes one bounded log record.
    pub log_write: extern "C" fn(
        level: u32,
        module: *const u8,
        module_len: u32,
        text: *const u8,
        text_len: u32,
    ) -> i64,
    /// Reports an oops without necessarily stopping the instance.
    pub oops: extern "C" fn(msg: *const u8, len: u32) -> i64,
    /// Stops the current instance without returning to the image.
    pub stop: extern "C" fn(kind: u32, code: u32, msg: *const u8, len: u32) -> !,
    /// VMA-baseline service call (`OP_VM_*`). Keeps the 160-byte `ServiceTable` ABI.
    pub buffer: extern "C" fn(u32, u64, u64, u64, u64) -> MmioResult,
}

/// VMA-baseline map operation: `token=linux_pgd_paddr`, `arg0=va`, `arg1=paddr`, `arg2=prot_bits`.
pub const OP_VM_MAP: u32 = 0x100;
/// VMA-baseline protect operation: `token=linux_pgd_paddr`, `arg0=va`, `arg1=prot_bits`, `arg2=0`.
pub const OP_VM_PROTECT: u32 = 0x101;
/// VMA-baseline unmap operation: `token=linux_pgd_paddr`, `arg0=va`, `arg1=len`, `arg2=0`.
pub const OP_VM_UNMAP: u32 = 0x102;

/// Read permission bit for `OP_VM_MAP` and `OP_VM_PROTECT`.
pub const KLET_PROT_READ: u64 = 1;
/// Write permission bit for `OP_VM_MAP` and `OP_VM_PROTECT`.
pub const KLET_PROT_WRITE: u64 = 2;
/// Execute permission bit for `OP_VM_MAP` and `OP_VM_PROTECT`.
pub const KLET_PROT_EXEC: u64 = 4;

/// Virtual timer tick is pending.
pub const VIRQ_TICK: u64 = 1 << 0;
/// Remote work is pending.
pub const VIRQ_KICK: u64 = 1 << 1;
/// One or more virtual device lines are pending.
pub const VIRQ_LINES: u64 = 1 << 2;

/// A tenant system call returned from `user_run`.
pub const USER_RETURN_SYSCALL: i32 = 0;
/// A tenant CPU exception returned from `user_run`.
pub const USER_RETURN_EXCEPTION: i32 = 1;
/// A physical interrupt or virtual work requires image-side processing.
pub const USER_RETURN_PENDING: i32 = 2;

/// User event code passed to `user_event_entry` for a system call.
pub const USER_EVENT_SYSCALL: u64 = 0;
/// User event code passed to `user_event_entry` for a CPU exception.
pub const USER_EVENT_EXCEPTION: u64 = 1;
/// User event code passed to `user_event_entry` for a pending kernel event.
pub const USER_EVENT_KERNEL_EVENT: u64 = 2;

/// The requested resource is not owned by this kernelet.
pub const NOT_OWNED: i64 = 2;
/// An argument or pointer is invalid.
pub const INVALID: i64 = 3;
/// A configured limit refuses the operation.
pub const LIMIT: i64 = 4;
/// The current lifecycle or service state refuses the operation.
pub const STATE: i64 = 5;
/// Console log level, written directly to the early serial console.
pub const LEVEL_CONSOLE: u32 = 8;
/// Maximum grains granted by one service crossing.
pub const MAX_GRAINS_PER_REQUEST: u32 = 32;
/// Maximum bytes in a log module name.
pub const MAX_LOG_MODULE_BYTES: u32 = 128;
/// Maximum bytes in a log text record.
pub const MAX_LOG_TEXT_BYTES: u32 = 1024;
/// Maximum bytes in an oops report.
pub const MAX_OOPS_BYTES: u32 = 4096;
/// Indicates an ordinary image exit.
pub const STOP_EXIT: u32 = 0;
/// Indicates an image panic.
pub const STOP_PANIC: u32 = 1;
/// Indicates a stack overflow reported by the image.
pub const STOP_STACK_OVERFLOW: u32 = 2;
/// Marks a requested restart in an exit code.
pub const EXIT_RESTART: u32 = crate::power::EXIT_RESTART;

const _: () = {
    assert!(size_of::<CpuSlot>() == 16);
    assert!(offset_of!(CpuSlot, kernelet) == 0);
    assert!(offset_of!(CpuSlot, vcpu) == 2);
    assert!(offset_of!(CpuSlot, generation) == 4);
    assert!(offset_of!(CpuSlot, _reserved) == 8);
    assert!(size_of::<EntryTable>() == 144);
    assert!(offset_of!(EntryTable, source_hash) == 40);
    assert!(offset_of!(EntryTable, ex_table_start_offset) == 72);
    assert!(offset_of!(EntryTable, yield_entry_offset) == 88);
    assert!(offset_of!(EntryTable, exit_entry_offset) == 96);
    assert!(offset_of!(EntryTable, stub_range_start_offset) == 104);
    assert!(offset_of!(EntryTable, stub_range_end_offset) == 112);
    assert!(offset_of!(EntryTable, cpu_access_start_offset) == 120);
    assert!(offset_of!(EntryTable, cpu_access_end_offset) == 128);
    assert!(offset_of!(EntryTable, user_event_entry_offset) == 136);
    assert!(size_of::<BootArgs>() == 2352);
    assert!(size_of::<DeviceEntry>() == 24);
    assert!(size_of::<RunDesc>() == 16);
    assert!(size_of::<InfoPage>() == 24);
    assert!(size_of::<PendingTaskTicks>() == 8);
    assert!(offset_of!(BootArgs, generation) == 4);
    assert!(offset_of!(BootArgs, source_hash) == 8);
    assert!(offset_of!(BootArgs, clock_origin_tsc) == 48);
    assert!(offset_of!(BootArgs, pti_enabled) == 2316);
    assert!(offset_of!(BootArgs, nx_supported) == 2317);
    assert!(offset_of!(BootArgs, pgtable_levels) == 2318);
    assert!(offset_of!(BootArgs, pt_mode) == 2319);
    assert!(offset_of!(BootArgs, realtime_base_ns) == 2320);
    assert!(offset_of!(BootArgs, monotonic_base_ns) == 2328);
    assert!(offset_of!(BootArgs, initramfs_base) == 2336);
    assert!(offset_of!(BootArgs, initramfs_len) == 2344);
    assert!(size_of::<VcpuRecord>() == 128);
    assert!(offset_of!(VcpuRecord, stolen_ns) == 64);
    assert!(offset_of!(VcpuRecord, guards) == 80);
    assert!(offset_of!(VcpuRecord, stack_limit) == 96);
    assert!(offset_of!(VcpuRecord, parked_ns) == 112);
    assert!(offset_of!(VcpuRecord, task_ticks) == 120);
    assert!(size_of::<CopyFaultRecord>() == 64);
    assert!(offset_of!(CopyFaultRecord, pending) == 16);
    assert!(size_of::<UserEventRecord>() == 64);
    assert!(offset_of!(UserEventRecord, pt_regs) == 0);
    assert!(offset_of!(UserEventRecord, event_rsp) == 8);
    assert!(offset_of!(UserEventRecord, event_stack_limit) == 16);
    assert!(offset_of!(UserEventRecord, trap_num) == 24);
    assert!(offset_of!(UserEventRecord, error_code) == 32);
    assert!(offset_of!(UserEventRecord, fault_addr) == 40);
    assert!(vcpu_shared_bytes(1) == 256);
    assert!(size_of::<KletUserContext>() == 168);
    assert!(offset_of!(KletUserContext, general) == 0);
    assert!(offset_of!(KletUserContext, rflags) == 17 * 8);
    assert!(offset_of!(KletUserContext, trap_num) == 18 * 8);
    assert!(offset_of!(KletUserContext, error_code) == 19 * 8);
    assert!(offset_of!(KletUserContext, fault_addr) == 20 * 8);
    assert!(size_of::<MmioResult>() == 16);
    assert!(size_of::<ServiceTable>() == 160);
    assert!(offset_of!(ServiceTable, user_run) == 104);
    assert!(offset_of!(ServiceTable, mmio_read) == 112);
    assert!(offset_of!(ServiceTable, stop) == 144);
};
