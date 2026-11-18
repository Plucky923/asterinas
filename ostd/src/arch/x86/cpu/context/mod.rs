// SPDX-License-Identifier: MPL-2.0

//! CPU execution context control.

use alloc::boxed::Box;
use core::arch::x86_64::{_fxrstor64, _fxsave64, _xrstor64, _xsave64};
#[cfg(feature = "kernelet")]
use core::{
    cell::UnsafeCell,
    ptr::NonNull,
    sync::atomic::{AtomicPtr, Ordering},
};

use bitflags::bitflags;
use ostd_pod::{FromZeros, IntoBytes};
use spin::Once;
use x86::bits64::segmentation::{rdfsbase, wrfsbase};
#[cfg(not(feature = "kernelet"))]
use x86::bits64::segmentation::{rdgsbase, swapgs, wrgsbase};
#[cfg(feature = "kernelet")]
use x86::msr::{rdmsr, wrmsr};
/// Saved processor status bits without exposing architecture instruction APIs.
pub use x86_64::registers::rflags::RFlags;
use x86_64::registers::{
    control::{Cr0, Cr0Flags},
    xcontrol::XCr0,
};

#[cfg(not(feature = "kernelet"))]
use crate::{
    arch::irq::HwIrqLine,
    arch::trap::RawUserContext,
    cpu::PrivilegeLevel,
    irq::call_irq_callback_functions,
    user::{ReturnReason, UserModeHooks},
};
use crate::{
    arch::trap::TrapFrame,
    debug,
    irq::DisabledLocalIrqGuard,
    mm::{FallibleVmRead, Vaddr},
    user::{UserContextApi, UserContextApiInternal},
};

cfg_select! {
    feature = "cvm_guest" => {
        mod tdx;

        use tdx::VirtualizationExceptionHandler;
    }
    _ => {}
}

/// RFLAGS bits that non-privileged code may modify.
///
/// This is the union of the flags that Linux allows `ptrace` and `rt_sigreturn`
/// to modify. Because the set allowed by `rt_sigreturn` is a strict subset of
/// the `ptrace` set (it excludes `NT`), this is effectively the set of flags
/// that `ptrace` may modify.
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/arch/x86/include/asm/sighandling.h#L11-L14>.
/// Reference: <https://elixir.bootlin.com/linux/v7.1/source/arch/x86/kernel/ptrace.c#L158-L163>.
pub const USER_MODIFIABLE_RFLAGS: usize = (RFlags::CARRY_FLAG.bits()
    | RFlags::PARITY_FLAG.bits()
    | RFlags::AUXILIARY_CARRY_FLAG.bits()
    | RFlags::ZERO_FLAG.bits()
    | RFlags::SIGN_FLAG.bits()
    | RFlags::TRAP_FLAG.bits()
    | RFlags::DIRECTION_FLAG.bits()
    | RFlags::OVERFLOW_FLAG.bits()
    | RFlags::RESUME_FLAG.bits()
    | RFlags::ALIGNMENT_CHECK.bits()
    | RFlags::NESTED_TASK.bits()) as usize;

#[cfg(feature = "kernelet")]
mod kernelet;
#[cfg(feature = "kernelet")]
pub(crate) use kernelet::{LinuxPtRegs, RFLAGS_FIXED, RFLAGS_USER};

/// Userspace CPU context, including general-purpose registers and exception information.
#[cfg(not(feature = "kernelet"))]
#[repr(C)]
#[derive(Clone, Debug)]
pub struct UserContext {
    user_context: RawUserContext,
    exception: Option<CpuException>,
}

#[cfg(not(feature = "kernelet"))]
impl Default for UserContext {
    fn default() -> Self {
        // RFLAGS bit 1 is reserved, and Linux always sets it to 1 on x86.
        // Set the interrupt flag to enable the reception of external interrupts in user mode.
        // Set the ID flag to indicate that the CPU supports the CPUID instruction.
        const USER_MODE_INITIAL_RFLAGS: usize =
            (1 << 1) | (RFlags::INTERRUPT_FLAG.bits() | RFlags::ID.bits()) as usize;

        Self {
            user_context: RawUserContext {
                general: GeneralRegs::default(),
                rflags: USER_MODE_INITIAL_RFLAGS,
                trap_num: 0,
                error_code: 0,
            },
            exception: None,
        }
    }
}

#[cfg(feature = "kernelet")]
#[derive(Debug)]
struct OwnedPtRegs {
    slot: AtomicPtr<LinuxPtRegs>,
    regs: UnsafeCell<LinuxPtRegs>,
}

#[cfg(feature = "kernelet")]
#[derive(Debug)]
struct OwnedPtRegsAllocation(NonNull<OwnedPtRegs>);

#[cfg(feature = "kernelet")]
impl OwnedPtRegsAllocation {
    fn new(regs: LinuxPtRegs) -> Self {
        let allocation = Box::into_raw(Box::new(OwnedPtRegs {
            slot: AtomicPtr::new(core::ptr::null_mut()),
            regs: UnsafeCell::new(regs),
        }));
        // SAFETY: The allocation is live and has reached its permanent address.
        // Its registers remain accessible through raw pointers until this owner drops.
        unsafe {
            (*allocation)
                .slot
                .store((*allocation).regs.get(), Ordering::Relaxed);
            Self(NonNull::new_unchecked(allocation))
        }
    }

    fn slot(&self) -> NonNull<AtomicPtr<LinuxPtRegs>> {
        // SAFETY: This owner retains the allocation, whose address never changes.
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.0.as_ptr()).slot)) }
    }
}

#[cfg(feature = "kernelet")]
impl Drop for OwnedPtRegsAllocation {
    fn drop(&mut self) {
        // SAFETY: This private owner uniquely retains the pointer from `Box::into_raw`.
        unsafe { drop(Box::from_raw(self.0.as_ptr())) };
    }
}

/// Userspace CPU context backed either by an owned [`LinuxPtRegs`] or a live
/// Host `struct pt_regs` frame on the current vCPU.
#[cfg(feature = "kernelet")]
#[derive(Debug)]
pub struct UserContext {
    // An owned context uses its allocation's slot; a borrowed context uses
    // the current task's slot, which must outlive this handle.
    slot: NonNull<AtomicPtr<LinuxPtRegs>>,
    owned: Option<OwnedPtRegsAllocation>,
    exception: Option<CpuException>,
}

#[cfg(feature = "kernelet")]
const _: () = assert!(size_of::<UserContext>() <= 40);

#[cfg(feature = "kernelet")]
impl !Send for UserContext {}
#[cfg(feature = "kernelet")]
impl !Sync for UserContext {}

#[cfg(feature = "kernelet")]
impl Clone for UserContext {
    fn clone(&self) -> Self {
        Self::new_owned(self.read_pt_regs(), self.exception)
    }
}

#[cfg(feature = "kernelet")]
impl Default for UserContext {
    fn default() -> Self {
        Self::new_owned(LinuxPtRegs::new_initial(), None)
    }
}

/// An owned, thread-safe snapshot of [`UserContext`].
#[derive(Clone, Debug, Default)]
pub struct OwnedUserContext(UserContext);

#[cfg(feature = "kernelet")]
// SAFETY: Construction always copies registers into a private owned allocation.
// No mutable accessor can replace the context or redirect its register slot.
unsafe impl Send for OwnedUserContext {}
#[cfg(feature = "kernelet")]
// SAFETY: Same as `Send`; `OwnedUserContext` holds plain register state only.
unsafe impl Sync for OwnedUserContext {}

impl From<&UserContext> for OwnedUserContext {
    fn from(ctx: &UserContext) -> Self {
        Self(ctx.clone())
    }
}

impl core::ops::Deref for OwnedUserContext {
    type Target = UserContext;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(not(feature = "kernelet"))]
impl core::ops::DerefMut for OwnedUserContext {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(feature = "kernelet")]
impl OwnedUserContext {
    /// Borrows the snapshot's general-purpose registers for modification.
    pub fn general_regs_mut(&mut self) -> GeneralRegsMut<'_> {
        self.0.general_regs_mut()
    }

    /// Updates the snapshot's user-modifiable RFLAGS bits.
    pub fn set_rflags(&mut self, rflags: usize) {
        self.0.set_rflags(rflags);
    }
}

impl UserContextApi for OwnedUserContext {
    fn set_instruction_pointer(&mut self, ip: usize) {
        self.0.set_instruction_pointer(ip);
    }

    fn instruction_pointer(&self) -> usize {
        self.0.instruction_pointer()
    }

    fn set_stack_pointer(&mut self, sp: usize) {
        self.0.set_stack_pointer(sp);
    }

    fn stack_pointer(&self) -> usize {
        self.0.stack_pointer()
    }
}

/// General registers.
#[expect(missing_docs)]
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GeneralRegs {
    pub rax: usize,
    pub rbx: usize,
    pub rcx: usize,
    pub rdx: usize,
    pub rsi: usize,
    pub rdi: usize,
    pub rbp: usize,
    pub rsp: usize,
    pub r8: usize,
    pub r9: usize,
    pub r10: usize,
    pub r11: usize,
    pub r12: usize,
    pub r13: usize,
    pub r14: usize,
    pub r15: usize,
    pub rip: usize,
}

/// The user-mode FS base register.
#[derive(Clone, Copy, Debug, Default)]
pub struct FsBase(usize);

impl FsBase {
    /// Creates a new `FsBase` with the given address.
    pub fn new(addr: usize) -> Self {
        Self(addr)
    }

    /// Returns the stored address.
    pub fn addr(&self) -> usize {
        self.0
    }

    /// Saves the current CPU FS base into this struct.
    pub fn save(&mut self) {
        // SAFETY: Reading the user FS base does not affect kernel code.
        self.0 = unsafe { rdfsbase() as usize };
    }

    /// Loads this struct's FS base onto the CPU.
    pub fn load(&self) {
        // SAFETY: Writing the user FS base does not affect kernel code.
        unsafe { wrfsbase(self.0 as u64) }
    }
}

/// The user-mode GS base register.
#[derive(Clone, Copy, Debug, Default)]
pub struct GsBase(usize);

impl GsBase {
    /// Creates a new `GsBase` with the given address.
    pub fn new(addr: usize) -> Self {
        Self(addr)
    }

    /// Returns the stored address.
    pub fn addr(&self) -> usize {
        self.0
    }

    /// Saves the current CPU GS base into this struct.
    pub fn save(&mut self, _guard: &DisabledLocalIrqGuard) {
        #[cfg(feature = "kernelet")]
        {
            self.save_inactive();
        }
        // SAFETY:
        // 1. In these steps, we have disabled the IRQ and are not using the kernel GS base.
        // 2. Reading the user GS base does not affect kernel code.
        #[cfg(not(feature = "kernelet"))]
        unsafe {
            swapgs();
            self.0 = rdgsbase() as usize;
            swapgs();
        }
    }

    /// Loads this struct's GS base onto the CPU.
    pub fn load(&self, _guard: &DisabledLocalIrqGuard) {
        #[cfg(feature = "kernelet")]
        {
            self.load_inactive();
        }
        // SAFETY:
        // 1. In these steps, we have disabled the IRQ and are not using the kernel GS base.
        // 2. Writing the user GS base does not affect kernel code.
        #[cfg(not(feature = "kernelet"))]
        unsafe {
            swapgs();
            wrgsbase(self.0 as u64);
            swapgs();
        }
    }

    /// Saves the inactive user GS base without changing the native GS base.
    #[cfg(feature = "kernelet")]
    pub(crate) fn save_inactive(&mut self) {
        // SAFETY: At CPL 0, the fixed MSR holds the inactive user GS base.
        // Reading it keeps the active native GS base valid for Host IRQs.
        self.0 = unsafe { rdmsr(IA32_KERNEL_GS_BASE) as usize };
    }

    /// Loads the inactive user GS base without changing the native GS base.
    #[cfg(feature = "kernelet")]
    #[inline(never)]
    pub(crate) fn load_inactive(&self) {
        // SAFETY: At CPL 0, writing this fixed MSR changes only the user base
        // restored by the native entry stubs' next SWAPGS, not the active
        // kernel GS base used for CPU-local accesses and Host interrupts.
        unsafe { wrmsr(IA32_KERNEL_GS_BASE, self.0 as u64) };
    }
}

#[cfg(feature = "kernelet")]
const IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;

/// Architectural CPU exceptions (x86-64 vectors 0-31).
///
/// For the authoritative specification of each vector, see the
/// Intel® 64 and IA-32 Architectures Software Developer’s Manual,
/// Volume 3 “System Programming Guide”, Chapter 6 “Interrupt and Exception
/// Handling”, in particular Section 6.15 “Exception and Interrupt
/// Reference”.
///
/// Every enum variant corresponds to one exception defined by the
/// Intel/AMD architecture.
/// Variants that naturally carry an error code (or other error information)
/// expose it through their associated data fields.
//
// TODO: Some exceptions (like `AlignmentCheck`) also push an
//       error code onto the stack, but that detail is not yet represented
//       in this type definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuException {
    ///  0 – #DE  Divide-by-zero error.
    DivisionError,
    ///  1 – #DB  Debug.
    Debug,
    ///  2 – NMI  Non-maskable interrupt.
    NonMaskableInterrupt,
    ///  3 – #BP  Breakpoint (INT3).
    BreakPoint,
    ///  4 – #OF  Overflow.
    Overflow,
    ///  5 – #BR  Bound-range exceeded.
    BoundRangeExceeded,
    ///  6 – #UD  Invalid or undefined opcode.
    InvalidOpcode,
    ///  7 – #NM  Device not available (FPU/MMX/SSE disabled).
    DeviceNotAvailable,
    ///  8 – #DF  Double fault (always pushes an error code of 0).
    DoubleFault,
    ///  9 – Coprocessor segment overrun (reserved on modern CPUs).
    CoprocessorSegmentOverrun,
    /// 10 – #TS  Invalid TSS.
    InvalidTss(SelectorErrorCode),
    /// 11 – #NP  Segment not present.
    SegmentNotPresent(SelectorErrorCode),
    /// 12 – #SS  Stack-segment fault.
    StackSegmentFault(SelectorErrorCode),
    /// 13 – #GP  General protection fault
    GeneralProtectionFault(Option<SelectorErrorCode>),
    /// 14 – #PF  Page fault.
    PageFault(RawPageFaultInfo),
    // 15: Reserved
    /// 16 – #MF  x87 floating-point exception.
    X87FloatingPointException,
    /// 17 – #AC  Alignment check.
    AlignmentCheck,
    /// 18 – #MC  Machine check.
    MachineCheck,
    /// 19 – #XM / #XF  SIMD/FPU floating-point exception.
    SIMDFloatingPointException,
    /// 20 – #VE  Virtualization exception.
    VirtualizationException,
    /// 21 – #CP  Control protection exception (CET).
    ControlProtectionException,
    // 22-27: Reserved
    /// 28 – #HV  Hypervisor injection exception.
    HypervisorInjectionException,
    /// 29 – #VC  VMM communication exception (SEV-ES GHCB).
    VMMCommunicationException,
    /// 30 – #SX  Security exception.
    SecurityException,
    // 31: Reserved
    /// Catch-all for reserved or undefined vector numbers.
    Reserved,
}

impl CpuException {
    pub(in crate::arch) fn new(trap_num: usize, error_code: usize) -> Option<Self> {
        Self::from_raw(
            trap_num,
            error_code,
            if trap_num == 14 {
                x86_64::registers::control::Cr2::read_raw() as usize
            } else {
                0
            },
        )
    }

    pub(crate) fn from_raw(trap_num: usize, error_code: usize, fault_addr: usize) -> Option<Self> {
        let exception = match trap_num {
            0 => Self::DivisionError,
            1 => Self::Debug,
            2 => Self::NonMaskableInterrupt,
            3 => Self::BreakPoint,
            4 => Self::Overflow,
            5 => Self::BoundRangeExceeded,
            6 => Self::InvalidOpcode,
            7 => Self::DeviceNotAvailable,
            8 => {
                // A double fault will always generate an error code with a value of zero.
                debug_assert_eq!(error_code, 0);
                Self::DoubleFault
            }
            9 => Self::CoprocessorSegmentOverrun,
            10 => Self::InvalidTss(SelectorErrorCode(error_code)),
            11 => Self::SegmentNotPresent(SelectorErrorCode(error_code)),
            12 => Self::StackSegmentFault(SelectorErrorCode(error_code)),
            13 => {
                let error_code = if error_code == 0 {
                    None
                } else {
                    Some(SelectorErrorCode(error_code))
                };
                Self::GeneralProtectionFault(error_code)
            }
            14 => Self::PageFault(RawPageFaultInfo {
                error_code: PageFaultErrorCode::from_bits(error_code).unwrap(),
                addr: fault_addr,
            }),
            // Reserved 15
            16 => Self::X87FloatingPointException,
            17 => Self::AlignmentCheck,
            18 => Self::MachineCheck,
            19 => Self::SIMDFloatingPointException,
            20 => Self::VirtualizationException,
            21 => Self::ControlProtectionException,
            // Reserved 22-27
            28 => Self::HypervisorInjectionException,
            29 => Self::VMMCommunicationException,
            30 => Self::SecurityException,
            // Reserved 31
            15 | 22..=27 | 31 => Self::Reserved,
            _ => return None,
        };

        Some(exception)
    }

    const fn type_(&self) -> CpuExceptionType {
        match self {
            Self::Debug => CpuExceptionType::FaultOrTrap,
            Self::NonMaskableInterrupt => CpuExceptionType::Interrupt,
            Self::BreakPoint | Self::Overflow => CpuExceptionType::Trap,
            Self::DoubleFault | Self::MachineCheck => CpuExceptionType::Abort,
            Self::Reserved => CpuExceptionType::Reserved,
            _ => CpuExceptionType::Fault,
        }
    }

    pub(in crate::arch) const fn is_cpu_exception(trap_num: usize) -> bool {
        trap_num <= 31
    }
}

/// Selector error code.
///
/// Reference: <https://wiki.osdev.org/Exceptions#Selector_Error_Code>.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SelectorErrorCode(usize);

#[cfg(not(feature = "kernelet"))]
impl UserContext {
    // Methods shared across all architectures (i.e., general registers and exceptions).

    /// Returns a reference to the general registers.
    pub fn general_regs(&self) -> &GeneralRegs {
        &self.user_context.general
    }

    /// Returns a mutable reference to the general registers.
    pub fn general_regs_mut(&mut self) -> &mut GeneralRegs {
        &mut self.user_context.general
    }

    /// Copies registers and exception state from `src` in place.
    pub fn copy_regs_from(&mut self, src: &OwnedUserContext) {
        *self = src.0.clone();
    }

    /// Resets the register context to its default initial state in place.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Takes the CPU exception out.
    pub fn take_exception(&mut self) -> Option<CpuException> {
        self.exception.take()
    }

    // Architecture-specific methods.

    /// Gets the value of the RFLAGS register.
    pub fn rflags(&self) -> usize {
        self.user_context.rflags
    }

    /// Sets the value of the RFLAGS register.
    ///
    /// We only allow the setting or clearing of the bits in [`USER_MODIFIABLE_RFLAGS`].
    /// Any other bits will be ignored and will remain unchanged.
    pub fn set_rflags(&mut self, rflags: usize) {
        self.user_context.rflags = (self.user_context.rflags & !USER_MODIFIABLE_RFLAGS)
            | (rflags & USER_MODIFIABLE_RFLAGS);
    }
}

/// Borrowed immutable view of general-purpose registers from [`UserContext`].
#[cfg(feature = "kernelet")]
pub struct GeneralRegsRef<'a> {
    regs: GeneralRegs,
    _marker: core::marker::PhantomData<&'a UserContext>,
}

#[cfg(feature = "kernelet")]
impl core::ops::Deref for GeneralRegsRef<'_> {
    type Target = GeneralRegs;

    fn deref(&self) -> &Self::Target {
        &self.regs
    }
}

/// Borrowed mutable view of general-purpose registers that writes back on drop.
#[cfg(feature = "kernelet")]
pub struct GeneralRegsMut<'a> {
    regs: GeneralRegs,
    ctx: &'a mut UserContext,
}

#[cfg(feature = "kernelet")]
impl core::ops::Deref for GeneralRegsMut<'_> {
    type Target = GeneralRegs;

    fn deref(&self) -> &Self::Target {
        &self.regs
    }
}

#[cfg(feature = "kernelet")]
impl core::ops::DerefMut for GeneralRegsMut<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.regs
    }
}

#[cfg(feature = "kernelet")]
impl Drop for GeneralRegsMut<'_> {
    fn drop(&mut self) {
        self.ctx.write_general_regs(&self.regs);
    }
}

#[cfg(feature = "kernelet")]
macro_rules! read_pt_reg {
    ($self:expr, $field:ident) => {{
        let values: [usize; 1] = read_frame_args!($self.slot.as_ptr(); $field offset);
        values[0]
    }};
}

#[cfg(feature = "kernelet")]
macro_rules! write_pt_reg {
    ($self:expr, $field:ident, $val:expr) => {{
        // SAFETY: The slot belongs to this owned context or the current task.
        // The Host cannot redirect this sequence between resolving the frame
        // and writing the register, so a task switch cannot invalidate it.
        unsafe {
            core::arch::asm!(
                "jmp 2f",
                ".pushsection .text.kernelet_cpu_access, \"ax\", @progbits",
                "2:",
                "mov {frame}, qword ptr [{slot}]",
                "mov qword ptr [{frame} + {offset}], {value}",
                "jmp 3f",
                ".popsection",
                "3:",
                slot = in(reg) $self.slot.as_ptr(),
                frame = out(reg) _,
                value = in(reg) $val as usize,
                offset = const core::mem::offset_of!(LinuxPtRegs, $field),
                options(nostack, preserves_flags),
            );
        }
    }};
}

#[cfg(feature = "kernelet")]
macro_rules! read_frame_args {
    ($slot:expr; $($field:ident $offset:ident),+) => {{
        $(let $field: usize;)+
        // SAFETY: An owned slot and its registers stay in the same allocation.
        // A task slot is refreshed on every switch-in, and the Host resumes this
        // protected sequence on the same carrier through the last load.
        unsafe {
            core::arch::asm!(
                "jmp 2f",
                ".pushsection .text.kernelet_cpu_access, \"ax\", @progbits",
                "2:",
                "mov {frame}, qword ptr [{slot}]",
                $(concat!("mov {", stringify!($field), "}, qword ptr [{frame} + {",
                          stringify!($offset), "}]"),)+
                "jmp 3f",
                ".popsection",
                "3:",
                slot = in(reg) $slot,
                frame = out(reg) _,
                $($field = lateout(reg) $field,
                  $offset = const core::mem::offset_of!(LinuxPtRegs, $field),)+
                options(nostack, readonly, preserves_flags),
            );
        }
        let args = [$($field),+];
        core::array::from_fn(|index| args[index])
    }};
}

#[cfg(feature = "kernelet")]
impl UserContext {
    fn new_owned(regs: LinuxPtRegs, exception: Option<CpuException>) -> Self {
        let owned = OwnedPtRegsAllocation::new(regs);
        Self {
            slot: owned.slot(),
            owned: Some(owned),
            exception,
        }
    }

    /// Constructs a [`UserContext`] borrowing the current user task's active `pt_regs` slot.
    ///
    /// # Safety
    ///
    /// `slot` must point to the current user task's `active_pt_regs` (which outlives
    /// this `UserContext` and always holds the live carrier `LinuxPtRegs` on the
    /// vCPU currently running that task).
    pub(crate) unsafe fn from_frame(
        slot: &AtomicPtr<LinuxPtRegs>,
        exception: Option<CpuException>,
    ) -> Self {
        Self {
            slot: NonNull::from(slot),
            owned: None,
            exception,
        }
    }

    pub(crate) fn read_pt_regs(&self) -> LinuxPtRegs {
        let mut regs = core::mem::MaybeUninit::<LinuxPtRegs>::uninit();
        // SAFETY: Both buffers hold a complete `LinuxPtRegs`. The Host cannot
        // redirect this bounded copy after resolving the source frame.
        // The x86-64 Rust ABI keeps the direction flag clear.
        unsafe {
            core::arch::asm!(
                "jmp 2f",
                ".pushsection .text.kernelet_cpu_access, \"ax\", @progbits",
                "2:",
                "mov rsi, qword ptr [{slot}]",
                "rep movsq",
                "jmp 3f",
                ".popsection",
                "3:",
                slot = in(reg) self.slot.as_ptr(),
                out("rsi") _,
                inout("rdi") regs.as_mut_ptr() => _,
                inout("rcx") size_of::<LinuxPtRegs>() / size_of::<u64>() => _,
                options(nostack, preserves_flags),
            );
            regs.assume_init()
        }
    }

    pub(crate) fn write_pt_regs(&mut self, mut regs: LinuxPtRegs) {
        regs.sanitize();
        // SAFETY: Both buffers hold a complete `LinuxPtRegs`. The Host cannot
        // redirect this bounded copy after resolving the destination frame.
        // The x86-64 Rust ABI keeps the direction flag clear.
        unsafe {
            core::arch::asm!(
                "jmp 2f",
                ".pushsection .text.kernelet_cpu_access, \"ax\", @progbits",
                "2:",
                "mov rdi, qword ptr [{slot}]",
                "rep movsq",
                "jmp 3f",
                ".popsection",
                "3:",
                slot = in(reg) self.slot.as_ptr(),
                out("rdi") _,
                inout("rsi") core::ptr::from_ref(&regs) => _,
                inout("rcx") size_of::<LinuxPtRegs>() / size_of::<u64>() => _,
                options(nostack, preserves_flags),
            );
        }
    }

    #[inline(always)]
    pub(crate) fn sync_to_frame(&mut self, slot: &AtomicPtr<LinuxPtRegs>) {
        if self.owned.is_none() {
            debug_assert_eq!(self.slot, NonNull::from(slot));
            return;
        }
        self.sync_owned_to_frame(slot);
    }

    #[cold]
    #[inline(never)]
    fn sync_owned_to_frame(&mut self, slot: &AtomicPtr<LinuxPtRegs>) {
        let mut copy = self.read_pt_regs();
        copy.sanitize();
        let frame = slot.load(Ordering::Relaxed);
        debug_assert!(!frame.is_null());
        // SAFETY: `frame` points to this vCPU's live `pt_regs`.
        unsafe { frame.write(copy) };
        self.slot = NonNull::from(slot);
        drop(self.owned.take());
    }

    /// Reads only the first `N` Linux syscall argument registers, up to six.
    /// A frame-backed context resolves the active frame once for all requested registers.
    #[inline(always)]
    pub fn read_syscall_args<const N: usize>(&self) -> [usize; N] {
        const { assert!(N <= 6) };
        let slot = self.slot.as_ptr();
        match N {
            0 => [0; N],
            1 => read_frame_args!(slot; rdi di),
            2 => read_frame_args!(slot; rdi di, rsi si),
            3 => read_frame_args!(slot; rdi di, rsi si, rdx dx),
            4 => read_frame_args!(slot; rdi di, rsi si, rdx dx, r10 arg4),
            5 => read_frame_args!(slot; rdi di, rsi si, rdx dx, r10 arg4, r8 arg5),
            6 => read_frame_args!(slot; rdi di, rsi si, rdx dx, r10 arg4, r8 arg5, r9 arg6),
            _ => unreachable!(),
        }
    }

    pub(crate) fn into_sanitized_pt_regs(self) -> LinuxPtRegs {
        let mut regs = self.read_pt_regs();
        regs.sanitize();
        regs
    }

    fn write_general_regs(&mut self, general: &GeneralRegs) {
        write_pt_reg!(self, rax, general.rax);
        write_pt_reg!(self, rbx, general.rbx);
        write_pt_reg!(self, rcx, general.rcx);
        write_pt_reg!(self, rdx, general.rdx);
        write_pt_reg!(self, rsi, general.rsi);
        write_pt_reg!(self, rdi, general.rdi);
        write_pt_reg!(self, rbp, general.rbp);
        write_pt_reg!(self, rsp, general.rsp);
        write_pt_reg!(self, r8, general.r8);
        write_pt_reg!(self, r9, general.r9);
        write_pt_reg!(self, r10, general.r10);
        write_pt_reg!(self, r11, general.r11);
        write_pt_reg!(self, r12, general.r12);
        write_pt_reg!(self, r13, general.r13);
        write_pt_reg!(self, r14, general.r14);
        write_pt_reg!(self, r15, general.r15);
        write_pt_reg!(self, rip, general.rip);
    }

    /// Returns a view of the general registers.
    pub fn general_regs(&self) -> GeneralRegsRef<'_> {
        GeneralRegsRef {
            regs: self.read_pt_regs().to_general_regs(),
            _marker: core::marker::PhantomData,
        }
    }

    /// Returns a mutable view of the general registers that writes back on drop.
    pub fn general_regs_mut(&mut self) -> GeneralRegsMut<'_> {
        let regs = self.read_pt_regs().to_general_regs();
        GeneralRegsMut { regs, ctx: self }
    }

    /// Copies registers and exception state from `src` in place, preserving the
    /// underlying frame or owned storage.
    pub fn copy_regs_from(&mut self, src: &OwnedUserContext) {
        self.write_pt_regs(src.0.read_pt_regs());
        self.exception = src.0.exception;
    }

    /// Resets the register context to its default initial state in place.
    pub fn reset(&mut self) {
        self.write_pt_regs(LinuxPtRegs::new_initial());
        self.exception = None;
    }

    /// Takes the CPU exception out.
    pub fn take_exception(&mut self) -> Option<CpuException> {
        self.exception.take()
    }

    /// Gets the value of the RFLAGS register.
    pub fn rflags(&self) -> usize {
        read_pt_reg!(self, rflags)
    }

    /// Sets the value of the RFLAGS register.
    ///
    /// We only allow the setting or clearing of the bits in [`USER_MODIFIABLE_RFLAGS`].
    /// Any other bits will be ignored and will remain unchanged.
    pub fn set_rflags(&mut self, rflags: usize) {
        let current = self.rflags();
        let next = (current & !USER_MODIFIABLE_RFLAGS) | (rflags & USER_MODIFIABLE_RFLAGS);
        let sanitized = (next as u64 & RFLAGS_USER) | RFLAGS_FIXED;
        write_pt_reg!(self, rflags, sanitized);
    }
}

#[cfg(feature = "kernelet")]
impl UserContextApiInternal for UserContext {
    fn as_trap_frame(&self) -> TrapFrame {
        let regs = self.read_pt_regs();
        TrapFrame {
            rax: regs.rax as usize,
            rbx: regs.rbx as usize,
            rcx: regs.rcx as usize,
            rdx: regs.rdx as usize,
            rsi: regs.rsi as usize,
            rdi: regs.rdi as usize,
            rbp: regs.rbp as usize,
            r8: regs.r8 as usize,
            r9: regs.r9 as usize,
            r10: regs.r10 as usize,
            r11: regs.r11 as usize,
            r12: regs.r12 as usize,
            r13: regs.r13 as usize,
            r14: regs.r14 as usize,
            r15: regs.r15 as usize,
            trap_num: 0,
            error_code: 0,
            rip: regs.rip as usize,
            cs: regs.cs as usize,
            rflags: regs.rflags as usize,
            rsp: regs.rsp as usize,
            ss: regs.ss as usize,
        }
    }
}

#[cfg(not(feature = "kernelet"))]
impl UserContextApiInternal for UserContext {
    fn execute<T: UserModeHooks>(&mut self, hooks: &T) -> ReturnReason {
        const SYSCALL_TRAPNUM: usize = 0x100;

        // Return when it is syscall or cpu exception type is Fault or Trap.
        loop {
            crate::task::scheduler::might_preempt();

            let guard = crate::irq::disable_local();
            hooks.pre_user_run(&guard);

            let fault_addr = self.user_context.run(guard);
            let exception = CpuException::from_raw(
                self.user_context.trap_num,
                self.user_context.error_code,
                fault_addr,
            );
            match exception {
                #[cfg(feature = "cvm_guest")]
                Some(CpuException::VirtualizationException) => {
                    let ve_handler = VirtualizationExceptionHandler::new();
                    // Check out the doc of `VirtualizationExceptionHandler::new` to
                    // see why IRQs must enabled _after_ instantiating a `VirtualizationExceptionHandler`.
                    crate::arch::irq::enable_local();
                    ve_handler.handle(self);
                }
                Some(exception) if exception.type_().is_fault_or_trap() => {
                    crate::arch::irq::enable_local();
                    self.exception = Some(exception);
                    return ReturnReason::UserException;
                }
                Some(exception) => {
                    panic!(
                        "Cannot handle user CPU exception: {:?}; trapframe: {:?}",
                        exception,
                        self.as_trap_frame()
                    );
                }
                None if self.user_context.trap_num == SYSCALL_TRAPNUM => {
                    crate::arch::irq::enable_local();
                    return ReturnReason::UserSyscall;
                }
                None => {
                    call_irq_callback_functions(
                        &self.as_trap_frame(),
                        &HwIrqLine::new(self.as_trap_frame().trap_num as u8),
                        PrivilegeLevel::User,
                    );
                    crate::arch::irq::enable_local();
                }
            }

            if hooks.has_kernel_event() {
                break ReturnReason::KernelEvent;
            }
        }
    }

    fn as_trap_frame(&self) -> TrapFrame {
        self.user_context.as_trap_frame()
    }
}

#[cfg(not(feature = "kernelet"))]
impl RawUserContext {
    pub(crate) fn as_trap_frame(&self) -> TrapFrame {
        TrapFrame {
            rax: self.general.rax,
            rbx: self.general.rbx,
            rcx: self.general.rcx,
            rdx: self.general.rdx,
            rsi: self.general.rsi,
            rdi: self.general.rdi,
            rbp: self.general.rbp,
            r8: self.general.r8,
            r9: self.general.r9,
            r10: self.general.r10,
            r11: self.general.r11,
            r12: self.general.r12,
            r13: self.general.r13,
            r14: self.general.r14,
            r15: self.general.r15,
            trap_num: self.trap_num,
            error_code: self.error_code,
            rip: self.general.rip,
            cs: 0,
            rflags: self.rflags,
            rsp: self.general.rsp,
            ss: 0,
        }
    }
}

/// Types of CPU exceptions.
///
/// As defined by Intel, there are three types of x86-64 CPU exceptions:
///  - **Faults** can be corrected and the program may continue as if nothing happened.
///  - **Traps** are reported immediately after the execution of the trapping instruction.
///  - **Aborts** represent some unrecoverable errors.
///
/// However, there are some special vectors. Vector 1 can be either a fault or a trap, and vector 2
/// is an interrupt. Here, we also define `FaultOrTrap` and `Interrupt`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CpuExceptionType {
    /// Faults. They can be corrected and the program may continue as if nothing happened.
    Fault,
    /// Traps. They are reported immediately after the execution of the trapping instruction.
    Trap,
    /// Faults or traps.
    FaultOrTrap,
    /// Interrupts.
    Interrupt,
    /// Aborts. They represent some unrecoverable errors.
    Abort,
    /// Reserved for future use.
    Reserved,
}

impl CpuExceptionType {
    /// Returns whether this exception type is a fault or a trap.
    fn is_fault_or_trap(self) -> bool {
        match self {
            CpuExceptionType::Trap | CpuExceptionType::Fault | CpuExceptionType::FaultOrTrap => {
                true
            }
            CpuExceptionType::Abort | CpuExceptionType::Interrupt | CpuExceptionType::Reserved => {
                false
            }
        }
    }
}

/// Architecture-specific data reported with a page-fault exception.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawPageFaultInfo {
    /// The error code pushed by the CPU for this page fault.
    pub error_code: PageFaultErrorCode,
    /// The linear (virtual) address that triggered the fault (contents of CR2).
    pub addr: Vaddr,
}

bitflags! {
    /// Page Fault error code. Following the Intel Architectures Software Developer's Manual Volume 3
    pub struct PageFaultErrorCode : usize{
        /// 0 if no translation for the linear address.
        const PRESENT       = 1 << 0;
        /// 1 if the access was a write.
        const WRITE         = 1 << 1;
        /// 1 if the access was a user-mode access.
        const USER          = 1 << 2;
        /// 1 if there is no translation for the linear address
        /// because a reserved bit was set.
        const RESERVED      = 1 << 3;
        /// 1 if the access was an instruction fetch.
        const INSTRUCTION   = 1 << 4;
        /// 1 if the access was a data access to a linear address with a protection key for which
        /// the protection-key rights registers disallow access.
        const PROTECTION    = 1 << 5;
        /// 1 if the access was a shadow-stack access.
        const SHADOW_STACK  = 1 << 6;
        /// 1 if there is no translation for the linear address using HLAT paging.
        const HLAT          = 1 << 7;
        /// 1 if the exception is unrelated to paging and resulted from violation of SGX-specific
        /// access-control requirements.
        const SGX           = 1 << 15;
    }
}

impl UserContextApi for UserContext {
    fn set_instruction_pointer(&mut self, ip: usize) {
        self.set_rip(ip);
    }

    fn set_stack_pointer(&mut self, sp: usize) {
        self.set_rsp(sp)
    }

    fn stack_pointer(&self) -> usize {
        self.rsp()
    }

    fn instruction_pointer(&self) -> usize {
        self.rip()
    }
}

macro_rules! cpu_context_impl_getter_setter {
    ( $( [ $field: ident, $setter_name: ident] ),*) => {
        impl UserContext {
            $(
                #[doc = concat!("Gets the value of ", stringify!($field))]
                #[inline(always)]
                pub fn $field(&self) -> usize {
                    #[cfg(not(feature = "kernelet"))]
                    {
                        self.user_context.general.$field
                    }
                    #[cfg(feature = "kernelet")]
                    {
                        read_pt_reg!(self, $field)
                    }
                }

                #[doc = concat!("Sets the value of ", stringify!(field))]
                #[inline(always)]
                pub fn $setter_name(&mut self, $field: usize) {
                    #[cfg(not(feature = "kernelet"))]
                    {
                        self.user_context.general.$field = $field;
                    }
                    #[cfg(feature = "kernelet")]
                    {
                        write_pt_reg!(self, $field, $field);
                    }
                }
            )*
        }
    };
}

cpu_context_impl_getter_setter!(
    [rax, set_rax],
    [rbx, set_rbx],
    [rcx, set_rcx],
    [rdx, set_rdx],
    [rsi, set_rsi],
    [rdi, set_rdi],
    [rbp, set_rbp],
    [rsp, set_rsp],
    [r8, set_r8],
    [r9, set_r9],
    [r10, set_r10],
    [r11, set_r11],
    [r12, set_r12],
    [r13, set_r13],
    [r14, set_r14],
    [r15, set_r15],
    [rip, set_rip]
);

/// Cached hardware `MXCSR_MASK` (defaulting to `0xffbf` if hardware leaves it zero).
static MXCSR_MASK: Once<u32> = Once::new();

fn mxcsr_mask() -> u32 {
    *MXCSR_MASK.call_once(|| {
        let mut tmp = FpuContext::new();
        tmp.save();
        let mask = tmp.xsave_area.fxsave_area.mxcsr_mask;
        if mask == 0 { 0x0000_ffbf } else { mask }
    })
}

/// The FPU context of user task.
///
/// This could be used for saving both legacy and modern state format.
#[derive(Debug)]
pub struct FpuContext {
    xsave_area: Box<XSaveArea>,
    area_size: usize,
}

impl FpuContext {
    /// Creates a new FPU context.
    #[cfg_attr(feature = "kernelet", inline(never))]
    pub fn new() -> Self {
        let mut area_size = size_of::<FxSaveArea>();
        if let Some(xsave_area_size) = XSAVE_AREA_SIZE.get() {
            area_size = area_size.max(*xsave_area_size);
        }

        Self {
            xsave_area: Box::new(XSaveArea::new()),
            area_size,
        }
    }

    /// Returns the size in bytes of the FPU save area for this CPU.
    pub fn area_size(&self) -> usize {
        self.area_size
    }

    /// Reads and validates a user-supplied FPU context from `reader`.
    ///
    /// Rejects unaligned or short frames, reserved `MXCSR` bits above hardware
    /// `MXCSR_MASK`, unsupported `XSTATE_BV` bits, nonzero `XCOMP_BV`, or nonzero
    /// reserved XSAVE header words with [`crate::Error::InvalidArgs`].
    #[cfg_attr(feature = "kernelet", inline(never))]
    pub fn read_from(
        &mut self,
        reader: &mut crate::mm::VmReader<'_, crate::mm::Fallible>,
    ) -> crate::Result<()> {
        let align = if XSTATE_MAX_FEATURES.is_completed() {
            64
        } else {
            16
        };
        if !reader.cursor().addr().is_multiple_of(align) || reader.remain() < self.area_size {
            return Err(crate::Error::InvalidArgs);
        }

        let mut staging = Self::new();
        let allowed = staging.xsave_area.features;
        staging.as_bytes_mut().fill(0);

        {
            let buf = staging.as_bytes_mut();
            // SAFETY: `buf` is kernel memory valid for writes of `buf.len()` bytes.
            let mut writer =
                unsafe { crate::mm::VmWriter::from_kernel_space(buf.as_mut_ptr(), buf.len()) };
            match reader.read_fallible(&mut writer) {
                Ok(copied) if copied == self.area_size => {}
                Ok(_) => return Err(crate::Error::PageFault),
                Err((err, _)) => return Err(err),
            }
        }

        if (staging.xsave_area.fxsave_area.mxcsr & !mxcsr_mask()) != 0 {
            return Err(crate::Error::InvalidArgs);
        }
        if XSTATE_MAX_FEATURES.is_completed()
            && ((staging.xsave_area.features & !allowed) != 0
                || staging.xsave_area.compaction != 0
                || staging.xsave_area.reserved != [0; 6])
        {
            return Err(crate::Error::InvalidArgs);
        }

        *self = staging;
        Ok(())
    }

    /// Saves CPU's current FPU context to this instance.
    // Keep Image state instructions in the wrapper recognized by the artifact
    // audit, independent of ThinLTO's caller-dependent inlining decisions.
    #[cfg_attr(feature = "kernelet", inline(never))]
    pub fn save(&mut self) {
        let mem_addr = self.as_bytes_mut().as_mut_ptr();

        // SAFETY: XSaveArea has the required alignment and size. CPU feature
        // initialization records whether the Host has enabled XSAVE.
        if XSTATE_MAX_FEATURES.is_completed() {
            unsafe { _xsave64(mem_addr, XFEATURE_MASK_USER_RESTORE) };
        } else {
            unsafe { _fxsave64(mem_addr) };
        }

        debug!("Save FPU context");
    }

    /// Loads CPU's FPU context from this instance.
    #[cfg_attr(feature = "kernelet", inline(never))]
    pub fn load(&self) {
        let mem_addr = self.as_bytes().as_ptr();

        // SAFETY: XSaveArea has the required alignment and size. CPU feature
        // initialization records the supported state restored by this path.
        if let Some(xstate_max_features) = XSTATE_MAX_FEATURES.get() {
            let rs_mask = XFEATURE_MASK_USER_RESTORE & *xstate_max_features;

            unsafe { _xrstor64(mem_addr, rs_mask) };
        } else {
            unsafe { _fxrstor64(mem_addr) };
        }

        debug!("Load FPU context");
    }

    /// Returns the FPU context as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.xsave_area.as_bytes()[..self.area_size]
    }

    /// Returns the FPU context as a mutable byte slice.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.xsave_area.as_mut_bytes()[..self.area_size]
    }
}

impl Default for FpuContext {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for FpuContext {
    fn clone(&self) -> Self {
        let mut xsave_area = Box::new(XSaveArea::new());
        xsave_area.fxsave_area = self.xsave_area.fxsave_area;
        xsave_area.features = self.xsave_area.features;
        xsave_area.compaction = self.xsave_area.compaction;
        if self.area_size > size_of::<FxSaveArea>() {
            let len = self.area_size - size_of::<FxSaveArea>() - 64;
            xsave_area.extended_state_area[..len]
                .copy_from_slice(&self.xsave_area.extended_state_area[..len]);
        }

        Self {
            xsave_area,
            area_size: self.area_size,
        }
    }
}

/// The modern FPU context format (as saved and restored by the `XSAVE` and `XRSTOR` instructions).
#[repr(C)]
#[repr(align(64))]
#[derive(Clone, Copy, Debug, Pod)]
struct XSaveArea {
    fxsave_area: FxSaveArea,
    features: u64,
    compaction: u64,
    reserved: [u64; 6],
    extended_state_area: [u8; MAX_XSAVE_AREA_SIZE - size_of::<FxSaveArea>() - 64],
}

impl XSaveArea {
    fn new() -> Self {
        let features = if let Some(xstate_max_features) = XSTATE_MAX_FEATURES.get() {
            XCr0::read().bits() & *xstate_max_features
        } else {
            0
        };

        let mut xsave_area = Self::new_zeroed();
        // Set the initial values for the FPU context. Refer to Intel SDM, Table 10-1:
        // "IA-32 and Intel® 64 Processor States Following Power-up, Reset, or INIT (Contd.)".
        xsave_area.fxsave_area.control = 0x037F;
        // Refer to Intel SDM, Volume 1, Section "x87 State". In the FXSAVE/XSAVE image the
        // `tag` field contains an abridged x87 Tag Word (FTW) - a compact (8-bit) encoding
        // used in saved/restore images. In this format, a bit value of 0 indicates the
        // corresponding x87 register is empty (this is the inverse of the legacy 16-bit
        // tag-word semantics). The `fninit` instruction clears all x87 registers, so the
        // abridged tag must be initialized to 0 to represent an empty register set.
        xsave_area.fxsave_area.tag = 0;
        xsave_area.fxsave_area.mxcsr = 0x1F80;
        xsave_area.features = features;

        xsave_area
    }
}

/// The legacy SSE/MMX FPU context format (as saved and restored by the `FXSAVE` and `FXRSTOR` instructions).
#[repr(C)]
#[repr(align(16))]
#[derive(Clone, Copy, Debug, Pod)]
struct FxSaveArea {
    control: u16,         // x87 FPU Control Word
    status: u16,          // x87 FPU Status Word
    tag: u8,              // x87 FPU Tag Byte (abridged format)
    reserved1: u8,        // Reserved
    op: u16,              // x87 FPU Last Instruction Opcode
    ip: u32,              // x87 FPU Instruction Pointer Offset
    cs: u32,              // x87 FPU Instruction Pointer Selector
    dp: u32,              // x87 FPU Instruction Operand (Data) Pointer Offset
    ds: u32,              // x87 FPU Instruction Operand (Data) Pointer Selector
    mxcsr: u32,           // MXCSR Register State
    mxcsr_mask: u32,      // MXCSR Mask
    st_space: [u32; 32], // x87 FPU or MMX technology registers (ST0-ST7 or MM0-MM7, 128 bits per field)
    xmm_space: [u32; 64], // XMM registers (XMM0-XMM15, 128 bits per field)
    reserved2: [u32; 12], // Reserved
    reserved3: [u32; 12], // Software reserved
}

/// The XSTATE features (user & supervisor) supported by the processor.
static XSTATE_MAX_FEATURES: Once<u64> = Once::new();

/// Mask features which are restored when returning to user space.
///
/// X87 | SSE | AVX | OPMASK | ZMM_HI256 | HI16_ZMM
const XFEATURE_MASK_USER_RESTORE: u64 = 0b1110_0111;

/// The real size in bytes of the XSAVE area containing all states enabled by XCRO | IA32_XSS.
static XSAVE_AREA_SIZE: Once<usize> = Once::new();

/// The max size in bytes of the XSAVE area.
const MAX_XSAVE_AREA_SIZE: usize = 4096;

pub(in crate::arch) fn record_fpu_features() {
    use super::extension::{IsaExtensions, has_extensions};

    if has_extensions(IsaExtensions::XSAVE) {
        XSTATE_MAX_FEATURES.call_once(|| super::cpuid::query_xstate_max_features().unwrap());
        XSAVE_AREA_SIZE.call_once(|| {
            let xsave_area_size = super::cpuid::query_xsave_area_size().unwrap() as usize;
            assert!(xsave_area_size <= MAX_XSAVE_AREA_SIZE);
            xsave_area_size
        });
    }
}

pub(in crate::arch) fn enable_essential_features() {
    record_fpu_features();

    // We now assume that all x86-64 CPUs should have the FPU. Otherwise, we should check
    // `has_extensions(IsaExtensions::FPU)` here.
    {
        let mut cr0 = Cr0::read();
        cr0.remove(Cr0Flags::TASK_SWITCHED | Cr0Flags::EMULATE_COPROCESSOR);

        unsafe {
            Cr0::write(cr0);
            // Flush out any pending x87 state.
            core::arch::asm!("fninit");
        }
    }
}

#[cfg(ktest)]
mod rflags_tests {
    use super::{RFlags, UserContext};
    use crate::{prelude::*, user::UserContextApiInternal};

    #[ktest]
    fn user_flags_preserve_required_bits_and_reject_privilege_bits() {
        let mut context = UserContext::default();
        let required = (RFlags::INTERRUPT_FLAG | RFlags::ID).bits() as usize | 2;
        let privileged = (RFlags::IOPL_LOW
            | RFlags::IOPL_HIGH
            | RFlags::VIRTUAL_8086_MODE
            | RFlags::VIRTUAL_INTERRUPT
            | RFlags::VIRTUAL_INTERRUPT_PENDING)
            .bits() as usize;
        assert_eq!(context.rflags(), required);

        context.set_rflags(usize::MAX);
        assert_eq!(context.rflags() & required, required);
        assert_eq!(context.rflags() & privileged, 0);
        assert_ne!(context.rflags() & RFlags::CARRY_FLAG.bits() as usize, 0);
        assert_eq!(context.as_trap_frame().rflags, context.rflags());

        context.general_regs_mut().rip = 0x400000;
        context.general_regs_mut().rax = usize::MAX;
        context.set_rflags(0);
        assert_eq!(context.rflags(), required);
        let frame = context.as_trap_frame();
        assert_eq!(frame.rflags, required);
        assert_eq!(frame.rip, 0x400000);
        assert_eq!(frame.rax, usize::MAX);
    }
}
