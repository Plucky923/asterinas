// SPDX-License-Identifier: MPL-2.0

//! Accesses the CPU-local replica assigned to the current virtual CPU.

use crate::{
    cpu::local::{
        CpuLocalCell,
        single_instr::{
            SingleInstructionAddAssign, SingleInstructionBitAndAssign,
            SingleInstructionBitOrAssign, SingleInstructionBitXorAssign, SingleInstructionLoad,
            SingleInstructionStore, SingleInstructionSubAssign,
        },
    },
    irq::DisabledLocalIrqGuard,
    kernelet::abi::VcpuRecord,
};

macro_rules! fast_cpu_asm {
    ($table_field:ident; $($instruction:expr),+; $($operands:tt)*) => {{
        core::arch::asm!(
            "jmp 2f",
            ".pushsection .text.kernelet_cpu_access, \"ax\", @progbits",
            "2:",
            "lea {record_base}, [rip + {fast_cpu}]",
            "mov {slot}, qword ptr [{record_base} + {slot_gs_off}]",
            "movzx {slot:e}, word ptr gs:[{slot} + 2]",
            "mov {record_base}, qword ptr [{record_base} + {slot} * 8 + {table_ptrs_off}]",
            $($instruction),+,
            "jmp 3f",
            ".popsection",
            "3:",
            record_base = out(reg) _,
            slot = out(reg) _,
            fast_cpu = sym $crate::kernelet::entry::KERNELET_FAST_CPU,
            slot_gs_off = const core::mem::offset_of!($crate::kernelet::entry::FastCpuTable, slot_gs_offset),
            table_ptrs_off = const core::mem::offset_of!($crate::kernelet::entry::FastCpuTable, $table_field),
            $($operands)*
        );
    }};
}

/// Executes a short access without allowing the Host to redirect its middle.
///
/// Inputs must be CPU-independent. The Host may interrupt this sequence, but
/// its CPU-access range gate resumes it on the same carrier instead of
/// delivering an upcall that could migrate the internal Task. Both jumps are
/// direct and the sequence neither calls nor modifies the stack.
macro_rules! record_asm {
    ($($instruction:expr),+; $($operands:tt)*) => {
        $crate::arch::cpu::local::fast_cpu_asm!(record_ptrs; $($instruction),+; $($operands)*)
    };
}
pub(crate) use fast_cpu_asm;
pub(crate) use record_asm;

/// Reuses this vCPU's addresses while a borrowed IRQ guard prevents Task switches.
pub(crate) struct CpuLocalAccess<'irq> {
    record: &'static VcpuRecord,
    local_base: usize,
    _irq: core::marker::PhantomData<&'irq DisabledLocalIrqGuard>,
}

impl<'irq> CpuLocalAccess<'irq> {
    #[inline]
    pub(crate) fn new(_irq: &'irq DisabledLocalIrqGuard) -> Self {
        let record: *const VcpuRecord;
        let local_base: usize;
        // SAFETY: Entry populated `KERNELET_FAST_CPU` before any vCPU runs.
        // Record selection and replica base load complete in one protected access;
        // the guard pins their use.
        unsafe {
            core::arch::asm!(
                "jmp 2f",
                ".pushsection .text.kernelet_cpu_access, \"ax\", @progbits",
                "2:",
                "lea {table}, [rip + {fast_cpu}]",
                "mov {slot}, qword ptr [{table} + {slot_gs_off}]",
                "movzx {slot:e}, word ptr gs:[{slot} + 2]",
                "mov {record}, qword ptr [{table} + {slot} * 8 + {record_ptrs_off}]",
                "mov {local_base}, qword ptr [{table} + {slot} * 8 + {local_bases_off}]",
                "jmp 3f",
                ".popsection",
                "3:",
                table = out(reg) _,
                slot = out(reg) _,
                record = out(reg) record,
                local_base = out(reg) local_base,
                fast_cpu = sym crate::kernelet::entry::KERNELET_FAST_CPU,
                slot_gs_off = const core::mem::offset_of!(crate::kernelet::entry::FastCpuTable, slot_gs_offset),
                record_ptrs_off = const core::mem::offset_of!(crate::kernelet::entry::FastCpuTable, record_ptrs),
                local_bases_off = const core::mem::offset_of!(crate::kernelet::entry::FastCpuTable, local_bases),
                options(nostack, readonly),
            );
        }
        Self {
            // SAFETY: The Host retains the validated record for the image lifetime.
            record: unsafe { &*record },
            local_base,
            _irq: core::marker::PhantomData,
        }
    }

    #[inline]
    pub(crate) fn record(&self) -> &VcpuRecord {
        self.record
    }

    #[inline]
    pub(crate) fn load<T: Copy + SingleInstructionLoad>(
        &self,
        cell: &'static CpuLocalCell<T>,
    ) -> T {
        // SAFETY: The borrowed guard excludes image IRQs and Task switches.
        // The Host never accesses the private replica; copying creates no borrow.
        unsafe { cell.as_mut_ptr_with_base(self.local_base).read_volatile() }
    }

    #[inline]
    pub(crate) fn store<T: Copy + SingleInstructionStore>(
        &self,
        cell: &'static CpuLocalCell<T>,
        value: T,
    ) {
        // SAFETY: The same exclusion permits a private cell write. Copy types
        // own no destructor, and the pointer stays in the validated replica.
        unsafe {
            cell.as_mut_ptr_with_base(self.local_base)
                .write_volatile(value)
        };
    }
}

/// Returns the current virtual CPU's private CPU-local base.
/// Borrowing through this address still requires the caller's CPU pin.
pub(crate) fn get_base() -> u64 {
    let base;
    // SAFETY: Entry populated `KERNELET_FAST_CPU`. The complete slot lookup
    // and replica base read execute in the protected CPU-access range.
    unsafe {
        fast_cpu_asm!(
            local_bases;
            "mov {base}, {record_base}";
            base = out(reg) base,
            options(nostack, readonly),
        );
    }
    base
}

macro_rules! cpu_local_asm {
    ($instruction:expr, $offset:expr; $($operands:tt)*) => {
        fast_cpu_asm!(
            local_bases;
            $instruction;
            offset = in(reg) $offset,
            $($operands)*
        )
    };
}

macro_rules! impl_numeric_single_instruction_for {
    ($([$typ:ty, $inout_type:ident, $register_format:expr])*) => {$(
        impl SingleInstructionAddAssign<$typ> for $typ {
            unsafe fn add_assign(offset: usize, val: Self) {
                // SAFETY: The caller supplies a scalar CPU-local offset. The
                // replica selection and access cannot be separated by migration.
                unsafe {
                    cpu_local_asm!(
                        concat!("add [{record_base} + {offset}], {value", $register_format, "}"), offset;
                        value = in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }
        impl SingleInstructionSubAssign<$typ> for $typ {
            unsafe fn sub_assign(offset: usize, val: Self) {
                // SAFETY: Same as add_assign.
                unsafe {
                    cpu_local_asm!(
                        concat!("sub [{record_base} + {offset}], {value", $register_format, "}"), offset;
                        value = in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }
        impl SingleInstructionBitAndAssign<$typ> for $typ {
            unsafe fn bitand_assign(offset: usize, val: Self) {
                // SAFETY: Same as add_assign.
                unsafe {
                    cpu_local_asm!(
                        concat!("and [{record_base} + {offset}], {value", $register_format, "}"), offset;
                        value = in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }
        impl SingleInstructionBitOrAssign<$typ> for $typ {
            unsafe fn bitor_assign(offset: usize, val: Self) {
                // SAFETY: Same as add_assign.
                unsafe {
                    cpu_local_asm!(
                        concat!("or [{record_base} + {offset}], {value", $register_format, "}"), offset;
                        value = in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }
        impl SingleInstructionBitXorAssign<$typ> for $typ {
            unsafe fn bitxor_assign(offset: usize, val: Self) {
                // SAFETY: Same as add_assign.
                unsafe {
                    cpu_local_asm!(
                        concat!("xor [{record_base} + {offset}], {value", $register_format, "}"), offset;
                        value = in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }
        impl SingleInstructionLoad for $typ {
            unsafe fn load(offset: usize) -> Self {
                let val;
                // SAFETY: Same as add_assign.
                unsafe {
                    cpu_local_asm!(
                        concat!("mov {value", $register_format, "}, [{record_base} + {offset}]"), offset;
                        value = out($inout_type) val,
                        options(nostack, readonly),
                    );
                }
                val
            }
        }
        impl SingleInstructionStore for $typ {
            unsafe fn store(offset: usize, val: Self) {
                // SAFETY: Same as add_assign.
                unsafe {
                    cpu_local_asm!(
                        concat!("mov [{record_base} + {offset}], {value", $register_format, "}"), offset;
                        value = in($inout_type) val,
                        options(nostack),
                    );
                }
            }
        }
    )*};
}

impl_numeric_single_instruction_for!(
    [u64, reg, ":r"] [usize, reg, ":r"] [u32, reg, ":e"]
    [u16, reg, ":x"] [u8, reg_byte, ""]
    [i64, reg, ":r"] [isize, reg, ":r"] [i32, reg, ":e"]
    [i16, reg, ":x"] [i8, reg_byte, ""]
);

macro_rules! impl_generic_single_instruction_for {
    ($([<$gen_type:ident $(, $more_gen_type:ident)*>, $typ:ty])*) => {$(
        impl<$gen_type $(, $more_gen_type)*> SingleInstructionLoad for $typ {
            unsafe fn load(offset: usize) -> Self {
                let val;
                // SAFETY: The caller supplies a scalar CPU-local offset. The
                // replica selection and load cannot be separated by migration.
                unsafe {
                    cpu_local_asm!("mov {value}, [{record_base} + {offset}]", offset;
                        value = out(reg) val,
                        options(nostack, readonly),
                    );
                }
                val
            }
        }
        impl<$gen_type $(, $more_gen_type)*> SingleInstructionStore for $typ {
            unsafe fn store(offset: usize, val: Self) {
                // SAFETY: Same as load.
                unsafe {
                    cpu_local_asm!("mov [{record_base} + {offset}], {value}", offset;
                        value = in(reg) val,
                        options(nostack),
                    );
                }
            }
        }
    )*}
}
impl_generic_single_instruction_for!(
    [<T>, *const T] [<T>, *mut T] [<T, R>, fn(T) -> R]
);

impl SingleInstructionLoad for bool {
    unsafe fn load(offset: usize) -> Self {
        let val: u8;
        // SAFETY: The caller supplies a CPU-local bool offset. The underlying
        // u8 access is one instruction in the nonredirectable sequence.
        unsafe { val = <u8 as SingleInstructionLoad>::load(offset) };
        debug_assert!(val <= 1);
        val != 0
    }
}
impl SingleInstructionStore for bool {
    unsafe fn store(offset: usize, val: Self) {
        // SAFETY: Same as load; converting bool to u8 preserves its layout.
        unsafe { <u8 as SingleInstructionStore>::store(offset, u8::from(val)) };
    }
}
