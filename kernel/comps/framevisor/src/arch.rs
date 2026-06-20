// SPDX-License-Identifier: MPL-2.0

//! Architecture APIs.

#[cfg(target_arch = "x86_64")]
pub use host_ostd::arch::if_tdx_enabled;

/// CPU context and state APIs.
pub mod cpu {
    /// CPU context types.
    pub mod context {
        #[cfg(target_arch = "loongarch64")]
        pub use host_ostd::arch::cpu::context::{
            CpuException, CpuExceptionInfo, FpuContext, GeneralRegs, UserContext,
        };
        #[cfg(target_arch = "riscv64")]
        pub use host_ostd::arch::cpu::context::{
            CpuException, DFpuContext, FFpuContext, FaultAddress, FaultInstruction, FpuContext,
            GeneralRegs, QFpuContext, UserContext,
        };
        #[cfg(target_arch = "x86_64")]
        pub use host_ostd::arch::cpu::context::{
            CpuException, FpuContext, FsBase, GeneralRegs, PageFaultErrorCode, RawPageFaultInfo,
            UserContext,
        };

        #[cfg(target_arch = "x86_64")]
        /// The user-mode GS base register.
        #[derive(Clone, Copy, Debug, Default)]
        pub struct GsBase(host_ostd::arch::cpu::context::GsBase);

        #[cfg(target_arch = "x86_64")]
        impl GsBase {
            /// Creates a new `GsBase` with the given address.
            pub fn new(addr: usize) -> Self {
                Self(host_ostd::arch::cpu::context::GsBase::new(addr))
            }

            /// Returns the stored address.
            pub fn addr(&self) -> usize {
                self.0.addr()
            }

            /// Saves the current CPU GS base into this struct.
            pub fn save(&mut self, _guard: &crate::irq::DisabledLocalIrqGuard) {
                let guard = host_ostd::irq::disable_local();
                self.0.save(&guard);
            }

            /// Loads this struct's GS base onto the CPU.
            pub fn load(&self, _guard: &crate::irq::DisabledLocalIrqGuard) {
                let guard = host_ostd::irq::disable_local();
                self.0.load(&guard);
            }
        }
    }
}

/// Trap APIs.
pub mod trap {
    #[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
    use host_ostd::arch::cpu::context::CpuException;
    #[cfg(target_arch = "loongarch64")]
    use host_ostd::arch::cpu::context::CpuExceptionInfo as CpuException;
    pub use host_ostd::arch::trap::TrapFrame;
    #[cfg(target_arch = "x86_64")]
    pub use host_ostd::arch::trap::{USER_CS_VALUE, USER_SS_VALUE};

    /// Injects a custom handler for page faults caused by user addresses.
    pub fn inject_user_page_fault_handler(handler: fn(info: &CpuException) -> Result<(), ()>) {
        crate::task::inject_user_page_fault_handler(handler);
    }
}

/// Returns the frequency of the architecture counter.
pub fn tsc_freq() -> u64 {
    host_ostd::arch::tsc_freq()
}

/// Reads the architecture counter.
pub fn read_tsc() -> u64 {
    host_ostd::arch::read_tsc()
}

/// Reads a hardware-generated random value if available.
pub fn read_random() -> Option<u64> {
    host_ostd::arch::read_random()
}

#[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
#[used]
static _PRESERVE_ARCH_TRAP_SYMBOLS: fn(
    fn(&host_ostd::arch::cpu::context::CpuException) -> Result<(), ()>,
) = trap::inject_user_page_fault_handler;

#[cfg(all(feature = "host-api", target_arch = "x86_64"))]
#[used]
static _PRESERVE_X86_CONTEXT_SYMBOLS: (
    fn(usize) -> cpu::context::GsBase,
    fn(&cpu::context::GsBase) -> usize,
    fn(&mut cpu::context::GsBase, &crate::irq::DisabledLocalIrqGuard),
    fn(&cpu::context::GsBase, &crate::irq::DisabledLocalIrqGuard),
) = (
    cpu::context::GsBase::new,
    cpu::context::GsBase::addr,
    cpu::context::GsBase::save,
    cpu::context::GsBase::load,
);

#[cfg(target_arch = "loongarch64")]
#[used]
static _PRESERVE_ARCH_TRAP_SYMBOLS: fn(
    fn(&host_ostd::arch::cpu::context::CpuExceptionInfo) -> Result<(), ()>,
) = trap::inject_user_page_fault_handler;
