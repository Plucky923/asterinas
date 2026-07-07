// SPDX-License-Identifier: MPL-2.0

use ostd::{
    arch::cpu::context::{CpuException, PageFaultErrorCode, RawPageFaultInfo, UserContext},
    mm::Vaddr,
};

use crate::vm::{perms::VmPerms, vmar::PageFaultInfo};

/// Represents the context of a signal handler.
///
/// This contains the context saved before a signal handler is invoked; it will be restored by
/// `sys_rt_sigreturn`.
///
/// Reference: <https://elixir.bootlin.com/linux/v6.15.7/source/arch/x86/include/uapi/asm/sigcontext.h#L325>
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod)]
pub struct SigContext {
    r8: usize,
    r9: usize,
    r10: usize,
    r11: usize,
    r12: usize,
    r13: usize,
    r14: usize,
    r15: usize,
    rdi: usize,
    rsi: usize,
    rbp: usize,
    rbx: usize,
    rdx: usize,
    rax: usize,
    rcx: usize,
    rsp: usize,
    rip: usize,
    rflags: usize,
    cs: u16,
    gs: u16,
    fs: u16,
    ss: u16,
    error_code: usize,
    trap_num: usize,
    old_mask: u64,
    page_fault_addr: usize,
    // A stack pointer to FPU context.
    fpu_context_addr: Vaddr,
    reserved: [u64; 8],
}

macro_rules! copy_gp_regs {
    ($src: ident, $dst: ident) => {
        $dst.rax = $src.rax;
        $dst.rbx = $src.rbx;
        $dst.rcx = $src.rcx;
        $dst.rdx = $src.rdx;
        $dst.rsi = $src.rsi;
        $dst.rdi = $src.rdi;
        $dst.rbp = $src.rbp;
        $dst.rsp = $src.rsp;
        $dst.r8 = $src.r8;
        $dst.r9 = $src.r9;
        $dst.r10 = $src.r10;
        $dst.r11 = $src.r11;
        $dst.r12 = $src.r12;
        $dst.r13 = $src.r13;
        $dst.r14 = $src.r14;
        $dst.r15 = $src.r15;
        $dst.rip = $src.rip;
        $dst.rflags = $src.rflags;
    };
}

impl SigContext {
    pub fn copy_user_regs_to(&self, dst: &mut UserContext) {
        let gp_regs = dst.general_regs_mut();
        copy_gp_regs!(self, gp_regs);
    }

    pub fn copy_user_regs_from(&mut self, src: &UserContext) {
        let gp_regs = src.general_regs();
        copy_gp_regs!(gp_regs, self);

        // TODO: Fill exception information in `SigContext`.
    }

    pub fn fpu_context_addr(&self) -> Vaddr {
        self.fpu_context_addr
    }

    pub fn set_fpu_context_addr(&mut self, addr: Vaddr) {
        self.fpu_context_addr = addr;
    }
}

impl From<&RawPageFaultInfo> for PageFaultInfo {
    fn from(raw_info: &RawPageFaultInfo) -> Self {
        let required_perms = if raw_info
            .error_code
            .contains(PageFaultErrorCode::INSTRUCTION)
        {
            VmPerms::EXEC
        } else if raw_info.error_code.contains(PageFaultErrorCode::WRITE) {
            // On x86_64, writable pages must also be readable.
            // Reference: Section 5.11.3 from <https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3a-part-1-manual.pdf>.
            VmPerms::READ | VmPerms::WRITE
        } else {
            VmPerms::READ
        };

        PageFaultInfo::new(raw_info.addr, required_perms)
    }
}

impl TryFrom<&CpuException> for PageFaultInfo {
    // [`Err`] indicates that the [`CpuExceptionInfo`] is not a page fault,
    // with no additional error information.
    type Error = ();

    fn try_from(value: &CpuException) -> Result<Self, ()> {
        let CpuException::PageFault(raw_info) = value else {
            return Err(());
        };

        Ok(raw_info.into())
    }
}
