// SPDX-License-Identifier: MPL-2.0

//! Linux `pt_regs` user-context support for kernelets.

/// User-mode code segment selector on x86-64 Linux.
pub(crate) const USER_CS: u64 = 0x33;

/// User-mode stack segment selector on x86-64 Linux.
pub(crate) const USER_SS: u64 = 0x2b;

/// Mandatory RFLAGS bits enforced for user mode (bit 1 reserved + `IF`).
pub(crate) const RFLAGS_FIXED: u64 = (1 << 1) | super::RFlags::INTERRUPT_FLAG.bits();

/// User-modifiable RFLAGS bits preserved across kernelet user returns.
pub(crate) const RFLAGS_USER: u64 = super::RFlags::CARRY_FLAG.bits()
    | super::RFlags::PARITY_FLAG.bits()
    | super::RFlags::AUXILIARY_CARRY_FLAG.bits()
    | super::RFlags::ZERO_FLAG.bits()
    | super::RFlags::SIGN_FLAG.bits()
    | super::RFlags::TRAP_FLAG.bits()
    | super::RFlags::DIRECTION_FLAG.bits()
    | super::RFlags::OVERFLOW_FLAG.bits()
    | super::RFlags::ALIGNMENT_CHECK.bits()
    | super::RFlags::ID.bits();

/// Register frame matching Linux's `struct pt_regs` on x86-64 (168 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct LinuxPtRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const _: () = {
    use core::mem::offset_of;
    assert!(size_of::<LinuxPtRegs>() == 168);
    assert!(offset_of!(LinuxPtRegs, r15) == 0);
    assert!(offset_of!(LinuxPtRegs, orig_rax) == 15 * 8);
    assert!(offset_of!(LinuxPtRegs, rip) == 16 * 8);
    assert!(offset_of!(LinuxPtRegs, cs) == 17 * 8);
    assert!(offset_of!(LinuxPtRegs, rflags) == 18 * 8);
    assert!(offset_of!(LinuxPtRegs, rsp) == 19 * 8);
    assert!(offset_of!(LinuxPtRegs, ss) == 20 * 8);
};

impl LinuxPtRegs {
    /// Returns a fresh, sanitized initial user-mode register state.
    pub(crate) const fn new_initial() -> Self {
        Self {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbp: 0,
            rbx: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            orig_rax: u64::MAX,
            rip: 0,
            cs: USER_CS,
            rflags: RFLAGS_FIXED | super::RFlags::ID.bits(),
            rsp: 0,
            ss: USER_SS,
        }
    }

    /// Sanitizes control segments and flags before returning to user space.
    pub(crate) fn sanitize(&mut self) {
        self.rflags = (self.rflags & RFLAGS_USER) | RFLAGS_FIXED;
        self.cs = USER_CS;
        self.ss = USER_SS;
    }

    /// Extracts [`super::GeneralRegs`] from this register frame.
    pub(crate) const fn to_general_regs(&self) -> super::GeneralRegs {
        super::GeneralRegs {
            rax: self.rax as usize,
            rbx: self.rbx as usize,
            rcx: self.rcx as usize,
            rdx: self.rdx as usize,
            rsi: self.rsi as usize,
            rdi: self.rdi as usize,
            rbp: self.rbp as usize,
            rsp: self.rsp as usize,
            r8: self.r8 as usize,
            r9: self.r9 as usize,
            r10: self.r10 as usize,
            r11: self.r11 as usize,
            r12: self.r12 as usize,
            r13: self.r13 as usize,
            r14: self.r14 as usize,
            r15: self.r15 as usize,
            rip: self.rip as usize,
        }
    }
}
