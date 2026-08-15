// SPDX-License-Identifier: MPL-2.0

//! CPU ABI helpers for the trimmed kernel image.

use ostd::arch::cpu::context::UserContext;

/// Describes the Linux system call convention for a user context.
///
/// This mirrors the kernel's `cpu::LinuxAbi` trait so syscall code can follow
/// the same shape while still depending only on the OSTD-compatible surface.
pub trait LinuxAbi {
    /// Returns the system call number.
    fn syscall_num(&self) -> usize;

    /// Returns the system call return value.
    #[expect(dead_code, reason = "Mirrors the kernel LinuxAbi trait shape.")]
    fn syscall_ret(&self) -> usize;

    /// Sets the system call return value.
    fn set_syscall_ret(&mut self, ret: usize);

    /// Returns the system call arguments.
    fn syscall_args(&self) -> [usize; 6];
}

#[cfg(target_arch = "x86_64")]
impl LinuxAbi for UserContext {
    fn syscall_num(&self) -> usize {
        self.rax()
    }

    fn syscall_ret(&self) -> usize {
        self.rax()
    }

    fn set_syscall_ret(&mut self, ret: usize) {
        self.set_rax(ret);
    }

    fn syscall_args(&self) -> [usize; 6] {
        [
            self.rdi(),
            self.rsi(),
            self.rdx(),
            self.r10(),
            self.r8(),
            self.r9(),
        ]
    }
}
