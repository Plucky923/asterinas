// SPDX-License-Identifier: MPL-2.0

use ostd::{
    arch::cpu::context::{FpuContext, UserContext},
    mm::VmIo,
    user::UserContextApi,
};

use super::SyscallReturn;
use crate::{
    prelude::*,
    process::{
        posix_thread::ContextPthreadAdminApi,
        signal::{c_types::ucontext_t, constants::SIGSEGV, signals::kernel::KernelSignal},
    },
    syscall::sigaltstack::set_new_stack,
};

pub(super) fn sys_rt_sigreturn(ctx: &Context, user_ctx: &mut UserContext) -> Result<SyscallReturn> {
    let sig_context_addr = user_ctx.stack_pointer() as Vaddr;
    debug!(
        "sys_rt_sigreturn: sig_context_addr = {:#x}",
        sig_context_addr
    );

    let user_space = ctx.user_space();
    let ucontext = match user_space.read_val::<ucontext_t>(sig_context_addr) {
        Ok(ucontext) => ucontext,
        Err(err) => {
            ctx.posix_thread
                .enqueue_signal(Box::new(KernelSignal::new(SIGSEGV)));
            return Err(err.into());
        }
    };

    // Read and validate the FPU context before mutating any thread state.
    let fpu_context_addr = cfg_select! {
        target_arch = "x86_64" => ucontext.uc_mcontext.fpu_context_addr(),
        any(target_arch = "riscv64", target_arch = "loongarch64", target_arch = "aarch64") => {
            // In RISC-V/LoongArch64/ARM, the FPU context is placed directly after `ucontext_t` on
            // the signal stack.
            sig_context_addr + size_of::<ucontext_t>()
        }
        _ => compile_error!("unsupported target"),
    };
    let mut fpu_context = FpuContext::new();
    let fpu_res: Result<()> = (|| {
        #[cfg(target_arch = "x86_64")]
        {
            let mut reader = user_space.reader(fpu_context_addr, fpu_context.area_size())?;
            fpu_context.read_from(&mut reader)?;
        }
        #[cfg(not(target_arch = "x86_64"))]
        user_space.read_bytes(fpu_context_addr, fpu_context.as_bytes_mut())?;
        Ok(())
    })();
    if let Err(err) = fpu_res {
        ctx.posix_thread
            .enqueue_signal(Box::new(KernelSignal::new(SIGSEGV)));
        return Err(err);
    }
    drop(user_space);

    // Restore general-purpose registers.
    ucontext.uc_mcontext.copy_user_regs_to(user_ctx);

    // Restore signal stack settings.
    let stack = ucontext.uc_stack;
    // If the stack setting is invalid, we silently ignore the error,
    // following Linux's behavior.
    // Reference: <https://elixir.bootlin.com/linux/v6.15/source/kernel/signal.c#L4456>.
    let _ = set_new_stack(stack, ctx, user_ctx.stack_pointer());

    // Restore the FPU context.
    ctx.thread_local.supp_user_context().fpu().set(fpu_context);

    // Restore the signal mask.
    let sig_mask = ucontext.uc_sigmask;
    ctx.set_sig_mask(sig_mask.into());

    Ok(SyscallReturn::NoReturn)
}
