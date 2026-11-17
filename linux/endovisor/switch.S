/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Stack-switching trampolines for `endovisor.ko`.
 *
 * Image code executes on guarded 256 KiB image stacks (`grant.c`), while
 * Linux kernel code executes strictly on the carrier's Linux kernel stack
 * (`c->linux_sp`, anchored just below `task_pt_regs(current)`).
 */

#include <linux/linkage.h>
#include <linux/objtool.h>
#include <asm/nospec-branch.h>

/*
 * void enter_image(unsigned long entry, unsigned long new_rsp,
 *                      u64 arg0, u64 arg1);
 */
SYM_FUNC_START(enter_image)
	movq	%rsi, %rsp
	movq	%rdi, %rax
	movq	%rdx, %rdi
	movq	%rcx, %rsi
	CALL_NOSPEC rax
	ud2
SYM_FUNC_END(enter_image)
STACK_FRAME_NON_STANDARD enter_image

/*
 * void jump_linux_stack(void *linux_sp, void (*fn)(void *), void *arg);
 */
SYM_FUNC_START(jump_linux_stack)
	movq	%rdi, %rsp
	movq	%rsi, %rax
	movq	%rdx, %rdi
	CALL_NOSPEC rax
	ud2
SYM_FUNC_END(jump_linux_stack)
STACK_FRAME_NON_STANDARD jump_linux_stack

/*
 * void jump_user_run(void *linux_sp, struct carrier *c);
 */
SYM_FUNC_START(jump_user_run)
	movq	%rdi, %rsp
	movq	%rsi, %rdi
	call	do_user_run_on_linux
	ud2
SYM_FUNC_END(jump_user_run)
STACK_FRAME_NON_STANDARD jump_user_run

/*
 * u64 call_on_linux_stack(void *linux_sp, u64 (*fn)(void *), void *arg);
 *
 * Preserves `%rax` and `%rdx` across epilogue so 16-byte `struct mmio_result`
 * returns pass through untouched.
 */
SYM_FUNC_START(call_on_linux_stack)
	pushq	%rbp
	movq	%rsp, %rbp
	movq	%rdi, %rsp
	movq	%rsi, %rax
	movq	%rdx, %rdi
	CALL_NOSPEC rax
	movq	%rbp, %rsp
	popq	%rbp
	RET
SYM_FUNC_END(call_on_linux_stack)
STACK_FRAME_NON_STANDARD call_on_linux_stack

/*
 * void return_to_user(struct pt_regs *regs, bool from_syscall);
 *
 * Non-`__noreturn` tail wrapper around `kernelet_return_to_user` so callers can
 * end in `BUG()` without `objtool` fall-through warnings.
 */
SYM_FUNC_START(return_to_user)
	jmp	kernelet_return_to_user
SYM_FUNC_END(return_to_user)
STACK_FRAME_NON_STANDARD return_to_user

/*
 * Safe non-returning stop stub entered when `on_kernel_fault`, `watch`,
 * or `evict` redirects `regs->ip` (with `regs->sp = c->linux_sp`).
 */
SYM_FUNC_START(exit_stub)
	call	evict_leave
	ud2
SYM_FUNC_END(exit_stub)
STACK_FRAME_NON_STANDARD exit_stub
