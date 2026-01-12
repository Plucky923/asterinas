/* SPDX-License-Identifier: MPL-2.0 */

/*
 * Stack switching routines for secure cross-domain calls.
 *
 * These functions allow switching to a service stack when the caller's
 * stack has insufficient space.
 */

.text
.code64

/*
 * call_on_stack - Execute a function on a different stack
 *
 * This function switches to a new stack, calls the target function,
 * and then switches back to the original stack.
 *
 * Arguments:
 *   rdi: new_stack_top - The top of the new stack (high address)
 *   rsi: func_ptr      - Pointer to the function to call
 *   rdx: arg_ptr       - Argument to pass to the function (in rdi)
 *
 * The target function signature should be: extern "C" fn(arg: usize)
 *
 * Calling convention: System V AMD64 ABI
 * - Callee-saved registers: rbx, rbp, r12-r15
 * - Caller-saved registers: rax, rcx, rdx, rsi, rdi, r8-r11
 */
.global call_on_stack
.type call_on_stack, @function
call_on_stack:
    # Save callee-saved registers on the original stack
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15

    # Save the original stack pointer
    mov r12, rsp

    # Save function pointer and argument
    mov r13, rsi        # r13 = func_ptr
    mov r14, rdx        # r14 = arg_ptr

    # Switch to the new stack
    mov rsp, rdi

    # Ensure 16-byte alignment
    and rsp, -16

    # Save original stack pointer on the new stack (for recovery)
    push r12

    # Adjust for alignment before call (need RSP % 16 == 8 before CALL)
    sub rsp, 8

    # Set up argument and call the function
    mov rdi, r14        # First argument = arg_ptr
    call r13            # Call the target function (Intel syntax: no *)

    # Restore alignment adjustment
    add rsp, 8

    # Restore original stack pointer
    pop rsp

    # Restore callee-saved registers from the original stack
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp

    ret
.size call_on_stack, .-call_on_stack
