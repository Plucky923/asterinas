/* SPDX-License-Identifier: MPL-2.0 OR MIT
 *
 * The original source code is from [trapframe-rs](https://github.com/rcore-os/trapframe-rs),
 * which is released under the following license:
 *
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2020 - 2024 Runji Wang
 *
 * We make the following new changes:
 * * Add the `trap_handler_table`.
 * * Adjust some symbol names.
 * * Disable alternate macro mode after using it.
 * * Report the RSP pushed by the CPU in the trap frame.
 *
 * These changes are released under the following license:
 *
 * SPDX-License-Identifier: MPL-2.0
 */

.equ NUM_INT, 256

.text
.code64

.altmacro # enable alternate macro mode to use "%i"

.macro DEF_HANDLER, i
_trap_handler_\i:
.if \i == 8 || (\i >= 10 && \i <= 14) || \i == 17
    # error code pushed by CPU
    push    \i          # interrupt vector
    jmp     trap_common
.else
    push    0           # fill in error code in TrapFrame
    push    \i          # interrupt vector
    jmp     trap_common
.endif
.endm

_trap_handlers:
.set i, 0
.rept NUM_INT
    DEF_HANDLER %i
    .set i, i + 1
.endr

.rodata

.macro DEF_TABLE_ENTRY, i
    .quad _trap_handler_\i
.endm

.global trap_handler_table
trap_handler_table:
.set i, 0
.rept NUM_INT
    DEF_TABLE_ENTRY %i
    .set i, i + 1
.endr

.noaltmacro # disable alternate macro mode; otherwise, it may leak to other files

.text
.code64

trap_common:
    cld                     # clear DF before going to Rust to conform to x86-64 calling convention
    push rax
    mov ax, [rsp + 4*8]     # load cs
    and ax, 0x3             # test
    jz _trap_from_kernel    # continue trap

    # Double fault always lands on its IST, including one attributed to user
    # mode. That stack has no UserContext pointer above the hardware frame.
    # Preserve the complete frame and apply the Host's fatal policy instead.
    cmp qword ptr [rsp + 8], 8
    jne _trap_from_user
    swapgs
    jmp _trap_from_kernel

_trap_from_user:
    # kernel stack:
    # - ptr to UserContext
    # - ss
    # - rsp
    # - rflags
    # - cs
    # - rip
    # - error code
    # - trap num
    # - rax

    swapgs                  # swap in kernel gs
    mov rax, [rsp + 6*8]    # rax = user rsp
    mov gs:12, rax          # store user rsp -> scratch at TSS.sp1

    mov rsp, [rsp + 8*8]    # load rsp <- UserContext
    add rsp, 20*8           # rsp -> top of UserContext
    mov rax, gs:4           # rax = kernel stack

    # push trap_num, error_code
    push [rax - 6*8]        # push error_code
    push [rax - 7*8]        # push trap_num
    # push general registers
    push [rax - 3*8]        # push rflags
    push [rax - 5*8]        # push rip
    mov rax, [rax - 8*8]    # pop rax
.extern trap_syscall_entry
    jmp trap_syscall_entry

_trap_from_kernel:
    # kernel stack:
    # - ss
    # - rsp                 # ss:rsp is unconditionally pushed in 64-bit mode
    # - rflags
    # - cs
    # - rip
    # - error code
    # - trap num
    # - rax

    pop rax
    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rbp
    push rdi
    push rsi
    push rdx
    push rcx
    push rbx
    push rax

    # Preserve the frame pointer across a Host stack handoff. No ownership,
    # interrupt accounting, callback or Rust frame precedes this prefix.
.if {kernelet_host}
    mov rbx, rsp
    xor r12d, r12d
    lea r11, [rip + KERNELET_HOST_STATE_PTR]
    lea r10, [rip + __cpu_local_start]
    sub r11, r10
    mov r11, gs:[r11]
    test r11, r11
    jz .Ltrap_stack_ready
    cmp qword ptr [rbx + 15*8], 8
    je .Ltrap_doublefault_stack
    # Authenticate the saved stack against the pinned pool geometry. Native
    # Host/IST stacks and nested IRQ stacks keep their interrupted pointer.
    mov rax, [rbx + 20*8]
    and rax, -524288
    cmp rax, [r11 + 64]
    jb .Ltrap_stack_ready
    cmp rax, [r11 + 72]
    jae .Ltrap_stack_ready
    cmp qword ptr [rbx + 15*8], 32
    jb .Ltrap_exception_stack
    lea r12, [rip + KERNELET_IRQ_STACK_BUSY]
    sub r12, r10
    cmp qword ptr gs:[r12], 0
    jne .Ltrap_nested_stack
    lea rax, [rip + KERNELET_IRQ_STACK_TOP]
    sub rax, r10
    mov rax, gs:[rax]
    test rax, rax
    jz .Ltrap_nested_stack
    mov qword ptr gs:[r12], 1
    mov rsp, rax
    jmp .Ltrap_stack_ready
.Ltrap_nested_stack:
    xor r12d, r12d
    jmp .Ltrap_stack_ready
.Ltrap_exception_stack:
    mov rsp, [r11]
    and rsp, -16
    jmp .Ltrap_stack_ready
.Ltrap_doublefault_stack:
    # The bounded precheck runs on the independent IST. Only attributed,
    # discardable Image execution may use the preserved carrier continuation.
    # No precheck frame or Host resource survives this synchronous call.
    mov rdi, rbx
    call kernelet_host_recovery_stack_impl
    test rax, rax
    jz .Ltrap_stack_ready
    mov rsp, rax
    and rsp, -16
.Ltrap_stack_ready:
    mov rdi, rbx
.else
    mov rdi, rsp
.endif
    call trap_handler
.if {kernelet_host}
    mov rsp, rbx
    # Leave the per-CPU stack before making it available to another entry.
    # IRQs remain masked through the fixed IRET tail.
    test r12, r12
    jz .Ltrap_stack_released
    mov qword ptr gs:[r12], 0
.Ltrap_stack_released:
.endif

    pop rax
    pop rbx
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop rbp
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15

    # skip trap_num, error_code
    add rsp, 16

    iretq
.global kernelet_kernel_trap_end
kernelet_kernel_trap_end:
