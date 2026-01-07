# SPDX-License-Identifier: MPL-2.0
# FrameVsock Client for FrameVM
#
# This program connects to Host (CID=2, Port=8080) and sends a test message.
# It uses non-blocking mode with polling if needed, or blocking connect if implemented.
#
# Test flow:
# 1. Create socket
# 2. Connect to Host (CID=2, Port=8080)
# 3. Send "Hello Host"
# 4. Receive echo response
# 5. Exit

.global _start
.section .text

# Constants
.equ AF_FRAMEVSOCK, 46
.equ SOCK_STREAM, 1

.equ VMADDR_CID_HOST, 2
.equ SERVER_PORT, 8080

# Syscall numbers
.equ SYS_WRITE, 1
.equ SYS_CLOSE, 3
.equ SYS_SOCKET, 41
.equ SYS_CONNECT, 42
.equ SYS_SENDTO, 44
.equ SYS_RECVFROM, 45
.equ SYS_EXIT, 60

_start:
    # Allocate stack space
    sub     $256, %rsp

    # Print start message
    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_start(%rip), %rsi
    mov     $(msg_start_end - msg_start), %rdx
    syscall

    # ============================================================
    # Create socket
    # ============================================================
    mov     $SYS_SOCKET, %rax
    mov     $AF_FRAMEVSOCK, %rdi
    mov     $SOCK_STREAM, %rsi
    xor     %rdx, %rdx
    syscall
    test    %rax, %rax
    js      error_socket
    mov     %rax, %r12              # r12 = socket_fd

    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_socket_ok(%rip), %rsi
    mov     $(msg_socket_ok_end - msg_socket_ok), %rdx
    syscall

    # ============================================================
    # Connect to Host (CID=2, Port=8080)
    # ============================================================
    # Setup sockaddr_vm at rsp
    movq    %rsp, %r14
    movw    $AF_FRAMEVSOCK, (%r14)  # family
    movw    $0, 2(%r14)             # reserved
    movl    $SERVER_PORT, 4(%r14)   # port = 8080
    movq    $VMADDR_CID_HOST, 8(%r14) # cid = 2

    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_connecting(%rip), %rsi
    mov     $(msg_connecting_end - msg_connecting), %rdx
    syscall

    mov     $SYS_CONNECT, %rax
    mov     %r12, %rdi
    mov     %r14, %rsi
    mov     $16, %rdx
    syscall
    test    %rax, %rax
    js      error_connect

    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_connected(%rip), %rsi
    mov     $(msg_connected_end - msg_connected), %rdx
    syscall

    # ============================================================
    # Send data
    # ============================================================
    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_sending(%rip), %rsi
    mov     $(msg_sending_end - msg_sending), %rdx
    syscall

    mov     $SYS_SENDTO, %rax
    mov     %r12, %rdi              # socket_fd
    lea     msg_hello(%rip), %rsi   # buffer
    mov     $(msg_hello_end - msg_hello), %rdx # length
    xor     %r10, %r10              # flags
    xor     %r8, %r8                # dest_addr = NULL
    xor     %r9, %r9                # addrlen = 0
    syscall
    test    %rax, %rax
    js      error_send

    # ============================================================
    # Receive echo
    # ============================================================
    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_waiting_echo(%rip), %rsi
    mov     $(msg_waiting_echo_end - msg_waiting_echo), %rdx
    syscall

    # Clear buffer at rsp
    movq    $0, (%rsp)
    movq    $0, 8(%rsp)
    movq    $0, 16(%rsp)
    movq    $0, 24(%rsp)

recv_loop:
    mov     $SYS_RECVFROM, %rax
    mov     %r12, %rdi              # socket_fd
    mov     %rsp, %rsi              # buffer
    mov     $256, %rdx              # len
    xor     %r10, %r10              # flags
    xor     %r8, %r8                # src_addr
    xor     %r9, %r9                # addrlen
    syscall
    
    # Check EAGAIN (should not happen if blocking is implemented, but handling just in case)
    cmp     $-11, %rax              # -EAGAIN
    je      recv_loop

    test    %rax, %rax
    js      error_recv
    jz      error_closed            # 0 means closed

    # Save len
    mov     %rax, %rbx

    # Print received data
    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_recv(%rip), %rsi
    mov     $(msg_recv_end - msg_recv), %rdx
    syscall

    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    mov     %rsp, %rsi
    mov     %rbx, %rdx
    syscall

    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_newline(%rip), %rsi
    mov     $1, %rdx
    syscall

    # ============================================================
    # Exit
    # ============================================================
    mov     $SYS_CLOSE, %rax
    mov     %r12, %rdi
    syscall

    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_done(%rip), %rsi
    mov     $(msg_done_end - msg_done), %rdx
    syscall

    mov     $SYS_EXIT, %rax
    xor     %rdi, %rdi
    syscall

# ============================================================
# Error handlers
# ============================================================

error_socket:
    lea     err_socket(%rip), %rsi
    mov     $(err_socket_end - err_socket), %rdx
    jmp     print_error

error_connect:
    lea     err_connect(%rip), %rsi
    mov     $(err_connect_end - err_connect), %rdx
    jmp     print_error

error_send:
    lea     err_send(%rip), %rsi
    mov     $(err_send_end - err_send), %rdx
    jmp     print_error

error_recv:
    lea     err_recv(%rip), %rsi
    mov     $(err_recv_end - err_recv), %rdx
    jmp     print_error

error_closed:
    lea     err_closed(%rip), %rsi
    mov     $(err_closed_end - err_closed), %rdx
    jmp     print_error

print_error:
    mov     $SYS_WRITE, %rax
    mov     $2, %rdi
    syscall
    
    mov     $SYS_EXIT, %rax
    mov     $1, %rdi
    syscall

# ============================================================
# Read-only data
# ============================================================
.section .rodata

msg_start:
    .ascii "[Guest Client] Starting...\n"
msg_start_end:

msg_socket_ok:
    .ascii "[Guest Client] Socket created\n"
msg_socket_ok_end:

msg_connecting:
    .ascii "[Guest Client] Connecting to Host...\n"
msg_connecting_end:

msg_connected:
    .ascii "[Guest Client] Connected!\n"
msg_connected_end:

msg_sending:
    .ascii "[Guest Client] Sending data...\n"
msg_sending_end:

msg_hello:
    .ascii "Hello Host"
msg_hello_end:

msg_waiting_echo:
    .ascii "[Guest Client] Waiting for echo...\n"
msg_waiting_echo_end:

msg_recv:
    .ascii "[Guest Client] Received: "
msg_recv_end:

msg_newline:
    .ascii "\n"

msg_done:
    .ascii "[Guest Client] Test PASSED!\n"
msg_done_end:

err_socket:
    .ascii "ERROR: socket() failed\n"
err_socket_end:

err_connect:
    .ascii "ERROR: connect() failed\n"
err_connect_end:

err_send:
    .ascii "ERROR: send() failed\n"
err_send_end:

err_recv:
    .ascii "ERROR: recv() failed\n"
err_recv_end:

err_closed:
    .ascii "ERROR: Connection closed unexpectedly\n"
err_closed_end:

