# SPDX-License-Identifier: MPL-2.0
# FrameVsock Echo Server for FrameVM
#
# This program creates a listening socket and echoes back any received data.
# It uses non-blocking mode with polling since blocking isn't implemented yet.
#
# Test flow:
# 1. Create socket, bind to port 12345, listen
# 2. Poll accept() until a connection arrives
# 3. Echo loop: recv data and send it back
# 4. Clean up and exit

.global _start
.section .text

# Constants
.equ AF_FRAMEVSOCK, 46
.equ SOCK_STREAM, 1
.equ SOCK_NONBLOCK, 0x800

.equ VMADDR_CID_ANY, -1
.equ VMADDR_CID_HOST, 2
.equ VMADDR_CID_GUEST, 3

.equ SERVER_PORT, 12345

# Syscall numbers
.equ SYS_READ, 0
.equ SYS_WRITE, 1
.equ SYS_CLOSE, 3
.equ SYS_SOCKET, 41
.equ SYS_ACCEPT, 43
.equ SYS_SENDTO, 44
.equ SYS_RECVFROM, 45
.equ SYS_BIND, 49
.equ SYS_LISTEN, 50
.equ SYS_EXIT, 60

# Error codes
.equ EAGAIN, 11

_start:
    # Allocate stack space for buffers
    sub     $512, %rsp              # 256 for recv buffer, 256 for sockaddr

    # Print start message
    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_start(%rip), %rsi
    mov     $(msg_start_end - msg_start), %rdx
    syscall

    # ============================================================
    # Create server socket (non-blocking for polling)
    # ============================================================
    mov     $SYS_SOCKET, %rax
    mov     $AF_FRAMEVSOCK, %rdi
    mov     $(SOCK_STREAM | SOCK_NONBLOCK), %rsi
    xor     %rdx, %rdx
    syscall
    test    %rax, %rax
    js      error_socket
    mov     %rax, %r12              # r12 = server_fd

    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_socket_ok(%rip), %rsi
    mov     $(msg_socket_ok_end - msg_socket_ok), %rdx
    syscall

    # ============================================================
    # Bind to port 12345
    # ============================================================
    # Setup sockaddr_vm at rsp+256
    lea     256(%rsp), %r14         # r14 = sockaddr buffer
    movw    $AF_FRAMEVSOCK, (%r14)  # family
    movw    $0, 2(%r14)             # reserved
    movl    $SERVER_PORT, 4(%r14)   # port = 12345
    movq    $VMADDR_CID_ANY, 8(%r14) # cid = ANY

    mov     $SYS_BIND, %rax
    mov     %r12, %rdi
    mov     %r14, %rsi
    mov     $16, %rdx
    syscall
    test    %rax, %rax
    js      error_bind

    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_bind_ok(%rip), %rsi
    mov     $(msg_bind_ok_end - msg_bind_ok), %rdx
    syscall

    # ============================================================
    # Listen
    # ============================================================
    mov     $SYS_LISTEN, %rax
    mov     %r12, %rdi
    mov     $1, %rsi                # backlog = 1
    syscall
    test    %rax, %rax
    js      error_listen

    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_listen_ok(%rip), %rsi
    mov     $(msg_listen_ok_end - msg_listen_ok), %rdx
    syscall

    # ============================================================
    # Poll accept() until connection arrives
    # ============================================================
    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_waiting(%rip), %rsi
    mov     $(msg_waiting_end - msg_waiting), %rdx
    syscall

accept_loop:
    mov     $SYS_ACCEPT, %rax
    mov     %r12, %rdi
    xor     %rsi, %rsi              # addr = NULL
    xor     %rdx, %rdx              # addrlen = NULL
    syscall

    # Check if EAGAIN - just retry without printing
    cmp     $-EAGAIN, %rax
    je      accept_loop

    # Check for other errors
    test    %rax, %rax
    js      error_accept

    # Accept succeeded!
    mov     %rax, %r13              # r13 = client_fd

accept_done:
    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_accepted(%rip), %rsi
    mov     $(msg_accepted_end - msg_accepted), %rdx
    syscall

    # ============================================================
    # Echo loop: recv and send back
    # ============================================================
echo_loop:
    # Try to receive data
    mov     $SYS_RECVFROM, %rax
    mov     %r13, %rdi              # client_fd
    mov     %rsp, %rsi              # buffer at rsp
    mov     $256, %rdx              # max 256 bytes
    xor     %r10, %r10              # flags = 0
    xor     %r8, %r8                # src_addr = NULL
    xor     %r9, %r9                # addrlen = NULL
    syscall

    # Check for EAGAIN (no data yet)
    cmp     $-EAGAIN, %rax
    je      echo_loop               # Keep polling

    # Check for errors or EOF
    test    %rax, %rax
    jle     echo_done               # EOF or error

    # Save received length
    mov     %rax, %rbx              # rbx = received bytes

    # Print received message
    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_recv(%rip), %rsi
    mov     $(msg_recv_end - msg_recv), %rdx
    syscall

    # Print the actual data
    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    mov     %rsp, %rsi
    mov     %rbx, %rdx
    syscall

    # Print newline
    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_newline(%rip), %rsi
    mov     $1, %rdx
    syscall

    # Send the data back (echo)
    mov     $SYS_SENDTO, %rax
    mov     %r13, %rdi              # client_fd
    mov     %rsp, %rsi              # buffer
    mov     %rbx, %rdx              # same length as received
    xor     %r10, %r10              # flags = 0
    xor     %r8, %r8                # dest_addr = NULL
    xor     %r9, %r9                # addrlen = 0
    syscall

    test    %rax, %rax
    js      error_send

    # Print sent confirmation
    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_echoed(%rip), %rsi
    mov     $(msg_echoed_end - msg_echoed), %rdx
    syscall

    jmp     echo_loop

echo_done:
    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_client_closed(%rip), %rsi
    mov     $(msg_client_closed_end - msg_client_closed), %rdx
    syscall

    # Close client socket
    mov     $SYS_CLOSE, %rax
    mov     %r13, %rdi
    syscall

    # Close server socket
    mov     $SYS_CLOSE, %rax
    mov     %r12, %rdi
    syscall

    # Print done
    mov     $SYS_WRITE, %rax
    mov     $1, %rdi
    lea     msg_done(%rip), %rsi
    mov     $(msg_done_end - msg_done), %rdx
    syscall

    # Exit successfully
    mov     $SYS_EXIT, %rax
    xor     %rdi, %rdi
    syscall

# ============================================================
# Error handlers
# ============================================================

error_socket:
    mov     $SYS_WRITE, %rax
    mov     $2, %rdi
    lea     err_socket(%rip), %rsi
    mov     $(err_socket_end - err_socket), %rdx
    syscall
    jmp     exit_error

error_bind:
    mov     $SYS_WRITE, %rax
    mov     $2, %rdi
    lea     err_bind(%rip), %rsi
    mov     $(err_bind_end - err_bind), %rdx
    syscall
    jmp     exit_error

error_listen:
    mov     $SYS_WRITE, %rax
    mov     $2, %rdi
    lea     err_listen(%rip), %rsi
    mov     $(err_listen_end - err_listen), %rdx
    syscall
    jmp     exit_error

error_accept:
    mov     $SYS_WRITE, %rax
    mov     $2, %rdi
    lea     err_accept(%rip), %rsi
    mov     $(err_accept_end - err_accept), %rdx
    syscall
    jmp     exit_error

error_send:
    mov     $SYS_WRITE, %rax
    mov     $2, %rdi
    lea     err_send(%rip), %rsi
    mov     $(err_send_end - err_send), %rdx
    syscall
    jmp     exit_error

exit_error:
    mov     $SYS_EXIT, %rax
    mov     $1, %rdi
    syscall

# ============================================================
# Read-only data
# ============================================================
.section .rodata

msg_start:
    .ascii "========================================\n"
    .ascii "[Echo Server] Starting FrameVsock Echo Server\n"
    .ascii "========================================\n"
msg_start_end:

msg_socket_ok:
    .ascii "[Echo Server] Socket created (non-blocking)\n"
msg_socket_ok_end:

msg_bind_ok:
    .ascii "[Echo Server] Bound to port 12345\n"
msg_bind_ok_end:

msg_listen_ok:
    .ascii "[Echo Server] Listening...\n"
msg_listen_ok_end:

msg_waiting:
    .ascii "[Echo Server] Waiting for connection"
msg_waiting_end:

msg_accepted:
    .ascii "\n[Echo Server] Connection accepted!\n"
msg_accepted_end:

msg_recv:
    .ascii "[Echo Server] Received: "
msg_recv_end:

msg_newline:
    .ascii "\n"

msg_echoed:
    .ascii "[Echo Server] Echoed back to client\n"
msg_echoed_end:

msg_client_closed:
    .ascii "[Echo Server] Client disconnected\n"
msg_client_closed_end:

msg_done:
    .ascii "========================================\n"
    .ascii "[Echo Server] Done!\n"
    .ascii "========================================\n"
msg_done_end:

err_socket:
    .ascii "[Echo Server] ERROR: socket() failed\n"
err_socket_end:

err_bind:
    .ascii "[Echo Server] ERROR: bind() failed\n"
err_bind_end:

err_listen:
    .ascii "[Echo Server] ERROR: listen() failed\n"
err_listen_end:

err_accept:
    .ascii "[Echo Server] ERROR: accept() failed\n"
err_accept_end:

err_send:
    .ascii "[Echo Server] ERROR: sendto() failed\n"
err_send_end:
