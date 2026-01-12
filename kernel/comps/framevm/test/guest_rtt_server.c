/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * FrameVsock RTT Benchmark (FrameVM Guest Server / Pong)
 *
 * This program runs in FrameVM Guest and echoes ping messages from Host.
 * Pairs with host_rtt_client on the Host side.
 *
 * Compile-time options:
 *   -DPORT=<port>              (default: 20002)
 */

#include "syscalls.h"

#ifndef PORT
#define PORT 20002
#endif

#ifndef MSG_SIZE
#define MSG_SIZE 4
#endif

static char buffer[MSG_SIZE];

void _start(void) {
    int server_fd, client_fd;
    uint64_t count = 0;

    print("\n========================================\n");
    print(" FrameVsock RTT Benchmark - Guest Server\n");
    print("========================================\n");
    print(" Port:     ");
    print_number(PORT);
    print("\n");
    print(" Message:  ");
    print_number(MSG_SIZE);
    print(" byte(s)\n");
    print("----------------------------------------\n");

    /* Create socket */
    server_fd = sys_socket(AF_FRAMEVSOCK, SOCK_STREAM, 0);
    if (server_fd < 0) {
        print("ERROR: socket() failed: ");
        print_number((uint64_t)(-server_fd));
        print("\n");
        sys_exit(1);
    }

    /* Bind */
    struct sockaddr_vm addr;
    addr.svm_family = AF_FRAMEVSOCK;
    addr.svm_reserved1 = 0;
    addr.svm_port = PORT;
    addr.svm_cid = VMADDR_CID_ANY;

    int err = sys_bind(server_fd, &addr, sizeof(addr));
    if (err < 0) {
        print("ERROR: bind() failed: ");
        print_number((uint64_t)(-err));
        print("\n");
        sys_close(server_fd);
        sys_exit(1);
    }

    /* Listen */
    err = sys_listen(server_fd, 1);
    if (err < 0) {
        print("ERROR: listen() failed: ");
        print_number((uint64_t)(-err));
        print("\n");
        sys_close(server_fd);
        sys_exit(1);
    }

    print(" Listening on port ");
    print_number(PORT);
    print("...\n");
    print(" Waiting for connection...\n");

    /* Accept */
    struct sockaddr_vm peer_addr;
    int peer_len = sizeof(peer_addr);
    client_fd = sys_accept(server_fd, &peer_addr, &peer_len);
    if (client_fd < 0) {
        print("ERROR: accept() failed: ");
        print_number((uint64_t)(-client_fd));
        print("\n");
        sys_close(server_fd);
        sys_exit(1);
    }

    print(" Connection from CID ");
    print_number(peer_addr.svm_cid);
    print(", port ");
    print_number(peer_addr.svm_port);
    print("\n");
    print(" Running ping-pong...\n");

    /* Ping-pong loop */
    while (1) {
        /* Receive ping */
        ssize_t n = sys_read(client_fd, buffer, MSG_SIZE);
        if (n <= 0) {
            break;
        }

        /* Send pong */
        n = sys_write(client_fd, buffer, n);
        if (n <= 0) {
            break;
        }

        count++;
    }

    print(" Session ended. Total ping-pong: ");
    print_number(count);
    print("\n");
    print("----------------------------------------\n");

    sys_close(client_fd);
    sys_close(server_fd);

    sys_exit(0);
}
