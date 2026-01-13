/*
 * FrameVsock RTT Benchmark (Guest Server / Pong)
 *
 * This program runs in FrameVM Guest and acts as a pong server.
 * It receives ping messages from Host and sends back pong responses.
 *
 * Compile with -DPORT=<port> to set port (default: 20002)
 */

#include "syscalls.h"

// Default port if not specified at compile time
#ifndef PORT
#define PORT 20002
#endif

#define MSG_SIZE 1

static char buffer[MSG_SIZE];

void _start(void) {
    int port = PORT;

    print("\n========================================\n");
    print(" FrameVsock RTT Benchmark - Server\n");
    print("========================================\n");
    print(" Port:        ");
    print_number(port);
    print("\n");
    print(" Message:     ");
    print_number(MSG_SIZE);
    print(" byte(s)\n");
    print("----------------------------------------\n");

    // 1. Create socket
    int listen_fd = sys_socket(AF_FRAMEVSOCK, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        print(" ERROR: socket() failed\n");
        sys_exit(1);
    }

    // 2. Bind
    struct sockaddr_vm addr;
    addr.svm_family = AF_FRAMEVSOCK;
    addr.svm_reserved1 = 0;
    addr.svm_port = port;
    addr.svm_cid = VMADDR_CID_ANY;

    if (sys_bind(listen_fd, &addr, sizeof(addr)) < 0) {
        print(" ERROR: bind() failed\n");
        sys_exit(1);
    }

    // 3. Listen
    if (sys_listen(listen_fd, 1) < 0) {
        print(" ERROR: listen() failed\n");
        sys_exit(1);
    }

    print(" Listening on port ");
    print_number(port);
    print(" (AF_FRAMEVSOCK)...\n");

    // 4. Accept loop
    while (1) {
        print(" Waiting for connection...\n");

        int client_fd = sys_accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            print(" ERROR: accept() failed\n");
            continue;
        }

        print(" Connected!\n");
        print(" Running ping-pong...\n");

        uint64_t count = 0;
        while (1) {
            // Receive ping
            ssize_t n = sys_recvfrom(client_fd, buffer, MSG_SIZE, 0);
            if (n <= 0) break;

            // Send pong
            n = sys_sendto(client_fd, buffer, MSG_SIZE, 0);
            if (n <= 0) break;

            count++;
        }

        print(" Session ended.\n");
        print(" Total:       ");
        print_number(count);
        print(" ping-pongs\n");
        print("========================================\n");
        print("\n");

        sys_close(client_fd);
    }

    sys_close(listen_fd);
    sys_exit(0);
}
