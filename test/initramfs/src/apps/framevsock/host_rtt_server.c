/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * FrameVsock RTT Benchmark (Asterinas Host Server / Pong)
 *
 * This program runs on Asterinas Host and acts as a pong server.
 * It receives ping messages from FrameVM Guest and sends back pong responses.
 *
 * Usage: ./host_rtt_server [port]
 * Example: ./host_rtt_server 20002
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>

// FrameVsock constants (not in standard headers)
#define AF_FRAMEVSOCK       46
#define VMADDR_CID_ANY      (-1U)
#define VMADDR_CID_HOST     2

// sockaddr_vm structure for FrameVsock
struct sockaddr_vm {
    unsigned short svm_family;
    unsigned short svm_reserved1;
    unsigned int svm_port;
    unsigned int svm_cid;
    unsigned char svm_zero[4];
};

#define DEFAULT_PORT    20002
#define MSG_SIZE        1

static char buffer[MSG_SIZE];

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    printf("\n========================================\n");
    printf(" FrameVsock RTT Benchmark - Server\n");
    printf("========================================\n");
    printf(" Port:        %d\n", port);
    printf(" Message:     %d byte(s)\n", MSG_SIZE);
    printf("----------------------------------------\n");

    int listen_fd = socket(AF_FRAMEVSOCK, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_vm addr = {
        .svm_family = AF_FRAMEVSOCK,
        .svm_reserved1 = 0,
        .svm_port = port,
        .svm_cid = VMADDR_CID_ANY,
    };

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 1) < 0) {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    printf(" Listening on port %d (AF_FRAMEVSOCK)...\n", port);

    while (1) {
        struct sockaddr_vm peer_addr;
        socklen_t peer_len = sizeof(peer_addr);

        printf(" Waiting for connection...\n");

        int client_fd = accept(listen_fd, (struct sockaddr *)&peer_addr, &peer_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        printf(" Connection from CID %u, port %u\n",
               peer_addr.svm_cid, peer_addr.svm_port);
        printf(" Running ping-pong...\n");

        unsigned long long count = 0;
        while (1) {
            // Receive ping
            ssize_t n = recv(client_fd, buffer, MSG_SIZE, 0);
            if (n <= 0) break;

            // Send pong
            n = send(client_fd, buffer, MSG_SIZE, 0);
            if (n <= 0) break;

            count++;
        }

        printf(" Session ended.\n");
        printf(" Total:       %llu ping-pongs\n", count);
        printf("========================================\n");
        printf("\n");

        close(client_fd);
    }

    close(listen_fd);
    return 0;
}
