/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * FrameVsock Throughput Benchmark (Asterinas Host Receiver)
 *
 * This program runs on Asterinas Host and receives data from FrameVM Guest.
 * Uses AF_FRAMEVSOCK (46) for FrameVsock communication.
 *
 * Usage: ./host_receiver [port]
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

#define DEFAULT_PORT    20001
#define BUFFER_SIZE     (64 * 1024)

static char rx_buffer[BUFFER_SIZE];

static double get_time_sec(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    if (argc > 1) {
        port = atoi(argv[1]);
    }

    printf("\n========================================\n");
    printf(" FrameVsock Throughput Benchmark - Receiver\n");
    printf("========================================\n");
    printf(" Port:        %d\n", port);
    printf(" RX Buffer:   %d bytes\n", BUFFER_SIZE);
    printf("----------------------------------------\n");
    printf(" Listening...\n");

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
        return 1;
    }

    if (listen(listen_fd, 1) < 0) {
        perror("listen");
        return 1;
    }

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
        printf(" Receiving data...\n");

        unsigned long long total_bytes = 0;
        double start = get_time_sec();

        while (1) {
            ssize_t n = recv(client_fd, rx_buffer, BUFFER_SIZE, 0);
            if (n <= 0) break;
            total_bytes += n;
        }

        double end = get_time_sec();
        double duration = end - start;
        double gbits = 0;
        if (duration > 0) {
            gbits = (total_bytes * 8.0) / duration / 1e9;
        }

        printf("----------------------------------------\n");
        printf(" Results:\n");
        printf("   Bytes:       %llu\n", total_bytes);
        printf("   Throughput:  %.6f Gbits/s\n", gbits);
        printf("   Time:        %.6f sec\n", duration);
        printf("========================================\n");
        printf("\n");

        close(client_fd);
    }

    close(listen_fd);
    return 0;
}
