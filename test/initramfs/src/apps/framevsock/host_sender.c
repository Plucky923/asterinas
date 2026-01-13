/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * FrameVsock Throughput Benchmark (Asterinas Host Sender)
 *
 * This program runs on Asterinas Host and sends data to FrameVM Guest.
 * Uses AF_FRAMEVSOCK (46) for FrameVsock communication.
 * Sends a specified total number of bytes using a given buffer size.
 *
 * Usage: ./host_sender <guest_cid> <total_bytes> <buf_size> [port]
 * Example: ./host_sender 3 104857600 1024 20001
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
// Note: svm_cid must be uint64_t to match kernel's CSocketAddrFrameVsock
struct sockaddr_vm {
    unsigned short svm_family;
    unsigned short svm_reserved1;
    unsigned int svm_port;
    unsigned long long svm_cid;  // 64-bit CID to match kernel definition
};

#define DEFAULT_PORT        20001
#define MAX_BUF_SIZE        (1024 * 1024)

static char tx_buffer[MAX_BUF_SIZE];

static double get_time_sec(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <guest_cid> <total_bytes> <buf_size> [port]\n", argv[0]);
        fprintf(stderr, "Example: %s 3 104857600 1024 20001\n", argv[0]);
        return 1;
    }

    int guest_cid = atoi(argv[1]);
    unsigned long long total_to_send = strtoull(argv[2], NULL, 10);
    size_t buf_size = (size_t)atol(argv[3]);
    int port = DEFAULT_PORT;
    if (argc > 4) {
        port = atoi(argv[4]);
    }

    if (buf_size == 0 || buf_size > MAX_BUF_SIZE) {
        fprintf(stderr, "Error: buf_size must be between 1 and %d\n", MAX_BUF_SIZE);
        return 1;
    }

    printf("\n========================================\n");
    printf(" FrameVsock Throughput Benchmark - Sender\n");
    printf("========================================\n");
    printf(" Target:      CID %d, Port %d\n", guest_cid, port);
    printf(" Total:       %llu bytes\n", total_to_send);
    printf(" TX Buffer:   %zu bytes\n", buf_size);
    printf("----------------------------------------\n");

    // Initialize buffer
    for (size_t i = 0; i < buf_size; i++) {
        tx_buffer[i] = (char)(i & 0xFF);
    }

    int fd = socket(AF_FRAMEVSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_vm addr = {
        .svm_family = AF_FRAMEVSOCK,
        .svm_reserved1 = 0,
        .svm_port = port,
        .svm_cid = guest_cid,
    };

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    unsigned long long bytes_sent = 0;
    double time_in_send = 0.0;
    double total_start = get_time_sec();

    while (bytes_sent < total_to_send) {
        size_t to_send = buf_size;
        if (total_to_send - bytes_sent < buf_size) {
            to_send = total_to_send - bytes_sent;
        }

        double send_start = get_time_sec();
        ssize_t ret = send(fd, tx_buffer, to_send, 0);
        double send_end = get_time_sec();

        if (ret < 0) {
            perror("send");
            close(fd);
            return 2;
        }
        bytes_sent += ret;
        time_in_send += (send_end - send_start);
    }

    double total_end = get_time_sec();
    double total_time = total_end - total_start;

    // Calculate throughput in Gbits/s
    double gbits = (bytes_sent * 8.0) / total_time / 1e9;

    printf("----------------------------------------\n");
    printf(" Results:\n");
    printf("   Bytes:       %llu\n", bytes_sent);
    printf("   Throughput:  %.6f Gbits/s\n", gbits);
    printf("   Time:        %.6f sec\n", total_time);
    printf("   Send Time:   %.6f sec\n", time_in_send);
    printf("========================================\n");
    printf("\n");

    close(fd);
    return 0;
}
