/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * Vsock Throughput Benchmark (Sender)
 *
 * This program sends data over traditional vsock (AF_VSOCK).
 * Can run on host or guest to test vsock communication.
 *
 * Usage: ./vsock_sender <target_cid> <total_bytes> <buf_size> [port]
 * Example: ./vsock_sender 3 104857600 1024 20001
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <linux/vm_sockets.h>

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
        fprintf(stderr, "Usage: %s <target_cid> <total_bytes> <buf_size> [port]\n", argv[0]);
        fprintf(stderr, "Example: %s 3 104857600 1024 20001\n", argv[0]);
        fprintf(stderr, "\nCommon CIDs:\n");
        fprintf(stderr, "  VMADDR_CID_HYPERVISOR = 0\n");
        fprintf(stderr, "  VMADDR_CID_LOCAL      = 1\n");
        fprintf(stderr, "  VMADDR_CID_HOST       = 2\n");
        fprintf(stderr, "  Guest CIDs            >= 3\n");
        return 1;
    }

    unsigned int target_cid = (unsigned int)atoi(argv[1]);
    unsigned long long total_to_send = strtoull(argv[2], NULL, 10);
    size_t buf_size = (size_t)atol(argv[3]);
    unsigned int port = DEFAULT_PORT;
    if (argc > 4) {
        port = (unsigned int)atoi(argv[4]);
    }

    if (buf_size == 0 || buf_size > MAX_BUF_SIZE) {
        fprintf(stderr, "Error: buf_size must be between 1 and %d\n", MAX_BUF_SIZE);
        return 1;
    }

    printf("\n========================================\n");
    printf(" Vsock Benchmark - Sender\n");
    printf("========================================\n");
    printf(" Target:      CID %u, Port %u\n", target_cid, port);
    printf(" Total:       %llu bytes\n", total_to_send);
    printf(" TX Buffer:   %zu bytes\n", buf_size);
    printf("----------------------------------------\n");

    // Initialize buffer with pattern
    for (size_t i = 0; i < buf_size; i++) {
        tx_buffer[i] = (char)(i & 0xFF);
    }

    // Create vsock socket
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    // Connect to target
    struct sockaddr_vm addr = {
        .svm_family = AF_VSOCK,
        .svm_reserved1 = 0,
        .svm_port = port,
        .svm_cid = target_cid,
    };

    printf(" Connecting to CID %u:%u...\n", target_cid, port);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    printf(" Connected! Sending data...\n");

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

    // Calculate throughput
    double gbits = (bytes_sent * 8.0) / total_time / 1e9;
    double mbs = (bytes_sent / total_time) / (1024.0 * 1024.0);

    printf("----------------------------------------\n");
    printf(" Results:\n");
    printf("   Bytes:      %llu\n", bytes_sent);
    printf("   Throughput: %.6f Gbits/s (%.2f MB/s)\n", gbits, mbs);
    printf("   Total Time: %.6f sec\n", total_time);
    printf("   Send Time:  %.6f sec\n", time_in_send);
    printf("========================================\n");

    close(fd);
    return 0;
}
