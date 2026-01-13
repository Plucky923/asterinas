/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * Vsock RTT Benchmark (Client / Ping)
 *
 * This program measures vsock round-trip latency using ping-pong pattern.
 * Records 10000 RTT samples, sorts them, and outputs statistics.
 *
 * Usage: ./vsock_rtt_client <target_cid> [port] [iterations]
 * Example: ./vsock_rtt_client 2 20002 10000
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <time.h>
#include <errno.h>
#include <linux/vm_sockets.h>

#define DEFAULT_PORT       20002
#define DEFAULT_ITERATIONS 10000
#define MAX_ITERATIONS     100000
#define MSG_SIZE           1

static double *rtt_samples = NULL;

static double get_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000.0 + ts.tv_nsec / 1000.0;
}

static int compare_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

static void print_statistics(double *samples, int count) {
    // Sort samples
    qsort(samples, count, sizeof(double), compare_double);

    // Calculate statistics
    double sum = 0;
    for (int i = 0; i < count; i++) {
        sum += samples[i];
    }
    double avg = sum / count;

    double min = samples[0];
    double max = samples[count - 1];
    double p50 = samples[count / 2];
    double p90 = samples[(int)(count * 0.90)];
    double p99 = samples[(int)(count * 0.99)];
    double p999 = samples[(int)(count * 0.999)];

    printf("----------------------------------------\n");
    printf(" Statistics (%d samples):\n", count);
    printf("----------------------------------------\n");
    printf("   Min:    %10.3f us\n", min);
    printf("   Max:    %10.3f us\n", max);
    printf("   Avg:    %10.3f us\n", avg);
    printf("   P50:    %10.3f us\n", p50);
    printf("   P90:    %10.3f us\n", p90);
    printf("   P99:    %10.3f us\n", p99);
    printf("   P99.9:  %10.3f us\n", p999);
    printf("----------------------------------------\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target_cid> [port] [iterations]\n", argv[0]);
        fprintf(stderr, "Example: %s 2 20002 10000\n", argv[0]);
        return 1;
    }

    unsigned int target_cid = (unsigned int)atoi(argv[1]);
    unsigned int port = DEFAULT_PORT;
    int iterations = DEFAULT_ITERATIONS;

    if (argc > 2) {
        port = (unsigned int)atoi(argv[2]);
    }
    if (argc > 3) {
        iterations = atoi(argv[3]);
        if (iterations <= 0 || iterations > MAX_ITERATIONS) {
            fprintf(stderr, "Error: iterations must be between 1 and %d\n", MAX_ITERATIONS);
            return 1;
        }
    }

    // Allocate RTT samples array
    rtt_samples = malloc(iterations * sizeof(double));
    if (!rtt_samples) {
        perror("malloc");
        return 1;
    }

    printf("\n========================================\n");
    printf(" Vsock RTT Benchmark - Client (Ping)\n");
    printf("========================================\n");
    printf(" Target:     CID %u, Port %u\n", target_cid, port);
    printf(" Iterations: %d\n", iterations);
    printf(" Message:    %d byte(s)\n", MSG_SIZE);
    printf("----------------------------------------\n");

    // Create vsock socket
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        free(rtt_samples);
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
        free(rtt_samples);
        return 1;
    }

    printf(" Connected! Running %d ping-pong iterations...\n", iterations);

    char buf[MSG_SIZE];
    buf[0] = 'P';

    for (int i = 0; i < iterations; i++) {
        double start = get_time_us();

        // Send ping
        if (send(fd, buf, MSG_SIZE, 0) != MSG_SIZE) {
            perror("send");
            break;
        }

        // Receive pong
        if (recv(fd, buf, MSG_SIZE, 0) != MSG_SIZE) {
            perror("recv");
            break;
        }

        double end = get_time_us();
        rtt_samples[i] = end - start;
    }

    close(fd);

    print_statistics(rtt_samples, iterations);
    printf("\n");

    free(rtt_samples);
    return 0;
}
