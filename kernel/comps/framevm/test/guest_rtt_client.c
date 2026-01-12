/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * FrameVsock RTT Benchmark (FrameVM Guest Client / Ping)
 *
 * This program runs in FrameVM Guest and measures round-trip latency to Host.
 * Pairs with host_rtt_server on the Host side.
 *
 * Compile-time options:
 *   -DPORT=<port>              (default: 20002)
 *   -DITERATIONS=<count>       (default: 100000)
 */

#include "syscalls.h"

#ifndef PORT
#define PORT 20002
#endif

#ifndef ITERATIONS
#define ITERATIONS 100000
#endif

#ifndef MSG_SIZE
#define MSG_SIZE 4
#endif

#if ITERATIONS > 100000
#define MAX_SAMPLES 100000
#else
#define MAX_SAMPLES ITERATIONS
#endif

static uint64_t rtt_samples[MAX_SAMPLES];
static char buffer[MSG_SIZE];

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtsc_fenced(void) {
    asm volatile ("lfence" ::: "memory");
    return rdtsc();
}

/* Insertion sort for percentile calculation */
static void sort_samples(uint64_t *arr, uint64_t n) {
    for (uint64_t i = 1; i < n; i++) {
        uint64_t key = arr[i];
        uint64_t j = i;
        while (j > 0 && arr[j - 1] > key) {
            arr[j] = arr[j - 1];
            j--;
        }
        arr[j] = key;
    }
}

void _start(void) {
    int sock_fd;
    uint64_t completed = 0;
    uint64_t total_cycles = 0;
    uint64_t min_cycles = (uint64_t)-1;
    uint64_t max_cycles = 0;

    print("\n========================================\n");
    print(" FrameVsock RTT Benchmark - Guest Client\n");
    print("========================================\n");
    print(" Target:     CID ");
    print_number(VMADDR_CID_HOST);
    print(", Port ");
    print_number(PORT);
    print("\n");
    print(" Iterations: ");
    print_number(ITERATIONS);
    print("\n");
    print(" Message:    ");
    print_number(MSG_SIZE);
    print(" byte(s)\n");
    print("----------------------------------------\n");

    /* Initialize buffer */
    buffer[0] = 'P';

    /* Create socket */
    sock_fd = sys_socket(AF_FRAMEVSOCK, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        print("ERROR: socket() failed: ");
        print_number((uint64_t)(-sock_fd));
        print("\n");
        sys_exit(1);
    }

    /* Connect to Host */
    struct sockaddr_vm addr;
    addr.svm_family = AF_FRAMEVSOCK;
    addr.svm_reserved1 = 0;
    addr.svm_port = PORT;
    addr.svm_cid = VMADDR_CID_HOST;

    print(" Connecting to Host...\n");
    int err = sys_connect(sock_fd, &addr, sizeof(addr));
    if (err < 0) {
        print("ERROR: connect() failed: ");
        print_number((uint64_t)(-err));
        print("\n");
        sys_close(sock_fd);
        sys_exit(1);
    }
    print(" Connected! Running ping-pong...\n");

    /* RTT measurement loop */
    for (uint64_t i = 0; i < ITERATIONS; i++) {
        uint64_t start = rdtsc_fenced();

        /* Send ping */
        ssize_t sent = sys_sendto(sock_fd, buffer, MSG_SIZE, 0);
        if (sent != MSG_SIZE) {
            continue;
        }

        /* Receive pong */
        ssize_t recv = sys_recvfrom(sock_fd, buffer, MSG_SIZE, 0);
        if (recv != MSG_SIZE) {
            continue;
        }

        uint64_t end = rdtsc_fenced();
        uint64_t rtt = end - start;

        if (completed < MAX_SAMPLES) {
            rtt_samples[completed] = rtt;
        }

        total_cycles += rtt;
        if (rtt < min_cycles) min_cycles = rtt;
        if (rtt > max_cycles) max_cycles = rtt;
        completed++;
    }

    sys_close(sock_fd);

    /* Calculate and report statistics */
    print("----------------------------------------\n");
    print(" Statistics (");
    print_number(completed);
    print(" samples):\n");
    print("----------------------------------------\n");

    if (completed > 0) {
        uint64_t avg_cycles = total_cycles / completed;

        /* Sort for percentiles */
        uint64_t sample_count = (completed < MAX_SAMPLES) ? completed : MAX_SAMPLES;
        sort_samples(rtt_samples, sample_count);

        uint64_t p50 = rtt_samples[sample_count / 2];
        uint64_t p90 = rtt_samples[(sample_count * 90) / 100];
        uint64_t p99 = rtt_samples[(sample_count * 99) / 100];
        uint64_t p999 = rtt_samples[(sample_count * 999) / 1000];

        print("   Min:      ");
        print_number(min_cycles);
        print(" cycles\n");
        print("   Max:      ");
        print_number(max_cycles);
        print(" cycles\n");
        print("   Avg:      ");
        print_number(avg_cycles);
        print(" cycles\n");
        print("   P50:      ");
        print_number(p50);
        print(" cycles\n");
        print("   P90:      ");
        print_number(p90);
        print(" cycles\n");
        print("   P99:      ");
        print_number(p99);
        print(" cycles\n");
        print("   P99.9:    ");
        print_number(p999);
        print(" cycles\n");

        /* Convert to microseconds assuming 2.5 GHz */
        /* us = cycles / 2500 */
        print("----------------------------------------\n");
        print(" Latency (@2.5GHz):\n");
        uint64_t min_us_x10 = (min_cycles * 10) / 2500;
        uint64_t avg_us_x10 = (avg_cycles * 10) / 2500;
        uint64_t p50_us_x10 = (p50 * 10) / 2500;
        uint64_t p99_us_x10 = (p99 * 10) / 2500;

        print("   Min:      ");
        print_number(min_us_x10 / 10);
        print(".");
        print_number(min_us_x10 % 10);
        print(" us\n");
        print("   Avg:      ");
        print_number(avg_us_x10 / 10);
        print(".");
        print_number(avg_us_x10 % 10);
        print(" us\n");
        print("   P50:      ");
        print_number(p50_us_x10 / 10);
        print(".");
        print_number(p50_us_x10 % 10);
        print(" us\n");
        print("   P99:      ");
        print_number(p99_us_x10 / 10);
        print(".");
        print_number(p99_us_x10 % 10);
        print(" us\n");
    }
    print("========================================\n\n");

    sys_exit(0);
}
