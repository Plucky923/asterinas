/*
 * FrameVsock RTT Benchmark (Guest Client / Ping)
 *
 * This program runs in FrameVM Guest and measures FrameVsock round-trip latency.
 * Connects to Host and performs ping-pong iterations.
 *
 * Compile with -DITERATIONS=<count> to set iteration count (default: 10000)
 * Compile with -DPORT=<port> to set port (default: 20002)
 */

#include "syscalls.h"

#define HOST_CID        2

// Default values if not specified at compile time
#ifndef ITERATIONS
#define ITERATIONS 10000
#endif

#ifndef PORT
#define PORT 20002
#endif

#define MSG_SIZE        1
#define MAX_ITERATIONS  100000

// RTT samples array (in .bss to avoid stack overflow)
static uint64_t rtt_samples[MAX_ITERATIONS];

// Print number with leading zeros to ensure fixed width
static void print_padded(uint64_t n, int width) {
    int len = 0;
    uint64_t tmp = n;
    if (n == 0) len = 1;
    else {
        while (tmp > 0) { len++; tmp /= 10; }
    }
    for (int i = len; i < width; i++) print("0");
    if (n > 0) print_number(n);
    else print("0");
}

// Simple bubble sort for percentile calculation
static void sort_samples(uint64_t *arr, int count) {
    for (int i = 0; i < count - 1; i++) {
        for (int j = 0; j < count - i - 1; j++) {
            if (arr[j] > arr[j + 1]) {
                uint64_t temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}

void _start(void) {
    int iterations = ITERATIONS;
    int port = PORT;

    if (iterations > MAX_ITERATIONS) {
        print("ERROR: iterations exceeds MAX_ITERATIONS\n");
        sys_exit(1);
    }

    print("\n========================================\n");
    print(" FrameVsock RTT Benchmark - Client\n");
    print("========================================\n");
    print(" Target:      CID ");
    print_number(HOST_CID);
    print(", Port ");
    print_number(port);
    print("\n");
    print(" Iterations:  ");
    print_number(iterations);
    print("\n");
    print(" Message:     ");
    print_number(MSG_SIZE);
    print(" byte(s)\n");
    print("----------------------------------------\n");

    // 1. Create socket
    int fd = sys_socket(AF_FRAMEVSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        print(" ERROR: socket() failed\n");
        sys_exit(1);
    }

    // 2. Connect
    struct sockaddr_vm addr;
    addr.svm_family = AF_FRAMEVSOCK;
    addr.svm_reserved1 = 0;
    addr.svm_port = port;
    addr.svm_cid = HOST_CID;

    print(" Connecting to CID ");
    print_number(HOST_CID);
    print(":");
    print_number(port);
    print("...\n");

    if (sys_connect(fd, &addr, sizeof(addr)) < 0) {
        print(" ERROR: connect() failed\n");
        sys_exit(1);
    }

    print(" Connected! Running ");
    print_number(iterations);
    print(" ping-pong iterations...\n");

    // 3. Perform RTT measurements
    char buf[MSG_SIZE];
    buf[0] = 'P';

    uint64_t total_rtt = 0;
    uint64_t min_rtt = (uint64_t)-1;
    uint64_t max_rtt = 0;

    for (int i = 0; i < iterations; i++) {
        uint64_t start = get_time_ns();

        // Send ping
        if (sys_sendto(fd, buf, MSG_SIZE, 0) != MSG_SIZE) {
            print(" ERROR: send() failed\n");
            break;
        }

        // Receive pong
        if (sys_recvfrom(fd, buf, MSG_SIZE, 0) != MSG_SIZE) {
            print(" ERROR: recv() failed\n");
            break;
        }

        uint64_t end = get_time_ns();
        uint64_t rtt_ns = end - start;

        // Convert to microseconds
        uint64_t rtt_us = rtt_ns / 1000;
        rtt_samples[i] = rtt_us;
        total_rtt += rtt_us;

        if (rtt_us < min_rtt) min_rtt = rtt_us;
        if (rtt_us > max_rtt) max_rtt = rtt_us;
    }

    sys_close(fd);

    // 4. Calculate statistics
    uint64_t avg_rtt = total_rtt / iterations;

    // Sort for percentiles
    sort_samples(rtt_samples, iterations);

    uint64_t p50 = rtt_samples[iterations / 2];
    uint64_t p90 = rtt_samples[(int)(iterations * 0.90)];
    uint64_t p99 = rtt_samples[(int)(iterations * 0.99)];
    uint64_t p999 = rtt_samples[(int)(iterations * 0.999)];

    // 5. Print results
    print("----------------------------------------\n");
    print(" Statistics (");
    print_number(iterations);
    print(" samples):\n");
    print("----------------------------------------\n");

    print("   Min:       ");
    print_number(min_rtt / 1000);
    print(".");
    print_padded(min_rtt % 1000, 3);
    print(" us\n");

    print("   Max:       ");
    print_number(max_rtt / 1000);
    print(".");
    print_padded(max_rtt % 1000, 3);
    print(" us\n");

    print("   Avg:       ");
    print_number(avg_rtt / 1000);
    print(".");
    print_padded(avg_rtt % 1000, 3);
    print(" us\n");

    print("   P50:       ");
    print_number(p50 / 1000);
    print(".");
    print_padded(p50 % 1000, 3);
    print(" us\n");

    print("   P90:       ");
    print_number(p90 / 1000);
    print(".");
    print_padded(p90 % 1000, 3);
    print(" us\n");

    print("   P99:       ");
    print_number(p99 / 1000);
    print(".");
    print_padded(p99 % 1000, 3);
    print(" us\n");

    print("   P99.9:     ");
    print_number(p999 / 1000);
    print(".");
    print_padded(p999 % 1000, 3);
    print(" us\n");

    print("========================================\n");
    print("\n");

    sys_exit(0);
}
