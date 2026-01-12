/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * FrameVsock Throughput Benchmark (FrameVM Guest Receiver)
 *
 * This program runs in FrameVM Guest and receives data from Asterinas Host.
 * Pairs with host_sender on the Host side.
 *
 * Compile-time options:
 *   -DPORT=<port>              (default: 20001)
 *   -DBUF_SIZE=<bytes>         (default: 4096)
 *   -DWARMUP_BYTES=<bytes>     (default: 64MB)
 */

#include "syscalls.h"

#ifndef PORT
#define PORT 20001
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 4096
#endif

#ifndef CPU_MHZ
#define CPU_MHZ 2600
#endif

#ifndef WARMUP_BYTES
#define WARMUP_BYTES (64ULL * 1024 * 1024)
#endif

static uint8_t rx_buffer[BUF_SIZE];

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtsc_fenced(void) {
    asm volatile ("lfence" ::: "memory");
    return rdtsc();
}

void _start(void) {
    int server_fd, client_fd;
    ssize_t n;
    uint64_t total_bytes = 0;
    uint64_t warmup_bytes_actual = 0;
    uint64_t measured_bytes = 0;
    uint64_t read_count = 0;
    uint64_t start_cycles = 0, end_cycles, elapsed;
    int started = 0;

    print("\n========================================\n");
    print(" FrameVsock Throughput - Guest Receiver\n");
    print("========================================\n");
    print(" Port:       ");
    print_number(PORT);
    print("\n");
    print(" RX Buffer:  ");
    print_number(BUF_SIZE);
    print(" bytes\n");
    print(" Warmup:     ");
    print_number(WARMUP_BYTES);
    print(" bytes\n");
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
    print(" Receiving data...\n");

    /* Receive loop with warmup */
    while (1) {
        n = sys_recvfrom(client_fd, rx_buffer, BUF_SIZE, 0);
        if (n <= 0) {
            break;
        }

        total_bytes += (uint64_t)n;
        read_count++;

        /* Warmup phase: don't start timing until warmup complete */
        if (!started && total_bytes >= WARMUP_BYTES) {
            start_cycles = rdtsc_fenced();
            warmup_bytes_actual = total_bytes;
            started = 1;
        }
    }

    end_cycles = rdtsc_fenced();
    elapsed = started ? (end_cycles - start_cycles) : 0;
    measured_bytes = started ? (total_bytes - warmup_bytes_actual) : 0;

    sys_close(client_fd);
    sys_close(server_fd);

    /* Report results */
    print("----------------------------------------\n");
    print(" Results:\n");
    print("   Total bytes:    ");
    print_number(total_bytes);
    print("\n");
    print("   Warmup bytes:   ");
    print_number(warmup_bytes_actual);
    print("\n");
    print("   Measured bytes: ");
    print_number(measured_bytes);
    print("\n");
    print("   Read calls:     ");
    print_number(read_count);
    print("\n");
    print("   Cycles:         ");
    print_number(elapsed);
    print("\n");

    if (elapsed > 0 && measured_bytes > 0) {
        uint64_t bytes_per_kcycle = (measured_bytes * 1000) / elapsed;
        print("   Bytes/Kcycle:   ");
        print_number(bytes_per_kcycle);
        print("\n");

        uint64_t gbits_x1000 = (measured_bytes * 8ULL * (uint64_t)CPU_MHZ) / elapsed;
        print("   ~Gbits/s:       ");
        print_number(gbits_x1000 / 1000);
        print(".");
        print_number((gbits_x1000 % 1000) / 100);
        print_number((gbits_x1000 % 100) / 10);
        print_number(gbits_x1000 % 10);
        print(" (@");
        print_number((uint64_t)CPU_MHZ / 1000);
        print(".");
        uint64_t ghz_frac = ((uint64_t)CPU_MHZ % 1000) / 10;
        if (ghz_frac < 10) {
            print("0");
        }
        print_number(ghz_frac);
        print("GHz)\n");
    }
    print("========================================\n\n");

    sys_exit(0);
}
