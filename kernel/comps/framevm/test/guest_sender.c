/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * FrameVsock Throughput Benchmark (FrameVM Guest Sender)
 *
 * This program runs in FrameVM Guest and sends data to Asterinas Host.
 * Pairs with host_receiver on the Host side.
 *
 * Compile-time options:
 *   -DPORT=<port>              (default: 20001)
 *   -DBUF_SIZE=<bytes>         (default: 4096)
 *   -DTOTAL_BYTES=<bytes>      (default: 1GB)
 *   -DWARMUP_BYTES=<bytes>     (default: 64MB)
 */

#include "syscalls.h"

#ifndef PORT
#define PORT 20001
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 4096
#endif

#ifndef TOTAL_BYTES
#define TOTAL_BYTES (1024ULL * 1024 * 1024)
#endif

#ifndef WARMUP_BYTES
#define WARMUP_BYTES (64ULL * 1024 * 1024)
#endif

#ifndef CPU_MHZ
#define CPU_MHZ 2600
#endif

static uint8_t tx_buffer[BUF_SIZE];

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
    int sock_fd;
    ssize_t ret;
    uint64_t bytes_sent = 0;
    uint64_t warmup_bytes_actual = 0;
    uint64_t measured_bytes = 0;
    uint64_t start_cycles = 0, end_cycles, elapsed;
    int started = 0;

    print("\n========================================\n");
    print(" FrameVsock Throughput - Guest Sender\n");
    print("========================================\n");
    print(" Target:     CID ");
    print_number(VMADDR_CID_HOST);
    print(", Port ");
    print_number(PORT);
    print("\n");
    print(" Total:      ");
    print_number(TOTAL_BYTES);
    print(" bytes\n");
    print(" Warmup:     ");
    print_number(WARMUP_BYTES);
    print(" bytes\n");
    print(" TX Buffer:  ");
    print_number(BUF_SIZE);
    print(" bytes\n");
    print("----------------------------------------\n");

    /* Initialize buffer with pattern */
    for (size_t i = 0; i < BUF_SIZE; i++) {
        tx_buffer[i] = (uint8_t)(i & 0xFF);
    }

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
    print(" Connected!\n");

    /* Send data with warmup */
    print(" Sending data...\n");

    while (bytes_sent < TOTAL_BYTES) {
        size_t to_send = BUF_SIZE;
        if (TOTAL_BYTES - bytes_sent < BUF_SIZE) {
            to_send = (size_t)(TOTAL_BYTES - bytes_sent);
        }

        ret = sys_sendto(sock_fd, tx_buffer, to_send, 0);
        if (ret < 0) {
            print("ERROR: sendto() failed: ");
            print_number((uint64_t)(-ret));
            print("\n");
            break;
        }
        bytes_sent += (uint64_t)ret;

        /* Warmup phase: don't start timing until warmup complete */
        if (!started && bytes_sent >= WARMUP_BYTES) {
            start_cycles = rdtsc_fenced();
            warmup_bytes_actual = bytes_sent;
            started = 1;
        }
    }

    end_cycles = rdtsc_fenced();
    elapsed = started ? (end_cycles - start_cycles) : 0;
    measured_bytes = started ? (bytes_sent - warmup_bytes_actual) : 0;

    sys_close(sock_fd);

    /* Report results */
    print("----------------------------------------\n");
    print(" Results:\n");
    print("   Total bytes:    ");
    print_number(bytes_sent);
    print("\n");
    print("   Warmup bytes:   ");
    print_number(warmup_bytes_actual);
    print("\n");
    print("   Measured bytes: ");
    print_number(measured_bytes);
    print("\n");
    print("   Cycles:         ");
    print_number(elapsed);
    print("\n");

    if (elapsed > 0 && measured_bytes > 0) {
        /* Bytes per 1000 cycles */
        uint64_t bytes_per_kcycle = (measured_bytes * 1000) / elapsed;
        print("   Bytes/Kcycle:   ");
        print_number(bytes_per_kcycle);
        print("\n");

        /* Approximate Gbits/s using CPU_MHZ */
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
