/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * FrameVsock Multi-Process Throughput Benchmark (FrameVM Guest Receiver)
 *
 * This program runs in FrameVM Guest and receives data from Asterinas Host.
 * It accepts PROCESSES connections on the same port, then forks one child per
 * connection to receive data concurrently.
 *
 * Compile-time options:
 *   -DPORT=<port>              (default: 20001)
 *   -DBUF_SIZE=<bytes>         (default: 65536)
 *   -DMAX_BUF_SIZE=<bytes>     (default: 1MB)
 *   -DPROCESSES=<count>        (default: 4)
 *   -DBYTES_PER_CONN=<bytes>   (default: 1GB)
 *   -DWARMUP_BYTES=<bytes>     (default: 0)
 *   -DCPU_MHZ=<mhz>            (default: 2600)
 */

#include "syscalls.h"

#ifndef PORT
#define PORT 20001
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 65536
#endif

#ifndef MAX_BUF_SIZE
#define MAX_BUF_SIZE (1024 * 1024)
#endif

#ifndef PROCESSES
#define PROCESSES 4
#endif

#ifndef BYTES_PER_CONN
#define BYTES_PER_CONN (1024ULL * 1024 * 1024)
#endif

#ifndef WARMUP_BYTES
#define WARMUP_BYTES 0
#endif

#ifndef CPU_MHZ
#define CPU_MHZ 2600
#endif

#if BUF_SIZE > MAX_BUF_SIZE
#error "BUF_SIZE must be <= MAX_BUF_SIZE"
#endif

/*
 * sys_fork() is implemented with CLONE_VM semantics in FrameVM, so children
 * share one address space. Give each child a dedicated RX buffer region to
 * avoid concurrent recv writes to the same user pages.
 */
static uint8_t rx_buffers[PROCESSES][MAX_BUF_SIZE];

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtsc_fenced(void) {
    asm volatile ("lfence" ::: "memory");
    return rdtsc();
}

#ifndef EAGAIN
#define EAGAIN 11
#endif

static volatile uint64_t total_measured_bytes = 0;
static volatile uint64_t first_start_cycles = 0;
static volatile uint64_t last_end_cycles = 0;

static inline void add_measured_bytes(uint64_t bytes) {
    __atomic_fetch_add(&total_measured_bytes, bytes, __ATOMIC_RELAXED);
}

static inline void record_start_cycle(void) {
    uint64_t now = rdtsc_fenced();
    uint64_t expected = 0;
    __atomic_compare_exchange_n(
        &first_start_cycles, &expected, now, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
}

static inline void record_end_cycle(void) {
    uint64_t now = rdtsc_fenced();
    uint64_t prev = __atomic_load_n(&last_end_cycles, __ATOMIC_RELAXED);
    while (now > prev &&
           !__atomic_compare_exchange_n(
               &last_end_cycles, &prev, now, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
    }
}

static void child_receiver(int fd, int child_id) {
    uint8_t *rx_buffer = rx_buffers[(child_id >= 0 && child_id < PROCESSES) ? child_id : 0];
    uint64_t total_bytes = 0;
    uint64_t measured_bytes = 0;
    uint64_t warmup_left = WARMUP_BYTES;

    while (1) {
        ssize_t n = sys_recvfrom(fd, rx_buffer, BUF_SIZE, 0);
        if (n < 0) {
            if ((-n) == EAGAIN) {
                continue;
            }
            print("Child ");
            print_number((uint64_t)child_id);
            print(" recv error: ");
            print_number((uint64_t)(-n));
            print("\n");
            break;
        }
        if (n <= 0) {
            break;
        }
        if (total_bytes == 0) {
            record_start_cycle();
        }
        total_bytes += (uint64_t)n;
        if (warmup_left > 0) {
            if ((uint64_t)n >= warmup_left) {
                measured_bytes += (uint64_t)n - warmup_left;
                warmup_left = 0;
            } else {
                warmup_left -= (uint64_t)n;
            }
        } else {
            measured_bytes += (uint64_t)n;
        }
    }

    print("Child ");
    print_number((uint64_t)child_id);
    print(": ");
    print_number(total_bytes);
    print(" bytes (measured: ");
    print_number(measured_bytes);
    print(")\n");

    add_measured_bytes(measured_bytes);
    record_end_cycle();
    sys_close(fd);
    sys_exit(0);
}

void _start(void) {
    int server_fd;
    int accepted = 0;

    print("\n========================================\n");
    print(" FrameVsock Multi-Process Receiver\n");
    print("========================================\n");
    print(" Port:       ");
    print_number(PORT);
    print("\n");
    print(" Processes:  ");
    print_number(PROCESSES);
    print("\n");
    print(" RX Buffer:  ");
    print_number(BUF_SIZE);
    print(" bytes\n");
    print(" Per Conn:   ");
    print_number(BYTES_PER_CONN);
    print(" bytes\n");
    if (WARMUP_BYTES > 0) {
        print(" Warmup:     ");
        print_number(WARMUP_BYTES);
        print(" bytes\n");
    }
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
    err = sys_listen(server_fd, PROCESSES);
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

    for (int i = 0; i < PROCESSES; i++) {
        struct sockaddr_vm peer_addr;
        int peer_len = sizeof(peer_addr);
        int conn_fd = sys_accept(server_fd, &peer_addr, &peer_len);
        if (conn_fd < 0) {
            print("ERROR: accept() failed: ");
            print_number((uint64_t)(-conn_fd));
            print("\n");
            if ((-conn_fd) == EAGAIN) {
                continue;
            }
            break;
        }

        print(" Accepted #");
        print_number((uint64_t)i);
        print(" from CID ");
        print_number((uint64_t)peer_addr.svm_cid);
        print(", port ");
        print_number((uint64_t)peer_addr.svm_port);
        print("\n");

        long pid = sys_fork();
        if (pid == 0) {
            sys_close(server_fd);
            print(" Child ");
            print_number((uint64_t)i);
            print(" started\n");
            child_receiver(conn_fd, i);
        } else if (pid > 0) {
            accepted++;
            print(" Parent forked child #");
            print_number((uint64_t)i);
            print(", pid ");
            print_number((uint64_t)pid);
            print("\n");
            sys_close(conn_fd);
        } else {
            print("ERROR: fork() failed: ");
            print_number((uint64_t)(-pid));
            print("\n");
            sys_close(conn_fd);
            break;
        }
    }

    sys_close(server_fd);

    for (int i = 0; i < accepted; i++) {
        sys_wait4(-1, NULL, 0, NULL);
    }

    uint64_t start_cycles = __atomic_load_n(&first_start_cycles, __ATOMIC_RELAXED);
    uint64_t end_cycles = __atomic_load_n(&last_end_cycles, __ATOMIC_RELAXED);

    print("----------------------------------------\n");
    print(" Results:\n");
    print("   Accepted:    ");
    print_number((uint64_t)accepted);
    print("\n");

    if (accepted > 0 && end_cycles > start_cycles) {
        uint64_t total_bytes = total_measured_bytes;
        uint64_t measured_bytes = total_measured_bytes;
        uint64_t elapsed = end_cycles - start_cycles;

        print("   Total bytes: ");
        print_number(total_bytes);
        print("\n");
        print("   Measured:    ");
        print_number(measured_bytes);
        print("\n");
        print("   Cycles:      ");
        print_number(elapsed);
        print("\n");

        if (measured_bytes > 0) {
            uint64_t bytes_per_kcycle = (measured_bytes * 1000) / elapsed;
            print("   Bytes/Kcycle:");
            print_number(bytes_per_kcycle);
            print("\n");

            uint64_t gbits_x1000 =
                (measured_bytes * 8ULL * (uint64_t)CPU_MHZ) / elapsed;
            print("   ~Gbits/s:    ");
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
    }

    print("========================================\n\n");
    sys_exit(0);
}
