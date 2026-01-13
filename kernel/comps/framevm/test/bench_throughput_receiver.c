/*
 * FrameVsock Throughput Benchmark (Guest Receiver)
 * 
 * Binds to port 20001 and receives data, measuring performance.
 * Compile with -DBUF_SIZE=<size> to set buffer size (default: 1024)
 */

#include "syscalls.h"

#define SERVER_PORT     20001
#define VSOCK_BUF_SIZE  262144

// Default buffer size if not specified at compile time
#ifndef BUF_SIZE
#define BUF_SIZE 1024
#endif

static char rx_buffer[1024 * 1024];  // Max 1MB buffer

// Print number with leading zeros to ensure fixed width
static void print_padded(uint64_t n, int width) {
    char buf[32];
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

void _start(void) {
    size_t buf_size = BUF_SIZE;

    print("\n========================================\n");
    print(" FrameVsock Throughput Benchmark - Receiver\n");
    print("========================================\n");
    print(" Port:        ");
    print_number(SERVER_PORT);
    print("\n");
    print(" RX Buffer:   ");
    print_number(buf_size);
    print(" bytes\n");
    print("----------------------------------------\n");
    print(" Waiting for connection...\n");

    // 1. Create socket
    int listen_fd = sys_socket(AF_FRAMEVSOCK, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        print(" ERROR: socket() failed\n");
        sys_exit(1);
    }

    // 2. Bind
    struct sockaddr_vm addr;
    addr.svm_family = AF_FRAMEVSOCK;
    addr.svm_reserved1 = 0;
    addr.svm_port = SERVER_PORT;
    addr.svm_cid = VMADDR_CID_ANY;

    if (sys_bind(listen_fd, &addr, sizeof(addr)) < 0) {
        print(" ERROR: bind() failed\n");
        sys_exit(1);
    }

    // 3. Listen
    if (sys_listen(listen_fd, 1) < 0) {
        print(" ERROR: listen() failed\n");
        sys_exit(1);
    }

    // 4. Accept
    int client_fd = sys_accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        print(" ERROR: accept() failed\n");
        sys_exit(1);
    }

    print(" Connected!\n");
    print(" Receiving data...\n");

    // 5. Receive Data
    uint64_t total_bytes = 0;
    uint64_t read_count = 0;
    uint64_t time_in_read_ns = 0;

    while (1) {
        uint64_t read_start = get_time_ns();
        ssize_t n = sys_recvfrom(client_fd, rx_buffer, buf_size, 0);
        uint64_t read_end = get_time_ns();

        if (n <= 0) break; // Closed
        
        total_bytes += n;
        read_count++;
        time_in_read_ns += (read_end - read_start);
    }
    
    // Calculate throughput in Gbits/s
    uint64_t gbits_micro = 0;
    uint64_t avg_read_ns = 0;
    if (time_in_read_ns > 0) {
        gbits_micro = (total_bytes * 8ULL * 1000000ULL) / time_in_read_ns;
        avg_read_ns = time_in_read_ns / read_count;
    }

    // Convert ns to sec with 6 decimal places
    uint64_t read_sec_int = time_in_read_ns / 1000000000ULL;
    uint64_t read_sec_frac = (time_in_read_ns % 1000000000ULL) / 1000;

    print("----------------------------------------\n");
    print(" Results:\n");
    print("   Bytes:       ");
    print_number(total_bytes);
    print("\n");

    print("   Throughput:  ");
    print_number(gbits_micro / 1000000);
    print(".");
    print_padded(gbits_micro % 1000000, 6);
    print(" Gbits/s\n");

    print("   Time:        ");
    print_number(read_sec_int);
    print(".");
    print_padded(read_sec_frac, 6);
    print(" sec\n");

    print("   Avg Read:    ");
    print_number(avg_read_ns);
    print(" ns\n");
    print("========================================\n");
    print("\n");

    sys_close(client_fd);
    sys_close(listen_fd);
    sys_exit(0);
}
