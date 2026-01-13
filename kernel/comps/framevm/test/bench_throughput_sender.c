/*
 * FrameVsock Throughput Benchmark (Guest Sender)
 * 
 * Sends a specified total number of bytes using a given buffer size.
 * Compile with -DTOTAL_BYTES=<bytes> and -DBUF_SIZE=<size> to configure.
 * Default: TOTAL_BYTES=104857600 (100MB), BUF_SIZE=1024
 */

#include "syscalls.h"

#define SERVER_PORT     20001
#define HOST_CID        2

// Default values if not specified at compile time
#ifndef TOTAL_BYTES
#define TOTAL_BYTES 104857600ULL  // 100MB
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 1024
#endif

// 1MB test buffer (in .bss to avoid stack overflow)
static char test_buffer[1024 * 1024];

void _start(void) {
    uint64_t total_to_send = TOTAL_BYTES;
    size_t buf_size = BUF_SIZE;
    
    print("\nRun as sender\n");
    print("Connect to ");
    print_number(HOST_CID);
    print(":");
    print_number(SERVER_PORT);
    print("\n");
    print("Send ");
    print_number(total_to_send);
    print(" bytes\n");
    print("TX buffer ");
    print_number(buf_size);
    print(" bytes\n");

    // Initialize buffer
    for (size_t i = 0; i < buf_size; i++) {
        test_buffer[i] = (char)(i & 0xFF);
    }

    // 1. Create socket
    int fd = sys_socket(AF_FRAMEVSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        print("ERROR: socket\n");
        sys_exit(1);
    }

    // 2. Connect
    struct sockaddr_vm addr;
    addr.svm_family = AF_FRAMEVSOCK;
    addr.svm_reserved1 = 0;
    addr.svm_port = SERVER_PORT;
    addr.svm_cid = HOST_CID;

    if (sys_connect(fd, &addr, sizeof(addr)) < 0) {
        print("ERROR: connect\n");
        sys_exit(1);
    }

    // 3. Send data
    uint64_t bytes_sent = 0;
    uint64_t time_in_send_ns = 0;
    uint64_t total_start = get_time_ns();
    
    while (bytes_sent < total_to_send) {
        size_t to_send = buf_size;
        if (total_to_send - bytes_sent < buf_size) {
            to_send = total_to_send - bytes_sent;
        }

        uint64_t send_start = get_time_ns();
        ssize_t ret = sys_sendto(fd, test_buffer, to_send, 0);
        uint64_t send_end = get_time_ns();

        if (ret < 0) {
            print("ERROR: send failed\n");
            sys_exit(2);
        }
        bytes_sent += ret;
        time_in_send_ns += (send_end - send_start);
    }
    
    uint64_t total_end = get_time_ns();
    uint64_t total_time_ns = total_end - total_start;
    
    // Calculate throughput in Gbits/s (integer approximation)
    // gbits = bytes * 8 / time_sec / 1e9 = bytes * 8 / (time_ns / 1e9) / 1e9 = bytes * 8 / time_ns
    uint64_t gbits_micro = (bytes_sent * 8ULL * 1000000ULL) / total_time_ns;  // in micro Gbits/s

    print("total bytes sent: ");
    print_number(bytes_sent);
    print("\n");
    
    print("tx performance: 0.");
    print_number(gbits_micro);
    print(" Gbits/s\n");
    
    // Convert ns to sec with 6 decimal places
    uint64_t total_sec_int = total_time_ns / 1000000000ULL;
    uint64_t total_sec_frac = (total_time_ns % 1000000000ULL) / 1000;  // microseconds
    print("total time in tx loop: ");
    print_number(total_sec_int);
    print(".");
    // Print with leading zeros
    if (total_sec_frac < 100000) print("0");
    if (total_sec_frac < 10000) print("0");
    if (total_sec_frac < 1000) print("0");
    if (total_sec_frac < 100) print("0");
    if (total_sec_frac < 10) print("0");
    print_number(total_sec_frac);
    print(" sec\n");
    
    uint64_t send_sec_int = time_in_send_ns / 1000000000ULL;
    uint64_t send_sec_frac = (time_in_send_ns % 1000000000ULL) / 1000;
    print("time in 'send()': ");
    print_number(send_sec_int);
    print(".");
    if (send_sec_frac < 100000) print("0");
    if (send_sec_frac < 10000) print("0");
    if (send_sec_frac < 1000) print("0");
    if (send_sec_frac < 100) print("0");
    if (send_sec_frac < 10) print("0");
    print_number(send_sec_frac);
    print(" sec\n");

    sys_close(fd);
    sys_exit(0);
}

