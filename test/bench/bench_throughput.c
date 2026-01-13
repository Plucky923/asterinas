/* SPDX-License-Identifier: MPL-2.0 */
/*
 * bench_throughput.c - Rigorous Throughput Benchmark
 *
 * A comprehensive throughput benchmark inspired by Linux vsock_perf.c with
 * proper statistical methodology.
 *
 * Features:
 *   - Bidirectional throughput measurement (send/receive)
 *   - Configurable buffer sizes and total transfer
 *   - Wall-clock vs in-syscall time differentiation
 *   - SO_RCVLOWAT optimization support
 *   - Zero-copy support (where available)
 *   - CPU affinity pinning
 *   - JSON/CSV output for automation
 *
 * Usage:
 *   Receiver: ./bench_throughput --receiver [--type vsock] [--port 20001]
 *   Sender:   ./bench_throughput --sender <cid> [--type vsock] [--bytes 1G]
 *
 * Copyright (C) 2024 Asterinas Developers.
 */

#include "bench_common.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>

/* Linux vsock header */
#ifdef __linux__
#include <linux/vm_sockets.h>
#endif

/* ============================================================================
 * Socket Type Definitions
 * ============================================================================ */

enum socket_type {
    SOCK_TYPE_VSOCK,
    SOCK_TYPE_FRAMEVSOCK,
    SOCK_TYPE_UNIX,
    SOCK_TYPE_TCP,
};

/* FrameVsock constants */
#ifndef AF_FRAMEVSOCK
#define AF_FRAMEVSOCK       46
#endif

#ifndef VMADDR_CID_ANY
#define VMADDR_CID_ANY      (-1U)
#endif

/* sockaddr_vm for FrameVsock */
struct sockaddr_fvm {
    unsigned short svm_family;
    unsigned short svm_reserved1;
    unsigned int svm_port;
    unsigned long long svm_cid;
};

/* ============================================================================
 * Configuration
 * ============================================================================ */

static struct {
    /* Mode */
    bool is_sender;
    bool is_receiver;

    /* Socket configuration */
    enum socket_type sock_type;
    unsigned int target_cid;
    unsigned int port;
    const char *unix_path;
    const char *tcp_host;

    /* Buffer and transfer parameters */
    size_t buf_size;
    uint64_t total_bytes;
    size_t vsock_buf_size;
    size_t rcvlowat;

    /* Options */
    int cpu_affinity;
    bool pin_cpu;
    bool verbose;
    bool json_output;
    bool csv_output;
    bool use_mmap;          /* Use mmap for buffer allocation */
    bool zerocopy;          /* MSG_ZEROCOPY (Linux 4.14+) */

    /* Runtime state */
    void *buffer;
    volatile sig_atomic_t running;
} config = {
    .port = 20001,
    .buf_size = 128 * 1024,         /* 128 KB default */
    .total_bytes = 1ULL << 30,      /* 1 GB default */
    .vsock_buf_size = 256 * 1024,   /* 256 KB vsock buffer */
    .rcvlowat = 1,
    .running = 1,
};

/* ============================================================================
 * Throughput Results
 * ============================================================================ */

struct throughput_result {
    uint64_t bytes_transferred;
    uint64_t total_time_ns;         /* Wall-clock time */
    uint64_t syscall_time_ns;       /* Time spent in send/recv */
    uint64_t syscall_count;         /* Number of syscalls */

    double throughput_gbps;         /* Gbits/s */
    double throughput_mbps;         /* Mbits/s */
    double avg_syscall_ns;          /* Average syscall latency */
    double effective_gbps;          /* Based on syscall time only */
};

/* ============================================================================
 * Signal Handler
 * ============================================================================ */

static void signal_handler(int sig)
{
    (void)sig;
    config.running = 0;
}

/* ============================================================================
 * Socket Operations
 * ============================================================================ */

static int create_socket(enum socket_type type)
{
    int fd = -1;

    switch (type) {
    case SOCK_TYPE_VSOCK:
#ifdef AF_VSOCK
        fd = socket(AF_VSOCK, SOCK_STREAM, 0);
#else
        fprintf(stderr, "VSOCK not supported\n");
        return -1;
#endif
        break;

    case SOCK_TYPE_FRAMEVSOCK:
        fd = socket(AF_FRAMEVSOCK, SOCK_STREAM, 0);
        break;

    case SOCK_TYPE_UNIX:
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        break;

    case SOCK_TYPE_TCP:
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            int flag = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        }
        break;
    }

    if (fd < 0) {
        perror("socket");
    }
    return fd;
}

static int bind_socket(int fd, enum socket_type type, unsigned int port, const char *path)
{
    int ret = -1;

    switch (type) {
#ifdef AF_VSOCK
    case SOCK_TYPE_VSOCK: {
        struct sockaddr_vm addr = {
            .svm_family = AF_VSOCK,
            .svm_port = port,
            .svm_cid = VMADDR_CID_ANY,
        };
        ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
        break;
    }
#endif

    case SOCK_TYPE_FRAMEVSOCK: {
        struct sockaddr_fvm addr = {
            .svm_family = AF_FRAMEVSOCK,
            .svm_port = port,
            .svm_cid = VMADDR_CID_ANY,
        };
        ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
        break;
    }

    case SOCK_TYPE_UNIX: {
        struct sockaddr_un addr = { .sun_family = AF_UNIX };
        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
        unlink(path);
        ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
        break;
    }

    case SOCK_TYPE_TCP: {
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
            .sin_addr.s_addr = INADDR_ANY,
        };
        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
        break;
    }

    default:
        break;
    }

    if (ret < 0) perror("bind");
    return ret;
}

static int connect_socket(int fd, enum socket_type type, unsigned int cid,
                          unsigned int port, const char *host, const char *path)
{
    int ret = -1;

    switch (type) {
#ifdef AF_VSOCK
    case SOCK_TYPE_VSOCK: {
        struct sockaddr_vm addr = {
            .svm_family = AF_VSOCK,
            .svm_port = port,
            .svm_cid = cid,
        };
        ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        break;
    }
#endif

    case SOCK_TYPE_FRAMEVSOCK: {
        struct sockaddr_fvm addr = {
            .svm_family = AF_FRAMEVSOCK,
            .svm_port = port,
            .svm_cid = cid,
        };
        ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        break;
    }

    case SOCK_TYPE_UNIX: {
        struct sockaddr_un addr = { .sun_family = AF_UNIX };
        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
        ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        break;
    }

    case SOCK_TYPE_TCP: {
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(port),
        };
        if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
            fprintf(stderr, "Invalid address: %s\n", host);
            return -1;
        }
        ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        break;
    }
    }

    if (ret < 0) perror("connect");
    return ret;
}

static void configure_socket_buffers(int fd, enum socket_type type)
{
    /* Set vsock-specific buffer sizes */
#ifdef AF_VSOCK
    if (type == SOCK_TYPE_VSOCK) {
        unsigned long long buf = config.vsock_buf_size;
        setsockopt(fd, AF_VSOCK, SO_VM_SOCKETS_BUFFER_MAX_SIZE, &buf, sizeof(buf));
        setsockopt(fd, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE, &buf, sizeof(buf));
    }
#endif

    /* Set SO_RCVLOWAT for receiver efficiency */
    if (config.rcvlowat > 1) {
        int lowat = config.rcvlowat;
        setsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &lowat, sizeof(lowat));
    }

    /* Set generic socket buffer sizes */
    int sndbuf = config.buf_size * 4;
    int rcvbuf = config.buf_size * 4;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    (void)type;
}

/* ============================================================================
 * Result Printing
 * ============================================================================ */

static void print_result(const struct throughput_result *result, const char *mode)
{
    char bytes_buf[32], time_buf[32];

    printf("\n");
    printf("================================================================================\n");
    printf(" Throughput Benchmark Results (%s)\n", mode);
    printf("================================================================================\n");
    printf(" Bytes transferred:    %s\n",
           bench_format_bytes(result->bytes_transferred, bytes_buf, sizeof(bytes_buf)));
    printf(" Wall-clock time:      %s\n",
           bench_format_time(result->total_time_ns, time_buf, sizeof(time_buf)));
    printf(" Syscall time:         %s\n",
           bench_format_time(result->syscall_time_ns, time_buf, sizeof(time_buf)));
    printf("--------------------------------------------------------------------------------\n");
    printf(" Throughput (wall):    %.3f Gbits/s (%.1f Mbits/s)\n",
           result->throughput_gbps, result->throughput_mbps);
    printf(" Throughput (syscall): %.3f Gbits/s\n", result->effective_gbps);
    printf("--------------------------------------------------------------------------------\n");
    printf(" Syscall count:        %lu\n", (unsigned long)result->syscall_count);
    printf(" Avg syscall latency:  %.1f ns\n", result->avg_syscall_ns);
    printf(" Avg bytes/syscall:    %.1f\n",
           (double)result->bytes_transferred / result->syscall_count);
    printf("================================================================================\n\n");
}

static void print_result_json(const struct throughput_result *result, const char *mode)
{
    printf("{\n");
    printf("  \"mode\": \"%s\",\n", mode);
    printf("  \"bytes_transferred\": %lu,\n", (unsigned long)result->bytes_transferred);
    printf("  \"total_time_ns\": %lu,\n", (unsigned long)result->total_time_ns);
    printf("  \"syscall_time_ns\": %lu,\n", (unsigned long)result->syscall_time_ns);
    printf("  \"syscall_count\": %lu,\n", (unsigned long)result->syscall_count);
    printf("  \"throughput_gbps\": %.6f,\n", result->throughput_gbps);
    printf("  \"throughput_mbps\": %.6f,\n", result->throughput_mbps);
    printf("  \"effective_gbps\": %.6f,\n", result->effective_gbps);
    printf("  \"avg_syscall_ns\": %.6f\n", result->avg_syscall_ns);
    printf("}\n");
}

static void print_result_csv(const struct throughput_result *result, const char *mode)
{
    printf("%s,%lu,%lu,%lu,%lu,%.6f,%.6f,%.6f,%.6f\n",
           mode,
           (unsigned long)result->bytes_transferred,
           (unsigned long)result->total_time_ns,
           (unsigned long)result->syscall_time_ns,
           (unsigned long)result->syscall_count,
           result->throughput_gbps,
           result->throughput_mbps,
           result->effective_gbps,
           result->avg_syscall_ns);
}

/* ============================================================================
 * Receiver Mode
 * ============================================================================ */

static int run_receiver(void)
{
    int listen_fd, client_fd;
    struct throughput_result result = {0};
    char bytes_buf[32];

    printf("\n");
    printf("================================================================================\n");
    printf(" Throughput Benchmark Receiver\n");
    printf("================================================================================\n");
    printf(" Socket type:     %s\n",
           config.sock_type == SOCK_TYPE_VSOCK ? "vsock" :
           config.sock_type == SOCK_TYPE_FRAMEVSOCK ? "framevsock" :
           config.sock_type == SOCK_TYPE_UNIX ? "unix" : "tcp");
    printf(" Port:            %u\n", config.port);
    printf(" RX buffer:       %s\n",
           bench_format_bytes(config.buf_size, bytes_buf, sizeof(bytes_buf)));
    printf(" SO_RCVLOWAT:     %zu bytes\n", config.rcvlowat);
    if (config.pin_cpu) {
        printf(" CPU affinity:    %d\n", config.cpu_affinity);
    }
    printf("--------------------------------------------------------------------------------\n");

    /* Pin CPU if requested */
    if (config.pin_cpu && bench_pin_cpu(config.cpu_affinity) < 0) {
        fprintf(stderr, "Warning: Failed to pin CPU\n");
    }

    /* Allocate receive buffer */
    if (config.use_mmap) {
        config.buffer = bench_alloc_aligned(config.buf_size);
    } else {
        config.buffer = malloc(config.buf_size);
    }
    if (!config.buffer) {
        perror("buffer allocation");
        return 1;
    }

    /* Create and bind socket */
    listen_fd = create_socket(config.sock_type);
    if (listen_fd < 0) goto error;

    if (bind_socket(listen_fd, config.sock_type, config.port, config.unix_path) < 0) {
        close(listen_fd);
        goto error;
    }

    if (listen(listen_fd, 1) < 0) {
        perror("listen");
        close(listen_fd);
        goto error;
    }

    printf(" Listening...\n");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Accept connection */
    client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        close(listen_fd);
        goto error;
    }

    printf(" Client connected, receiving data...\n");

    configure_socket_buffers(client_fd, config.sock_type);

    /* Receive loop with timing */
    uint64_t total_start = bench_gettime_ns(CLOCK_MONOTONIC);

    while (config.running) {
        struct pollfd pfd = { .fd = client_fd, .events = POLLIN | POLLHUP | POLLRDHUP };

        int ret = poll(&pfd, 1, 1000);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        if (ret == 0) continue;

        if (pfd.revents & (POLLHUP | POLLRDHUP | POLLERR)) {
            break;
        }

        if (pfd.revents & POLLIN) {
            uint64_t syscall_start = bench_gettime_ns(CLOCK_MONOTONIC);
            ssize_t n = read(client_fd, config.buffer, config.buf_size);
            uint64_t syscall_end = bench_gettime_ns(CLOCK_MONOTONIC);

            if (n <= 0) break;

            result.bytes_transferred += n;
            result.syscall_time_ns += (syscall_end - syscall_start);
            result.syscall_count++;
        }
    }

    uint64_t total_end = bench_gettime_ns(CLOCK_MONOTONIC);
    result.total_time_ns = total_end - total_start;

    close(client_fd);
    close(listen_fd);

    /* Calculate throughput */
    if (result.total_time_ns > 0) {
        result.throughput_gbps = bench_calc_throughput_gbps(
            result.bytes_transferred, result.total_time_ns);
        result.throughput_mbps = bench_calc_throughput_mbps(
            result.bytes_transferred, result.total_time_ns);
    }
    if (result.syscall_time_ns > 0) {
        result.effective_gbps = bench_calc_throughput_gbps(
            result.bytes_transferred, result.syscall_time_ns);
    }
    if (result.syscall_count > 0) {
        result.avg_syscall_ns = (double)result.syscall_time_ns / result.syscall_count;
    }

    /* Print results */
    if (config.json_output) {
        print_result_json(&result, "receiver");
    } else if (config.csv_output) {
        printf("mode,bytes,total_ns,syscall_ns,syscall_count,gbps,mbps,effective_gbps,avg_syscall_ns\n");
        print_result_csv(&result, "receiver");
    } else {
        print_result(&result, "Receiver");
    }

    if (config.use_mmap) {
        bench_free_aligned(config.buffer, config.buf_size);
    } else {
        free(config.buffer);
    }

    if (config.sock_type == SOCK_TYPE_UNIX && config.unix_path) {
        unlink(config.unix_path);
    }

    return 0;

error:
    if (config.use_mmap) {
        bench_free_aligned(config.buffer, config.buf_size);
    } else {
        free(config.buffer);
    }
    return 1;
}

/* ============================================================================
 * Sender Mode
 * ============================================================================ */

static int run_sender(void)
{
    int fd;
    struct throughput_result result = {0};
    char bytes_buf[32];

    printf("\n");
    printf("================================================================================\n");
    printf(" Throughput Benchmark Sender\n");
    printf("================================================================================\n");
    printf(" Socket type:     %s\n",
           config.sock_type == SOCK_TYPE_VSOCK ? "vsock" :
           config.sock_type == SOCK_TYPE_FRAMEVSOCK ? "framevsock" :
           config.sock_type == SOCK_TYPE_UNIX ? "unix" : "tcp");
    if (config.sock_type == SOCK_TYPE_VSOCK || config.sock_type == SOCK_TYPE_FRAMEVSOCK) {
        printf(" Target CID:      %u\n", config.target_cid);
    } else if (config.sock_type == SOCK_TYPE_TCP) {
        printf(" Target host:     %s\n", config.tcp_host);
    }
    printf(" Port:            %u\n", config.port);
    printf(" TX buffer:       %s\n",
           bench_format_bytes(config.buf_size, bytes_buf, sizeof(bytes_buf)));
    printf(" Total to send:   %s\n",
           bench_format_bytes(config.total_bytes, bytes_buf, sizeof(bytes_buf)));
    if (config.zerocopy) {
        printf(" Zero-copy:       enabled\n");
    }
    if (config.pin_cpu) {
        printf(" CPU affinity:    %d\n", config.cpu_affinity);
    }
    printf("--------------------------------------------------------------------------------\n");

    /* Pin CPU if requested */
    if (config.pin_cpu && bench_pin_cpu(config.cpu_affinity) < 0) {
        fprintf(stderr, "Warning: Failed to pin CPU\n");
    }

    /* Allocate send buffer */
    if (config.use_mmap || config.zerocopy) {
        config.buffer = bench_alloc_aligned(config.buf_size);
    } else {
        config.buffer = malloc(config.buf_size);
    }
    if (!config.buffer) {
        perror("buffer allocation");
        return 1;
    }

    /* Initialize buffer with pattern */
    memset(config.buffer, 'X', config.buf_size);

    /* Create and connect socket */
    fd = create_socket(config.sock_type);
    if (fd < 0) goto error;

    printf(" Connecting...\n");

    if (connect_socket(fd, config.sock_type, config.target_cid, config.port,
                       config.tcp_host, config.unix_path) < 0) {
        close(fd);
        goto error;
    }

    printf(" Connected, sending data...\n");

    configure_socket_buffers(fd, config.sock_type);

    /* Enable zerocopy if requested */
#ifdef SO_ZEROCOPY
    if (config.zerocopy) {
        int val = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &val, sizeof(val)) < 0) {
            perror("setsockopt(SO_ZEROCOPY)");
            fprintf(stderr, "Warning: Falling back to copy mode\n");
            config.zerocopy = false;
        }
    }
#endif

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Send loop with timing */
    uint64_t total_start = bench_gettime_ns(CLOCK_MONOTONIC);

    while (result.bytes_transferred < config.total_bytes && config.running) {
        uint64_t remaining = config.total_bytes - result.bytes_transferred;
        size_t to_send = (remaining > config.buf_size) ? config.buf_size : remaining;

        int flags = 0;
#ifdef MSG_ZEROCOPY
        if (config.zerocopy) flags |= MSG_ZEROCOPY;
#endif

        uint64_t syscall_start = bench_gettime_ns(CLOCK_MONOTONIC);
        ssize_t n = send(fd, config.buffer, to_send, flags);
        uint64_t syscall_end = bench_gettime_ns(CLOCK_MONOTONIC);

        if (n <= 0) {
            if (n < 0) perror("send");
            break;
        }

        result.bytes_transferred += n;
        result.syscall_time_ns += (syscall_end - syscall_start);
        result.syscall_count++;

        /* Progress indicator */
        if (config.verbose && config.total_bytes >= (1ULL << 20)) {
            size_t percent = (result.bytes_transferred * 100) / config.total_bytes;
            static size_t last_percent = 0;
            if (percent != last_percent && percent % 10 == 0) {
                fprintf(stderr, "\r Sending: %zu%% complete", percent);
                fflush(stderr);
                last_percent = percent;
            }
        }
    }

    if (config.verbose && config.total_bytes >= (1ULL << 20)) {
        fprintf(stderr, "\r Sending: 100%% complete\n");
    }

    uint64_t total_end = bench_gettime_ns(CLOCK_MONOTONIC);
    result.total_time_ns = total_end - total_start;

    close(fd);

    /* Calculate throughput */
    if (result.total_time_ns > 0) {
        result.throughput_gbps = bench_calc_throughput_gbps(
            result.bytes_transferred, result.total_time_ns);
        result.throughput_mbps = bench_calc_throughput_mbps(
            result.bytes_transferred, result.total_time_ns);
    }
    if (result.syscall_time_ns > 0) {
        result.effective_gbps = bench_calc_throughput_gbps(
            result.bytes_transferred, result.syscall_time_ns);
    }
    if (result.syscall_count > 0) {
        result.avg_syscall_ns = (double)result.syscall_time_ns / result.syscall_count;
    }

    /* Print results */
    if (config.json_output) {
        print_result_json(&result, "sender");
    } else if (config.csv_output) {
        printf("mode,bytes,total_ns,syscall_ns,syscall_count,gbps,mbps,effective_gbps,avg_syscall_ns\n");
        print_result_csv(&result, "sender");
    } else {
        print_result(&result, "Sender");
    }

    if (config.use_mmap || config.zerocopy) {
        bench_free_aligned(config.buffer, config.buf_size);
    } else {
        free(config.buffer);
    }

    return 0;

error:
    if (config.use_mmap || config.zerocopy) {
        bench_free_aligned(config.buffer, config.buf_size);
    } else {
        free(config.buffer);
    }
    return 1;
}

/* ============================================================================
 * Command Line Parsing
 * ============================================================================ */

static void usage(const char *progname)
{
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("\n");
    printf("Throughput benchmark with detailed timing analysis.\n");
    printf("\n");
    printf("Modes:\n");
    printf("  --receiver            Run as receiver\n");
    printf("  --sender <cid|host>   Run as sender, connect to CID or host\n");
    printf("\n");
    printf("Socket Options:\n");
    printf("  --type <type>         Socket type: vsock, framevsock, unix, tcp\n");
    printf("  --port <port>         Port number (default: %u)\n", config.port);
    printf("  --path <path>         Unix socket path\n");
    printf("\n");
    printf("Transfer Options:\n");
    printf("  --bytes <size>        Total bytes to transfer (default: 1G)\n");
    printf("                        Supports K/M/G suffixes\n");
    printf("  --buf-size <size>     Buffer size per syscall (default: 128K)\n");
    printf("  --vsk-size <size>     Vsock buffer size (default: 256K)\n");
    printf("  --rcvlowat <size>     SO_RCVLOWAT value (default: 1)\n");
    printf("\n");
    printf("Performance Options:\n");
    printf("  --cpu <n>             Pin to CPU core N\n");
    printf("  --mmap                Use mmap for buffer allocation\n");
    printf("  --zerocopy            Enable MSG_ZEROCOPY (sender only)\n");
    printf("\n");
    printf("Output Options:\n");
    printf("  --json                Output results in JSON format\n");
    printf("  --csv                 Output results in CSV format\n");
    printf("  --verbose             Enable verbose output\n");
    printf("  --help                Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  Receiver: %s --receiver --type vsock --port 20001\n", progname);
    printf("  Sender:   %s --sender 2 --type vsock --bytes 1G --buf-size 128K\n", progname);
    printf("\n");
}

static const struct option long_options[] = {
    {"receiver",        no_argument,       NULL, 'r'},
    {"sender",          required_argument, NULL, 's'},
    {"type",            required_argument, NULL, 't'},
    {"port",            required_argument, NULL, 'p'},
    {"path",            required_argument, NULL, 'P'},
    {"bytes",           required_argument, NULL, 'b'},
    {"buf-size",        required_argument, NULL, 'B'},
    {"vsk-size",        required_argument, NULL, 'V'},
    {"rcvlowat",        required_argument, NULL, 'R'},
    {"cpu",             required_argument, NULL, 'C'},
    {"mmap",            no_argument,       NULL, 'M'},
    {"zerocopy",        no_argument,       NULL, 'Z'},
    {"json",            no_argument,       NULL, 'j'},
    {"csv",             no_argument,       NULL, 'c'},
    {"verbose",         no_argument,       NULL, 'v'},
    {"help",            no_argument,       NULL, 'h'},
    {NULL, 0, NULL, 0}
};

int main(int argc, char *argv[])
{
    int opt;

    while ((opt = getopt_long(argc, argv, "rs:t:p:P:b:B:V:R:C:MZjcvh",
                               long_options, NULL)) != -1) {
        switch (opt) {
        case 'r':
            config.is_receiver = true;
            break;

        case 's':
            config.is_sender = true;
            if (optarg[0] >= '0' && optarg[0] <= '9') {
                config.target_cid = atoi(optarg);
            } else {
                config.tcp_host = optarg;
            }
            break;

        case 't':
            if (strcmp(optarg, "vsock") == 0) {
                config.sock_type = SOCK_TYPE_VSOCK;
            } else if (strcmp(optarg, "framevsock") == 0) {
                config.sock_type = SOCK_TYPE_FRAMEVSOCK;
            } else if (strcmp(optarg, "unix") == 0) {
                config.sock_type = SOCK_TYPE_UNIX;
            } else if (strcmp(optarg, "tcp") == 0) {
                config.sock_type = SOCK_TYPE_TCP;
            } else {
                fprintf(stderr, "Unknown socket type: %s\n", optarg);
                return 1;
            }
            break;

        case 'p':
            config.port = atoi(optarg);
            break;

        case 'P':
            config.unix_path = optarg;
            break;

        case 'b':
            config.total_bytes = bench_memparse(optarg);
            break;

        case 'B':
            config.buf_size = bench_memparse(optarg);
            break;

        case 'V':
            config.vsock_buf_size = bench_memparse(optarg);
            break;

        case 'R':
            config.rcvlowat = bench_memparse(optarg);
            break;

        case 'C':
            config.cpu_affinity = atoi(optarg);
            config.pin_cpu = true;
            break;

        case 'M':
            config.use_mmap = true;
            break;

        case 'Z':
            config.zerocopy = true;
            break;

        case 'j':
            config.json_output = true;
            break;

        case 'c':
            config.csv_output = true;
            break;

        case 'v':
            config.verbose = true;
            break;

        case 'h':
            usage(argv[0]);
            return 0;

        default:
            usage(argv[0]);
            return 1;
        }
    }

    /* Validate */
    if (!config.is_sender && !config.is_receiver) {
        fprintf(stderr, "Error: Must specify --sender or --receiver\n");
        usage(argv[0]);
        return 1;
    }

    if (config.is_sender && config.is_receiver) {
        fprintf(stderr, "Error: Cannot specify both --sender and --receiver\n");
        return 1;
    }

    if (config.sock_type == SOCK_TYPE_UNIX && !config.unix_path) {
        config.unix_path = "/tmp/bench_throughput.sock";
    }

    if (config.sock_type == SOCK_TYPE_TCP && config.is_sender && !config.tcp_host) {
        fprintf(stderr, "Error: TCP sender requires hostname/IP\n");
        return 1;
    }

    /* Run */
    if (config.is_receiver) {
        return run_receiver();
    } else {
        return run_sender();
    }
}
