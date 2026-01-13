/* SPDX-License-Identifier: MPL-2.0 */
/*
 * bench_rtt.c - Rigorous Round-Trip Time Benchmark
 *
 * A comprehensive RTT benchmark inspired by Linux vsock_perf.c with
 * proper statistical methodology.
 *
 * Features:
 *   - Configurable warmup with stability verification
 *   - Multiple socket types: vsock, framevsock, unix, tcp
 *   - Statistical analysis with outlier detection
 *   - CPU affinity pinning for reduced jitter
 *   - JSON/CSV output for automation
 *
 * Usage:
 *   Server: ./bench_rtt --server [--type vsock] [--port 20000]
 *   Client: ./bench_rtt --client <cid> [--type vsock] [--port 20000] [--iterations 10000]
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

/* FrameVsock constants (not in standard headers) */
#ifndef AF_FRAMEVSOCK
#define AF_FRAMEVSOCK       46
#endif

#ifndef VMADDR_CID_ANY
#define VMADDR_CID_ANY      (-1U)
#endif

#ifndef VMADDR_CID_HOST
#define VMADDR_CID_HOST     2
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
    bool is_server;
    bool is_client;

    /* Socket configuration */
    enum socket_type sock_type;
    unsigned int target_cid;
    unsigned int port;
    const char *unix_path;
    const char *tcp_host;

    /* Benchmark parameters */
    size_t iterations;
    size_t warmup_iterations;
    size_t msg_size;

    /* Options */
    int cpu_affinity;
    bool pin_cpu;
    bool remove_outliers;
    bool verbose;
    bool json_output;
    bool csv_output;
    bool verify_warmup;

    /* Runtime state */
    double *samples;
    volatile sig_atomic_t running;
} config = {
    .port = 20000,
    .iterations = 10000,
    .warmup_iterations = 1000,
    .msg_size = 64,
    .cpu_affinity = -1,
    .remove_outliers = true,
    .verify_warmup = true,
    .running = 1,
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
        fprintf(stderr, "VSOCK not supported on this platform\n");
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
            /* Disable Nagle's algorithm for latency testing */
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
        struct sockaddr_un addr = {
            .sun_family = AF_UNIX,
        };
        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
        unlink(path);  /* Remove existing socket */
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

    if (ret < 0) {
        perror("bind");
    }
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
        struct sockaddr_un addr = {
            .sun_family = AF_UNIX,
        };
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

    if (ret < 0) {
        perror("connect");
    }
    return ret;
}

/* ============================================================================
 * Server Mode
 * ============================================================================ */

static int run_server(void)
{
    int listen_fd, client_fd;
    char *buffer;
    uint64_t total_pingpongs = 0;

    printf("\n");
    printf("================================================================================\n");
    printf(" RTT Benchmark Server\n");
    printf("================================================================================\n");
    printf(" Socket type:     %s\n",
           config.sock_type == SOCK_TYPE_VSOCK ? "vsock" :
           config.sock_type == SOCK_TYPE_FRAMEVSOCK ? "framevsock" :
           config.sock_type == SOCK_TYPE_UNIX ? "unix" : "tcp");
    printf(" Port:            %u\n", config.port);
    printf(" Message size:    %zu bytes\n", config.msg_size);
    if (config.pin_cpu) {
        printf(" CPU affinity:    %d\n", config.cpu_affinity);
    }
    printf("--------------------------------------------------------------------------------\n");

    /* Pin CPU if requested */
    if (config.pin_cpu && bench_pin_cpu(config.cpu_affinity) < 0) {
        fprintf(stderr, "Warning: Failed to pin CPU\n");
    }

    /* Allocate buffer */
    buffer = malloc(config.msg_size);
    if (!buffer) {
        perror("malloc");
        return 1;
    }

    /* Create and bind socket */
    listen_fd = create_socket(config.sock_type);
    if (listen_fd < 0) {
        free(buffer);
        return 1;
    }

    if (bind_socket(listen_fd, config.sock_type, config.port, config.unix_path) < 0) {
        close(listen_fd);
        free(buffer);
        return 1;
    }

    if (listen(listen_fd, 1) < 0) {
        perror("listen");
        close(listen_fd);
        free(buffer);
        return 1;
    }

    printf(" Listening...\n");

    /* Setup signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Accept loop */
    while (config.running) {
        struct pollfd pfd = {
            .fd = listen_fd,
            .events = POLLIN,
        };

        if (poll(&pfd, 1, 1000) <= 0) {
            continue;
        }

        client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        printf(" Client connected\n");

        /* Ping-pong loop */
        uint64_t session_count = 0;
        while (config.running) {
            ssize_t n = recv(client_fd, buffer, config.msg_size, MSG_WAITALL);
            if (n <= 0) break;

            n = send(client_fd, buffer, n, 0);
            if (n <= 0) break;

            session_count++;
        }

        total_pingpongs += session_count;
        printf(" Session ended: %lu ping-pongs (total: %lu)\n",
               (unsigned long)session_count, (unsigned long)total_pingpongs);

        close(client_fd);
    }

    printf("--------------------------------------------------------------------------------\n");
    printf(" Server shutting down. Total ping-pongs: %lu\n", (unsigned long)total_pingpongs);
    printf("================================================================================\n\n");

    close(listen_fd);
    free(buffer);

    if (config.sock_type == SOCK_TYPE_UNIX && config.unix_path) {
        unlink(config.unix_path);
    }

    return 0;
}

/* ============================================================================
 * Client Mode
 * ============================================================================ */

static int run_client(void)
{
    int fd;
    char *buffer;
    struct bench_stats stats;
    struct bench_timer timer;
    size_t warmup_done = 0;
    double *warmup_samples = NULL;

    printf("\n");
    printf("================================================================================\n");
    printf(" RTT Benchmark Client\n");
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
    printf(" Message size:    %zu bytes\n", config.msg_size);
    printf(" Iterations:      %zu\n", config.iterations);
    printf(" Warmup:          %zu\n", config.warmup_iterations);
    printf(" Outlier removal: %s\n", config.remove_outliers ? "enabled" : "disabled");
    if (config.pin_cpu) {
        printf(" CPU affinity:    %d\n", config.cpu_affinity);
    }
    printf("--------------------------------------------------------------------------------\n");

    /* Pin CPU if requested */
    if (config.pin_cpu && bench_pin_cpu(config.cpu_affinity) < 0) {
        fprintf(stderr, "Warning: Failed to pin CPU\n");
    }

    /* Allocate buffers */
    buffer = malloc(config.msg_size);
    config.samples = malloc(config.iterations * sizeof(double));
    warmup_samples = malloc(config.warmup_iterations * sizeof(double));

    if (!buffer || !config.samples || !warmup_samples) {
        perror("malloc");
        free(buffer);
        free(config.samples);
        free(warmup_samples);
        return 1;
    }

    /* Initialize buffer with pattern */
    memset(buffer, 'X', config.msg_size);

    /* Create and connect socket */
    fd = create_socket(config.sock_type);
    if (fd < 0) {
        free(buffer);
        free(config.samples);
        free(warmup_samples);
        return 1;
    }

    printf(" Connecting...\n");

    if (connect_socket(fd, config.sock_type, config.target_cid, config.port,
                       config.tcp_host, config.unix_path) < 0) {
        close(fd);
        free(buffer);
        free(config.samples);
        free(warmup_samples);
        return 1;
    }

    printf(" Connected!\n");

    /* ========== Warmup Phase ========== */
    printf(" Running warmup (%zu iterations)...\n", config.warmup_iterations);

    for (size_t i = 0; i < config.warmup_iterations && config.running; i++) {
        bench_timer_start(&timer, CLOCK_MONOTONIC);

        if (send(fd, buffer, config.msg_size, 0) != (ssize_t)config.msg_size) {
            perror("send (warmup)");
            goto error;
        }

        if (recv(fd, buffer, config.msg_size, MSG_WAITALL) != (ssize_t)config.msg_size) {
            perror("recv (warmup)");
            goto error;
        }

        uint64_t elapsed_ns = bench_timer_stop(&timer);
        warmup_samples[i] = (double)elapsed_ns / 1000.0;  /* Convert to microseconds */
        warmup_done++;
    }

    /* Verify warmup stability */
    if (config.verify_warmup && warmup_done >= 100) {
        /* Check last 100 samples for stability */
        size_t check_start = warmup_done > 100 ? warmup_done - 100 : 0;
        bool stable = bench_verify_warmup(&warmup_samples[check_start], 100, 0.15);

        if (!stable) {
            printf(" Warning: Warmup may not have stabilized (CV > 15%%)\n");
            if (config.verbose) {
                double mean = bench_mean(&warmup_samples[check_start], 100);
                double sd = bench_stddev(&warmup_samples[check_start], 100, mean);
                printf("   Last 100 samples: mean=%.2f us, stddev=%.2f us, CV=%.1f%%\n",
                       mean, sd, (sd / mean) * 100);
            }
        } else {
            printf(" Warmup stabilized\n");
        }
    }

    /* ========== Measurement Phase ========== */
    printf(" Running benchmark (%zu iterations)...\n", config.iterations);

    uint64_t total_start = bench_gettime_ns(CLOCK_MONOTONIC);

    for (size_t i = 0; i < config.iterations && config.running; i++) {
        bench_timer_start(&timer, CLOCK_MONOTONIC);

        if (send(fd, buffer, config.msg_size, 0) != (ssize_t)config.msg_size) {
            perror("send");
            goto error;
        }

        if (recv(fd, buffer, config.msg_size, MSG_WAITALL) != (ssize_t)config.msg_size) {
            perror("recv");
            goto error;
        }

        uint64_t elapsed_ns = bench_timer_stop(&timer);
        config.samples[i] = (double)elapsed_ns / 1000.0;  /* Convert to microseconds */

        /* Progress indicator for long runs */
        if (config.verbose && config.iterations >= 10000) {
            bench_progress(i + 1, config.iterations, "Benchmark");
        }
    }

    uint64_t total_end = bench_gettime_ns(CLOCK_MONOTONIC);
    double total_time_sec = (double)(total_end - total_start) / 1e9;

    printf(" Benchmark complete in %.3f seconds\n", total_time_sec);

    close(fd);
    fd = -1;

    /* ========== Statistical Analysis ========== */
    printf(" Computing statistics...\n");

    if (bench_compute_stats(config.samples, config.iterations, &stats,
                            config.remove_outliers) < 0) {
        fprintf(stderr, "Failed to compute statistics\n");
        goto error;
    }

    /* ========== Output Results ========== */
    if (config.json_output) {
        bench_print_json(&stats, "RTT");
    } else if (config.csv_output) {
        bench_print_csv_header();
        bench_print_csv(&stats, "RTT");
    } else {
        bench_print_stats(&stats, "RTT (Round-Trip Time)", "us");

        /* Additional metrics */
        printf(" Additional Metrics:\n");
        printf("--------------------------------------------------------------------------------\n");
        printf("   Total time:        %.3f seconds\n", total_time_sec);
        printf("   Throughput:        %.2f ping-pongs/sec\n",
               config.iterations / total_time_sec);
        printf("   One-way latency:   ~%.3f us (estimated)\n", stats.median / 2.0);
        printf("================================================================================\n\n");
    }

    bench_free_stats(&stats);
    free(buffer);
    free(config.samples);
    free(warmup_samples);
    return 0;

error:
    if (fd >= 0) close(fd);
    free(buffer);
    free(config.samples);
    free(warmup_samples);
    return 1;
}

/* ============================================================================
 * Command Line Parsing
 * ============================================================================ */

static void usage(const char *progname)
{
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("\n");
    printf("RTT (Round-Trip Time) Benchmark with rigorous statistical analysis.\n");
    printf("\n");
    printf("Modes:\n");
    printf("  --server              Run as server (pong)\n");
    printf("  --client <cid|host>   Run as client (ping), connect to CID or host\n");
    printf("\n");
    printf("Socket Options:\n");
    printf("  --type <type>         Socket type: vsock, framevsock, unix, tcp\n");
    printf("                        (default: vsock)\n");
    printf("  --port <port>         Port number (default: %u)\n", config.port);
    printf("  --path <path>         Unix socket path (for --type unix)\n");
    printf("\n");
    printf("Benchmark Options:\n");
    printf("  --iterations <n>      Number of measurement iterations (default: %zu)\n",
           config.iterations);
    printf("  --warmup <n>          Number of warmup iterations (default: %zu)\n",
           config.warmup_iterations);
    printf("  --msg-size <bytes>    Message size in bytes (default: %zu)\n",
           config.msg_size);
    printf("  --no-outliers         Disable outlier removal\n");
    printf("  --no-warmup-verify    Disable warmup stability verification\n");
    printf("\n");
    printf("System Options:\n");
    printf("  --cpu <n>             Pin to CPU core N\n");
    printf("\n");
    printf("Output Options:\n");
    printf("  --json                Output results in JSON format\n");
    printf("  --csv                 Output results in CSV format\n");
    printf("  --verbose             Enable verbose output\n");
    printf("  --help                Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  Server:  %s --server --type vsock --port 20000\n", progname);
    printf("  Client:  %s --client 2 --type vsock --port 20000 --iterations 10000\n", progname);
    printf("  TCP:     %s --client 127.0.0.1 --type tcp --port 20000\n", progname);
    printf("\n");
}

static const struct option long_options[] = {
    {"server",          no_argument,       NULL, 's'},
    {"client",          required_argument, NULL, 'c'},
    {"type",            required_argument, NULL, 't'},
    {"port",            required_argument, NULL, 'p'},
    {"path",            required_argument, NULL, 'P'},
    {"iterations",      required_argument, NULL, 'i'},
    {"warmup",          required_argument, NULL, 'w'},
    {"msg-size",        required_argument, NULL, 'm'},
    {"cpu",             required_argument, NULL, 'C'},
    {"no-outliers",     no_argument,       NULL, 'O'},
    {"no-warmup-verify", no_argument,      NULL, 'W'},
    {"json",            no_argument,       NULL, 'j'},
    {"csv",             no_argument,       NULL, 'V'},
    {"verbose",         no_argument,       NULL, 'v'},
    {"help",            no_argument,       NULL, 'h'},
    {NULL, 0, NULL, 0}
};

int main(int argc, char *argv[])
{
    int opt;

    while ((opt = getopt_long(argc, argv, "sc:t:p:P:i:w:m:C:OWjVvh", long_options, NULL)) != -1) {
        switch (opt) {
        case 's':
            config.is_server = true;
            break;

        case 'c':
            config.is_client = true;
            /* Check if argument is numeric (CID) or hostname */
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

        case 'i':
            config.iterations = bench_memparse(optarg);
            if (config.iterations < BENCH_MIN_ITERATIONS) {
                fprintf(stderr, "Iterations must be at least %d\n", BENCH_MIN_ITERATIONS);
                return 1;
            }
            if (config.iterations > BENCH_MAX_ITERATIONS) {
                fprintf(stderr, "Iterations must be at most %d\n", BENCH_MAX_ITERATIONS);
                return 1;
            }
            break;

        case 'w':
            config.warmup_iterations = bench_memparse(optarg);
            break;

        case 'm':
            config.msg_size = bench_memparse(optarg);
            if (config.msg_size == 0) {
                fprintf(stderr, "Message size must be > 0\n");
                return 1;
            }
            break;

        case 'C':
            config.cpu_affinity = atoi(optarg);
            config.pin_cpu = true;
            break;

        case 'O':
            config.remove_outliers = false;
            break;

        case 'W':
            config.verify_warmup = false;
            break;

        case 'j':
            config.json_output = true;
            break;

        case 'V':
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

    /* Validate options */
    if (!config.is_server && !config.is_client) {
        fprintf(stderr, "Error: Must specify --server or --client\n");
        usage(argv[0]);
        return 1;
    }

    if (config.is_server && config.is_client) {
        fprintf(stderr, "Error: Cannot specify both --server and --client\n");
        return 1;
    }

    if (config.sock_type == SOCK_TYPE_UNIX && !config.unix_path) {
        config.unix_path = "/tmp/bench_rtt.sock";
    }

    if (config.sock_type == SOCK_TYPE_TCP && config.is_client && !config.tcp_host) {
        fprintf(stderr, "Error: TCP client requires hostname/IP\n");
        return 1;
    }

    /* Run benchmark */
    if (config.is_server) {
        return run_server();
    } else {
        return run_client();
    }
}
