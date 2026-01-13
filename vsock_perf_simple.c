// SPDX-License-Identifier: GPL-2.0-only
/*
 * vsock_perf_simple - simplified benchmark utility for vsock.
 * Removed unsupported features for Asterinas compatibility.
 *
 * Based on vsock_perf by Arseniy Krasnov <AVKrasnov@sberdevices.ru>
 */
#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <poll.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>

#define DEFAULT_BUF_SIZE_BYTES  4096
#define DEFAULT_TO_SEND_BYTES   (64 * 1024)
#define DEFAULT_PORT            1234
#define DEFAULT_RTT_COUNT       100

#define NSEC_PER_SEC            (1000000000ULL)

static unsigned int port = DEFAULT_PORT;
static unsigned long buf_size_bytes = DEFAULT_BUF_SIZE_BYTES;

static void error(const char *s)
{
    perror(s);
    exit(EXIT_FAILURE);
}

static time_t current_nsec(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts))
        error("clock_gettime");
    return (ts.tv_sec * NSEC_PER_SEC) + ts.tv_nsec;
}

static unsigned long memparse(const char *ptr)
{
    char *endptr;
    unsigned long long ret = strtoull(ptr, &endptr, 0);

    switch (*endptr) {
    case 'G':
    case 'g':
        ret <<= 10;
        /* fall through */
    case 'M':
    case 'm':
        ret <<= 10;
        /* fall through */
    case 'K':
    case 'k':
        ret <<= 10;
        endptr++;
        /* fall through */
    default:
        break;
    }
    return ret;
}

static int vsock_connect(unsigned int cid, unsigned int port)
{
    union {
        struct sockaddr sa;
        struct sockaddr_vm svm;
    } addr = {
        .svm = {
            .svm_family = AF_VSOCK,
            .svm_port = port,
            .svm_cid = cid,
        },
    };
    int fd;

    fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    if (connect(fd, &addr.sa, sizeof(addr.svm)) < 0) {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

static float get_gbps(unsigned long bits, time_t ns_delta)
{
    return ((float)bits / 1000000000ULL) / ((float)ns_delta / NSEC_PER_SEC);
}

/* ==================== Throughput Test ==================== */

static void run_throughput_receiver(void)
{
    time_t rx_begin_ns;
    time_t in_read_ns;
    size_t total_recv;
    unsigned int read_cnt;
    int client_fd;
    char *data;
    int fd;
    union {
        struct sockaddr sa;
        struct sockaddr_vm svm;
    } addr = {
        .svm = {
            .svm_family = AF_VSOCK,
            .svm_port = port,
            .svm_cid = VMADDR_CID_ANY,
        },
    };
    union {
        struct sockaddr sa;
        struct sockaddr_vm svm;
    } clientaddr;
    socklen_t clientaddr_len = sizeof(clientaddr.svm);

    printf("Run as receiver\n");
    printf("Listen port %u\n", port);
    printf("RX buffer %lu bytes\n", buf_size_bytes);

    fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0)
        error("socket");

    if (bind(fd, &addr.sa, sizeof(addr.svm)) < 0)
        error("bind");

    if (listen(fd, 1) < 0)
        error("listen");

    client_fd = accept(fd, &clientaddr.sa, &clientaddr_len);
    if (client_fd < 0)
        error("accept");

    data = malloc(buf_size_bytes);
    if (!data) {
        fprintf(stderr, "malloc failed\n");
        exit(EXIT_FAILURE);
    }

    read_cnt = 0;
    in_read_ns = 0;
    total_recv = 0;
    rx_begin_ns = current_nsec();

    while (1) {
        struct pollfd fds = { 0 };
        fds.fd = client_fd;
        fds.events = POLLIN | POLLERR | POLLHUP | POLLRDHUP;

        if (poll(&fds, 1, -1) < 0)
            error("poll");

        if (fds.revents & POLLERR) {
            fprintf(stderr, "'poll()' error\n");
            exit(EXIT_FAILURE);
        }

        if (fds.revents & POLLIN) {
            ssize_t bytes_read;
            time_t t;

            t = current_nsec();
            bytes_read = read(fds.fd, data, buf_size_bytes);
            in_read_ns += (current_nsec() - t);
            read_cnt++;

            if (bytes_read == 0)
                break;

            if (bytes_read < 0) {
                perror("read");
                exit(EXIT_FAILURE);
            }

            total_recv += bytes_read;
        }

        if (fds.revents & (POLLHUP | POLLRDHUP))
            break;
    }

    printf("total bytes received: %zu\n", total_recv);
    printf("rx performance: %f Gbits/s\n",
           get_gbps(total_recv * 8, current_nsec() - rx_begin_ns));
    printf("total time in 'read()': %f sec\n", (float)in_read_ns / NSEC_PER_SEC);
    printf("average time in 'read()': %f ns\n", (float)in_read_ns / read_cnt);
    printf("POLLIN wakeups: %u\n", read_cnt);

    free(data);
    close(client_fd);
    close(fd);
}

static void run_throughput_sender(int peer_cid, unsigned long to_send_bytes)
{
    time_t tx_begin_ns;
    time_t tx_total_ns;
    size_t total_send;
    time_t time_in_send;
    char *data;
    int fd;

    printf("Run as sender\n");
    printf("Connect to %d:%u\n", peer_cid, port);
    printf("Send %lu bytes\n", to_send_bytes);
    printf("TX buffer %lu bytes\n", buf_size_bytes);

    fd = vsock_connect(peer_cid, port);
    if (fd < 0)
        exit(EXIT_FAILURE);

    data = malloc(buf_size_bytes);
    if (!data) {
        fprintf(stderr, "malloc failed\n");
        exit(EXIT_FAILURE);
    }
    memset(data, 'A', buf_size_bytes);

    total_send = 0;
    time_in_send = 0;
    tx_begin_ns = current_nsec();

    while (total_send < to_send_bytes) {
        size_t rest_bytes = to_send_bytes - total_send;
        size_t to_write = (rest_bytes > buf_size_bytes) ? buf_size_bytes : rest_bytes;
        time_t before;
        ssize_t sent;

        before = current_nsec();
        sent = send(fd, data, to_write, 0);
        time_in_send += (current_nsec() - before);

        if (sent <= 0) {
            perror("send");
            break;
        }
        total_send += sent;
    }

    tx_total_ns = current_nsec() - tx_begin_ns;

    printf("total bytes sent: %zu\n", total_send);
    printf("tx performance: %f Gbits/s\n", get_gbps(total_send * 8, time_in_send));
    printf("total time in tx loop: %f sec\n", (float)tx_total_ns / NSEC_PER_SEC);
    printf("time in 'send()': %f sec\n", (float)time_in_send / NSEC_PER_SEC);

    free(data);
    close(fd);
}

/* ==================== RTT Test ==================== */

static void run_rtt_receiver(void)
{
    int client_fd;
    char buf[64];
    int fd;
    union {
        struct sockaddr sa;
        struct sockaddr_vm svm;
    } addr = {
        .svm = {
            .svm_family = AF_VSOCK,
            .svm_port = port,
            .svm_cid = VMADDR_CID_ANY,
        },
    };
    union {
        struct sockaddr sa;
        struct sockaddr_vm svm;
    } clientaddr;
    socklen_t clientaddr_len = sizeof(clientaddr.svm);

    printf("=== RTT Test: Receiver (Echo Server) ===\n");
    printf("Listen port: %u\n", port);

    fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0)
        error("socket");

    if (bind(fd, &addr.sa, sizeof(addr.svm)) < 0)
        error("bind");

    if (listen(fd, 1) < 0)
        error("listen");

    printf("Waiting for connection...\n");
    client_fd = accept(fd, &clientaddr.sa, &clientaddr_len);
    if (client_fd < 0)
        error("accept");

    printf("Connected from CID %u, echoing...\n", clientaddr.svm.svm_cid);

    while (1) {
        ssize_t n = read(client_fd, buf, sizeof(buf));
        if (n <= 0)
            break;

        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(client_fd, buf + written, n - written);
            if (w <= 0)
                break;
            written += w;
        }
    }

    printf("Connection closed.\n");
    close(client_fd);
    close(fd);
}

static void run_rtt_sender(int peer_cid, int count)
{
    char buf[64] = "PING";
    time_t *rtts;
    int fd;
    int i;

    printf("=== RTT Test: Sender ===\n");
    printf("Connect to CID %d, port %u\n", peer_cid, port);
    printf("Ping count: %d\n", count);

    fd = vsock_connect(peer_cid, port);
    if (fd < 0)
        exit(EXIT_FAILURE);

    rtts = malloc(sizeof(time_t) * count);
    if (!rtts) {
        fprintf(stderr, "malloc failed\n");
        exit(EXIT_FAILURE);
    }

    printf("Measuring RTT...\n");

    for (i = 0; i < count; i++) {
        time_t start = current_nsec();

        ssize_t sent = write(fd, buf, 4);
        if (sent != 4) {
            perror("write");
            break;
        }

        char recv_buf[64];
        ssize_t received = read(fd, recv_buf, 4);
        if (received != 4) {
            perror("read");
            break;
        }

        rtts[i] = current_nsec() - start;
    }

    /* Calculate statistics */
    time_t min_rtt = rtts[0], max_rtt = rtts[0], sum_rtt = 0;
    for (i = 0; i < count; i++) {
        if (rtts[i] < min_rtt) min_rtt = rtts[i];
        if (rtts[i] > max_rtt) max_rtt = rtts[i];
        sum_rtt += rtts[i];
    }
    time_t avg_rtt = sum_rtt / count;

    printf("\n=== Results ===\n");
    printf("Ping count: %d\n", count);
    printf("RTT min: %.3f us\n", (float)min_rtt / 1000.0);
    printf("RTT max: %.3f us\n", (float)max_rtt / 1000.0);
    printf("RTT avg: %.3f us\n", (float)avg_rtt / 1000.0);

    free(rtts);
    close(fd);
}

/* ==================== Main ==================== */

static const char optstring[] = "";
static const struct option longopts[] = {
    { .name = "help",      .has_arg = no_argument,       .val = 'H' },
    { .name = "sender",    .has_arg = required_argument, .val = 'S' },
    { .name = "port",      .has_arg = required_argument, .val = 'P' },
    { .name = "bytes",     .has_arg = required_argument, .val = 'M' },
    { .name = "buf-size",  .has_arg = required_argument, .val = 'B' },
    { .name = "rtt",       .has_arg = no_argument,       .val = 'T' },
    { .name = "count",     .has_arg = required_argument, .val = 'C' },
    {},
};

static void usage(void)
{
    printf("Usage: ./vsock_perf_simple [--help] [options]\n"
           "\n"
           "Simplified vsock benchmark for Asterinas.\n"
           "Runs in two modes: sender or receiver.\n"
           "\n"
           "Options:\n"
           "  --help              This message\n"
           "  --sender <cid>      Sender mode (receiver default)\n"
           "  --port <port>       Port (default %d)\n"
           "  --bytes <bytes>KMG  Bytes to send for throughput test (default %d)\n"
           "  --buf-size <bytes>  Buffer size (default %d)\n"
           "  --rtt               RTT test mode (default: throughput)\n"
           "  --count <n>         Ping count for RTT test (default %d)\n"
           "\n"
           "Examples:\n"
           "  Guest (receiver):  ./vsock_perf_simple\n"
           "  Host (sender):     ./vsock_perf_simple --sender 3 --bytes 10M\n"
           "\n"
           "  RTT test:\n"
           "  Guest (echo):      ./vsock_perf_simple --rtt\n"
           "  Host (ping):       ./vsock_perf_simple --rtt --sender 3 --count 1000\n"
           "\n",
           DEFAULT_PORT, DEFAULT_TO_SEND_BYTES,
           DEFAULT_BUF_SIZE_BYTES, DEFAULT_RTT_COUNT);
    exit(EXIT_FAILURE);
}

static long strtolx(const char *arg)
{
    long value;
    char *end;
    value = strtol(arg, &end, 10);
    if (end != arg + strlen(arg))
        usage();
    return value;
}

int main(int argc, char **argv)
{
    unsigned long to_send_bytes = DEFAULT_TO_SEND_BYTES;
    int rtt_count = DEFAULT_RTT_COUNT;
    int peer_cid = -1;
    bool sender = false;
    bool rtt_mode = false;

    while (1) {
        int opt = getopt_long(argc, argv, optstring, longopts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'P':
            port = strtolx(optarg);
            break;
        case 'M':
            to_send_bytes = memparse(optarg);
            break;
        case 'B':
            buf_size_bytes = memparse(optarg);
            break;
        case 'S':
            peer_cid = strtolx(optarg);
            sender = true;
            break;
        case 'T':
            rtt_mode = true;
            break;
        case 'C':
            rtt_count = strtolx(optarg);
            break;
        case 'H':
        default:
            usage();
        }
    }

    if (rtt_mode) {
        if (sender)
            run_rtt_sender(peer_cid, rtt_count);
        else
            run_rtt_receiver();
    } else {
        if (sender)
            run_throughput_sender(peer_cid, to_send_bytes);
        else
            run_throughput_receiver();
    }

    return 0;
}
