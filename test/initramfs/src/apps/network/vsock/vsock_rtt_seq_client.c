/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * Vsock RTT Sequenced Client (for segment decomposition)
 *
 * This client sends one in-flight request at a time and records per-seq user
 * timestamps so kernel-side events can be aligned in post-analysis.
 *
 * Usage:
 *   ./vsock_rtt_seq_client <target_cid> [port] [iterations] [payload_bytes] [csv_path] [start_delay_ms]
 *
 * Example:
 *   ./vsock_rtt_seq_client 2 20002 100000 4 /tmp/client_user.csv 1500
 */

#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT 20002
#define DEFAULT_ITERATIONS 100000
#define MAX_ITERATIONS 1000000
#define DEFAULT_PAYLOAD_BYTES 4
#define MAX_PAYLOAD_BYTES (1024 * 1024)

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

struct msg_hdr {
	uint64_t seq;
	uint8_t dir; // 0: request (client->server), 1: response
	uint8_t reserved[7];
	uint32_t payload_len;
} __attribute__((packed));

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static ssize_t write_full(int fd, const void *buf, size_t len)
{
	size_t off = 0;
	const char *p = (const char *)buf;

	while (off < len) {
		ssize_t n = send(fd, p + off, len - off, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		off += (size_t)n;
	}

	return (ssize_t)off;
}

static ssize_t read_full(int fd, void *buf, size_t len)
{
	size_t off = 0;
	char *p = (char *)buf;

	while (off < len) {
		ssize_t n = recv(fd, p + off, len - off, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return 0;
		off += (size_t)n;
	}

	return (ssize_t)off;
}

static void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <target_cid> [port] [iterations] [payload_bytes] [csv_path] [start_delay_ms]\n",
		prog);
}

int main(int argc, char *argv[])
{
	unsigned int target_cid;
	unsigned int port = DEFAULT_PORT;
	int iterations = DEFAULT_ITERATIONS;
	size_t payload_bytes = DEFAULT_PAYLOAD_BYTES;
	FILE *csv = stdout;
	int fd;
	int completed = 0;
	uint64_t rtt_sum_ns = 0;
	unsigned int start_delay_ms = 0;

	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	target_cid = (unsigned int)strtoul(argv[1], NULL, 10);
	if (argc > 2)
		port = (unsigned int)strtoul(argv[2], NULL, 10);
	if (argc > 3) {
		iterations = atoi(argv[3]);
		if (iterations <= 0 || iterations > MAX_ITERATIONS) {
			fprintf(stderr, "iterations must be in [1, %d]\n",
				MAX_ITERATIONS);
			return 1;
		}
	}
	if (argc > 4) {
		payload_bytes = (size_t)strtoull(argv[4], NULL, 10);
		if (payload_bytes > MAX_PAYLOAD_BYTES) {
			fprintf(stderr, "payload_bytes too large (max %d)\n",
				MAX_PAYLOAD_BYTES);
			return 1;
		}
	}
	if (argc > 5) {
		csv = fopen(argv[5], "w");
		if (!csv) {
			perror("fopen csv");
			return 1;
		}
	}
	if (argc > 6) {
		start_delay_ms = (unsigned int)strtoul(argv[6], NULL, 10);
	}

	size_t msg_len = sizeof(struct msg_hdr) + payload_bytes;
	unsigned char *send_buf = (unsigned char *)malloc(msg_len);
	unsigned char *recv_buf = (unsigned char *)malloc(msg_len);
	if (!send_buf || !recv_buf) {
		perror("malloc");
		if (csv != stdout)
			fclose(csv);
		free(send_buf);
		free(recv_buf);
		return 1;
	}

	memset(send_buf, 0, msg_len);
	memset(recv_buf, 0, msg_len);

	fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		if (csv != stdout)
			fclose(csv);
		free(send_buf);
		free(recv_buf);
		return 1;
	}

	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_reserved1 = 0,
		.svm_port = port,
		.svm_cid = target_cid,
	};

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		close(fd);
		if (csv != stdout)
			fclose(csv);
		free(send_buf);
		free(recv_buf);
		return 1;
	}

	fprintf(stderr,
		"Connected to CID %u:%u, iterations=%d payload=%zu bytes start_delay_ms=%u\n",
		target_cid, port, iterations, payload_bytes, start_delay_ms);

	if (start_delay_ms > 0) {
		struct timespec ts = {
			.tv_sec = start_delay_ms / 1000,
			.tv_nsec = (long)(start_delay_ms % 1000) * 1000000L,
		};
		nanosleep(&ts, NULL);
	}

	fprintf(csv,
		"seq,send_pre_ns,send_post_ns,recv_ret_ns,rtt_ns,send_ns,recv_wait_ns,msg_bytes\n");

	for (int i = 0; i < iterations; i++) {
		struct msg_hdr *tx = (struct msg_hdr *)send_buf;
		struct msg_hdr *rx = (struct msg_hdr *)recv_buf;
		uint64_t send_pre_ns;
		uint64_t send_post_ns;
		uint64_t recv_ret_ns;
		uint64_t rtt_ns;
		uint64_t send_ns;
		uint64_t recv_wait_ns;

		tx->seq = (uint64_t)i;
		tx->dir = 0;
		tx->payload_len = (uint32_t)payload_bytes;

		send_pre_ns = now_ns();
		if (write_full(fd, send_buf, msg_len) < 0) {
			perror("send");
			break;
		}
		send_post_ns = now_ns();

		if (read_full(fd, recv_buf, msg_len) <= 0) {
			perror("recv");
			break;
		}
		recv_ret_ns = now_ns();

		if (rx->seq != tx->seq || rx->dir != 1 ||
		    rx->payload_len != tx->payload_len) {
			fprintf(stderr,
				"protocol mismatch seq=%" PRIu64
				" got(seq=%" PRIu64 ",dir=%u,payload=%u)\n",
				tx->seq, rx->seq, (unsigned int)rx->dir,
				rx->payload_len);
			break;
		}

		send_ns = send_post_ns - send_pre_ns;
		rtt_ns = recv_ret_ns - send_pre_ns;
		recv_wait_ns = recv_ret_ns - send_post_ns;

		fprintf(csv,
			"%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
			",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%zu\n",
			tx->seq, send_pre_ns, send_post_ns, recv_ret_ns, rtt_ns,
			send_ns, recv_wait_ns, msg_len);

		rtt_sum_ns += rtt_ns;
		completed++;
	}

	fflush(csv);
	close(fd);
	if (csv != stdout)
		fclose(csv);
	free(send_buf);
	free(recv_buf);

	if (completed == 0) {
		fprintf(stderr, "no samples collected\n");
		return 1;
	}

	fprintf(stderr, "completed=%d avg_rtt=%.3f us\n", completed,
		(double)rtt_sum_ns / (double)completed / 1000.0);
	return (completed == iterations) ? 0 : 1;
}
