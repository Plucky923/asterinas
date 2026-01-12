/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * Vsock RTT Sequenced Server (for segment decomposition)
 *
 * The server receives request messages (dir=0), records user-side receive/send
 * timestamps, and replies with dir=1 using the same seq/payload.
 *
 * Usage:
 *   ./vsock_rtt_seq_server [port] [payload_bytes] [csv_path]
 *
 * Example:
 *   ./vsock_rtt_seq_server 20002 4 /tmp/server_user.csv
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

int main(int argc, char *argv[])
{
	unsigned int port = DEFAULT_PORT;
	size_t payload_bytes = DEFAULT_PAYLOAD_BYTES;
	FILE *csv = stdout;
	int listen_fd;

	if (argc > 1)
		port = (unsigned int)strtoul(argv[1], NULL, 10);
	if (argc > 2) {
		payload_bytes = (size_t)strtoull(argv[2], NULL, 10);
		if (payload_bytes > MAX_PAYLOAD_BYTES) {
			fprintf(stderr, "payload_bytes too large (max %d)\n",
				MAX_PAYLOAD_BYTES);
			return 1;
		}
	}
	if (argc > 3) {
		csv = fopen(argv[3], "w");
		if (!csv) {
			perror("fopen csv");
			return 1;
		}
	}

	size_t msg_len = sizeof(struct msg_hdr) + payload_bytes;
	unsigned char *buf = (unsigned char *)malloc(msg_len);
	if (!buf) {
		perror("malloc");
		if (csv != stdout)
			fclose(csv);
		return 1;
	}
	memset(buf, 0, msg_len);

	listen_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		perror("socket");
		free(buf);
		if (csv != stdout)
			fclose(csv);
		return 1;
	}

	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_reserved1 = 0,
		.svm_port = port,
		.svm_cid = VMADDR_CID_ANY,
	};

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(listen_fd);
		free(buf);
		if (csv != stdout)
			fclose(csv);
		return 1;
	}

	if (listen(listen_fd, 1) < 0) {
		perror("listen");
		close(listen_fd);
		free(buf);
		if (csv != stdout)
			fclose(csv);
		return 1;
	}

	fprintf(stderr, "listening on port %u payload=%zu bytes\n", port,
		payload_bytes);
	fprintf(csv,
		"seq,req_recv_ret_ns,resp_send_pre_ns,resp_send_post_ns,msg_bytes\n");

	for (;;) {
		struct sockaddr_vm peer_addr;
		socklen_t peer_len = sizeof(peer_addr);
		int client_fd;
		unsigned long long count = 0;

		client_fd = accept(listen_fd, (struct sockaddr *)&peer_addr,
				   &peer_len);
		if (client_fd < 0) {
			perror("accept");
			continue;
		}

		fprintf(stderr, "accepted CID=%u port=%u\n", peer_addr.svm_cid,
			peer_addr.svm_port);

		for (;;) {
			struct msg_hdr *h = (struct msg_hdr *)buf;
			uint64_t req_recv_ret_ns;
			uint64_t resp_send_pre_ns;
			uint64_t resp_send_post_ns;

			ssize_t n = read_full(client_fd, buf, msg_len);
			if (n <= 0)
				break;

			req_recv_ret_ns = now_ns();

			if (h->payload_len != payload_bytes || h->dir != 0) {
				fprintf(stderr,
					"protocol mismatch: seq=%" PRIu64
					" dir=%u payload=%u\n",
					h->seq, (unsigned int)h->dir,
					h->payload_len);
				break;
			}

			h->dir = 1;
			resp_send_pre_ns = now_ns();
			if (write_full(client_fd, buf, msg_len) < 0) {
				perror("send");
				break;
			}
			resp_send_post_ns = now_ns();

			fprintf(csv,
				"%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64
				",%zu\n",
				h->seq, req_recv_ret_ns, resp_send_pre_ns,
				resp_send_post_ns, msg_len);
			count++;
		}

		fflush(csv);
		fprintf(stderr, "session ended count=%llu\n", count);
		close(client_fd);
	}

	close(listen_fd);
	free(buf);
	if (csv != stdout)
		fclose(csv);
	return 0;
}
