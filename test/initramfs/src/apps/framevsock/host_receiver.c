/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * FrameVsock Throughput Benchmark (Asterinas Host Receiver)
 *
 * This program runs on Asterinas Host and receives data from FrameVM Guest.
 * Uses AF_FRAMEVSOCK (46) for FrameVsock communication.
 *
 * Usage: ./host_receiver [port] [buf_size]
 * Example: ./host_receiver 20001 65536
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>

// FrameVsock constants (not in standard headers)
#define AF_FRAMEVSOCK 46
#define VMADDR_CID_ANY ((unsigned long long)-1)
#define VMADDR_CID_HOST 2

// sockaddr_vm structure for FrameVsock
// Note: svm_cid must be uint64_t to match kernel's CSocketAddrFrameVsock
struct sockaddr_vm {
	unsigned short svm_family;
	unsigned short svm_reserved1;
	unsigned int svm_port;
	unsigned long long svm_cid; // 64-bit CID to match kernel definition
};

#define DEFAULT_PORT 20001
#define DEFAULT_BUF_SIZE (64 * 1024)
#define MAX_BUF_SIZE (1024 * 1024)

static char rx_buffer[MAX_BUF_SIZE];

static double get_time_sec(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec + tv.tv_usec / 1000000.0;
}

int main(int argc, char *argv[])
{
	int port = DEFAULT_PORT;
	size_t buf_size = DEFAULT_BUF_SIZE;

	if (argc > 1) {
		port = atoi(argv[1]);
	}
	if (argc > 2) {
		buf_size = (size_t)atol(argv[2]);
		if (buf_size == 0 || buf_size > MAX_BUF_SIZE) {
			fprintf(stderr,
				"Error: buf_size must be between 1 and %d\n",
				MAX_BUF_SIZE);
			return 1;
		}
	}

	printf("\n========================================\n");
	printf(" FrameVsock Throughput Benchmark - Receiver\n");
	printf("========================================\n");
	printf(" Port:        %d\n", port);
	printf(" RX Buffer:   %zu bytes\n", buf_size);
	printf("----------------------------------------\n");

	int listen_fd = socket(AF_FRAMEVSOCK, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		perror("socket");
		return 1;
	}

	struct sockaddr_vm addr = {
		.svm_family = AF_FRAMEVSOCK,
		.svm_reserved1 = 0,
		.svm_port = port,
		.svm_cid = VMADDR_CID_ANY,
	};

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(listen_fd);
		return 1;
	}

	if (listen(listen_fd, 1) < 0) {
		perror("listen");
		close(listen_fd);
		return 1;
	}

	printf(" Listening on port %d...\n", port);

	while (1) {
		struct sockaddr_vm peer_addr;
		socklen_t peer_len = sizeof(peer_addr);

		printf(" Waiting for connection...\n");

		int client_fd = accept(listen_fd, (struct sockaddr *)&peer_addr,
				       &peer_len);
		if (client_fd < 0) {
			perror("accept");
			continue;
		}

		printf(" Connection from CID %llu, port %u\n",
		       (unsigned long long)peer_addr.svm_cid,
		       peer_addr.svm_port);
		printf(" Receiving data...\n");

		unsigned long long total_bytes = 0;
		unsigned long long read_count = 0;
		double total_read_time = 0.0;
		double start = get_time_sec();

		while (1) {
			double read_start = get_time_sec();
			ssize_t n = recv(client_fd, rx_buffer, buf_size, 0);
			double read_end = get_time_sec();

			if (n <= 0)
				break;

			total_bytes += n;
			read_count++;
			total_read_time += (read_end - read_start);
		}

		double end = get_time_sec();
		double duration = end - start;

		// Calculate statistics
		double gbits = 0.0;
		double avg_read_us = 0.0;

		if (duration > 0) {
			gbits = (total_bytes * 8.0) / duration / 1e9;
		}
		if (read_count > 0) {
			avg_read_us = (total_read_time / read_count) * 1e6;
		}

		printf("----------------------------------------\n");
		printf(" Results:\n");
		printf("   Bytes:      %llu\n", total_bytes);
		printf("   Throughput: %.6f Gbits/s\n", gbits);
		printf("   Duration:   %.6f sec\n", duration);
		printf("   Read calls: %llu\n", read_count);
		printf("   Avg read:   %.2f us\n", avg_read_us);
		printf("========================================\n\n");

		close(client_fd);
	}

	close(listen_fd);
	return 0;
}
