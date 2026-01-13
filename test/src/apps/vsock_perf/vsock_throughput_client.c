// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

/*
 * VSOCK Throughput Test Client (Guest -> Host)
 *
 * This program measures the throughput of vsock communication
 * from guest to host with varying message sizes.
 *
 * Usage: vsock_throughput_client [host_cid] [port]
 *   - host_cid: CID of the host (default: 2, VMADDR_CID_HOST)
 *   - port: Port number (default: 5000)
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT 5000
#define MIN_MSG_SIZE 64
#define MAX_MSG_SIZE (1024 * 1024) // 1MB
#define TOTAL_DATA_SIZE (64 * 1024 * 1024) // 64MB per test
#define ACK_SIZE 4

// Message sizes to test (exponential: 64, 128, 256, ..., 1MB)
static const size_t MSG_SIZES[] = {
	64,	   128,	    256,     512,     1024,    2048,
	4096,	   8192,    16384,   32768,   65536,   131072,
	262144,	   524288,  1048576
};
#define NUM_MSG_SIZES (sizeof(MSG_SIZES) / sizeof(MSG_SIZES[0]))

static double get_time_sec(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static const char *format_size(size_t size, char *buf, size_t buf_len)
{
	if (size >= 1024 * 1024) {
		snprintf(buf, buf_len, "%zuMB", size / (1024 * 1024));
	} else if (size >= 1024) {
		snprintf(buf, buf_len, "%zuKB", size / 1024);
	} else {
		snprintf(buf, buf_len, "%zuB", size);
	}
	return buf;
}

static int run_throughput_test(int cid, int port, size_t msg_size,
			       double *throughput_gbps)
{
	int sock;
	struct sockaddr_vm addr;
	char *buffer;
	char ack[ACK_SIZE];
	size_t total_sent = 0;
	size_t iterations;
	double start_time, end_time, elapsed;
	ssize_t ret;

	// Calculate iterations to send at least TOTAL_DATA_SIZE bytes
	iterations = (TOTAL_DATA_SIZE + msg_size - 1) / msg_size;
	if (iterations < 10)
		iterations = 10; // At least 10 iterations

	// Allocate buffer
	buffer = malloc(msg_size);
	if (!buffer) {
		perror("malloc");
		return -1;
	}
	memset(buffer, 'A', msg_size);

	// Create socket
	sock = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		free(buffer);
		return -1;
	}

	// Connect to host
	memset(&addr, 0, sizeof(addr));
	addr.svm_family = AF_VSOCK;
	addr.svm_cid = cid;
	addr.svm_port = port;

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		close(sock);
		free(buffer);
		return -1;
	}

	// Send message size first (as 8-byte value)
	uint64_t size_to_send = msg_size;
	if (send(sock, &size_to_send, sizeof(size_to_send), 0) !=
	    sizeof(size_to_send)) {
		perror("send size");
		close(sock);
		free(buffer);
		return -1;
	}

	// Send iteration count
	uint64_t iter_to_send = iterations;
	if (send(sock, &iter_to_send, sizeof(iter_to_send), 0) !=
	    sizeof(iter_to_send)) {
		perror("send iterations");
		close(sock);
		free(buffer);
		return -1;
	}

	// Start timing
	start_time = get_time_sec();

	// Send data
	for (size_t i = 0; i < iterations; i++) {
		size_t sent = 0;
		while (sent < msg_size) {
			ret = send(sock, buffer + sent, msg_size - sent, 0);
			if (ret < 0) {
				perror("send");
				close(sock);
				free(buffer);
				return -1;
			}
			sent += ret;
		}
		total_sent += msg_size;
	}

	// Wait for ACK
	ret = recv(sock, ack, ACK_SIZE, MSG_WAITALL);
	if (ret != ACK_SIZE) {
		perror("recv ack");
		close(sock);
		free(buffer);
		return -1;
	}

	// Stop timing
	end_time = get_time_sec();
	elapsed = end_time - start_time;

	// Calculate throughput in GB/s
	*throughput_gbps = (double)total_sent / elapsed / (1024.0 * 1024.0 * 1024.0);

	close(sock);
	free(buffer);
	return 0;
}

int main(int argc, char *argv[])
{
	int cid = VMADDR_CID_HOST;
	int port = DEFAULT_PORT;
	char size_buf[32];

	if (argc >= 2) {
		cid = atoi(argv[1]);
	}
	if (argc >= 3) {
		port = atoi(argv[2]);
	}

	printf("=== VSOCK Throughput Test (Guest -> Host) ===\n");
	printf("Target: CID=%d, Port=%d\n", cid, port);
	printf("Data per test: %d MB\n", TOTAL_DATA_SIZE / (1024 * 1024));
	printf("----------------------------------------------\n");

	for (size_t i = 0; i < NUM_MSG_SIZES; i++) {
		size_t msg_size = MSG_SIZES[i];
		double throughput;

		if (run_throughput_test(cid, port, msg_size, &throughput) == 0) {
			printf("Size: %-8s Throughput: %.2f GB/s\n",
			       format_size(msg_size, size_buf, sizeof(size_buf)),
			       throughput);
		} else {
			printf("Size: %-8s FAILED\n",
			       format_size(msg_size, size_buf, sizeof(size_buf)));
		}
	}

	printf("----------------------------------------------\n");
	printf("Test completed.\n");

	return 0;
}
