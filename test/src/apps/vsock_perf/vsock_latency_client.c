// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT 5001
#define DEFAULT_ITERATIONS 10000
#define MSG_SIZE 64

static int compare_double(const void *a, const void *b)
{
	double da = *(const double *)a;
	double db = *(const double *)b;
	if (da < db)
		return -1;
	if (da > db)
		return 1;
	return 0;
}

static double get_time_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static double percentile(double *sorted_data, size_t n, double p)
{
	double index = (p / 100.0) * (n - 1);
	size_t lower = (size_t)index;
	size_t upper = lower + 1;
	double frac = index - lower;

	if (upper >= n)
		return sorted_data[n - 1];
	return sorted_data[lower] * (1 - frac) + sorted_data[upper] * frac;
}

int main(int argc, char *argv[])
{
	int sock;
	struct sockaddr_vm addr;
	int cid = VMADDR_CID_HOST;
	int port = DEFAULT_PORT;
	size_t iterations = DEFAULT_ITERATIONS;
	char send_buf[MSG_SIZE];
	char recv_buf[MSG_SIZE];
	double *latencies;
	double start_time, end_time;
	double total_latency = 0;
	double min_latency = 1e9;
	double max_latency = 0;
	ssize_t ret;

	// Parse arguments
	if (argc >= 2) {
		cid = atoi(argv[1]);
	}
	if (argc >= 3) {
		port = atoi(argv[2]);
	}
	if (argc >= 4) {
		iterations = atoi(argv[3]);
		if (iterations < 100)
			iterations = 100;
	}

	// Allocate latency array
	latencies = malloc(iterations * sizeof(double));
	if (!latencies) {
		perror("malloc");
		return 1;
	}

	// Initialize send buffer
	memset(send_buf, 'P', MSG_SIZE);

	// Create socket
	sock = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		free(latencies);
		return 1;
	}

	// Connect to host
	memset(&addr, 0, sizeof(addr));
	addr.svm_family = AF_VSOCK;
	addr.svm_cid = cid;
	addr.svm_port = port;

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		close(sock);
		free(latencies);
		return 1;
	}

	printf("=== VSOCK Latency Test (Guest -> Host) ===\n");
	printf("Target: CID=%d, Port=%d\n", cid, port);
	printf("Iterations: %zu\n", iterations);
	printf("Message Size: %d bytes\n", MSG_SIZE);
	printf("------------------------------------------\n");
	printf("Running latency test...\n");

	// Warm-up: do a few iterations without recording
	for (int i = 0; i < 100; i++) {
		if (send(sock, send_buf, MSG_SIZE, 0) != MSG_SIZE) {
			perror("send (warmup)");
			close(sock);
			free(latencies);
			return 1;
		}
		if (recv(sock, recv_buf, MSG_SIZE, MSG_WAITALL) != MSG_SIZE) {
			perror("recv (warmup)");
			close(sock);
			free(latencies);
			return 1;
		}
	}

	// Run latency test
	for (size_t i = 0; i < iterations; i++) {
		start_time = get_time_us();

		// Send ping
		ret = send(sock, send_buf, MSG_SIZE, 0);
		if (ret != MSG_SIZE) {
			perror("send");
			close(sock);
			free(latencies);
			return 1;
		}

		// Receive pong
		ret = recv(sock, recv_buf, MSG_SIZE, MSG_WAITALL);
		if (ret != MSG_SIZE) {
			perror("recv");
			close(sock);
			free(latencies);
			return 1;
		}

		end_time = get_time_us();
		double latency = end_time - start_time;
		latencies[i] = latency;
		total_latency += latency;

		if (latency < min_latency)
			min_latency = latency;
		if (latency > max_latency)
			max_latency = latency;
	}

	// Signal end of test (first byte 'E' is the marker)
	memset(send_buf, 'E', MSG_SIZE);
	send(sock, send_buf, MSG_SIZE, 0);

	close(sock);

	// Sort latencies for percentile calculation
	qsort(latencies, iterations, sizeof(double), compare_double);

	// Calculate statistics
	double p50 = percentile(latencies, iterations, 50);
	double p95 = percentile(latencies, iterations, 95);
	double p99 = percentile(latencies, iterations, 99);
	double avg = total_latency / iterations;

	// Print results
	printf("------------------------------------------\n");
	printf("P50 (Median):  %.2f us\n", p50);
	printf("P95:           %.2f us\n", p95);
	printf("P99:           %.2f us\n", p99);
	printf("Min:           %.2f us\n", min_latency);
	printf("Max:           %.2f us\n", max_latency);
	printf("Avg:           %.2f us\n", avg);
	printf("------------------------------------------\n");
	printf("Test completed.\n");

	free(latencies);
	return 0;
}
