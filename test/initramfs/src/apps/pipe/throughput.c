// SPDX-License-Identifier: MPL-2.0

/*
 * Pipe Throughput Benchmark
 *
 * This program measures pipe throughput using various buffer sizes.
 * Similar to FrameVsock throughput test, it outputs results in Gbits/s.
 *
 * Tests buffer sizes from 64B to 1MB.
 */

#define _GNU_SOURCE

#include "../test.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TOTAL_BYTES (100 * 1024 * 1024ULL) // 100 MB total transfer
#define MAX_BUF_SIZE (1024 * 1024)         // 1 MB max buffer

static char tx_buffer[MAX_BUF_SIZE];
static char rx_buffer[MAX_BUF_SIZE];

// Buffer sizes to test: 64B, 128B, 256B, 512B, 1K, 2K, 4K, 8K, 16K, 32K, 64K, 128K, 256K, 512K, 1M
static const size_t buffer_sizes[] = {
	64,
	128,
	256,
	512,
	1024,
	2 * 1024,
	4 * 1024,
	8 * 1024,
	16 * 1024,
	32 * 1024,
	64 * 1024,
	128 * 1024,
	256 * 1024,
	512 * 1024,
	1024 * 1024,
};
static const int num_sizes = sizeof(buffer_sizes) / sizeof(buffer_sizes[0]);

static double get_time_sec(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec + tv.tv_usec / 1000000.0;
}

static const char *format_size(size_t size)
{
	static char buf[32];
	if (size >= 1024 * 1024) {
		snprintf(buf, sizeof(buf), "%zuMB", size / (1024 * 1024));
	} else if (size >= 1024) {
		snprintf(buf, sizeof(buf), "%zuKB", size / 1024);
	} else {
		snprintf(buf, sizeof(buf), "%zuB", size);
	}
	return buf;
}

static int run_throughput_test(size_t buf_size, double *throughput_gbps)
{
	int pipe_fd[2];
	int result_fd[2]; // Pipe to send result from receiver to parent
	pid_t pid;
	unsigned long long total_to_send = TOTAL_BYTES;

	if (pipe(pipe_fd) < 0) {
		perror("pipe");
		return -1;
	}

	if (pipe(result_fd) < 0) {
		perror("result pipe");
		close(pipe_fd[0]);
		close(pipe_fd[1]);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(pipe_fd[0]);
		close(pipe_fd[1]);
		close(result_fd[0]);
		close(result_fd[1]);
		return -1;
	}

	if (pid == 0) {
		// Child process: receiver (measures throughput)
		close(pipe_fd[1]); // Close write end of data pipe
		close(result_fd[0]); // Close read end of result pipe

		unsigned long long bytes_received = 0;
		double start = get_time_sec();

		while (bytes_received < total_to_send) {
			ssize_t n = read(pipe_fd[0], rx_buffer, buf_size);
			if (n <= 0)
				break;
			bytes_received += n;
		}

		double end = get_time_sec();
		double duration = end - start;

		// Calculate throughput in Gbits/s
		double throughput = (bytes_received * 8.0) / duration / 1e9;

		// Send result back to parent
		(void)!write(result_fd[1], &throughput, sizeof(throughput));

		close(pipe_fd[0]);
		close(result_fd[1]);
		_exit(0);
	}

	// Parent process: sender
	close(pipe_fd[0]); // Close read end of data pipe
	close(result_fd[1]); // Close write end of result pipe

	unsigned long long bytes_sent = 0;

	while (bytes_sent < total_to_send) {
		size_t to_send = buf_size;
		if (total_to_send - bytes_sent < buf_size) {
			to_send = total_to_send - bytes_sent;
		}

		ssize_t ret = write(pipe_fd[1], tx_buffer, to_send);
		if (ret < 0) {
			perror("write");
			close(pipe_fd[1]);
			close(result_fd[0]);
			waitpid(pid, NULL, 0);
			return -1;
		}
		bytes_sent += ret;
	}

	close(pipe_fd[1]);

	// Read throughput result from receiver
	if (read(result_fd[0], throughput_gbps, sizeof(*throughput_gbps)) !=
	    sizeof(*throughput_gbps)) {
		perror("read result");
		close(result_fd[0]);
		waitpid(pid, NULL, 0);
		return -1;
	}

	close(result_fd[0]);

	// Wait for child
	int status;
	waitpid(pid, &status, 0);

	return 0;
}

FN_TEST(pipe_throughput_test)
{
	// Initialize buffer
	for (size_t i = 0; i < MAX_BUF_SIZE; i++) {
		tx_buffer[i] = (char)(i & 0xFF);
	}

	printf("\n");
	printf("========================================\n");
	printf(" Pipe Throughput Benchmark\n");
	printf("========================================\n");
	printf(" Total:       %llu bytes per test\n", TOTAL_BYTES);
	printf("----------------------------------------\n");
	printf(" %-10s | %15s\n", "Buffer", "Throughput");
	printf("----------------------------------------\n");

	int all_passed = 1;

	for (int i = 0; i < num_sizes; i++) {
		size_t buf_size = buffer_sizes[i];
		double throughput;

		if (run_throughput_test(buf_size, &throughput) == 0) {
			printf(" %-10s | %12.6f Gbps\n", format_size(buf_size),
			       throughput);
		} else {
			printf(" %-10s | %15s\n", format_size(buf_size),
			       "FAILED");
			all_passed = 0;
		}
		fflush(stdout);
	}

	printf("========================================\n");
	printf("\n");

	TEST_RES(all_passed, _ret != 0);
}
END_TEST()
