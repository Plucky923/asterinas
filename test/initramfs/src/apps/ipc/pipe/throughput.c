// SPDX-License-Identifier: MPL-2.0

/*
 * Pipe Throughput Benchmark
 *
 * This program measures pipe throughput using various buffer sizes.
 * Uses rdtsc for cycle-accurate timing to enable fair comparison with
 * other IPC mechanisms (unix socket, vsock, framevsock).
 *
 * Tests buffer sizes from 64B to 1MB.
 */

#define _GNU_SOURCE

#include "../../rdtsc_timing.h"
#include "../../common/test.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TOTAL_PACKETS 100000U // packets per test (same for all buffer sizes)
#define WARMUP_PACKETS 10000U // warmup packets (not measured)
#define MAX_BUF_SIZE (1024 * 1024) // 1 MB max buffer

static char tx_buffer[MAX_BUF_SIZE];
static char rx_buffer[MAX_BUF_SIZE];

// Buffer sizes to test: 64B, 128B, 256B, 512B, 1K, 2K, 4K, 8K, 16K, 32K, 64K, 128K, 256K, 512K, 1M
static const size_t buffer_sizes[] = {
	64,	   128,	       256,	   512,	       1024,
	2 * 1024,  4 * 1024,   8 * 1024,   16 * 1024,  32 * 1024,
	64 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024,
};
static const int num_sizes = sizeof(buffer_sizes) / sizeof(buffer_sizes[0]);

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

/* Result structure to pass from child to parent */
struct bench_result {
	uint64_t bytes;
	uint64_t cycles;
};

static int run_throughput_test(size_t buf_size, double *throughput_gbps,
			       uint64_t *out_cycles)
{
	int pipe_fd[2];
	int result_fd[2]; // Pipe to send result from receiver to parent
	pid_t pid;
	unsigned long long total_to_send =
		(unsigned long long)buf_size * TOTAL_PACKETS;
	unsigned long long warmup_threshold =
		(unsigned long long)buf_size * WARMUP_PACKETS;

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
		unsigned long long warmup_bytes = 0;
		uint64_t start_cycles = 0, end_cycles;
		int started = 0;

		while (bytes_received < total_to_send) {
			ssize_t n = read(pipe_fd[0], rx_buffer, buf_size);
			if (n <= 0)
				break;

			bytes_received += n;

			// Warmup phase: don't start timing until warmup complete
			if (!started && bytes_received >= warmup_threshold) {
				start_cycles = rdtsc_fenced();
				warmup_bytes = bytes_received;
				started = 1;
			}
		}

		end_cycles = rdtsc_fenced();

		struct bench_result result;
		// Only count bytes after warmup
		result.bytes = started ? (bytes_received - warmup_bytes) : 0;
		result.cycles = started ? (end_cycles - start_cycles) : 0;

		// Send result back to parent
		(void)!write(result_fd[1], &result, sizeof(result));

		close(pipe_fd[0]);
		close(result_fd[1]);
		_exit(0);
	}

	// Parent process: sender
	close(pipe_fd[0]); // Close read end of data pipe
	close(result_fd[1]); // Close write end of result pipe

	unsigned int packets_sent = 0;

	while (packets_sent < TOTAL_PACKETS) {
		size_t offset = 0;
		while (offset < buf_size) {
			ssize_t ret = write(pipe_fd[1], tx_buffer + offset,
					    buf_size - offset);
			if (ret < 0) {
				perror("write");
				close(pipe_fd[1]);
				close(result_fd[0]);
				waitpid(pid, NULL, 0);
				return -1;
			}
			offset += (size_t)ret;
		}
		packets_sent++;
	}

	close(pipe_fd[1]);

	// Read result from receiver
	struct bench_result result;
	if (read(result_fd[0], &result, sizeof(result)) != sizeof(result)) {
		perror("read result");
		close(result_fd[0]);
		waitpid(pid, NULL, 0);
		return -1;
	}

	close(result_fd[0]);

	// Wait for child
	int status;
	waitpid(pid, &status, 0);

	// Calculate throughput
	*throughput_gbps = cycles_to_gbps(result.bytes, result.cycles);
	*out_cycles = result.cycles;

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
	printf(" Pipe Throughput Benchmark (rdtsc)\n");
	printf("========================================\n");
	printf(" Packets:     %u per test\n", TOTAL_PACKETS);
	printf(" Warmup:      %u packets (not measured)\n", WARMUP_PACKETS);
	printf(" Measured:    %u packets\n",
	       (unsigned)(TOTAL_PACKETS - WARMUP_PACKETS));
	printf(" CPU MHz:     %d (for Gbps calculation)\n", CPU_MHZ);
	printf("----------------------------------------\n");
	printf(" %-10s | %15s | %15s\n", "Buffer", "Throughput", "Cycles");
	printf("----------------------------------------\n");

	int all_passed = 1;

	for (int i = 0; i < num_sizes; i++) {
		size_t buf_size = buffer_sizes[i];
		double throughput;
		uint64_t cycles;

		if (run_throughput_test(buf_size, &throughput, &cycles) == 0) {
			printf(" %-10s | %12.6f Gbps | %15llu\n",
			       format_size(buf_size), throughput,
			       (unsigned long long)cycles);
		} else {
			printf(" %-10s | %15s | %15s\n", format_size(buf_size),
			       "FAILED", "-");
			all_passed = 0;
		}
		fflush(stdout);
	}

	printf("========================================\n");
	printf("\n");

	TEST_RES(all_passed, _ret != 0);
}
END_TEST()
