// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

#include "../test.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RTT_ITERATIONS 10000
#define BUFFER_SIZE 64

// Calculate time difference in microseconds
static long long timespec_diff_us(struct timespec *start, struct timespec *end)
{
	long long sec_diff = end->tv_sec - start->tv_sec;
	long long nsec_diff = end->tv_nsec - start->tv_nsec;
	return sec_diff * 1000000LL + nsec_diff / 1000LL;
}

FN_TEST(pipe_rtt_test)
{
	int pipe_parent_to_child[2]; // Parent writes, child reads
	int pipe_child_to_parent[2]; // Child writes, parent reads
	pid_t pid;
	char send_buf[BUFFER_SIZE];
	char recv_buf[BUFFER_SIZE];
	struct timespec start_time, end_time;
	long long rtt_times[RTT_ITERATIONS];
	long long total_rtt = 0;
	long long min_rtt = LLONG_MAX;
	long long max_rtt = 0;
	long long avg_rtt;
	int i;

	// Initialize send buffer
	memset(send_buf, 'A', BUFFER_SIZE);

	// Create two pipes for bidirectional communication
	CHECK(pipe(pipe_parent_to_child));
	CHECK(pipe(pipe_child_to_parent));

	pid = fork();
	CHECK(pid);

	if (pid == 0) {
		// Child process: echo server
		// Close unused ends
		close(pipe_parent_to_child[1]); // Close write end of parent-to-child
		close(pipe_child_to_parent[0]); // Close read end of child-to-parent

		for (i = 0; i < RTT_ITERATIONS; i++) {
			ssize_t bytes_read, bytes_written;

			// Read from parent
			bytes_read = read(pipe_parent_to_child[0], recv_buf,
					  BUFFER_SIZE);
			if (bytes_read <= 0) {
				_exit(1);
			}

			// Echo back to parent immediately
			bytes_written = write(pipe_child_to_parent[1], recv_buf,
					      bytes_read);
			if (bytes_written != bytes_read) {
				_exit(1);
			}
		}

		close(pipe_parent_to_child[0]);
		close(pipe_child_to_parent[1]);
		_exit(0);
	}

	// Close unused ends
	close(pipe_parent_to_child[0]); // Close read end of parent-to-child
	close(pipe_child_to_parent[1]); // Close write end of child-to-parent

	// Perform RTT measurements
	for (i = 0; i < RTT_ITERATIONS; i++) {
		ssize_t bytes_written, bytes_read;

		// Record start time
		CHECK(clock_gettime(CLOCK_MONOTONIC, &start_time));

		// Send data to child
		bytes_written = write(pipe_parent_to_child[1], send_buf,
				      BUFFER_SIZE);
		CHECK_WITH(bytes_written, _ret == BUFFER_SIZE);

		// Receive echoed data from child
		bytes_read = read(pipe_child_to_parent[0], recv_buf,
				  BUFFER_SIZE);
		CHECK_WITH(bytes_read, _ret == BUFFER_SIZE);

		// Record end time
		CHECK(clock_gettime(CLOCK_MONOTONIC, &end_time));

		// Calculate RTT for this iteration
		rtt_times[i] = timespec_diff_us(&start_time, &end_time);
		total_rtt += rtt_times[i];

		// Update min and max
		if (rtt_times[i] < min_rtt) {
			min_rtt = rtt_times[i];
		}
		if (rtt_times[i] > max_rtt) {
			max_rtt = rtt_times[i];
		}
	}

	printf("\n========================================\n");
	printf(" Pipe RTT Benchmark\n");
	printf("========================================\n");
	printf(" Iterations: %d\n", RTT_ITERATIONS);
	printf(" Message:    %d byte(s)\n", BUFFER_SIZE);
	printf("----------------------------------------\n");
	printf(" Running %d ping-pong iterations...\n", RTT_ITERATIONS);

	// Close pipes
	close(pipe_parent_to_child[1]);
	close(pipe_child_to_parent[0]);

	// Wait for child process
	int status;
	CHECK(waitpid(pid, &status, 0));
	CHECK_WITH(WIFEXITED(status), _ret != 0);
	CHECK_WITH(WEXITSTATUS(status), _ret == 0);

	// Calculate average RTT
	avg_rtt = total_rtt / RTT_ITERATIONS;

	// Calculate percentiles (need to sort first)
	long long sorted_times[RTT_ITERATIONS];
	for (i = 0; i < RTT_ITERATIONS; i++) {
		sorted_times[i] = rtt_times[i];
	}

	// Simple bubble sort for percentile calculation
	for (i = 0; i < RTT_ITERATIONS - 1; i++) {
		for (int j = 0; j < RTT_ITERATIONS - i - 1; j++) {
			if (sorted_times[j] > sorted_times[j + 1]) {
				long long temp = sorted_times[j];
				sorted_times[j] = sorted_times[j + 1];
				sorted_times[j + 1] = temp;
			}
		}
	}

	long long p50 = sorted_times[RTT_ITERATIONS / 2];
	long long p90 = sorted_times[(int)(RTT_ITERATIONS * 0.90)];
	long long p99 = sorted_times[(int)(RTT_ITERATIONS * 0.99)];
	long long p999 = sorted_times[(int)(RTT_ITERATIONS * 0.999)];

	// Print results
	printf("\n========================================\n");
	printf(" Pipe RTT Benchmark\n");
	printf("========================================\n");
	printf(" Iterations: %d\n", RTT_ITERATIONS);
	printf(" Message:    %d byte(s)\n", BUFFER_SIZE);
	printf("----------------------------------------\n");
	printf(" Statistics (%d samples):\n", RTT_ITERATIONS);
	printf("----------------------------------------\n");
	printf("   Min:       %10lld us\n", min_rtt);
	printf("   Max:       %10lld us\n", max_rtt);
	printf("   Avg:       %10lld us\n", avg_rtt);
	printf("   P50:       %10lld us\n", p50);
	printf("   P90:       %10lld us\n", p90);
	printf("   P99:       %10lld us\n", p99);
	printf("   P99.9:     %10lld us\n", p999);
	printf("========================================\n");
	printf("\n");
	fflush(stdout);

	// Verify the test succeeded
	TEST_RES(avg_rtt > 0 && min_rtt > 0 && max_rtt >= min_rtt, _ret != 0);
}
END_TEST()