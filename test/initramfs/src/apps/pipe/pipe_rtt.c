// SPDX-License-Identifier: MPL-2.0

/*
 * Pipe RTT (Round-Trip Time) Benchmark
 *
 * This program measures pipe round-trip latency using ping-pong pattern.
 * Records 10000 RTT samples, sorts them, and outputs statistics.
 */

#define _GNU_SOURCE

#include "../test.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define NUM_ITERATIONS 10000
#define MSG_SIZE 1

static double rtt_samples[NUM_ITERATIONS];

static double get_time_us(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000.0 + ts.tv_nsec / 1000.0;
}

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

static void print_statistics(double *samples, int count)
{
	// Sort samples
	qsort(samples, count, sizeof(double), compare_double);

	// Calculate statistics
	double sum = 0;
	for (int i = 0; i < count; i++) {
		sum += samples[i];
	}
	double avg = sum / count;

	double min = samples[0];
	double max = samples[count - 1];
	double p50 = samples[count / 2];
	double p90 = samples[(int)(count * 0.90)];
	double p99 = samples[(int)(count * 0.99)];
	double p999 = samples[(int)(count * 0.999)];

	printf("----------------------------------------\n");
	printf(" Statistics (%d samples):\n", count);
	printf("----------------------------------------\n");
	printf("   Min:    %10.3f us\n", min);
	printf("   Max:    %10.3f us\n", max);
	printf("   Avg:    %10.3f us\n", avg);
	printf("   P50:    %10.3f us\n", p50);
	printf("   P90:    %10.3f us\n", p90);
	printf("   P99:    %10.3f us\n", p99);
	printf("   P99.9:  %10.3f us\n", p999);
	printf("----------------------------------------\n");
}

FN_TEST(pipe_rtt_test)
{
	int pipe_to_child[2];   // parent -> child
	int pipe_to_parent[2];  // child -> parent
	pid_t pid;
	char buf[MSG_SIZE];

	printf("\n");
	printf("========================================\n");
	printf(" Pipe RTT Benchmark\n");
	printf("========================================\n");
	printf(" Iterations: %d\n", NUM_ITERATIONS);
	printf(" Message:    %d byte(s)\n", MSG_SIZE);
	printf("----------------------------------------\n");

	if (pipe(pipe_to_child) < 0 || pipe(pipe_to_parent) < 0) {
		perror("pipe");
		TEST_RES(0, 1);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		TEST_RES(0, 1);
	}

	if (pid == 0) {
		// Child: pong server
		close(pipe_to_child[1]);  // close write end
		close(pipe_to_parent[0]); // close read end

		for (int i = 0; i < NUM_ITERATIONS; i++) {
			// Receive ping
			if (read(pipe_to_child[0], buf, MSG_SIZE) != MSG_SIZE) {
				_exit(1);
			}
			// Send pong
			if (write(pipe_to_parent[1], buf, MSG_SIZE) != MSG_SIZE) {
				_exit(1);
			}
		}

		close(pipe_to_child[0]);
		close(pipe_to_parent[1]);
		_exit(0);
	}

	// Parent: ping client
	close(pipe_to_child[0]);  // close read end
	close(pipe_to_parent[1]); // close write end

	buf[0] = 'P';

	printf(" Running %d ping-pong iterations...\n", NUM_ITERATIONS);

	for (int i = 0; i < NUM_ITERATIONS; i++) {
		double start = get_time_us();

		// Send ping
		if (write(pipe_to_child[1], buf, MSG_SIZE) != MSG_SIZE) {
			perror("write");
			break;
		}

		// Receive pong
		if (read(pipe_to_parent[0], buf, MSG_SIZE) != MSG_SIZE) {
			perror("read");
			break;
		}

		double end = get_time_us();
		rtt_samples[i] = end - start;
	}

	close(pipe_to_child[1]);
	close(pipe_to_parent[0]);

	// Wait for child
	int status;
	waitpid(pid, &status, 0);

	print_statistics(rtt_samples, NUM_ITERATIONS);

	printf("\n");

	TEST_RES(WIFEXITED(status) && WEXITSTATUS(status) == 0, _ret != 0);
}
END_TEST()
