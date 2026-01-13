// SPDX-License-Identifier: MPL-2.0

/*
 * Unix Domain Socket RTT (Round-Trip Time) Benchmark
 *
 * This program measures Unix socket round-trip latency using ping-pong pattern.
 * Records 10000 RTT samples, sorts them, and outputs statistics.
 */

#define _GNU_SOURCE

#include "../test.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
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

FN_TEST(unix_socket_rtt_test)
{
	int sv[2];
	pid_t pid;
	char buf[MSG_SIZE];

	printf("\n");
	printf("========================================\n");
	printf(" Unix Socket RTT Benchmark\n");
	printf("========================================\n");
	printf(" Iterations: %d\n", NUM_ITERATIONS);
	printf(" Message:    %d byte(s)\n", MSG_SIZE);
	printf("----------------------------------------\n");

	// Create Unix domain socket pair
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		perror("socketpair");
		TEST_RES(0, 1);
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		close(sv[0]);
		close(sv[1]);
		TEST_RES(0, 1);
	}

	if (pid == 0) {
		// Child: pong server
		close(sv[0]);

		for (int i = 0; i < NUM_ITERATIONS; i++) {
			// Receive ping
			if (recv(sv[1], buf, MSG_SIZE, 0) != MSG_SIZE) {
				_exit(1);
			}
			// Send pong
			if (send(sv[1], buf, MSG_SIZE, 0) != MSG_SIZE) {
				_exit(1);
			}
		}

		close(sv[1]);
		_exit(0);
	}

	// Parent: ping client
	close(sv[1]);

	buf[0] = 'P';

	printf(" Running %d ping-pong iterations...\n", NUM_ITERATIONS);

	for (int i = 0; i < NUM_ITERATIONS; i++) {
		double start = get_time_us();

		// Send ping
		if (send(sv[0], buf, MSG_SIZE, 0) != MSG_SIZE) {
			perror("send");
			break;
		}

		// Receive pong
		if (recv(sv[0], buf, MSG_SIZE, 0) != MSG_SIZE) {
			perror("recv");
			break;
		}

		double end = get_time_us();
		rtt_samples[i] = end - start;
	}

	close(sv[0]);

	// Wait for child
	int status;
	waitpid(pid, &status, 0);

	print_statistics(rtt_samples, NUM_ITERATIONS);

	printf("\n");

	TEST_RES(WIFEXITED(status) && WEXITSTATUS(status) == 0, _ret != 0);
}
END_TEST()
