/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * FrameVsock RTT Benchmark (Asterinas Host Client / Ping)
 *
 * This program runs on Asterinas Host and measures FrameVsock round-trip latency.
 * Records RTT samples, sorts them, and outputs statistics.
 *
 * Usage: ./host_rtt_client <guest_cid> [port] [iterations]
 * Example: ./host_rtt_client 3 20002 100000
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <time.h>
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

#define DEFAULT_PORT 20002
#define DEFAULT_ITERATIONS 100000
#define MAX_ITERATIONS 100000
#define MSG_SIZE 4

static double *rtt_samples = NULL;

struct PhaseStats {
	double min;
	double max;
	double sum;
	int count;
};

static void phase_stats_init(struct PhaseStats *stats)
{
	stats->min = 1e30;
	stats->max = 0.0;
	stats->sum = 0.0;
	stats->count = 0;
}

static void phase_stats_record(struct PhaseStats *stats, double value)
{
	if (value < stats->min)
		stats->min = value;
	if (value > stats->max)
		stats->max = value;
	stats->sum += value;
	stats->count++;
}

static void print_phase_stats(const char *label, const struct PhaseStats *stats)
{
	double avg = stats->count ? (stats->sum / stats->count) : 0.0;

	printf("   %-5s:  min %9.3f us  max %9.3f us  avg %9.3f us\n", label,
	       stats->min, stats->max, avg);
}

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
	printf("========================================\n");
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <guest_cid> [port] [iterations]\n",
			argv[0]);
		fprintf(stderr, "Example: %s 3 20002 100000\n", argv[0]);
		return 1;
	}

	int guest_cid = atoi(argv[1]);
	int port = DEFAULT_PORT;
	int iterations = DEFAULT_ITERATIONS;

	if (argc > 2) {
		port = atoi(argv[2]);
	}
	if (argc > 3) {
		iterations = atoi(argv[3]);
		if (iterations <= 0 || iterations > MAX_ITERATIONS) {
			fprintf(stderr,
				"Error: iterations must be between 1 and %d\n",
				MAX_ITERATIONS);
			return 1;
		}
	}

	// Allocate RTT samples array
	rtt_samples = malloc(iterations * sizeof(double));
	if (!rtt_samples) {
		perror("malloc");
		return 1;
	}

	printf("\n========================================\n");
	printf(" FrameVsock RTT Benchmark - Client (Ping)\n");
	printf("========================================\n");
	printf(" Target:     CID %d, Port %d\n", guest_cid, port);
	printf(" Iterations: %d\n", iterations);
	printf(" Message:    %d byte(s)\n", MSG_SIZE);
	printf("----------------------------------------\n");

	int fd = socket(AF_FRAMEVSOCK, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		free(rtt_samples);
		return 1;
	}

	struct sockaddr_vm addr = {
		.svm_family = AF_FRAMEVSOCK,
		.svm_reserved1 = 0,
		.svm_port = port,
		.svm_cid = guest_cid,
	};

	printf(" Connecting to CID %d:%d...\n", guest_cid, port);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		close(fd);
		free(rtt_samples);
		return 1;
	}

	printf(" Connected! Running %d ping-pong iterations...\n", iterations);

	char buf[MSG_SIZE];
	buf[0] = 'P';

	int completed = 0;
	struct PhaseStats send_stats;
	struct PhaseStats recv_stats;
	phase_stats_init(&send_stats);
	phase_stats_init(&recv_stats);
	for (int i = 0; i < iterations; i++) {
		double start = get_time_us();

		// Send ping
		if (send(fd, buf, MSG_SIZE, 0) != MSG_SIZE) {
			perror("send");
			break;
		}
		double after_send = get_time_us();

		// Receive pong
		if (recv(fd, buf, MSG_SIZE, 0) != MSG_SIZE) {
			perror("recv");
			break;
		}

		double end = get_time_us();
		phase_stats_record(&send_stats, after_send - start);
		phase_stats_record(&recv_stats, end - after_send);
		rtt_samples[i] = end - start;
		completed++;
	}

	close(fd);

	if (completed == 0) {
		fprintf(stderr, "Error: no RTT samples collected\n");
		free(rtt_samples);
		return 1;
	}

	print_statistics(rtt_samples, completed);
	printf(" Timing breakdown (%d samples):\n", completed);
	print_phase_stats("send", &send_stats);
	print_phase_stats("recv", &recv_stats);
	printf("\n");

	if (completed != iterations) {
		fprintf(stderr, "Warning: completed %d/%d iterations\n",
			completed, iterations);
	}

	free(rtt_samples);
	return (completed == iterations) ? 0 : 1;
}
