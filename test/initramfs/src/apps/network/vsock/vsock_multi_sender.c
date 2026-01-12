/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * Vsock Multi-Connection Throughput Benchmark (Linux Host Sender)
 *
 * This program runs on Linux Host and opens multiple concurrent
 * connections to an Asterinas Guest, sending a fixed number of bytes per
 * connection. One thread per connection.
 *
 * This is the Vsock counterpart to FrameVsock's host_multi_sender.c for
 * fair performance comparison.
 *
 * Usage:
 *   ./vsock_multi_sender <num_threads> <guest_cid> <buf_size> <bytes_per_conn> [port] [warmup_bytes]
 *
 * Example:
 *   ./vsock_multi_sender 4 3 65536 1073741824
 */

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <linux/vm_sockets.h>

#define DEFAULT_PORT 20001
#define MAX_BUF_SIZE (1024 * 1024)

struct sender_args {
	int thread_id;
	uint32_t guest_cid;
	uint32_t port;
	size_t buf_size;
	uint64_t bytes_per_conn;
	uint64_t warmup_bytes;

	uint64_t bytes_sent;
	uint64_t duration_ns;
	int error;
};

static uint64_t timespec_to_ns(const struct timespec *ts)
{
	return (uint64_t)ts->tv_sec * 1000000000ULL + (uint64_t)ts->tv_nsec;
}

static void *sender_thread(void *arg)
{
	struct sender_args *args = (struct sender_args *)arg;
	int fd = -1;
	void *buffer = NULL;

	fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (fd < 0) {
		args->error = errno;
		return NULL;
	}

	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_reserved1 = 0,
		.svm_port = args->port,
		.svm_cid = args->guest_cid,
	};

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		args->error = errno;
		goto out;
	}

	if (posix_memalign(&buffer, 4096, args->buf_size) != 0) {
		buffer = malloc(args->buf_size);
	}
	if (!buffer) {
		args->error = ENOMEM;
		goto out;
	}

	memset(buffer, 0xA5, args->buf_size);

	/* Warmup (not measured) */
	uint64_t warm_sent = 0;
	while (warm_sent < args->warmup_bytes) {
		size_t to_send = args->buf_size;
		if (args->warmup_bytes - warm_sent < args->buf_size) {
			to_send = (size_t)(args->warmup_bytes - warm_sent);
		}
		ssize_t ret = send(fd, buffer, to_send, 0);
		if (ret < 0 && (errno == EINTR || errno == EAGAIN ||
				errno == EWOULDBLOCK)) {
			continue;
		}
		if (ret <= 0) {
			args->error = errno ? errno : EIO;
			goto out;
		}
		warm_sent += (uint64_t)ret;
	}

	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);

	args->bytes_sent = 0;
	while (args->bytes_sent < args->bytes_per_conn) {
		size_t to_send = args->buf_size;
		if (args->bytes_per_conn - args->bytes_sent < args->buf_size) {
			to_send = (size_t)(args->bytes_per_conn -
					   args->bytes_sent);
		}
		ssize_t ret = send(fd, buffer, to_send, 0);
		if (ret < 0 && (errno == EINTR || errno == EAGAIN ||
				errno == EWOULDBLOCK)) {
			continue;
		}
		if (ret <= 0) {
			args->error = errno ? errno : EIO;
			break;
		}
		args->bytes_sent += (uint64_t)ret;
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	args->duration_ns = timespec_to_ns(&end) - timespec_to_ns(&start);
out:
	if (buffer) {
		free(buffer);
	}
	if (fd >= 0) {
		close(fd);
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	if (argc < 5) {
		fprintf(stderr,
			"Usage: %s <num_threads> <guest_cid> <buf_size> <bytes_per_conn> [port] [warmup_bytes]\n",
			argv[0]);
		fprintf(stderr, "Example: %s 4 3 65536 1073741824\n", argv[0]);
		return 1;
	}

	int num_threads = atoi(argv[1]);
	uint32_t guest_cid = (uint32_t)strtoul(argv[2], NULL, 10);
	size_t buf_size = (size_t)strtoull(argv[3], NULL, 10);
	uint64_t bytes_per_conn = strtoull(argv[4], NULL, 10);
	uint32_t port = DEFAULT_PORT;
	uint64_t warmup_bytes = 0;

	if (argc > 5) {
		port = (uint32_t)atoi(argv[5]);
	}
	if (argc > 6) {
		warmup_bytes = strtoull(argv[6], NULL, 10);
	}

	if (num_threads <= 0) {
		fprintf(stderr, "Error: num_threads must be > 0\n");
		return 1;
	}
	if (buf_size == 0 || buf_size > MAX_BUF_SIZE) {
		fprintf(stderr, "Error: buf_size must be between 1 and %d\n",
			MAX_BUF_SIZE);
		return 1;
	}

	printf("\n========================================\n");
	printf(" Vsock Multi-Connection Sender\n");
	printf("========================================\n");
	printf(" Threads:    %d\n", num_threads);
	printf(" Target:     CID %u, Port %u\n", guest_cid, port);
	printf(" Per Conn:   %llu bytes\n", (unsigned long long)bytes_per_conn);
	printf(" Buffer:     %zu bytes\n", buf_size);
	if (warmup_bytes > 0) {
		printf(" Warmup:     %llu bytes\n",
		       (unsigned long long)warmup_bytes);
	}
	printf("----------------------------------------\n");

	pthread_t *threads = calloc((size_t)num_threads, sizeof(pthread_t));
	struct sender_args *args =
		calloc((size_t)num_threads, sizeof(struct sender_args));
	if (!threads || !args) {
		fprintf(stderr, "Error: out of memory\n");
		free(threads);
		free(args);
		return 1;
	}

	for (int i = 0; i < num_threads; i++) {
		args[i].thread_id = i;
		args[i].guest_cid = guest_cid;
		args[i].port = port;
		args[i].buf_size = buf_size;
		args[i].bytes_per_conn = bytes_per_conn;
		args[i].warmup_bytes = warmup_bytes;
		args[i].bytes_sent = 0;
		args[i].duration_ns = 0;
		args[i].error = 0;

		if (pthread_create(&threads[i], NULL, sender_thread,
				   &args[i]) != 0) {
			fprintf(stderr, "Error: pthread_create failed\n");
			num_threads = i;
			break;
		}
	}

	for (int i = 0; i < num_threads; i++) {
		pthread_join(threads[i], NULL);
	}

	uint64_t total_bytes = 0;
	uint64_t max_duration = 0;
	int had_error = 0;

	for (int i = 0; i < num_threads; i++) {
		if (args[i].error) {
			had_error = 1;
			fprintf(stderr, "Thread %d error: %d\n", i,
				args[i].error);
		}
		total_bytes += args[i].bytes_sent;
		if (args[i].duration_ns > max_duration) {
			max_duration = args[i].duration_ns;
		}
		printf("Thread %d: sent %llu bytes in %.3f ms\n", i,
		       (unsigned long long)args[i].bytes_sent,
		       args[i].duration_ns / 1e6);
	}

	printf("----------------------------------------\n");
	printf(" Summary:\n");
	printf("   Total bytes:  %llu\n", (unsigned long long)total_bytes);
	if (max_duration > 0) {
		double seconds = max_duration / 1e9;
		double gbits = (total_bytes * 8.0) / (seconds * 1e9);
		printf("   Duration:     %.6f sec\n", seconds);
		printf("   Throughput:   %.6f Gbits/s\n", gbits);
	}
	printf("========================================\n\n");

	free(threads);
	free(args);

	return had_error ? 2 : 0;
}
