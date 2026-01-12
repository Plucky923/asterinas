/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * Vsock Multi-Process Throughput Benchmark (Asterinas Guest Receiver)
 *
 * This program runs in Asterinas Guest and receives data from Linux Host.
 * It accepts multiple connections on the same port, then forks one child per
 * connection to receive data concurrently.
 *
 * This is the Vsock counterpart to FrameVM's guest_fork_receiver.c for
 * fair performance comparison.
 *
 * Usage: ./vsock_fork_receiver <num_processes> <buf_size> <bytes_per_conn> [port] [warmup_bytes]
 * Example: ./vsock_fork_receiver 4 65536 1073741824 20001 0
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/vm_sockets.h>

#define DEFAULT_PORT 20001
#define MAX_BUF_SIZE (1024 * 1024)

#ifndef CPU_MHZ
#define CPU_MHZ 2600
#endif

static char *rx_buffer = NULL;
struct shared_stats {
	volatile uint64_t total_measured_bytes;
	volatile uint64_t first_start_cycles;
	volatile uint64_t last_end_cycles;
};

static struct shared_stats *stats = NULL;

/* Read Time Stamp Counter */
static inline uint64_t rdtsc(void)
{
	uint32_t lo, hi;
	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
}

/* Read TSC with serializing fence for accurate measurement */
static inline uint64_t rdtsc_fenced(void)
{
	__asm__ volatile("lfence" ::: "memory");
	return rdtsc();
}

static inline void add_measured_bytes(uint64_t bytes)
{
	__atomic_fetch_add(&stats->total_measured_bytes, bytes,
			   __ATOMIC_RELAXED);
}

static inline void record_start_cycle(void)
{
	uint64_t now = rdtsc_fenced();
	uint64_t expected = 0;
	__atomic_compare_exchange_n(&stats->first_start_cycles, &expected, now,
				    0, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
}

static inline void record_end_cycle(void)
{
	uint64_t now = rdtsc_fenced();
	uint64_t prev =
		__atomic_load_n(&stats->last_end_cycles, __ATOMIC_RELAXED);
	while (now > prev && !__atomic_compare_exchange_n(
				     &stats->last_end_cycles, &prev, now, 0,
				     __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
	}
}

static void child_receiver(int fd, int child_id, size_t buf_size,
			   uint64_t warmup_bytes)
{
	uint64_t total_bytes = 0;
	uint64_t measured_bytes = 0;
	uint64_t warmup_left = warmup_bytes;

	while (1) {
		ssize_t n = recv(fd, rx_buffer, buf_size, 0);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				continue;
			}
			break;
		}
		if (n <= 0) {
			break;
		}
		if (total_bytes == 0) {
			record_start_cycle();
		}
		total_bytes += (uint64_t)n;
		if (warmup_left > 0) {
			if ((uint64_t)n >= warmup_left) {
				measured_bytes += (uint64_t)n - warmup_left;
				warmup_left = 0;
			} else {
				warmup_left -= (uint64_t)n;
			}
		} else {
			measured_bytes += (uint64_t)n;
		}
	}

	printf("Child %d: %llu bytes (measured: %llu)\n", child_id,
	       (unsigned long long)total_bytes,
	       (unsigned long long)measured_bytes);

	add_measured_bytes(measured_bytes);
	record_end_cycle();
	close(fd);
	exit(0);
}

int main(int argc, char *argv[])
{
	if (argc < 4) {
		fprintf(stderr,
			"Usage: %s <num_processes> <buf_size> <bytes_per_conn> [port] [warmup_bytes]\n",
			argv[0]);
		fprintf(stderr, "Example: %s 4 65536 1073741824 20001 0\n",
			argv[0]);
		return 1;
	}

	int num_processes = atoi(argv[1]);
	size_t buf_size = (size_t)strtoull(argv[2], NULL, 10);
	uint64_t bytes_per_conn = strtoull(argv[3], NULL, 10);
	unsigned int port = DEFAULT_PORT;
	uint64_t warmup_bytes = 0;

	if (argc > 4) {
		port = (unsigned int)atoi(argv[4]);
	}
	if (argc > 5) {
		warmup_bytes = strtoull(argv[5], NULL, 10);
	}

	if (num_processes <= 0) {
		fprintf(stderr, "Error: num_processes must be > 0\n");
		return 1;
	}
	if (buf_size == 0 || buf_size > MAX_BUF_SIZE) {
		fprintf(stderr, "Error: buf_size must be between 1 and %d\n",
			MAX_BUF_SIZE);
		return 1;
	}

	rx_buffer = malloc(buf_size);
	if (!rx_buffer) {
		fprintf(stderr, "Error: failed to allocate rx_buffer\n");
		return 1;
	}

	stats = mmap(NULL, sizeof(*stats), PROT_READ | PROT_WRITE,
		     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (stats == MAP_FAILED) {
		perror("mmap");
		free(rx_buffer);
		return 1;
	}
	memset((void *)stats, 0, sizeof(*stats));

	printf("\n========================================\n");
	printf(" Vsock Multi-Process Receiver\n");
	printf("========================================\n");
	printf(" Port:       %u\n", port);
	printf(" Processes:  %d\n", num_processes);
	printf(" RX Buffer:  %zu bytes\n", buf_size);
	printf(" Per Conn:   %llu bytes\n", (unsigned long long)bytes_per_conn);
	if (warmup_bytes > 0) {
		printf(" Warmup:     %llu bytes\n",
		       (unsigned long long)warmup_bytes);
	}
	printf("----------------------------------------\n");

	/* Create socket */
	int server_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (server_fd < 0) {
		perror("socket");
		free(rx_buffer);
		return 1;
	}

	/* Bind */
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_reserved1 = 0,
		.svm_port = port,
		.svm_cid = VMADDR_CID_ANY,
	};

	if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(server_fd);
		free(rx_buffer);
		return 1;
	}

	/* Listen */
	if (listen(server_fd, num_processes) < 0) {
		perror("listen");
		close(server_fd);
		free(rx_buffer);
		return 1;
	}

	printf(" Listening on port %u...\n", port);

	uint64_t start_cycles = 0;
	int started = 0;
	int accepted = 0;

	for (int i = 0; i < num_processes; i++) {
		struct sockaddr_vm peer_addr;
		socklen_t peer_len = sizeof(peer_addr);
		int conn_fd = accept(server_fd, (struct sockaddr *)&peer_addr,
				     &peer_len);
		if (conn_fd < 0) {
			if (errno == EINTR) {
				continue;
			}
			perror("accept");
			break;
		}

		if (!started) {
			start_cycles = rdtsc_fenced();
			started = 1;
		}

		pid_t pid = fork();
		if (pid == 0) {
			/* Child process: close server fd and handle connection */
			close(server_fd);
			child_receiver(conn_fd, i, buf_size, warmup_bytes);
			/* child_receiver calls exit(), should not reach here */
		} else if (pid > 0) {
			/* Parent process: close connection fd and continue */
			close(conn_fd);
			accepted++;
		} else {
			perror("fork");
			close(conn_fd);
			break;
		}
	}

	close(server_fd);

	/* Wait for all children */
	for (int i = 0; i < accepted; i++) {
		wait(NULL);
	}

	uint64_t end_cycles = started ? rdtsc_fenced() : 0;
	uint64_t first_start =
		__atomic_load_n(&stats->first_start_cycles, __ATOMIC_RELAXED);
	uint64_t last_end =
		__atomic_load_n(&stats->last_end_cycles, __ATOMIC_RELAXED);
	if (first_start != 0 && last_end > first_start) {
		start_cycles = first_start;
		end_cycles = last_end;
	}

	printf("----------------------------------------\n");
	printf(" Results:\n");
	printf("   Accepted:    %d\n", accepted);

	if (accepted > 0 && end_cycles > start_cycles) {
		uint64_t expected_bytes = (uint64_t)accepted * bytes_per_conn;
		uint64_t total_bytes = stats->total_measured_bytes;
		uint64_t measured_bytes = stats->total_measured_bytes;
		uint64_t elapsed = end_cycles - start_cycles;

		printf("   Expected:    %llu\n",
		       (unsigned long long)expected_bytes);
		printf("   Total bytes: %llu\n",
		       (unsigned long long)total_bytes);
		printf("   Measured:    %llu\n",
		       (unsigned long long)measured_bytes);
		printf("   Cycles:      %llu\n", (unsigned long long)elapsed);

		if (measured_bytes > 0) {
			unsigned long long bytes_per_kcycle =
				(measured_bytes * 1000) / elapsed;
			unsigned long long gbits_x1000 =
				(measured_bytes * 8ULL *
				 (unsigned long long)CPU_MHZ) /
				elapsed;
			unsigned int ghz_int = CPU_MHZ / 1000;
			unsigned int ghz_frac = (CPU_MHZ % 1000) / 10;

			printf("   Bytes/Kcycle:%llu\n", bytes_per_kcycle);
			printf("   ~Gbits/s:    %llu.%03llu (@%u.%02uGHz)\n",
			       gbits_x1000 / 1000, gbits_x1000 % 1000, ghz_int,
			       ghz_frac);
		}
	}

	printf("========================================\n\n");

	munmap(stats, sizeof(*stats));
	free(rx_buffer);
	return 0;
}
