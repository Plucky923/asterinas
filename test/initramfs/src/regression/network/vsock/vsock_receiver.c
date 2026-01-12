/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * Vsock Throughput Benchmark (Receiver)
 *
 * This program receives data over traditional vsock (AF_VSOCK).
 * Uses rdtsc for cycle-accurate timing to enable fair comparison with
 * other IPC mechanisms (pipe, unix socket, framevsock).
 *
 * Usage: ./vsock_receiver [port] [buf_size]
 * Example: ./vsock_receiver 20001 4096
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <linux/vm_sockets.h>
#include <stdint.h>

#define DEFAULT_PORT 20001
#define DEFAULT_BUF_SIZE 4096
#define MAX_BUF_SIZE (1024 * 1024) // 1MB max
#define WARMUP_BYTES (64 * 1024 * 1024ULL) // 64 MB warmup (not measured)

#ifndef CPU_MHZ
#define CPU_MHZ 2600
#endif

static char rx_buffer[MAX_BUF_SIZE];

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

int main(int argc, char *argv[])
{
	unsigned int port = DEFAULT_PORT;
	size_t buf_size = DEFAULT_BUF_SIZE;

	if (argc > 1) {
		port = (unsigned int)atoi(argv[1]);
	}
	if (argc > 2) {
		buf_size = (size_t)atol(argv[2]);
		if (buf_size == 0 || buf_size > MAX_BUF_SIZE) {
			fprintf(stderr,
				"Error: buf_size must be between 1 and %d\n",
				MAX_BUF_SIZE);
			return 1;
		}
	}

	printf("\n========================================\n");
	printf(" Vsock Throughput - Receiver\n");
	printf("========================================\n");
	printf(" Port:       %u\n", port);
	printf(" RX Buffer:  %zu bytes\n", buf_size);
	printf(" Warmup:     %llu bytes\n", (unsigned long long)WARMUP_BYTES);
	printf("----------------------------------------\n");

	// Create vsock socket
	int listen_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		perror("socket");
		return 1;
	}

	// Bind to port
	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_reserved1 = 0,
		.svm_port = port,
		.svm_cid = VMADDR_CID_ANY,
	};

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(listen_fd);
		return 1;
	}

	if (listen(listen_fd, 1) < 0) {
		perror("listen");
		close(listen_fd);
		return 1;
	}

	printf(" Listening on port %u...\n", port);

	while (1) {
		struct sockaddr_vm peer_addr;
		socklen_t peer_len = sizeof(peer_addr);

		printf(" Waiting for connection...\n");

		int client_fd = accept(listen_fd, (struct sockaddr *)&peer_addr,
				       &peer_len);
		if (client_fd < 0) {
			perror("accept");
			continue;
		}

		printf(" Connection from CID %u, port %u\n", peer_addr.svm_cid,
		       peer_addr.svm_port);
		printf(" Receiving data...\n");

		unsigned long long total_bytes = 0;
		unsigned long long warmup_bytes_actual = 0;
		unsigned long long read_count = 0;
		uint64_t start_cycles = 0, end_cycles;
		int started = 0;

		while (1) {
			ssize_t n = recv(client_fd, rx_buffer, buf_size, 0);

			if (n <= 0)
				break;

			total_bytes += n;
			read_count++;

			// Warmup phase: don't start timing until warmup complete
			if (!started && total_bytes >= WARMUP_BYTES) {
				start_cycles = rdtsc_fenced();
				warmup_bytes_actual = total_bytes;
				started = 1;
			}
		}

		end_cycles = rdtsc_fenced();
		uint64_t elapsed_cycles =
			started ? (end_cycles - start_cycles) : 0;
		uint64_t measured_bytes =
			started ? (total_bytes - warmup_bytes_actual) : 0;

		printf("----------------------------------------\n");
		printf(" Results:\n");
		printf("   Total bytes:    %llu\n", total_bytes);
		printf("   Warmup bytes:   %llu\n", warmup_bytes_actual);
		printf("   Measured bytes: %llu\n",
		       (unsigned long long)measured_bytes);
		printf("   Read calls:     %llu\n", read_count);
		printf("   Cycles:         %llu\n",
		       (unsigned long long)elapsed_cycles);
		if (elapsed_cycles > 0 && measured_bytes > 0) {
			unsigned long long bytes_per_kcycle =
				(measured_bytes * 1000) / elapsed_cycles;
			unsigned long long gbits_x1000 =
				(measured_bytes * 8ULL *
				 (unsigned long long)CPU_MHZ) /
				elapsed_cycles;
			unsigned int ghz_int = CPU_MHZ / 1000;
			unsigned int ghz_frac = (CPU_MHZ % 1000) / 10;

			printf("   Bytes/Kcycle:   %llu\n", bytes_per_kcycle);
			printf("   ~Gbits/s:       %llu.%03llu (@%u.%02uGHz)\n",
			       gbits_x1000 / 1000, gbits_x1000 % 1000, ghz_int,
			       ghz_frac);
		}
		printf("========================================\n\n");

		close(client_fd);
	}

	close(listen_fd);
	return 0;
}
