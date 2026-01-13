// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

/*
 * VSOCK Throughput Test Server (Host side)
 *
 * This server receives data from the guest client and sends ACK
 * after all data is received. It runs on the host machine.
 *
 * Usage: vsock_throughput_server [port]
 *   - port: Port number to listen on (default: 5000)
 *
 * Compile: gcc -o vsock_throughput_server vsock_throughput_server.c
 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <unistd.h>

#define DEFAULT_PORT 5000
#define MAX_MSG_SIZE (1024 * 1024) // 1MB
#define ACK_MSG "ACK"
#define ACK_SIZE 4

static volatile int running = 1;

static void signal_handler(int sig)
{
	(void)sig;
	running = 0;
}

static int handle_client(int client_sock)
{
	char *buffer;
	uint64_t msg_size;
	uint64_t iterations;
	ssize_t ret;

	// Receive message size
	ret = recv(client_sock, &msg_size, sizeof(msg_size), MSG_WAITALL);
	if (ret != sizeof(msg_size)) {
		perror("recv msg_size");
		return -1;
	}

	if (msg_size > MAX_MSG_SIZE) {
		fprintf(stderr, "Invalid message size: %lu\n",
			(unsigned long)msg_size);
		return -1;
	}

	// Receive iteration count
	ret = recv(client_sock, &iterations, sizeof(iterations), MSG_WAITALL);
	if (ret != sizeof(iterations)) {
		perror("recv iterations");
		return -1;
	}

	printf("  Message size: %lu bytes, Iterations: %lu\n",
	       (unsigned long)msg_size, (unsigned long)iterations);

	// Allocate receive buffer
	buffer = malloc(msg_size);
	if (!buffer) {
		perror("malloc");
		return -1;
	}

	// Receive all data
	size_t total_received = 0;
	size_t expected_total = msg_size * iterations;

	while (total_received < expected_total) {
		size_t to_recv = msg_size;
		if (expected_total - total_received < to_recv)
			to_recv = expected_total - total_received;

		size_t received = 0;
		while (received < to_recv) {
			ret = recv(client_sock, buffer + received,
				   to_recv - received, 0);
			if (ret <= 0) {
				if (ret < 0)
					perror("recv data");
				else
					fprintf(stderr, "Connection closed\n");
				free(buffer);
				return -1;
			}
			received += ret;
		}
		total_received += received;
	}

	printf("  Received %zu bytes total\n", total_received);

	// Send ACK
	ret = send(client_sock, ACK_MSG, ACK_SIZE, 0);
	if (ret != ACK_SIZE) {
		perror("send ack");
		free(buffer);
		return -1;
	}

	free(buffer);
	return 0;
}

int main(int argc, char *argv[])
{
	int server_sock, client_sock;
	struct sockaddr_vm server_addr, client_addr;
	socklen_t client_len;
	int port = DEFAULT_PORT;
	int opt = 1;

	if (argc >= 2) {
		port = atoi(argv[1]);
	}

	// Set up signal handler
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	// Create socket
	server_sock = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (server_sock < 0) {
		perror("socket");
		return 1;
	}

	// Set socket options
	setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	// Bind
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.svm_family = AF_VSOCK;
	server_addr.svm_cid = VMADDR_CID_ANY;
	server_addr.svm_port = port;

	if (bind(server_sock, (struct sockaddr *)&server_addr,
		 sizeof(server_addr)) < 0) {
		perror("bind");
		close(server_sock);
		return 1;
	}

	// Listen
	if (listen(server_sock, 5) < 0) {
		perror("listen");
		close(server_sock);
		return 1;
	}

	printf("=== VSOCK Throughput Server ===\n");
	printf("Listening on port %d...\n", port);
	printf("Server will exit after test completes.\n");
	printf("-------------------------------\n");

	while (running) {
		client_len = sizeof(client_addr);
		client_sock = accept(server_sock, (struct sockaddr *)&client_addr,
				     &client_len);
		if (client_sock < 0) {
			if (errno == EINTR)
				continue;
			perror("accept");
			continue;
		}

		printf("Client connected (CID: %u)\n", client_addr.svm_cid);

		if (handle_client(client_sock) < 0) {
			fprintf(stderr, "  Test failed\n");
		} else {
			printf("  Test completed successfully\n");
			// Exit server after one successful test session
			close(client_sock);
			break;
		}

		close(client_sock);
	}

	printf("\nShutting down...\n");
	close(server_sock);
	return 0;
}
