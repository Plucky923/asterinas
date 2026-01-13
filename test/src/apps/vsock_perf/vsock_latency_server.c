// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE

/*
 * VSOCK Latency Test Server (Host side)
 *
 * This server echoes back all received messages for latency measurement.
 * It runs on the host machine and exits after one test session.
 *
 * Usage: vsock_latency_server [port]
 *   - port: Port number to listen on (default: 5001)
 *
 * Compile: gcc -o vsock_latency_server vsock_latency_server.c
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>
#include <unistd.h>

#define DEFAULT_PORT 5001
#define MSG_SIZE 64
#define END_MARKER 'E'

static volatile int running = 1;

static void signal_handler(int sig)
{
	(void)sig;
	running = 0;
}

static int handle_client(int client_sock)
{
	char buffer[MSG_SIZE];
	ssize_t ret;
	size_t count = 0;

	printf("  Starting echo loop...\n");

	while (1) {
		// Receive message
		ret = recv(client_sock, buffer, MSG_SIZE, MSG_WAITALL);
		if (ret <= 0) {
			if (ret < 0 && errno != ECONNRESET)
				perror("recv");
			break;
		}

		// Check for end marker (first byte is 'E')
		if (buffer[0] == END_MARKER) {
			printf("  Received end marker after %zu messages\n", count);
			return 1; // Signal to exit server
		}

		// Echo back
		ret = send(client_sock, buffer, MSG_SIZE, 0);
		if (ret != MSG_SIZE) {
			if (ret < 0)
				perror("send");
			break;
		}

		count++;
	}

	printf("  Echoed %zu messages\n", count);
	return 0; // Continue accepting clients
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

	printf("=== VSOCK Latency Server (Echo) ===\n");
	printf("Listening on port %d...\n", port);
	printf("Server will exit after test completes.\n");
	printf("-----------------------------------\n");

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

		int should_exit = handle_client(client_sock);
		close(client_sock);

		if (should_exit) {
			printf("Test completed. Exiting server.\n");
			break;
		}
	}

	close(server_sock);
	return 0;
}
