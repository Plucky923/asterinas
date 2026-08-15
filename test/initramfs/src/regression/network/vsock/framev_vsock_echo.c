// SPDX-License-Identifier: MPL-2.0

#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <linux/vm_sockets.h>
#include <unistd.h>

#define DEFAULT_BACKLOG 8
#define CHUNK_SIZE 4096

static void fill_payload(char *buf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		buf[i] = 'A' + (i % 26);
	}
}

static int write_all(int fd, const char *buf, size_t len)
{
	size_t written = 0;

	while (written < len) {
		ssize_t ret = write(fd, buf + written, len - written);
		if (ret < 0) {
			perror("write");
			return -1;
		}
		if (ret == 0) {
			fprintf(stderr, "write returned zero\n");
			return -1;
		}
		written += (size_t)ret;
	}

	return 0;
}

static int read_exact(int fd, char *buf, size_t len)
{
	size_t read_len = 0;

	while (read_len < len) {
		ssize_t ret = read(fd, buf + read_len, len - read_len);
		if (ret < 0) {
			perror("read");
			return -1;
		}
		if (ret == 0) {
			fprintf(stderr, "unexpected EOF after %zu bytes\n",
				read_len);
			return -1;
		}
		read_len += (size_t)ret;
	}

	return 0;
}

static int parse_u32(const char *arg, const char *name, unsigned int *value)
{
	char *end = NULL;
	unsigned long parsed = strtoul(arg, &end, 0);

	if (*arg == '\0' || *end != '\0' || parsed > UINT32_MAX) {
		fprintf(stderr, "invalid %s: %s\n", name, arg);
		return -1;
	}

	*value = (unsigned int)parsed;
	return 0;
}

static int parse_size(const char *arg, const char *name, size_t *value)
{
	char *end = NULL;
	unsigned long parsed = strtoul(arg, &end, 0);

	if (*arg == '\0' || *end != '\0') {
		fprintf(stderr, "invalid %s: %s\n", name, arg);
		return -1;
	}

	*value = (size_t)parsed;
	return 0;
}

static int run_client(int argc, char **argv)
{
	if (argc < 5) {
		fprintf(stderr,
			"usage: %s client <cid> <port> <payload_len> [shutdown]\n",
			argv[0]);
		return -1;
	}

	unsigned int cid;
	unsigned int port;
	size_t payload_len;
	if (parse_u32(argv[2], "cid", &cid) != 0 ||
	    parse_u32(argv[3], "port", &port) != 0 ||
	    parse_size(argv[4], "payload_len", &payload_len) != 0) {
		return -1;
	}
	bool do_shutdown = argc > 5 && strcmp(argv[5], "shutdown") == 0;

	int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = cid,
		.svm_port = port,
	};
	printf("client connecting cid=%u port=%u payload=%zu\n", cid, port,
	       payload_len);
	fflush(stdout);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("connect");
		close(fd);
		return -1;
	}
	printf("client connected cid=%u port=%u payload=%zu\n", cid, port,
	       payload_len);
	fflush(stdout);

	char *payload = malloc(payload_len);
	char *echo = malloc(payload_len);
	if (payload == NULL || echo == NULL) {
		perror("malloc");
		close(fd);
		free(payload);
		free(echo);
		return -1;
	}
	fill_payload(payload, payload_len);

	printf("client writing payload=%zu\n", payload_len);
	fflush(stdout);
	int ret = write_all(fd, payload, payload_len);
	if (ret == 0 && do_shutdown && shutdown(fd, SHUT_WR) < 0) {
		perror("shutdown");
		ret = -1;
	}
	if (ret == 0) {
		printf("client reading echo payload=%zu\n", payload_len);
		fflush(stdout);
		ret = read_exact(fd, echo, payload_len);
	}
	if (ret == 0 && memcmp(payload, echo, payload_len) != 0) {
		fprintf(stderr, "echo payload mismatch\n");
		ret = -1;
	}
	if (ret == 0 && do_shutdown) {
		char byte;
		printf("client waiting for EOF\n");
		fflush(stdout);
		ssize_t eof_ret = read(fd, &byte, 1);
		if (eof_ret != 0) {
			fprintf(stderr,
				"expected EOF after shutdown, got %zd\n",
				eof_ret);
			ret = -1;
		}
	}

	free(payload);
	free(echo);
	close(fd);
	return ret;
}

static int echo_one_connection(int fd)
{
	char buf[CHUNK_SIZE];

	for (;;) {
		ssize_t ret = read(fd, buf, sizeof(buf));
		if (ret < 0) {
			perror("read");
			return -1;
		}
		if (ret == 0) {
			return 0;
		}
		printf("server read %zd bytes\n", ret);
		fflush(stdout);
		if (write_all(fd, buf, (size_t)ret) != 0) {
			return -1;
		}
		printf("server wrote %zd bytes\n", ret);
		fflush(stdout);
	}
}

static int run_server(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr,
			"usage: %s server <cid|any> <port> [connections] [done_marker]\n",
			argv[0]);
		return -1;
	}

	unsigned int cid;
	unsigned int port;
	unsigned int connections = 1;
	if (strcmp(argv[2], "any") == 0) {
		cid = VMADDR_CID_ANY;
	} else if (parse_u32(argv[2], "cid", &cid) != 0) {
		return -1;
	}
	if (parse_u32(argv[3], "port", &port) != 0) {
		return -1;
	}
	if (argc > 4 && parse_u32(argv[4], "connections", &connections) != 0) {
		return -1;
	}
	const char *done_marker = argc > 5 ? argv[5] : NULL;

	int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = cid,
		.svm_port = port,
	};
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		close(fd);
		return -1;
	}
	if (listen(fd, DEFAULT_BACKLOG) < 0) {
		perror("listen");
		close(fd);
		return -1;
	}
	printf("server listening cid=%u port=%u connections=%u\n", cid, port,
	       connections);
	fflush(stdout);

	for (unsigned int i = 0; i < connections; i++) {
		printf("server accepting connection %u\n", i + 1);
		fflush(stdout);
		int conn = accept(fd, NULL, NULL);
		if (conn < 0) {
			perror("accept");
			close(fd);
			return -1;
		}
		printf("server accepted connection %u\n", i + 1);
		fflush(stdout);
		if (echo_one_connection(conn) != 0) {
			close(conn);
			close(fd);
			return -1;
		}
		close(conn);
		printf("server echoed connection %u\n", i + 1);
		fflush(stdout);
	}

	close(fd);
	if (done_marker != NULL) {
		printf("%s\n", done_marker);
		fflush(stdout);
	}
	return 0;
}

static int expect_connect_failure(unsigned int cid, unsigned int port)
{
	int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = cid,
		.svm_port = port,
	};
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
		fprintf(stderr,
			"connect unexpectedly succeeded for cid=%u port=%u\n",
			cid, port);
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static int expect_local_port_conflict(void)
{
	int first = socket(AF_VSOCK, SOCK_STREAM, 0);
	int second = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (first < 0 || second < 0) {
		perror("socket");
		close(first);
		close(second);
		return -1;
	}

	struct sockaddr_vm addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = VMADDR_CID_ANY,
		.svm_port = 62000,
	};
	if (bind(first, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		perror("bind first");
		close(first);
		close(second);
		return -1;
	}
	if (bind(second, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
		fprintf(stderr, "second bind unexpectedly succeeded\n");
		close(first);
		close(second);
		return -1;
	}

	close(first);
	close(second);
	return 0;
}

static int run_expect_fail(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "usage: %s expect-fail <cid> <port>\n",
			argv[0]);
		return -1;
	}

	unsigned int cid;
	unsigned int port;
	if (parse_u32(argv[2], "cid", &cid) != 0 ||
	    parse_u32(argv[3], "port", &port) != 0) {
		return -1;
	}

	return expect_connect_failure(cid, port);
}

static int run_negative(int argc, char **argv)
{
	if (argc < 4) {
		fprintf(stderr, "usage: %s negative <host_cid> <closed_port>\n",
			argv[0]);
		return -1;
	}

	unsigned int host_cid;
	unsigned int closed_port;
	if (parse_u32(argv[2], "host_cid", &host_cid) != 0 ||
	    parse_u32(argv[3], "closed_port", &closed_port) != 0) {
		return -1;
	}

	if (expect_connect_failure(host_cid, closed_port) != 0 ||
	    expect_connect_failure(4, closed_port) != 0 ||
	    expect_connect_failure(VMADDR_CID_ANY, VMADDR_PORT_ANY) != 0 ||
	    expect_local_port_conflict() != 0) {
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr,
			"usage: %s <client|server|expect-fail|negative> ...\n",
			argv[0]);
		return EXIT_FAILURE;
	}

	if (strcmp(argv[1], "client") == 0) {
		return run_client(argc, argv) == 0 ? EXIT_SUCCESS :
						     EXIT_FAILURE;
	}
	if (strcmp(argv[1], "server") == 0) {
		return run_server(argc, argv) == 0 ? EXIT_SUCCESS :
						     EXIT_FAILURE;
	}
	if (strcmp(argv[1], "expect-fail") == 0) {
		return run_expect_fail(argc, argv) == 0 ? EXIT_SUCCESS :
							  EXIT_FAILURE;
	}
	if (strcmp(argv[1], "negative") == 0) {
		return run_negative(argc, argv) == 0 ? EXIT_SUCCESS :
						       EXIT_FAILURE;
	}

	fprintf(stderr, "unknown mode: %s\n", argv[1]);
	return EXIT_FAILURE;
}
