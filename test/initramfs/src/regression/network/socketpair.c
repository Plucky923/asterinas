// SPDX-License-Identifier: MPL-2.0

#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <unistd.h>

#define MESG1 "Hello from child"
#define MESG2 "Hello from parent"

static int count_fds(void)
{
	DIR *dir = opendir("/proc/self/fd");
	if (dir == NULL) {
		perror("opendir /proc/self/fd");
		return -1;
	}

	int count = 0;
	struct dirent *entry;
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") != 0 &&
		    strcmp(entry->d_name, "..") != 0) {
			count++;
		}
	}

	if (closedir(dir) < 0) {
		perror("closedir /proc/self/fd");
		return -1;
	}

	return count;
}

static int expect_socketpair_errno_no_fd_leak(int ret, int expected_errno,
					      int before_count)
{
	if (ret != -1 || errno != expected_errno) {
		fprintf(stderr, "socketpair failed: got ret=%d errno=%d\n", ret,
			errno);
		return -1;
	}

	int after_count = count_fds();
	if (after_count < 0) {
		return -1;
	}
	if (after_count != before_count) {
		fprintf(stderr, "socketpair leaked fd: before=%d after=%d\n",
			before_count, after_count);
		return -1;
	}

	return 0;
}

static int test_invalid_flags_no_fd_leak(void)
{
	int before_count = count_fds();
	if (before_count < 0) {
		return -1;
	}

	int sockets[2] = { -1, -1 };
	errno = 0;
	int ret = socketpair(AF_UNIX, SOCK_STREAM | 0x40000000, 0, sockets);
	return expect_socketpair_errno_no_fd_leak(ret, EINVAL, before_count);
}

static int test_bad_copyout_no_fd_leak(void)
{
	int before_count = count_fds();
	if (before_count < 0) {
		return -1;
	}

	errno = 0;
	int ret = socketpair(AF_UNIX, SOCK_STREAM, 0,
			     (int *)(uintptr_t)-1);
	return expect_socketpair_errno_no_fd_leak(ret, EFAULT, before_count);
}

static int test_basic_exchange(void)
{
	int sockets[2], child;
	char buf[1024];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
		perror("create socket pair");
		return -1;
	}
	if ((child = fork()) == -1) {
		perror("fork");
		return -1;
	} else if (child) {
		// parent
		close(sockets[0]);
		if (read(sockets[1], buf, 1024) < 0) {
			perror("read from child");
			return -1;
		}
		if (write(sockets[1], MESG2, sizeof(MESG2)) < 0) {
			perror("write to child");
			return -1;
		}
		close(sockets[1]);
		if (waitpid(child, NULL, 0) < 0) {
			perror("wait child");
			return -1;
		}
	} else {
		// child
		close(sockets[1]);
		if (write(sockets[0], MESG1, sizeof(MESG1)) < 0) {
			perror("write to parent");
			_exit(1);
		}
		if (read(sockets[0], buf, 1024) < 0) {
			perror("read from parent");
			_exit(1);
		}
		close(sockets[0]);
		_exit(0);
	}
	return 0;
}

int main()
{
	if (test_invalid_flags_no_fd_leak() < 0) {
		return 1;
	}
	if (test_bad_copyout_no_fd_leak() < 0) {
		return 1;
	}
	if (test_basic_exchange() < 0) {
		return 1;
	}
	return 0;
}
