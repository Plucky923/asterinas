// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

enum { FD_LIMIT = 64, HIGH_FD = 128 };

static int duplicate(int fd, int command)
{
	return command == -1 ? dup(fd) : fcntl(fd, command, 0);
}

static int first_free_fd(void)
{
	for (int fd = 0; fd < FD_LIMIT; ++fd) {
		errno = 0;
		if (fcntl(fd, F_GETFD) == -1) {
			assert(errno == EBADF);
			return fd;
		}
	}
	return -1;
}

static void expect_error(int result, int expected)
{
	assert(result == -1 && errno == expected);
}

static void check_allocation(int source, int high, int command)
{
	int allocated[FD_LIMIT];
	int count = 0;
	for (;;) {
		int expected = first_free_fd();
		errno = 0;
		/* A valid source above the lowered limit remains usable. */
		int fd = duplicate(high, command);
		if (expected == -1) {
			expect_error(fd, EMFILE);
			break;
		}
		assert(fd == expected);
		assert(count < FD_LIMIT);
		allocated[count++] = fd;
		int flags = fcntl(fd, F_GETFD);
		assert(flags >= 0);
		assert(!!(flags & FD_CLOEXEC) == (command == F_DUPFD_CLOEXEC));
	}
	assert(count > 0);
	errno = 0;
	expect_error(duplicate(INT_MAX, command), EBADF);

	/* A full table may still contain a reusable low descriptor after close. */
	int hole = allocated[count / 2];
	assert(close(hole) == 0);
	assert(duplicate(source, command) == hole);
	errno = 0;
	expect_error(duplicate(source, command), EMFILE);
	for (int i = 0; i < count; ++i)
		assert(close(allocated[i]) == 0);
}

static void check_boundaries(int source, int high, struct rlimit limit)
{
	const int commands[] = { F_DUPFD, F_DUPFD_CLOEXEC };
	for (unsigned i = 0; i < sizeof(commands) / sizeof(commands[0]); ++i) {
		int command = commands[i];
		errno = 0;
		expect_error(fcntl(source, command, FD_LIMIT), EINVAL);
		errno = 0;
		expect_error(fcntl(source, command, -1), EINVAL);
		errno = 0;
		expect_error(fcntl(source, command, INT_MAX), EINVAL);
		/* Linux validates the original descriptor before the minimum. */
		errno = 0;
		expect_error(fcntl(INT_MAX, command, FD_LIMIT), EBADF);
	}

	limit.rlim_cur = 0;
	assert(setrlimit(RLIMIT_NOFILE, &limit) == 0);
	errno = 0;
	expect_error(dup(high), EMFILE);
	errno = 0;
	expect_error(dup(INT_MAX), EBADF);
	for (unsigned i = 0; i < sizeof(commands) / sizeof(commands[0]); ++i) {
		errno = 0;
		expect_error(fcntl(high, commands[i], 0), EINVAL);
		errno = 0;
		expect_error(fcntl(INT_MAX, commands[i], 0), EBADF);
	}
	/* dup2 of an existing descriptor onto itself allocates no descriptor. */
	assert(dup2(high, high) == high);
}

static void run_case(const char *name)
{
	struct rlimit limit;
	assert(getrlimit(RLIMIT_NOFILE, &limit) == 0);
	assert(limit.rlim_cur > HIGH_FD);
	int source = open("/dev/null", O_RDWR);
	assert(source >= 0 && source < FD_LIMIT);
	int high = fcntl(source, F_DUPFD_CLOEXEC, HIGH_FD);
	assert(high >= HIGH_FD);
	limit.rlim_cur = FD_LIMIT;
	assert(setrlimit(RLIMIT_NOFILE, &limit) == 0);
	struct rlimit observed;
	assert(getrlimit(RLIMIT_NOFILE, &observed) == 0);
	assert(observed.rlim_cur == FD_LIMIT &&
	       observed.rlim_max == limit.rlim_max);
	printf("dup_rlimit: %s soft=%lu hard=%lu source=%d high=%d\n", name,
	       (unsigned long)observed.rlim_cur,
	       (unsigned long)observed.rlim_max, source, high);
	assert(fflush(stdout) == 0);
	if (strcmp(name, "boundaries") == 0) {
		check_boundaries(source, high, limit);
	} else {
		int command = -1;
		if (strcmp(name, "fcntl") == 0)
			command = F_DUPFD;
		else if (strcmp(name, "cloexec") == 0)
			command = F_DUPFD_CLOEXEC;
		check_allocation(source, high, command);
	}
	assert(close(high) == 0);
	assert(close(source) == 0);
	printf("dup_rlimit: %s PASS\n", name);
}

int main(int argc, char **argv)
{
	const char *cases[] = { "dup", "fcntl", "cloexec", "boundaries" };
	if (argc > 2)
		return 2;
	int selected = 0, failures = 0;
	for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		if (argc == 2 && strcmp(argv[1], "all") != 0 &&
		    strcmp(argv[1], cases[i]) != 0)
			continue;
		++selected;
		pid_t child = fork();
		assert(child >= 0);
		if (child == 0) {
			run_case(cases[i]);
			assert(fflush(stdout) == 0);
			_exit(0);
		}
		int status;
		assert(waitpid(child, &status, 0) == child);
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			fprintf(stderr, "dup_rlimit: %s FAIL status=%d\n",
				cases[i], status);
			++failures;
		}
	}
	if (!selected)
		return 2;
	printf("dup_rlimit: %d cases, %d failures\n", selected, failures);
	return failures ? 1 : 0;
}
