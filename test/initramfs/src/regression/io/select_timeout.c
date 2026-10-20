// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* Linux's raw select/pselect6 update timeout; libc pselect hides that update.
 * Keep the upstream performance benchmark unchanged and test this ABI here.
 */
enum interface { RAW_SELECT, LIBC_SELECT, RAW_PSELECT6, LIBC_PSELECT, INTERFACES };
static const char *const interface_names[] = {
	"raw-select", "libc-select", "raw-pselect6", "libc-pselect",
};

struct timeout {
	struct timeval tv;
	struct timespec ts;
};

static unsigned failures;
static volatile sig_atomic_t alarm_seen;

#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "FAIL line=%d condition=%s errno=%d\n", \
			__LINE__, #condition, errno); \
		++failures; \
	} \
} while (0)

static void fail_system(const char *operation)
{
	perror(operation);
	exit(2);
}

static void initialize(struct timeout *timeout, int64_t nanoseconds)
{
	memset(timeout, 0, sizeof(*timeout));
	timeout->tv.tv_sec = nanoseconds / 1000000000;
	timeout->tv.tv_usec = nanoseconds % 1000000000 / 1000;
	timeout->ts.tv_sec = nanoseconds / 1000000000;
	timeout->ts.tv_nsec = nanoseconds % 1000000000;
}

static int64_t remaining(enum interface interface, const struct timeout *timeout)
{
	if (interface <= LIBC_SELECT) {
		CHECK(timeout->tv.tv_sec >= 0 && timeout->tv.tv_usec >= 0 &&
		      timeout->tv.tv_usec < 1000000);
		return timeout->tv.tv_sec * INT64_C(1000000000) +
		       timeout->tv.tv_usec * INT64_C(1000);
	}
	CHECK(timeout->ts.tv_sec >= 0 && timeout->ts.tv_nsec >= 0 &&
	      timeout->ts.tv_nsec < 1000000000);
	return timeout->ts.tv_sec * INT64_C(1000000000) + timeout->ts.tv_nsec;
}

static int64_t monotonic_ns(void)
{
	struct timespec time;
	if (clock_gettime(CLOCK_MONOTONIC, &time) != 0)
		fail_system("clock_gettime");
	return time.tv_sec * INT64_C(1000000000) + time.tv_nsec;
}

static long invoke(enum interface interface, int nfds, fd_set *readfds,
		   struct timeout *timeout)
{
	switch (interface) {
	case RAW_SELECT:
		return syscall(SYS_select, nfds, readfds, NULL, NULL,
			       timeout ? &timeout->tv : NULL);
	case LIBC_SELECT:
		return select(nfds, readfds, NULL, NULL,
			      timeout ? &timeout->tv : NULL);
	case RAW_PSELECT6:
		return syscall(SYS_pselect6, nfds, readfds, NULL, NULL,
			       timeout ? &timeout->ts : NULL, NULL);
	case LIBC_PSELECT:
		return pselect(nfds, readfds, NULL, NULL,
			       timeout ? &timeout->ts : NULL, NULL);
	default:
		abort();
	}
}

static long observe(const char *test, enum interface interface, int nfds,
		    fd_set *readfds, struct timeout *timeout, int *error)
{
	int64_t start = monotonic_ns();
	errno = 0;
	long result = invoke(interface, nfds, readfds, timeout);
	*error = errno;
	int64_t elapsed = monotonic_ns() - start;
	int64_t value = timeout ? remaining(interface, timeout) : -1;
	printf("case=%s interface=%s result=%ld errno=%d remaining_ns=%lld elapsed_ns=%lld\n",
	       test, interface_names[interface], result, *error,
	       (long long)value, (long long)elapsed);
	if (fflush(stdout) != 0)
		fail_system("fflush");
	return result;
}

static void test_expire(void)
{
	for (enum interface interface = 0; interface < INTERFACES; ++interface) {
		struct timeout timeout;
		initialize(&timeout, 20000000);
		int error;
		CHECK(observe("expire", interface, 0, NULL, &timeout, &error) == 0);
		CHECK(remaining(interface, &timeout) ==
		      (interface == LIBC_PSELECT ? 20000000 : 0));
		/* This is the reuse pattern in gVisor BM_SelectTimeout. */
		CHECK(observe("reuse", interface, 0, NULL, &timeout, &error) == 0);
		CHECK(remaining(interface, &timeout) ==
		      (interface == LIBC_PSELECT ? 20000000 : 0));
	}
}

static void test_ready(void)
{
	int descriptors[2];
	if (pipe(descriptors) != 0)
		fail_system("pipe");
	if (write(descriptors[1], "x", 1) != 1)
		fail_system("pipe write");
	for (enum interface interface = 0; interface < INTERFACES; ++interface) {
		struct timeout timeout;
		initialize(&timeout, 5000000000);
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(descriptors[0], &readfds);
		int error;
		CHECK(observe("ready", interface, descriptors[0] + 1,
			      &readfds, &timeout, &error) == 1);
		CHECK(FD_ISSET(descriptors[0], &readfds));
		CHECK(remaining(interface, &timeout) > 0 &&
		      remaining(interface, &timeout) <= 5000000000);
		if (interface == LIBC_PSELECT)
			CHECK(remaining(interface, &timeout) == 5000000000);
	}
	CHECK(close(descriptors[0]) == 0);
	CHECK(close(descriptors[1]) == 0);
}

static void on_alarm(int signal)
{
	(void)signal;
	alarm_seen = 1;
}

static void test_eintr(void)
{
	struct sigaction action = { .sa_handler = on_alarm }, previous;
	struct itimerval old_timer, disabled = { 0 };
	sigset_t alarm_set, old_mask;
	if (sigemptyset(&action.sa_mask) != 0 ||
	    sigaction(SIGALRM, &action, &previous) != 0 ||
	    sigemptyset(&alarm_set) != 0 ||
	    sigaddset(&alarm_set, SIGALRM) != 0 ||
	    sigprocmask(SIG_UNBLOCK, &alarm_set, &old_mask) != 0 ||
	    getitimer(ITIMER_REAL, &old_timer) != 0)
		fail_system("prepare signal");
	/* This standalone regression must not replace an existing active timer. */
	CHECK(old_timer.it_value.tv_sec == 0 && old_timer.it_value.tv_usec == 0);
	for (enum interface interface = 0; interface < INTERFACES; ++interface) {
		struct itimerval timer = { .it_value = { .tv_usec = 50000 } };
		struct timeout timeout;
		initialize(&timeout, 5000000000);
		alarm_seen = 0;
		if (setitimer(ITIMER_REAL, &timer, NULL) != 0)
			fail_system("setitimer");
		int error;
		long result = observe("eintr", interface, 0, NULL, &timeout, &error);
		if (setitimer(ITIMER_REAL, &disabled, NULL) != 0)
			fail_system("disable timer");
		CHECK(result == -1 && error == EINTR && alarm_seen);
		CHECK(remaining(interface, &timeout) > 0);
		if (interface == LIBC_PSELECT)
			CHECK(remaining(interface, &timeout) == 5000000000);
		else
			CHECK(remaining(interface, &timeout) < 5000000000);
		alarm_seen = 0;
		if (setitimer(ITIMER_REAL, &timer, NULL) != 0)
			fail_system("setitimer null timeout");
		result = observe("eintr-null", interface, 0, NULL, NULL, &error);
		if (setitimer(ITIMER_REAL, &disabled, NULL) != 0)
			fail_system("disable null-timeout timer");
		CHECK(result == -1 && error == EINTR && alarm_seen);
	}
	if (setitimer(ITIMER_REAL, &old_timer, NULL) != 0 ||
	    sigprocmask(SIG_SETMASK, &old_mask, NULL) != 0 ||
	    sigaction(SIGALRM, &previous, NULL) != 0)
		fail_system("restore signal");
}

static void test_validation(void)
{
	for (enum interface interface = 0; interface < INTERFACES; ++interface) {
		struct timeout timeout;
		initialize(&timeout, 0);
		if (interface <= LIBC_SELECT)
			timeout.tv.tv_sec = -1;
		else
			timeout.ts.tv_nsec = 1000000000;
		struct timeout original = timeout;
		errno = 0;
		long result = invoke(interface, 0, NULL, &timeout);
		int error = errno;
		printf("case=invalid-timeout interface=%s result=%ld errno=%d\n",
		       interface_names[interface], result, error);
		CHECK(result == -1 && error == EINVAL);
		CHECK(memcmp(&timeout, &original, sizeof(timeout)) == 0);
		initialize(&timeout, 5000000000);
		result = observe("negative-nfds", interface, -1, NULL, &timeout, &error);
		CHECK(result == -1 && error == EINVAL);
		CHECK(remaining(interface, &timeout) <= 5000000000);
		if (interface == LIBC_PSELECT)
			CHECK(remaining(interface, &timeout) == 5000000000);
	}
}

static void test_readonly(void)
{
	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		fail_system("sysconf");
	struct timeout *timeout = mmap(NULL, (size_t)page_size,
		PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (timeout == MAP_FAILED)
		fail_system("mmap");
	for (enum interface interface = 0; interface < INTERFACES; ++interface) {
		/* libc select may copy its local pselect6 timeout back in userspace.
		 * Its mutable argument is not a raw-kernel best-effort write test.
		 */
		if (interface == LIBC_SELECT)
			continue;
		for (unsigned zero = 0; zero < 2; ++zero) {
			if (mprotect(timeout, (size_t)page_size, PROT_READ | PROT_WRITE) != 0)
				fail_system("mprotect writable");
			int64_t initial = zero ? 0 : 20000000;
			initialize(timeout, initial);
			if (mprotect(timeout, (size_t)page_size, PROT_READ) != 0)
				fail_system("mprotect readonly");
			int error;
			CHECK(observe(zero ? "readonly-zero" : "readonly", interface,
				      0, NULL, timeout, &error) == 0);
			CHECK(remaining(interface, timeout) == initial);
		}
	}
	CHECK(munmap(timeout, (size_t)page_size) == 0);
}

static void test_sticky(void)
{
	long previous = syscall(SYS_personality, 0xffffffffUL);
	if (previous == -1)
		fail_system("personality query");
	if (syscall(SYS_personality, (unsigned long)previous | STICKY_TIMEOUTS) == -1)
		fail_system("personality STICKY_TIMEOUTS");
	for (enum interface interface = 0; interface < INTERFACES; ++interface) {
		struct timeout timeout;
		initialize(&timeout, 20000000);
		int error;
		CHECK(observe("sticky", interface, 0, NULL, &timeout, &error) == 0);
		CHECK(remaining(interface, &timeout) == 20000000);
	}
	if (syscall(SYS_personality, (unsigned long)previous) == -1)
		fail_system("personality restore");
}

int main(int argc, char **argv)
{
	const struct {
		const char *name;
		void (*test)(void);
	} tests[] = {
		{ "expire", test_expire }, { "ready", test_ready },
		{ "eintr", test_eintr }, { "validation", test_validation },
		{ "readonly", test_readonly }, { "sticky", test_sticky },
	};
	const char *mode = argc == 1 ? "all" : argv[1];
	if (argc > 2) {
		fprintf(stderr, "usage: %s [all|expire|ready|eintr|validation|readonly|sticky]\n", argv[0]);
		return 2;
	}
	unsigned executed = 0;
	for (unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
		if (strcmp(mode, "all") == 0 || strcmp(mode, tests[i].name) == 0) {
			tests[i].test();
			++executed;
		}
	}
	if (executed == 0) {
		fprintf(stderr, "unknown mode: %s\n", mode);
		return 2;
	}
	printf("select_timeout: %s modes=%u failures=%u\n",
	       failures ? "FAIL" : "PASS", executed, failures);
	return failures ? 1 : 0;
}
