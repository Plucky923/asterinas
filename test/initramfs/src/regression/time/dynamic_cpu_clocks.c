// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define NSEC_PER_SEC UINT64_C(1000000000)

static uint64_t read_clock(clockid_t clock)
{
	struct timespec value;
	if (clock_gettime(clock, &value) != 0) {
		perror("clock_gettime");
		exit(1);
	}
	if (value.tv_sec < 0 || value.tv_nsec < 0 ||
	    value.tv_nsec >= (long)NSEC_PER_SEC) {
		fprintf(stderr, "invalid clock value\n");
		exit(1);
	}
	return (uint64_t)value.tv_sec * NSEC_PER_SEC + value.tv_nsec;
}

static void check_timer(clockid_t clock)
{
	struct sigevent event = { .sigev_notify = SIGEV_NONE };
	timer_t timer;
	struct itimerspec armed = { .it_value.tv_sec = 1 }, remaining;
	if (timer_create(clock, &event, &timer) != 0 ||
	    timer_settime(timer, 0, &armed, NULL) != 0 ||
	    timer_gettime(timer, &remaining) != 0 ||
	    (remaining.it_value.tv_sec == 0 && remaining.it_value.tv_nsec == 0) ||
	    timer_delete(timer) != 0) {
		perror("dynamic CPU timer");
		exit(1);
	}
}

int main(void)
{
	alarm(15);
	clockid_t thread_clock, process_clock;
	if (pthread_getcpuclockid(pthread_self(), &thread_clock) != 0 ||
	    clock_getcpuclockid(getpid(), &process_clock) != 0) {
		fprintf(stderr, "cannot obtain dynamic CPU clock IDs\n");
		return 1;
	}
	uint64_t thread_start = read_clock(thread_clock);
	check_timer((clockid_t)-2);
	check_timer((clockid_t)-6);
	check_timer(thread_clock);
	check_timer(process_clock);
	struct timespec resolution;
	if (clock_getres(thread_clock, &resolution) != 0 ||
	    clock_getres(thread_clock, NULL) != 0 || resolution.tv_sec < 0 ||
	    resolution.tv_nsec <= 0 ||
	    resolution.tv_nsec >= (long)NSEC_PER_SEC) {
		fprintf(stderr, "invalid dynamic CPU clock resolution\n");
		return 1;
	}
	uint64_t process_start = read_clock(process_clock);
	uint64_t wall_start = read_clock(CLOCK_MONOTONIC);
	volatile uint64_t work = 1;
	do {
		for (int i = 0; i < 10000; ++i)
			work = work * 6364136223846793005ULL + 1;
	} while (read_clock(CLOCK_MONOTONIC) - wall_start < 200000000);
	uint64_t thread_end = read_clock(thread_clock);
	uint64_t process_end = read_clock(process_clock);
	if (thread_end <= thread_start || process_end <= process_start) {
		fprintf(stderr,
			"dynamic CPU clocks did not advance during work\n");
		return 1;
	}
	/* TID/PID zero encodings must refer to the calling thread/process. */
	if (read_clock((clockid_t)-2) < thread_start ||
	    read_clock((clockid_t)-6) < process_start) {
		fprintf(stderr, "current CPU clock encoding moved backwards\n");
		return 1;
	}
	uint64_t fixed = read_clock(CLOCK_THREAD_CPUTIME_ID);
	uint64_t dynamic = read_clock(thread_clock);
	if (dynamic < fixed || dynamic - fixed > 50000000) {
		fprintf(stderr, "fixed and dynamic thread clocks disagree\n");
		return 1;
	}
	struct timespec delay = { .tv_nsec = 100000000 };
	while (nanosleep(&delay, &delay) != 0) {
		if (errno != EINTR)
			return 1;
	}
	uint64_t after_sleep = read_clock(thread_clock);
	if (after_sleep < dynamic || after_sleep - dynamic > 50000000) {
		fprintf(stderr, "sleep was charged as thread CPU execution\n");
		return 1;
	}
	struct timespec ignored;
	errno = 0;
	if (clock_gettime((clockid_t)-1, &ignored) != -1 || errno != EINVAL) {
		fprintf(stderr, "invalid dynamic clock ID was accepted\n");
		return 1;
	}
	puts("PASS: dynamic CPU clocks");
	return 0;
}
