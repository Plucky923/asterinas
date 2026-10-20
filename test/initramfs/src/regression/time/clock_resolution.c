// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
	const clockid_t clocks[] = {
		CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_BOOTTIME,
	};
	for (unsigned i = 0; i < sizeof(clocks) / sizeof(clocks[0]); ++i) {
		struct timespec library = { -1, -1 }, kernel = { -1, -1 };
		assert(clock_getres(clocks[i], &library) == 0);
		assert(syscall(SYS_clock_getres, clocks[i], &kernel) == 0);
		printf("clock=%d libc=%ld.%09ld syscall=%ld.%09ld\n",
		       clocks[i], library.tv_sec, library.tv_nsec,
		       kernel.tv_sec, kernel.tv_nsec);
		assert(fflush(stdout) == 0);
		assert(library.tv_sec == kernel.tv_sec && library.tv_nsec == kernel.tv_nsec);
		assert(kernel.tv_sec >= 0 && kernel.tv_nsec >= 0 &&
		       kernel.tv_nsec < 1000000000);
		assert(kernel.tv_sec > 0 || kernel.tv_nsec > 0);
		assert(clock_getres(clocks[i], NULL) == 0);
	}
	puts("clock_resolution: PASS");
	return 0;
}
