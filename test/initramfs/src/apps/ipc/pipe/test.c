#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * Minimal repro for the Asterinas vs Linux mismatch seen in
 * 104dacecd7275ab3bf5aa16b644de6bad39457d546247cb658fa7f49bb2d1051.
 *
 * Expected Linux behavior:
 *   pwrite64(pipe_write_end, ..., count=0, offset=3) -> -1, errno=ESPIPE
 *
 * Observed Asterinas behavior:
 *   pwrite64(pipe_write_end, ..., count=0, offset=3) -> 0, errno=0
 */
int main(void)
{
	int fds[2];
	char dummy = 0;
	long ret;

	if (pipe(fds) != 0) {
		perror("pipe");
		return 1;
	}

	errno = 0;
	ret = syscall(__NR_pwrite64, fds[1], &dummy, 0, 3);

	printf("pwrite64(pipe_write_end, count=0, offset=3) => ret=%ld errno=%d (%s)\n",
	       ret, errno, strerror(errno));

	close(fds[0]);
	close(fds[1]);
	return 0;
}
