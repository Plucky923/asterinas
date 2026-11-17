// SPDX-License-Identifier: GPL-2.0
//
// Pre-evaluation probe verifying `clock_gettime` and `gettimeofday` stay in vDSO.
//
// Measures untraced latency and exact syscall entries observed via
// `ptrace(PTRACE_SYSCALL)` over the full configured iteration count, failing
// closed if any `ptrace` call, child exit, or `SYS_getpid` bracket fails.

#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int trace_vdso_syscalls(long trace_iters, long *cg_syscalls, long *gtod_syscalls)
{
	pid_t pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	}

	if (pid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0)
			_exit(120);
		if (raise(SIGSTOP) != 0)
			_exit(121);

		struct timespec ts;
		struct timeval tv;
		// Bracket the measured calls with `SYS_getpid` so startup libc
		// syscalls are excluded from the counts.
		(void)syscall(SYS_getpid);
		for (long i = 0; i < trace_iters; i++) {
			if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
				_exit(122);
		}
		for (long i = 0; i < trace_iters; i++) {
			if (gettimeofday(&tv, NULL) != 0)
				_exit(123);
		}
		(void)syscall(SYS_getpid);
		_exit(0);
	}

	int status = 0;
	if (waitpid(pid, &status, 0) < 0 || !WIFSTOPPED(status)) {
		fprintf(stderr, "vdso_selfcheck: child did not stop for ptrace\n");
		return -1;
	}
	if (ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)(long)PTRACE_O_TRACESYSGOOD) != 0) {
		perror("PTRACE_SETOPTIONS");
		(void)kill(pid, SIGKILL);
		(void)waitpid(pid, NULL, 0);
		return -1;
	}

	int active = 0;
	int in_entry = 1;
	int marker_count = 0;
	int child_ok = 0;
	long cg = 0;
	long gtod = 0;

	while (1) {
		if (ptrace(PTRACE_SYSCALL, pid, 0, 0) != 0) {
			perror("PTRACE_SYSCALL");
			(void)kill(pid, SIGKILL);
			(void)waitpid(pid, NULL, 0);
			return -1;
		}
		if (waitpid(pid, &status, 0) < 0) {
			if (errno == EINTR)
				continue;
			perror("waitpid");
			return -1;
		}
		if (WIFEXITED(status)) {
			child_ok = (WEXITSTATUS(status) == 0);
			if (!child_ok)
				fprintf(stderr, "vdso_selfcheck: tracee exited %d\n", WEXITSTATUS(status));
			break;
		}
		if (WIFSIGNALED(status)) {
			fprintf(stderr, "vdso_selfcheck: tracee killed by signal %d\n", WTERMSIG(status));
			return -1;
		}
		if (!WIFSTOPPED(status))
			continue;

		int sig = WSTOPSIG(status);
		if (sig == (SIGTRAP | 0x80) || sig == SIGTRAP) {
			if (in_entry) {
				struct user_regs_struct regs;
				memset(&regs, 0, sizeof(regs));
				if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0) {
					perror("PTRACE_GETREGS");
					(void)kill(pid, SIGKILL);
					(void)waitpid(pid, NULL, 0);
					return -1;
				}
				long nr = (long)regs.orig_rax;
				if (nr == SYS_getpid) {
					active = !active;
					marker_count++;
				} else if (active) {
					if (nr == SYS_clock_gettime)
						cg++;
					else if (nr == SYS_gettimeofday)
						gtod++;
				}
			}
			in_entry = !in_entry;
		} else {
			fprintf(stderr, "vdso_selfcheck: unexpected stop signal %d\n", sig);
			(void)kill(pid, SIGKILL);
			(void)waitpid(pid, NULL, 0);
			return -1;
		}
	}

	if (!child_ok || marker_count != 2 || active != 0) {
		fprintf(stderr, "vdso_selfcheck: incomplete trace (child_ok=%d markers=%d active=%d)\n",
			child_ok, marker_count, active);
		return -1;
	}

	*cg_syscalls = cg;
	*gtod_syscalls = gtod;
	return 0;
}

int main(int argc, char **argv)
{
	long iters = 100000;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc)
			iters = atol(argv[++i]);
	}
	if (iters <= 0)
		iters = 100000;

	unsigned long vdso_hdr = getauxval(AT_SYSINFO_EHDR);

	struct timespec ts;
	struct timeval tv;
	uint64_t t0 = now_ns();
	for (long i = 0; i < iters; i++) {
		if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
			return 2;
	}
	uint64_t t1 = now_ns();
	for (long i = 0; i < iters; i++) {
		if (gettimeofday(&tv, NULL) != 0)
			return 3;
	}
	uint64_t t2 = now_ns();

	long cg_syscalls = -1;
	long gtod_syscalls = -1;
	if (trace_vdso_syscalls(iters, &cg_syscalls, &gtod_syscalls) != 0)
		return 4;

	printf("VDSO_SELFCHECK iters=%ld clock_gettime_syscalls=%ld gettimeofday_syscalls=%ld "
	       "auxv_vdso=0x%lx cg_ns=%.2f gtod_ns=%.2f\n",
	       iters, cg_syscalls, gtod_syscalls, vdso_hdr,
	       (double)(t1 - t0) / (double)iters,
	       (double)(t2 - t1) / (double)iters);

	return (vdso_hdr != 0 && cg_syscalls == 0 && gtod_syscalls == 0) ? 0 : 1;
}
