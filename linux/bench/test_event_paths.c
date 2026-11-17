// SPDX-License-Identifier: GPL-2.0
// Exercise register arguments, ptrace, exceptions, blocking, and process retirement.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define REQUIRE(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "%s:%d: %s (errno=%d)\n", __func__, __LINE__, #condition, errno); \
		exit(1); \
	} \
} while (0)

static int wait_child(pid_t child)
{
	int status;
	pid_t result;
	do {
		result = waitpid(child, &status, 0);
	} while (result < 0 && errno == EINTR);
	REQUIRE(result == child);
	return status;
}

static void check_arguments(void)
{
	int fd = open("/arity-data", O_CREAT | O_RDWR | O_TRUNC, 0600);
	REQUIRE(fd >= 0);
	REQUIRE(ftruncate(fd, 8192) == 0);
	const uint64_t expected = UINT64_C(0x3141592653589793);
	REQUIRE(syscall(SYS_pwrite64, fd, &expected, sizeof(expected), 4096) == sizeof(expected));
	void *address = (void *)syscall(SYS_mmap, 0x60000000UL, 4096,
				      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 4096);
	REQUIRE(address != MAP_FAILED);
	REQUIRE(*(volatile uint64_t *)address == expected);
	REQUIRE(munmap(address, 4096) == 0);
	REQUIRE(close(fd) == 0);
	REQUIRE(unlink("/arity-data") == 0);
	errno = 0;
	REQUIRE(syscall(SYS_close, -1) == -1 && errno == EBADF);
	printf("RESULT syscall_arguments 1 bool\n");
}

static void check_ptrace(void)
{
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0)
			_exit(70);
		raise(SIGSTOP);
		_exit(syscall(SYS_getpid) > 0 ? 0 : 71);
	}
	int status = wait_child(child);
	REQUIRE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP);
	struct user_regs_struct original, changed;
	REQUIRE(ptrace(PTRACE_GETREGS, child, NULL, &original) == 0);
	changed = original;
	changed.r12 = UINT64_C(0x1122334455667788);
	REQUIRE(ptrace(PTRACE_SETREGS, child, NULL, &changed) == 0);
	REQUIRE(ptrace(PTRACE_GETREGS, child, NULL, &changed) == 0);
	REQUIRE(changed.r12 == UINT64_C(0x1122334455667788));
	REQUIRE(ptrace(PTRACE_POKEUSER, child,
		      (void *)offsetof(struct user, regs.r12), (void *)original.r12) == 0);
	REQUIRE(ptrace(PTRACE_GETREGS, child, NULL, &changed) == 0);
	REQUIRE(changed.r12 == original.r12);
	REQUIRE(ptrace(PTRACE_SINGLESTEP, child, NULL, NULL) == 0);
	status = wait_child(child);
	REQUIRE(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP);
	REQUIRE(ptrace(PTRACE_CONT, child, NULL, NULL) == 0);
	status = wait_child(child);
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	printf("RESULT ptrace_snapshot_and_single_step 1 bool\n");
}

static void check_exception(int instruction, int expected_signal)
{
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		if (instruction == 0)
			__asm__ volatile("ud2");
		else if (instruction == 1)
			__asm__ volatile("int3");
		else
			__asm__ volatile("movq (%0), %%rax" : : "r"(UINT64_C(0x0100000000000000)) : "rax", "memory");
		_exit(72);
	}
	int status = wait_child(child);
	REQUIRE(WIFSIGNALED(status) && WTERMSIG(status) == expected_signal);
}

static void check_blocking_and_retirement(void)
{
	for (int iteration = 0; iteration < 32; iteration++) {
		int ready[2], reply[2];
		REQUIRE(pipe(ready) == 0 && pipe(reply) == 0);
		pid_t child = fork();
		REQUIRE(child >= 0);
		if (child == 0) {
			close(ready[1]);
			close(reply[0]);
			unsigned char byte;
			if (read(ready[0], &byte, 1) != 1 || byte != iteration)
				_exit(73);
			void *pages = mmap(NULL, 65536, PROT_READ | PROT_WRITE,
					   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			if (pages == MAP_FAILED)
				_exit(74);
			memset(pages, byte, 65536);
			if (write(reply[1], &byte, 1) != 1)
				_exit(75);
			_exit(0);
		}
		close(ready[0]);
		close(reply[1]);
		struct timespec delay = { .tv_nsec = 1000000 };
		REQUIRE(nanosleep(&delay, NULL) == 0);
		unsigned char byte = iteration, answer;
		REQUIRE(write(ready[1], &byte, 1) == 1);
		REQUIRE(read(reply[0], &answer, 1) == 1 && answer == byte);
		close(ready[1]);
		close(reply[0]);
		int status = wait_child(child);
		REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
	printf("RESULT blocking_and_retirement 1 bool\n");
}

int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "--exec-child") == 0)
		return 42;
	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(45);
	check_arguments();
	check_ptrace();
	check_exception(0, SIGILL);
	check_exception(1, SIGTRAP);
	check_exception(2, SIGSEGV);
	printf("RESULT user_exceptions 1 bool\n");
	check_blocking_and_retirement();
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		execl(argv[0], argv[0], "--exec-child", NULL);
		_exit(76);
	}
	int status = wait_child(child);
	REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 42);
	printf("RESULT exec_return_path 1 bool\n");
	printf("RESULT suite_done 1 bool\n");
	return 0;
}
