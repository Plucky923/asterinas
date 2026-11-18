// SPDX-License-Identifier: GPL-2.0
//
// Measures raw getpid under ptrace and pending-signal states.

#define _GNU_SOURCE

#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "This benchmark requires the x86-64 syscall ABI"
#endif

#define GETPID_WARMUP 50000
#define GETPID_ITERS 1000000
#define GETPID_SAMPLES 9

enum benchmark_case {
	CASE_PLAIN,
	CASE_PTRACE_CONT,
	CASE_BLOCKED_SIGNAL,
};

static pid_t active_child;
static pid_t active_descendant;
static volatile sig_atomic_t delivered;

static void cleanup_child(void)
{
	if (active_descendant > 0)
		kill(active_descendant, SIGKILL);
	if (active_child > 0) {
		int status;

		kill(active_child, SIGKILL);
		while (waitpid(active_child, &status, 0) < 0 && errno == EINTR)
			;
	}
}

static void require(int condition, const char *operation)
{
	if (!condition) {
		fprintf(stderr, "FAIL %s: errno=%d (%s)\n", operation, errno,
			strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static int wait_child(pid_t child)
{
	int status;
	pid_t result;

	do {
		result = waitpid(child, &status, 0);
	} while (result < 0 && errno == EINTR);
	require(result == child, "waitpid");
	return status;
}

static void require_stopped(int status, int signal_number)
{
	require(WIFSTOPPED(status) && WSTOPSIG(status) == signal_number,
		"expected ptrace stop");
}

static void require_exited(int status)
{
	require(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		"child completed successfully");
	active_child = 0;
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	require(clock_gettime(CLOCK_MONOTONIC, &ts) == 0, "clock_gettime");
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void pipe_send(int fd, const void *data, size_t size)
{
	ssize_t result;

	do {
		result = write(fd, data, size);
	} while (result < 0 && errno == EINTR);
	require(result == (ssize_t)size, "pipe handshake write");
}

static void pipe_receive(int fd, void *data, size_t size, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int ready;
	ssize_t result;

	do {
		ready = poll(&pfd, 1, timeout_ms);
	} while (ready < 0 && errno == EINTR);
	require(ready == 1 && (pfd.revents & (POLLIN | POLLHUP)),
		"pipe handshake before deadline");
	do {
		result = read(fd, data, size);
	} while (result < 0 && errno == EINTR);
	require(result == (ssize_t)size, "pipe handshake read");
}

static void wait_exit_before_deadline(pid_t child)
{
	uint64_t deadline = now_ns() + 10000000000ULL;
	int status;

	for (;;) {
		pid_t result = waitpid(child, &status, WNOHANG);

		if (result == child) {
			require_exited(status);
			return;
		}
		require(result == 0 || (result < 0 && errno == EINTR), "waitpid deadline");
		require(now_ns() < deadline, "child exits before deadline");
		struct timespec delay = { .tv_sec = 0, .tv_nsec = 1000000L };

		while (nanosleep(&delay, &delay) < 0)
			require(errno == EINTR, "waitpid settling delay");
	}
}

static uint64_t ordered_tsc(void)
{
	unsigned int lo, hi;

	__asm__ __volatile__("lfence; rdtsc; lfence"
			     : "=a"(lo), "=d"(hi) : : "memory");
	return ((uint64_t)hi << 32) | lo;
}

static int current_cpu(void)
{
	unsigned int cpu;

	require(syscall(SYS_getcpu, &cpu, NULL, NULL) == 0, "getcpu");
	return (int)cpu;
}

static void pin_to_cpu_zero(void)
{
	cpu_set_t wanted, actual;

	CPU_ZERO(&wanted);
	CPU_SET(0, &wanted);
	require(sched_setaffinity(0, sizeof(wanted), &wanted) == 0,
		"sched_setaffinity");
	require(sched_yield() == 0, "sched_yield");
	if (current_cpu() != 0) {
		struct timespec delay = { .tv_sec = 0, .tv_nsec = 200000L };

		require(nanosleep(&delay, NULL) == 0, "affinity settling delay");
	}
	require(sched_getaffinity(0, sizeof(actual), &actual) == 0 &&
		CPU_COUNT(&actual) == 1 && CPU_ISSET(0, &actual) && current_cpu() == 0,
		"singleton CPU 0 affinity");
}

__attribute__((noinline))
static long raw_getpid_loop(int iterations)
{
	long remaining = iterations;
	long pid;

	__asm__ __volatile__(
		"1:\n\t"
		"mov $39, %%eax\n\t"
		"syscall\n\t"
		"dec %[remaining]\n\t"
		"jnz 1b\n\t"
		: [remaining] "+r"(remaining), "=&a"(pid)
		:
		: "rcx", "r11", "cc", "memory");
	return pid;
}

static int compare_u64(const void *left, const void *right)
{
	uint64_t a = *(const uint64_t *)left;
	uint64_t b = *(const uint64_t *)right;

	return (a > b) - (a < b);
}

static void measure_getpid(const char *name, int verify_only)
{
	uint64_t samples[GETPID_SAMPLES];
	long pid = syscall(SYS_getpid);

	require(pid > 0, "positive PID");
	pin_to_cpu_zero();
	if (verify_only) {
		require(raw_getpid_loop(256) == pid, "short getpid validation");
		return;
	}
	for (int sample = 0; sample < GETPID_SAMPLES; sample++) {
		require(raw_getpid_loop(GETPID_WARMUP) == pid && current_cpu() == 0,
			"getpid warmup");
		uint64_t ns_start = now_ns();
		uint64_t tsc_start = ordered_tsc();
		long observed = raw_getpid_loop(GETPID_ITERS);
		uint64_t ticks = ordered_tsc() - tsc_start;
		uint64_t elapsed_ns = now_ns() - ns_start;
		int cpu = current_cpu();

		require(observed == pid && cpu == 0 && elapsed_ns > 0 && ticks > 0,
			"timed getpid validation");
		printf("REVIEW_SYSCALL_SAMPLE {\"case\":\"%s\",\"sample\":%d,"
		       "\"iterations\":%d,\"elapsed_ns\":%llu,\"tsc_ticks\":%llu,"
		       "\"cpu\":%d,\"pid\":%ld,\"valid\":true}\n",
		       name, sample, GETPID_ITERS, (unsigned long long)elapsed_ns,
		       (unsigned long long)ticks, cpu, observed);
		samples[sample] = elapsed_ns;
	}
	qsort(samples, GETPID_SAMPLES, sizeof(samples[0]), compare_u64);
	printf("RESULT review_getpid_%s_ns %.3f ns\n", name,
	       (double)samples[GETPID_SAMPLES / 2] / GETPID_ITERS);
}

static void signal_handler(int signal_number)
{
	(void)signal_number;
	delivered++;
}

static void block_signal(int signal_number, sigset_t *original)
{
	struct sigaction action = { .sa_handler = signal_handler };
	sigset_t blocked;

	sigemptyset(&action.sa_mask);
	require(sigaction(signal_number, &action, NULL) == 0, "sigaction");
	sigemptyset(&blocked);
	sigaddset(&blocked, signal_number);
	delivered = 0;
	require(sigprocmask(SIG_BLOCK, &blocked, original) == 0, "block signal");
}

static void require_signal_pending(int signal_number)
{
	sigset_t pending;

	require(sigpending(&pending) == 0 && sigismember(&pending, signal_number) == 1 &&
		delivered == 0, "blocked signal remains pending");
}

static void unblock_and_check(int signal_number, const sigset_t *original, int expected)
{
	sigset_t pending;

	require(sigprocmask(SIG_SETMASK, original, NULL) == 0, "restore signal mask");
	for (int attempt = 0; delivered < expected && attempt < 10000; attempt++)
		require(raw_getpid_loop(1) > 0, "signal delivery progress");
	require(delivered == expected, "exact signal delivery count");
	require(sigpending(&pending) == 0 && sigismember(&pending, signal_number) == 0,
		"delivered signal removed from pending set");
}

static void require_signal_absent(int signal_number)
{
	sigset_t pending;

	require(sigpending(&pending) == 0 && sigismember(&pending, signal_number) == 0,
		"signal absent from pending set");
}

static void verify_ignored_requeue(int signal_number, int realtime)
{
	struct sigaction ignore = { .sa_handler = SIG_IGN };
	sigset_t original;
	long pid = syscall(SYS_getpid);
	long tid = syscall(SYS_gettid);

	block_signal(signal_number, &original);
	for (int instance = 0; instance < 2; instance++)
		require(syscall(SYS_tgkill, pid, tid, signal_number) == 0,
			"queue signal before ignoring");
	require_signal_pending(signal_number);
	sigemptyset(&ignore.sa_mask);
	require(sigaction(signal_number, &ignore, NULL) == 0, "ignore queued signal");
	require(sigprocmask(SIG_SETMASK, &original, NULL) == 0, "unblock ignored signal");
	require(raw_getpid_loop(256) == pid && delivered == 0, "ignored signal discarded");
	require_signal_absent(signal_number);
	block_signal(signal_number, &original);
	for (int instance = 0; instance < 2; instance++)
		require(syscall(SYS_tgkill, pid, tid, signal_number) == 0,
			"requeue previously ignored signal");
	require_signal_pending(signal_number);
	unblock_and_check(signal_number, &original, realtime ? 2 : 1);
}

static void verify_signalfd_requeue(void)
{
	int realtime_signal = SIGRTMIN + 3;
	sigset_t original, intermediate, mask;
	long pid = syscall(SYS_getpid);
	long tid = syscall(SYS_gettid);

	block_signal(SIGUSR1, &original);
	block_signal(realtime_signal, &intermediate);
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	sigaddset(&mask, realtime_signal);
	int fd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);

	require(fd >= 0, "create signalfd");
	for (int round = 0; round < 2; round++) {
		int standard_count = 0, realtime_count = 0;
		struct signalfd_siginfo info;
		struct pollfd pfd = { .fd = fd, .events = POLLIN };

		for (int instance = 0; instance < 2; instance++) {
			require(kill((pid_t)pid, SIGUSR1) == 0, "signalfd standard enqueue");
			require(syscall(SYS_tgkill, pid, tid, realtime_signal) == 0,
				"signalfd realtime enqueue");
		}
		require_signal_pending(SIGUSR1);
		require_signal_pending(realtime_signal);
		require(poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLIN), "signalfd readiness");
		for (int instance = 0; instance < 3; instance++) {
			require(read(fd, &info, sizeof(info)) == sizeof(info), "signalfd signal read");
			if (info.ssi_signo == SIGUSR1) {
				standard_count++;
			} else {
				require(info.ssi_signo == (unsigned int)realtime_signal,
					"signalfd expected signal number");
				realtime_count++;
				if (realtime_count == 1)
					require_signal_pending(realtime_signal);
			}
		}
		require(standard_count == 1 && realtime_count == 2 && delivered == 0,
			"signalfd exact consumption counts");
		require_signal_absent(SIGUSR1);
		require_signal_absent(realtime_signal);
		require(read(fd, &info, sizeof(info)) == -1 && errno == EAGAIN,
			"signalfd exhausted");
		pfd.revents = 0;
		require(poll(&pfd, 1, 0) == 0, "exhausted signalfd is not readable");
	}
	require(close(fd) == 0, "close signalfd");
	require(sigprocmask(SIG_SETMASK, &original, NULL) == 0, "restore signalfd signal mask");
	require(raw_getpid_loop(256) == pid && delivered == 0, "signalfd consumed all signals");
}

static void run_case(enum benchmark_case which, const char *name, int verify_only)
{
	pid_t child = fork();

	require(child >= 0, "fork benchmark child");
	if (child == 0) {
		sigset_t original;

		active_child = 0;
		if (which == CASE_PTRACE_CONT) {
			require(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0, "PTRACE_TRACEME");
			require(raise(SIGSTOP) == 0, "initial tracee stop");
		}
		if (which == CASE_BLOCKED_SIGNAL) {
			block_signal(SIGUSR1, &original);
			require(kill(getpid(), SIGUSR1) == 0, "queue blocked process signal");
			require_signal_pending(SIGUSR1);
		}
		measure_getpid(name, verify_only);
		if (which == CASE_BLOCKED_SIGNAL) {
			require_signal_pending(SIGUSR1);
			unblock_and_check(SIGUSR1, &original, 1);
		}
		if (which == CASE_PTRACE_CONT)
			require(raise(SIGSTOP) == 0, "verify tracer remains attached");
		printf("RESULT review_getpid_%s_ok 1 bool\n", name);
		_exit(0);
	}
	active_child = child;
	if (which == CASE_PTRACE_CONT) {
		require_stopped(wait_child(child), SIGSTOP);
		require(ptrace(PTRACE_CONT, child, NULL, NULL) == 0, "start benchmark tracee");
	}
	if (which == CASE_PTRACE_CONT) {
		struct user_regs_struct regs;

		require_stopped(wait_child(child), SIGSTOP);
		require(ptrace(PTRACE_GETREGS, child, NULL, &regs) == 0,
			"tracer can read registers after measurement");
		require(ptrace(PTRACE_CONT, child, NULL, NULL) == 0, "finish tracee");
	}
	require_exited(wait_child(child));
}

static void run_tracer_exit_detached(int verify_only)
{
	int reports[2], start[2];
	char byte;

	require(pipe(reports) == 0 && pipe(start) == 0, "tracer exit pipes");
	pid_t tracer = fork();

	require(tracer >= 0, "fork exiting tracer");
	if (tracer == 0) {
		active_child = 0;
		close(reports[0]);
		close(start[1]);
		pid_t tracee = fork();

		require(tracee >= 0, "fork tracee of exiting tracer");
		if (tracee == 0) {
			long pid = syscall(SYS_getpid);

			require(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0, "tracer exit TRACEME");
			require(raise(SIGSTOP) == 0, "tracer exit initial stop");
			pipe_receive(start[0], &byte, sizeof(byte), 10000);
			require(byte == 'S' && raw_getpid_loop(256) == pid, "detached tracee resumed");
			pipe_send(reports[1], "R", 1);
			measure_getpid("tracer_exit_detached", verify_only);
			printf("RESULT review_getpid_tracer_exit_detached_ok 1 bool\n");
			pipe_send(reports[1], "D", 1);
			_exit(0);
		}
		active_child = tracee;
		pipe_send(reports[1], &tracee, sizeof(tracee));
		require_stopped(wait_child(tracee), SIGSTOP);
		require(ptrace(PTRACE_SETOPTIONS, tracee, NULL,
			       (void *)(uintptr_t)PTRACE_O_TRACESYSGOOD) == 0,
			"tracer exit syscall-stop option");
		require(ptrace(PTRACE_SYSCALL, tracee, NULL, NULL) == 0,
			"arm syscall stops before tracer exit");
		require_stopped(wait_child(tracee), SIGTRAP | 0x80);
		_exit(0);
	}
	active_child = tracer;
	close(reports[1]);
	close(start[0]);
	pipe_receive(reports[0], &active_descendant, sizeof(active_descendant), 10000);
	require(active_descendant > 0, "reported detached tracee PID");
	wait_exit_before_deadline(tracer);
	pipe_send(start[1], "S", 1);
	pipe_receive(reports[0], &byte, sizeof(byte), 10000);
	require(byte == 'R', "tracer exit releases syscall-stopped tracee");
	pipe_receive(reports[0], &byte, sizeof(byte), 120000);
	require(byte == 'D', "detached tracee completed workload");
	struct pollfd pfd = { .fd = reports[0], .events = POLLIN };

	require(poll(&pfd, 1, 10000) == 1 && read(reports[0], &byte, 1) == 0,
		"detached tracee closed completion pipe");
	active_descendant = 0;
	close(reports[0]);
	close(start[1]);
	printf("RESULT review_ptrace_tracer_exit 1 bool\n");
}

static void verify_syscall_stops(void)
{
	pid_t child = fork();

	require(child >= 0, "fork syscall-stop child");
	if (child == 0) {
		long expected = syscall(SYS_getpid);

		active_child = 0;
		require(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0, "syscall-stop TRACEME");
		require(raise(SIGSTOP) == 0, "syscall-stop initial stop");
		require(raw_getpid_loop(1) == expected, "traced getpid result");
		_exit(0);
	}
	active_child = child;
	require_stopped(wait_child(child), SIGSTOP);
	require(ptrace(PTRACE_SETOPTIONS, child, NULL,
		       (void *)(uintptr_t)PTRACE_O_TRACESYSGOOD) == 0,
		"PTRACE_O_TRACESYSGOOD");
	int getpid_stops = 0;

	for (int attempt = 0; getpid_stops < 2 && attempt < 32; attempt++) {
		struct user_regs_struct regs;

		require(ptrace(PTRACE_SYSCALL, child, NULL, NULL) == 0, "PTRACE_SYSCALL");
		require_stopped(wait_child(child), SIGTRAP | 0x80);
		require(ptrace(PTRACE_GETREGS, child, NULL, &regs) == 0,
			"syscall-stop GETREGS");
		if (regs.orig_rax == SYS_getpid) {
			getpid_stops++;
			if (getpid_stops == 2)
				require(regs.rax == (unsigned long)child, "getpid exit-stop result");
		}
	}
	require(getpid_stops == 2, "getpid entry and exit stops");
	require(ptrace(PTRACE_CONT, child, NULL, NULL) == 0, "resume after syscall stops");
	require_exited(wait_child(child));
	printf("RESULT review_ptrace_syscall_stops 1 bool\n");
}

static void verify_signal_queues(void)
{
	pid_t child = fork();

	require(child >= 0, "fork signal validation child");
	if (child == 0) {
		sigset_t original;
		int realtime_signal = SIGRTMIN + 2;
		long pid = syscall(SYS_getpid);
		long tid = syscall(SYS_gettid);

		active_child = 0;
		block_signal(SIGUSR1, &original);
		require(kill((pid_t)pid, SIGUSR1) == 0 && kill((pid_t)pid, SIGUSR1) == 0,
			"standard signal coalescing");
		require_signal_pending(SIGUSR1);
		unblock_and_check(SIGUSR1, &original, 1);
		block_signal(realtime_signal, &original);
		require(syscall(SYS_tgkill, pid, tid, realtime_signal) == 0 &&
			syscall(SYS_tgkill, pid, tid, realtime_signal) == 0,
			"queue two realtime thread signals");
		require_signal_pending(realtime_signal);
		unblock_and_check(realtime_signal, &original, 2);
		verify_ignored_requeue(SIGUSR2, 0);
		verify_ignored_requeue(SIGRTMIN + 4, 1);
		verify_signalfd_requeue();
		_exit(0);
	}
	active_child = child;
	require_exited(wait_child(child));
	printf("RESULT review_signal_queue_semantics 1 bool\n");
	printf("RESULT review_signal_ignored_requeue 1 bool\n");
	printf("RESULT review_signalfd_requeue 1 bool\n");
}

static void verify_concurrent_signals(void)
{
	const int batches = 32, per_batch = 32;
	int realtime_signal = SIGRTMIN + 5;
	int reports[2];
	int sender_cpu = -1;
	cpu_set_t original_affinity, sender_affinity;
	char byte;

	require(sched_getaffinity(0, sizeof(original_affinity), &original_affinity) == 0,
		"concurrent signal CPU affinity");
	for (int cpu = 1; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &original_affinity)) {
			sender_cpu = cpu;
			break;
		}
	}
	require(CPU_ISSET(0, &original_affinity) && sender_cpu >= 0,
		"concurrent signal validation requires CPU 0 and another allowed CPU");
	require(pipe(reports) == 0, "concurrent signal pipe");
	pid_t child = fork();

	require(child >= 0, "fork concurrent signal receiver");
	if (child == 0) {
		sigset_t original;
		long pid = syscall(SYS_getpid);

		active_child = 0;
		close(reports[0]);
		pin_to_cpu_zero();
		block_signal(realtime_signal, &original);
		require(sigprocmask(SIG_SETMASK, &original, NULL) == 0, "enable concurrent RT delivery");
		pipe_send(reports[1], "R", 1);
		for (int batch = 1; batch <= batches; batch++) {
			int expected = batch * per_batch;
			uint64_t deadline = now_ns() + 10000000000ULL;

			while (delivered < expected) {
				require(raw_getpid_loop(64) == pid, "busy receiver getpid");
				require(now_ns() < deadline, "concurrent signals delivered before deadline");
			}
			require(delivered == expected, "concurrent batch exact RT delivery count");
			require_signal_absent(realtime_signal);
			pipe_send(reports[1], "A", 1);
		}
		require(raw_getpid_loop(256) == pid && delivered == batches * per_batch,
			"all concurrent RT signals delivered exactly once");
		_exit(0);
	}
	active_child = child;
	close(reports[1]);
	CPU_ZERO(&sender_affinity);
	CPU_SET(sender_cpu, &sender_affinity);
	require(sched_setaffinity(0, sizeof(sender_affinity), &sender_affinity) == 0,
		"pin concurrent signal sender");
	require(sched_yield() == 0, "settle concurrent sender affinity");
	if (current_cpu() != sender_cpu) {
		struct timespec delay = { .tv_sec = 0, .tv_nsec = 200000L };

		require(nanosleep(&delay, NULL) == 0, "concurrent sender affinity delay");
	}
	require(current_cpu() == sender_cpu, "sender and receiver use distinct CPUs");
	pipe_receive(reports[0], &byte, sizeof(byte), 10000);
	require(byte == 'R', "concurrent signal receiver ready");
	for (int batch = 0; batch < batches; batch++) {
		for (int instance = 0; instance < per_batch; instance++) {
			if (instance & 1)
				require(kill(child, realtime_signal) == 0, "concurrent process RT enqueue");
			else
				require(syscall(SYS_tgkill, child, child, realtime_signal) == 0,
					"concurrent thread RT enqueue");
		}
		pipe_receive(reports[0], &byte, sizeof(byte), 10000);
		require(byte == 'A', "concurrent signal batch drained");
	}
	wait_exit_before_deadline(child);
	close(reports[0]);
	require(sched_setaffinity(0, sizeof(original_affinity), &original_affinity) == 0,
		"restore sender CPU affinity");
	printf("RESULT review_signal_concurrent_delivered %d signals\n", batches * per_batch);
	printf("RESULT review_signal_concurrent 1 bool\n");
}

int main(int argc, char **argv)
{
	int verify_only = 0;

	for (int argument = 1; argument < argc; argument++) {
		if (strcmp(argv[argument], "--verify-only") == 0)
			verify_only = 1;
		else
			fprintf(stderr, "REVIEW_SYSCALL_IGNORED_ARGUMENT %s\n", argv[argument]);
	}
	require(setvbuf(stdout, NULL, _IONBF, 0) == 0, "unbuffered results");
	require(atexit(cleanup_child) == 0, "register child cleanup");
	verify_syscall_stops();
	verify_signal_queues();
	verify_concurrent_signals();
	run_case(CASE_PLAIN, "plain", verify_only);
	run_case(CASE_PTRACE_CONT, "ptrace_cont", verify_only);
	run_tracer_exit_detached(verify_only);
	run_case(CASE_BLOCKED_SIGNAL, "blocked_signal", verify_only);
	printf("RESULT suite_done 1 bool\n");
	return 0;
}
