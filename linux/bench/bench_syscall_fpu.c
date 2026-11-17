// SPDX-License-Identifier: GPL-2.0
//
// Standalone SMP, syscall, FPU, and rt_sigreturn benchmark/verification suite.
//
// Compiles statically (`gcc -O2 -static -pthread -o bench_syscall_fpu bench_syscall_fpu.c`)
// and runs identically on Native Linux and as `/init` inside Asterinas.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#define GETPID_WARMUP 50000
#define GETPID_ITERS  1000000
#define GETPID_SAMPLES 9
#define FPU_ABA_TRIPS 50000
#define SMP_ROUNDS    1000

static uint64_t now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int current_cpu(void)
{
	unsigned int cpu;

	if (syscall(SYS_getcpu, &cpu, NULL, NULL) != 0)
		return -1;
	return (int)cpu;
}

static int pin_to_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set) != 0)
		return -1;
	sched_yield();
	if (current_cpu() != cpu) {
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 200000L };
		nanosleep(&ts, NULL);
	}
	return current_cpu() == cpu ? 0 : -1;
}

static void restore_all_cpus(long nproc)
{
	cpu_set_t set;
	long limit = nproc;

	if (limit < 1)
		limit = 1;
	if (limit > CPU_SETSIZE)
		limit = CPU_SETSIZE;
	CPU_ZERO(&set);
	for (long i = 0; i < limit; i++)
		CPU_SET((int)i, &set);
	(void)sched_setaffinity(0, sizeof(set), &set);
}

static int detect_avx_support(void)
{
	uint32_t eax, ebx, ecx, edx;
	uint32_t xcr0_lo, xcr0_hi;

	__asm__ __volatile__("cpuid"
			     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
			     : "a"(1), "c"(0));
	// Bit 27 = OSXSAVE, Bit 28 = AVX
	if ((ecx & ((1U << 27) | (1U << 28))) != ((1U << 27) | (1U << 28)))
		return 0;
	__asm__ __volatile__("xgetbv" : "=a"(xcr0_lo), "=d"(xcr0_hi) : "c"(0));
	// XCR0[2:1] = SSE (bit 1) + AVX (bit 2)
	return (xcr0_lo & 0x6U) == 0x6U;
}

// ------------------------------------------------------------------
// 1. SMP check (2 pthreads + 2 forked children across >=2 CPUs)
// ------------------------------------------------------------------

struct smp_shared {
	atomic_int turn;
	atomic_int pings;
	atomic_int cpu_seen[2];
};

struct smp_thread_arg {
	struct smp_shared *sh;
	int id;
	int nproc;
};

static void *smp_pthread_fn(void *arg)
{
	struct smp_thread_arg *a = (struct smp_thread_arg *)arg;
	struct smp_shared *sh = a->sh;
	int id = a->id;
	int target_cpu = (a->nproc >= 2) ? id : 0;

	pin_to_cpu(target_cpu);
	for (int i = 0; i < SMP_ROUNDS; i++) {
		while (atomic_load_explicit(&sh->turn, memory_order_acquire) != id)
			sched_yield();
		int c = current_cpu();
		if (c >= 0)
			atomic_store_explicit(&sh->cpu_seen[id], c, memory_order_relaxed);
		atomic_fetch_add_explicit(&sh->pings, 1, memory_order_relaxed);
		atomic_store_explicit(&sh->turn, 1 - id, memory_order_release);
	}
	return NULL;
}

static int run_smp_check(void)
{
	long nproc = sysconf(_SC_NPROCESSORS_ONLN);
	int ok = 1;

	if (nproc < 1)
		nproc = 1;

	// Part A: 2 pthreads
	{
		struct smp_shared sh;
		atomic_init(&sh.turn, 0);
		atomic_init(&sh.pings, 0);
		atomic_init(&sh.cpu_seen[0], -1);
		atomic_init(&sh.cpu_seen[1], -1);

		pthread_t t[2];
		struct smp_thread_arg args[2] = {
			{ .sh = &sh, .id = 0, .nproc = (int)nproc },
			{ .sh = &sh, .id = 1, .nproc = (int)nproc },
		};
		for (int i = 0; i < 2; i++) {
			if (nproc >= 2)
				pin_to_cpu(i);
			if (pthread_create(&t[i], NULL, smp_pthread_fn, &args[i]) != 0) {
				restore_all_cpus(nproc);
				printf("RESULT smp_pthreads_cpus 0 cpus\n");
				printf("RESULT smp_check 0 bool\n");
				return 1;
			}
		}
		restore_all_cpus(nproc);
		for (int i = 0; i < 2; i++)
			pthread_join(t[i], NULL);

		int c0 = atomic_load(&sh.cpu_seen[0]);
		int c1 = atomic_load(&sh.cpu_seen[1]);
		int pings = atomic_load(&sh.pings);
		int distinct = (c0 >= 0 && c1 >= 0) ? ((c0 != c1) ? 2 : 1) : 0;

		printf("RESULT smp_pthreads_cpus %d cpus\n", distinct);
		if (pings != 2 * SMP_ROUNDS) {
			fprintf(stderr, "smp pthreads pings=%d expected=%d\n", pings, 2 * SMP_ROUNDS);
			ok = 0;
		}
		if (nproc >= 2 && distinct < 2) {
			fprintf(stderr, "smp pthreads c0=%d c1=%d nproc=%ld\n", c0, c1, nproc);
			ok = 0;
		}
	}

	// Part B: 2 forked children
	{
		struct smp_shared *sh = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
					     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (sh == MAP_FAILED) {
			perror("mmap smp_shared");
			printf("RESULT smp_fork_cpus 0 cpus\n");
			printf("RESULT smp_check 0 bool\n");
			return 1;
		}
		atomic_init(&sh->turn, 0);
		atomic_init(&sh->pings, 0);
		atomic_init(&sh->cpu_seen[0], -1);
		atomic_init(&sh->cpu_seen[1], -1);

		pid_t pids[2];
		for (int id = 0; id < 2; id++) {
			if (nproc >= 2)
				pin_to_cpu(id);
			pids[id] = fork();
			if (pids[id] < 0) {
				restore_all_cpus(nproc);
				perror("fork");
				munmap(sh, 4096);
				printf("RESULT smp_fork_cpus 0 cpus\n");
				printf("RESULT smp_check 0 bool\n");
				return 1;
			}
			if (pids[id] == 0) {
				int target_cpu = (nproc >= 2) ? id : 0;
				pin_to_cpu(target_cpu);
				for (int i = 0; i < SMP_ROUNDS; i++) {
					while (atomic_load_explicit(&sh->turn, memory_order_acquire) != id)
						sched_yield();
					int c = current_cpu();
					if (c >= 0)
						atomic_store_explicit(&sh->cpu_seen[id], c, memory_order_relaxed);
					atomic_fetch_add_explicit(&sh->pings, 1, memory_order_relaxed);
					atomic_store_explicit(&sh->turn, 1 - id, memory_order_release);
				}
				_exit(0);
			}
		}
		restore_all_cpus(nproc);
		for (int id = 0; id < 2; id++) {
			int st = 0;
			waitpid(pids[id], &st, 0);
			if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
				ok = 0;
		}
		int c0 = atomic_load(&sh->cpu_seen[0]);
		int c1 = atomic_load(&sh->cpu_seen[1]);
		int pings = atomic_load(&sh->pings);
		int distinct = (c0 >= 0 && c1 >= 0) ? ((c0 != c1) ? 2 : 1) : 0;
		munmap(sh, 4096);

		printf("RESULT smp_fork_cpus %d cpus\n", distinct);
		if (pings != 2 * SMP_ROUNDS) {
			fprintf(stderr, "smp fork pings=%d expected=%d\n", pings, 2 * SMP_ROUNDS);
			ok = 0;
		}
		if (nproc >= 2 && distinct < 2) {
			fprintf(stderr, "smp fork c0=%d c1=%d nproc=%ld\n", c0, c1, nproc);
			ok = 0;
		}
	}

	printf("RESULT smp_check %d bool\n", ok);
	fflush(stdout);
	return ok ? 0 : 1;
}

// ------------------------------------------------------------------
// 2. PR #3 getpid benchmark & register preservation
// ------------------------------------------------------------------

__attribute__((noinline))
static long raw_getpid_loop(int iters)
{
	long cnt = iters;
	long pid;
	__asm__ __volatile__(
		"1:\n\t"
		"mov $39, %%eax\n\t"
		"syscall\n\t"
		"dec %[cnt]\n\t"
		"jnz 1b\n\t"
		: [cnt] "+r"(cnt), "=&a"(pid)
		:
		: "rcx", "r11", "cc", "memory");
	return pid;
}

struct reg_check_req {
	uint64_t nr;
	uint64_t arg1;
	uint64_t arg2;
	uint64_t out_ptr;
};

// Verify rbx, rbp, rdi, rsi, rdx, r8, r9, r10, r12, r13, r14, r15 across syscall.
// Store observed values in out[12] to compare in C.
__attribute__((noinline))
static void check_regs_syscall(uint64_t nr, uint64_t arg1, uint64_t arg2, uint64_t out[12])
{
	struct reg_check_req req = {
		.nr = nr,
		.arg1 = arg1,
		.arg2 = arg2,
		.out_ptr = (uint64_t)(uintptr_t)out,
	};

	__asm__ __volatile__(
		"push %%rbp\n\t"
		"push %%rbx\n\t"
		"mov 24(%%rax), %%rcx\n\t"
		"push %%rcx\n\t"          // [rsp] = out_ptr
		"mov  8(%%rax), %%rdi\n\t"
		"mov 16(%%rax), %%rsi\n\t"
		"mov  0(%%rax), %%rax\n\t"
		"mov $0x4444444444444401, %%rbx\n\t"
		"mov $0x5555555555555502, %%rbp\n\t"
		"mov $0x6666666666666603, %%rdx\n\t"
		"mov $0x1111111111111108, %%r8\n\t"
		"mov $0x2222222222222209, %%r9\n\t"
		"mov $0x333333333333330a, %%r10\n\t"
		"mov $0x777777777777770c, %%r12\n\t"
		"mov $0x888888888888880d, %%r13\n\t"
		"mov $0x999999999999990e, %%r14\n\t"
		"mov $0xaaaaaaaaaaaaaa0f, %%r15\n\t"
		"syscall\n\t"
		"pop %%rcx\n\t"           // rcx = out_ptr
		"mov %%rbx,  0(%%rcx)\n\t"
		"mov %%rbp,  8(%%rcx)\n\t"
		"mov %%rdi, 16(%%rcx)\n\t"
		"mov %%rsi, 24(%%rcx)\n\t"
		"mov %%rdx, 32(%%rcx)\n\t"
		"mov %%r8,  40(%%rcx)\n\t"
		"mov %%r9,  48(%%rcx)\n\t"
		"mov %%r10, 56(%%rcx)\n\t"
		"mov %%r12, 64(%%rcx)\n\t"
		"mov %%r13, 72(%%rcx)\n\t"
		"mov %%r14, 80(%%rcx)\n\t"
		"mov %%r15, 88(%%rcx)\n\t"
		"pop %%rbx\n\t"
		"pop %%rbp\n\t"
		:
		: "a"(&req)
		: "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
		  "r12", "r13", "r14", "r15", "cc", "memory");
}

static int verify_regs_array(const char *tag, uint64_t arg1, uint64_t arg2, const uint64_t out[12])
{
	const uint64_t exp[12] = {
		0x4444444444444401ULL, // rbx
		0x5555555555555502ULL, // rbp
		arg1,                  // rdi
		arg2,                  // rsi
		0x6666666666666603ULL, // rdx
		0x1111111111111108ULL, // r8
		0x2222222222222209ULL, // r9
		0x333333333333330aULL, // r10
		0x777777777777770cULL, // r12
		0x888888888888880dULL, // r13
		0x999999999999990eULL, // r14
		0xaaaaaaaaaaaaaa0fULL, // r15
	};
	int ok = 1;

	for (int i = 0; i < 12; i++) {
		if (out[i] != exp[i]) {
			fprintf(stderr, "%s reg[%d] mismatch: got=0x%llx exp=0x%llx\n",
				tag, i, (unsigned long long)out[i], (unsigned long long)exp[i]);
			ok = 0;
		}
	}
	return ok;
}

static uint64_t ordered_tsc(void)
{
	unsigned int lo, hi;

	__asm__ __volatile__("lfence; rdtsc; lfence"
			     : "=a"(lo), "=d"(hi) : : "memory");
	return ((uint64_t)hi << 32) | lo;
}

static int compare_u64(const void *left, const void *right)
{
	uint64_t a = *(const uint64_t *)left;
	uint64_t b = *(const uint64_t *)right;

	return (a > b) - (a < b);
}

static int run_getpid_bench(void)
{
	uint64_t out[12];
	uint64_t samples[GETPID_SAMPLES];
	cpu_set_t original, actual;
	long pid = syscall(SYS_getpid);
	int ok = 1;

	if (sched_getaffinity(0, sizeof(original), &original) != 0 ||
	    pin_to_cpu(0) != 0 ||
	    sched_getaffinity(0, sizeof(actual), &actual) != 0 ||
	    CPU_COUNT(&actual) != 1 || !CPU_ISSET(0, &actual) || pid <= 0) {
		fprintf(stderr, "getpid benchmark requires a valid PID and CPU 0 affinity\n");
		return 1;
	}
	for (int sample = 0; sample < GETPID_SAMPLES; sample++) {
		if (raw_getpid_loop(GETPID_WARMUP) != pid || current_cpu() != 0) {
			ok = 0;
			break;
		}
		uint64_t ns_start = now_ns();
		uint64_t tsc_start = ordered_tsc();
		long observed = raw_getpid_loop(GETPID_ITERS);
		uint64_t cycles = ordered_tsc() - tsc_start;
		uint64_t elapsed_ns = now_ns() - ns_start;
		int cpu = current_cpu();
		int valid = observed == pid && cpu == 0 && elapsed_ns > 0;

		printf("SYSCALL_SAMPLE {\"sample\":%d,\"iterations\":%d,"
		       "\"elapsed_ns\":%llu,\"tsc_ticks\":%llu,\"cpu\":%d,"
		       "\"pid\":%ld,\"valid\":%s}\n", sample, GETPID_ITERS,
		       (unsigned long long)elapsed_ns, (unsigned long long)cycles,
		       cpu, observed, valid ? "true" : "false");
		if (!valid) {
			ok = 0;
			break;
		}
		samples[sample] = elapsed_ns;
	}
	if (sched_setaffinity(0, sizeof(original), &original) != 0)
		ok = 0;
	if (!ok) {
		fprintf(stderr, "getpid benchmark validation failed\n");
		return 1;
	}
	qsort(samples, GETPID_SAMPLES, sizeof(samples[0]), compare_u64);
	printf("RESULT getpid_ns %.2f ns\n",
	       (double)samples[GETPID_SAMPLES / 2] / GETPID_ITERS);

	memset(out, 0, sizeof(out));
	check_regs_syscall(SYS_getpid, 0x123456789abcdef0ULL, 0xfedcba9876543210ULL, out);
	int g_ok = verify_regs_array("getpid", 0x123456789abcdef0ULL, 0xfedcba9876543210ULL, out);
	printf("RESULT reg_preserve_getpid %d bool\n", g_ok);
	if (!g_ok)
		ok = 0;

	struct timespec req = { .tv_sec = 0, .tv_nsec = 1000000L };
	memset(out, 0, sizeof(out));
	check_regs_syscall(SYS_nanosleep, (uint64_t)(uintptr_t)&req, 0ULL, out);
	int n_ok = verify_regs_array("nanosleep", (uint64_t)(uintptr_t)&req, 0ULL, out);
	printf("RESULT reg_preserve_nanosleep %d bool\n", n_ok);
	if (!n_ok)
		ok = 0;

	fflush(stdout);
	return ok ? 0 : 1;
}

// ------------------------------------------------------------------
// 3. PR #7 Same-tenant FPU getpid (x87 + SSE, x87 + AVX)
// ------------------------------------------------------------------

struct __attribute__((aligned(32))) fpu_state_buf {
	uint8_t x87[8][10];
	uint64_t ymm[16][4];
};

static void fill_fpu_pattern(struct fpu_state_buf *buf, uint64_t seed)
{
	memset(buf, 0, sizeof(*buf));
	for (int i = 0; i < 8; i++) {
		long double val = (long double)(1.25L + (long double)i * 0.125L +
						(long double)(seed & 0xff) * 0.001L);
		memcpy(buf->x87[i], &val, 10);
	}
	for (int r = 0; r < 16; r++) {
		for (int q = 0; q < 4; q++) {
			buf->ymm[r][q] = (seed * 0x9e3779b97f4a7c15ULL) ^
					 ((uint64_t)(r + 1) << 40) ^
					 ((uint64_t)(q + 1) << 16) ^
					 0xa5a55a5a01234567ULL;
		}
	}
}

__attribute__((noinline))
static void run_fpu_sse_getpid_asm(const struct fpu_state_buf *in,
				   struct fpu_state_buf *out,
				   int iters)
{
	long cnt = iters;

	__asm__ __volatile__(
		"fninit\n\t"
		"fldt 70(%[in])\n\t"
		"fldt 60(%[in])\n\t"
		"fldt 50(%[in])\n\t"
		"fldt 40(%[in])\n\t"
		"fldt 30(%[in])\n\t"
		"fldt 20(%[in])\n\t"
		"fldt 10(%[in])\n\t"
		"fldt  0(%[in])\n\t"
		"movdqu  80(%[in]), %%xmm0\n\t"
		"movdqu 112(%[in]), %%xmm1\n\t"
		"movdqu 144(%[in]), %%xmm2\n\t"
		"movdqu 176(%[in]), %%xmm3\n\t"
		"movdqu 208(%[in]), %%xmm4\n\t"
		"movdqu 240(%[in]), %%xmm5\n\t"
		"movdqu 272(%[in]), %%xmm6\n\t"
		"movdqu 304(%[in]), %%xmm7\n\t"
		"movdqu 336(%[in]), %%xmm8\n\t"
		"movdqu 368(%[in]), %%xmm9\n\t"
		"movdqu 400(%[in]), %%xmm10\n\t"
		"movdqu 432(%[in]), %%xmm11\n\t"
		"movdqu 464(%[in]), %%xmm12\n\t"
		"movdqu 496(%[in]), %%xmm13\n\t"
		"movdqu 528(%[in]), %%xmm14\n\t"
		"movdqu 560(%[in]), %%xmm15\n\t"
		"1:\n\t"
		"mov $39, %%eax\n\t"
		"syscall\n\t"
		"dec %[cnt]\n\t"
		"jnz 1b\n\t"
		"movdqu %%xmm0,   80(%[out])\n\t"
		"movdqu %%xmm1,  112(%[out])\n\t"
		"movdqu %%xmm2,  144(%[out])\n\t"
		"movdqu %%xmm3,  176(%[out])\n\t"
		"movdqu %%xmm4,  208(%[out])\n\t"
		"movdqu %%xmm5,  240(%[out])\n\t"
		"movdqu %%xmm6,  272(%[out])\n\t"
		"movdqu %%xmm7,  304(%[out])\n\t"
		"movdqu %%xmm8,  336(%[out])\n\t"
		"movdqu %%xmm9,  368(%[out])\n\t"
		"movdqu %%xmm10, 400(%[out])\n\t"
		"movdqu %%xmm11, 432(%[out])\n\t"
		"movdqu %%xmm12, 464(%[out])\n\t"
		"movdqu %%xmm13, 496(%[out])\n\t"
		"movdqu %%xmm14, 528(%[out])\n\t"
		"movdqu %%xmm15, 560(%[out])\n\t"
		"fstpt  0(%[out])\n\t"
		"fstpt 10(%[out])\n\t"
		"fstpt 20(%[out])\n\t"
		"fstpt 30(%[out])\n\t"
		"fstpt 40(%[out])\n\t"
		"fstpt 50(%[out])\n\t"
		"fstpt 60(%[out])\n\t"
		"fstpt 70(%[out])\n\t"
		: [cnt] "+r"(cnt)
		: [in] "r"(in), [out] "r"(out)
		: "rax", "rcx", "r11", "cc", "memory",
		  "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
		  "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
		  "st", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)");
}

__attribute__((noinline, target("avx")))
static void run_fpu_avx_getpid_asm(const struct fpu_state_buf *in,
				   struct fpu_state_buf *out,
				   int iters)
{
	long cnt = iters;

	__asm__ __volatile__(
		"fninit\n\t"
		"fldt 70(%[in])\n\t"
		"fldt 60(%[in])\n\t"
		"fldt 50(%[in])\n\t"
		"fldt 40(%[in])\n\t"
		"fldt 30(%[in])\n\t"
		"fldt 20(%[in])\n\t"
		"fldt 10(%[in])\n\t"
		"fldt  0(%[in])\n\t"
		"vmovdqu  80(%[in]), %%ymm0\n\t"
		"vmovdqu 112(%[in]), %%ymm1\n\t"
		"vmovdqu 144(%[in]), %%ymm2\n\t"
		"vmovdqu 176(%[in]), %%ymm3\n\t"
		"vmovdqu 208(%[in]), %%ymm4\n\t"
		"vmovdqu 240(%[in]), %%ymm5\n\t"
		"vmovdqu 272(%[in]), %%ymm6\n\t"
		"vmovdqu 304(%[in]), %%ymm7\n\t"
		"vmovdqu 336(%[in]), %%ymm8\n\t"
		"vmovdqu 368(%[in]), %%ymm9\n\t"
		"vmovdqu 400(%[in]), %%ymm10\n\t"
		"vmovdqu 432(%[in]), %%ymm11\n\t"
		"vmovdqu 464(%[in]), %%ymm12\n\t"
		"vmovdqu 496(%[in]), %%ymm13\n\t"
		"vmovdqu 528(%[in]), %%ymm14\n\t"
		"vmovdqu 560(%[in]), %%ymm15\n\t"
		"1:\n\t"
		"mov $39, %%eax\n\t"
		"syscall\n\t"
		"dec %[cnt]\n\t"
		"jnz 1b\n\t"
		"vmovdqu %%ymm0,   80(%[out])\n\t"
		"vmovdqu %%ymm1,  112(%[out])\n\t"
		"vmovdqu %%ymm2,  144(%[out])\n\t"
		"vmovdqu %%ymm3,  176(%[out])\n\t"
		"vmovdqu %%ymm4,  208(%[out])\n\t"
		"vmovdqu %%ymm5,  240(%[out])\n\t"
		"vmovdqu %%ymm6,  272(%[out])\n\t"
		"vmovdqu %%ymm7,  304(%[out])\n\t"
		"vmovdqu %%ymm8,  336(%[out])\n\t"
		"vmovdqu %%ymm9,  368(%[out])\n\t"
		"vmovdqu %%ymm10, 400(%[out])\n\t"
		"vmovdqu %%ymm11, 432(%[out])\n\t"
		"vmovdqu %%ymm12, 464(%[out])\n\t"
		"vmovdqu %%ymm13, 496(%[out])\n\t"
		"vmovdqu %%ymm14, 528(%[out])\n\t"
		"vmovdqu %%ymm15, 560(%[out])\n\t"
		"fstpt  0(%[out])\n\t"
		"fstpt 10(%[out])\n\t"
		"fstpt 20(%[out])\n\t"
		"fstpt 30(%[out])\n\t"
		"fstpt 40(%[out])\n\t"
		"fstpt 50(%[out])\n\t"
		"fstpt 60(%[out])\n\t"
		"fstpt 70(%[out])\n\t"
		"vzeroupper\n\t"
		: [cnt] "+r"(cnt)
		: [in] "r"(in), [out] "r"(out)
		: "rax", "rcx", "r11", "cc", "memory",
		  "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
		  "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",
		  "st", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)");
}

static int verify_fpu_buf(const char *tag, const struct fpu_state_buf *exp,
			  const struct fpu_state_buf *obs, int check_avx)
{
	int ok = 1;

	for (int i = 0; i < 8; i++) {
		if (memcmp(exp->x87[i], obs->x87[i], 10) != 0) {
			fprintf(stderr, "%s x87 st(%d) mismatch\n", tag, i);
			ok = 0;
		}
	}
	int qwords = check_avx ? 4 : 2;
	for (int r = 0; r < 16; r++) {
		for (int q = 0; q < qwords; q++) {
			if (exp->ymm[r][q] != obs->ymm[r][q]) {
				fprintf(stderr, "%s %s%d[%d] mismatch: got=0x%llx exp=0x%llx\n",
					tag, check_avx ? "ymm" : "xmm", r, q,
					(unsigned long long)obs->ymm[r][q],
					(unsigned long long)exp->ymm[r][q]);
				ok = 0;
			}
		}
	}
	return ok;
}

static int run_fpu_getpid_bench(int has_avx)
{
	struct fpu_state_buf in, out;
	int ok = 1;

	fill_fpu_pattern(&in, 0x13572468ULL);
	memset(&out, 0, sizeof(out));
	run_fpu_sse_getpid_asm(&in, &out, GETPID_WARMUP);
	if (!verify_fpu_buf("fpu_sse_warmup", &in, &out, 0))
		ok = 0;

	memset(&out, 0, sizeof(out));
	uint64_t t0 = now_ns();
	run_fpu_sse_getpid_asm(&in, &out, GETPID_ITERS);
	uint64_t dt = now_ns() - t0;
	int sse_ok = verify_fpu_buf("fpu_sse_getpid", &in, &out, 0);
	printf("RESULT fpu_sse_getpid_ns %.2f ns\n", (double)dt / (double)GETPID_ITERS);
	printf("RESULT fpu_sse_getpid_ok %d bool\n", sse_ok);
	if (!sse_ok)
		ok = 0;

	if (has_avx) {
		fill_fpu_pattern(&in, 0x24681357ULL);
		memset(&out, 0, sizeof(out));
		run_fpu_avx_getpid_asm(&in, &out, GETPID_WARMUP);
		if (!verify_fpu_buf("fpu_avx_warmup", &in, &out, 1))
			ok = 0;

		memset(&out, 0, sizeof(out));
		t0 = now_ns();
		run_fpu_avx_getpid_asm(&in, &out, GETPID_ITERS);
		dt = now_ns() - t0;
		int avx_ok = verify_fpu_buf("fpu_avx_getpid", &in, &out, 1);
		printf("RESULT fpu_avx_getpid_ns %.2f ns\n", (double)dt / (double)GETPID_ITERS);
		printf("RESULT fpu_avx_getpid_ok %d bool\n", avx_ok);
		if (!avx_ok)
			ok = 0;
	} else {
		printf("RESULT fpu_avx_getpid_ns SKIP na\n");
	}

	fflush(stdout);
	return ok ? 0 : 1;
}

// ------------------------------------------------------------------
// 4. PR #7 Intra-carrier A <-> B FPU switch on CPU 0
// ------------------------------------------------------------------

struct __attribute__((aligned(32))) aba_state {
	double x87[4];
	double vec[8][4]; // 8 registers * 4 doubles (256-bit)
};

struct aba_shared {
	atomic_int turn;
	atomic_int ready;
	atomic_int errors;
	int trips;
	int use_avx;
};

struct aba_thread_arg {
	struct aba_shared *sh;
	int id;
};

// Perform x87 add + SSE addpd across SYS_sched_yield, handing turn to other thread right before yield.
__attribute__((noinline))
static void aba_step_sse(struct aba_state *st, const struct aba_state *delta,
			 atomic_int *turn, int next_id)
{
	__asm__ __volatile__(
		"fninit\n\t"
		"fldl 24(%[st])\n\t"
		"fldl 16(%[st])\n\t"
		"fldl  8(%[st])\n\t"
		"fldl  0(%[st])\n\t"
		"faddl  0(%[d])\n\t"
		"fxch %%st(1)\n\t"
		"faddl  8(%[d])\n\t"
		"fxch %%st(2)\n\t"
		"faddl 16(%[d])\n\t"
		"fxch %%st(3)\n\t"
		"faddl 24(%[d])\n\t"
		"fxch %%st(3)\n\t"
		"fxch %%st(2)\n\t"
		"fxch %%st(1)\n\t"
		"movupd  32(%[st]), %%xmm0\n\t"
		"movupd  64(%[st]), %%xmm1\n\t"
		"movupd  96(%[st]), %%xmm2\n\t"
		"movupd 128(%[st]), %%xmm3\n\t"
		"movupd 160(%[st]), %%xmm4\n\t"
		"movupd 192(%[st]), %%xmm5\n\t"
		"movupd 224(%[st]), %%xmm6\n\t"
		"movupd 256(%[st]), %%xmm7\n\t"
		"movupd  32(%[d]), %%xmm8\n\t"
		"addpd %%xmm8, %%xmm0\n\t"
		"movupd  64(%[d]), %%xmm8\n\t"
		"addpd %%xmm8, %%xmm1\n\t"
		"movupd  96(%[d]), %%xmm8\n\t"
		"addpd %%xmm8, %%xmm2\n\t"
		"movupd 128(%[d]), %%xmm8\n\t"
		"addpd %%xmm8, %%xmm3\n\t"
		"movupd 160(%[d]), %%xmm8\n\t"
		"addpd %%xmm8, %%xmm4\n\t"
		"movupd 192(%[d]), %%xmm8\n\t"
		"addpd %%xmm8, %%xmm5\n\t"
		"movupd 224(%[d]), %%xmm8\n\t"
		"addpd %%xmm8, %%xmm6\n\t"
		"movupd 256(%[d]), %%xmm8\n\t"
		"addpd %%xmm8, %%xmm7\n\t"
		"xchg %[nxt], (%[tp])\n\t"
		"mov $24, %%eax\n\t"
		"syscall\n\t"
		"movupd %%xmm0,  32(%[st])\n\t"
		"movupd %%xmm1,  64(%[st])\n\t"
		"movupd %%xmm2,  96(%[st])\n\t"
		"movupd %%xmm3, 128(%[st])\n\t"
		"movupd %%xmm4, 160(%[st])\n\t"
		"movupd %%xmm5, 192(%[st])\n\t"
		"movupd %%xmm6, 224(%[st])\n\t"
		"movupd %%xmm7, 256(%[st])\n\t"
		"fstpl  0(%[st])\n\t"
		"fstpl  8(%[st])\n\t"
		"fstpl 16(%[st])\n\t"
		"fstpl 24(%[st])\n\t"
		: [nxt] "+r"(next_id)
		: [st] "r"(st), [d] "r"(delta), [tp] "r"(turn)
		: "rax", "rcx", "r11", "cc", "memory",
		  "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8",
		  "st", "st(1)", "st(2)", "st(3)");
}

__attribute__((noinline, target("avx")))
static void aba_step_avx(struct aba_state *st, const struct aba_state *delta,
			 atomic_int *turn, int next_id)
{
	__asm__ __volatile__(
		"fninit\n\t"
		"fldl 24(%[st])\n\t"
		"fldl 16(%[st])\n\t"
		"fldl  8(%[st])\n\t"
		"fldl  0(%[st])\n\t"
		"faddl  0(%[d])\n\t"
		"fxch %%st(1)\n\t"
		"faddl  8(%[d])\n\t"
		"fxch %%st(2)\n\t"
		"faddl 16(%[d])\n\t"
		"fxch %%st(3)\n\t"
		"faddl 24(%[d])\n\t"
		"fxch %%st(3)\n\t"
		"fxch %%st(2)\n\t"
		"fxch %%st(1)\n\t"
		"vmovupd  32(%[st]), %%ymm0\n\t"
		"vmovupd  64(%[st]), %%ymm1\n\t"
		"vmovupd  96(%[st]), %%ymm2\n\t"
		"vmovupd 128(%[st]), %%ymm3\n\t"
		"vmovupd 160(%[st]), %%ymm4\n\t"
		"vmovupd 192(%[st]), %%ymm5\n\t"
		"vmovupd 224(%[st]), %%ymm6\n\t"
		"vmovupd 256(%[st]), %%ymm7\n\t"
		"vaddpd  32(%[d]), %%ymm0, %%ymm0\n\t"
		"vaddpd  64(%[d]), %%ymm1, %%ymm1\n\t"
		"vaddpd  96(%[d]), %%ymm2, %%ymm2\n\t"
		"vaddpd 128(%[d]), %%ymm3, %%ymm3\n\t"
		"vaddpd 160(%[d]), %%ymm4, %%ymm4\n\t"
		"vaddpd 192(%[d]), %%ymm5, %%ymm5\n\t"
		"vaddpd 224(%[d]), %%ymm6, %%ymm6\n\t"
		"vaddpd 256(%[d]), %%ymm7, %%ymm7\n\t"
		"xchg %[nxt], (%[tp])\n\t"
		"mov $24, %%eax\n\t"
		"syscall\n\t"
		"vmovupd %%ymm0,  32(%[st])\n\t"
		"vmovupd %%ymm1,  64(%[st])\n\t"
		"vmovupd %%ymm2,  96(%[st])\n\t"
		"vmovupd %%ymm3, 128(%[st])\n\t"
		"vmovupd %%ymm4, 160(%[st])\n\t"
		"vmovupd %%ymm5, 192(%[st])\n\t"
		"vmovupd %%ymm6, 224(%[st])\n\t"
		"vmovupd %%ymm7, 256(%[st])\n\t"
		"fstpl  0(%[st])\n\t"
		"fstpl  8(%[st])\n\t"
		"fstpl 16(%[st])\n\t"
		"fstpl 24(%[st])\n\t"
		"vzeroupper\n\t"
		: [nxt] "+r"(next_id)
		: [st] "r"(st), [d] "r"(delta), [tp] "r"(turn)
		: "rax", "rcx", "r11", "cc", "memory",
		  "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
		  "st", "st(1)", "st(2)", "st(3)");
}

static void init_aba_state(struct aba_state *st, struct aba_state *delta, int id)
{
	double base = (id == 0) ? 1000.0 : -2000.0;
	double step = (id == 0) ? 1.0 : -1.0;

	memset(st, 0, sizeof(*st));
	memset(delta, 0, sizeof(*delta));
	for (int i = 0; i < 4; i++) {
		st->x87[i] = base + (double)(i * 10);
		delta->x87[i] = step * (double)(i + 1);
	}
	for (int r = 0; r < 8; r++) {
		for (int q = 0; q < 4; q++) {
			st->vec[r][q] = base + (double)(r * 100 + q);
			delta->vec[r][q] = step * (double)(r + q + 1);
		}
	}
}

static void *aba_worker(void *arg)
{
	struct aba_thread_arg *a = (struct aba_thread_arg *)arg;
	struct aba_shared *sh = a->sh;
	int id = a->id;
	struct aba_state st, exp, delta;

	pin_to_cpu(0);
	if (current_cpu() != 0)
		atomic_fetch_add(&sh->errors, 1);
	init_aba_state(&st, &delta, id);
	exp = st;

	atomic_fetch_add_explicit(&sh->ready, 1, memory_order_release);
	while (atomic_load_explicit(&sh->ready, memory_order_acquire) < 2)
		sched_yield();

	int vec_lanes = sh->use_avx ? 4 : 2;
	for (int t = 0; t < sh->trips; t++) {
		while (atomic_load_explicit(&sh->turn, memory_order_acquire) != id)
			sched_yield();

		if (sh->use_avx)
			aba_step_avx(&st, &delta, &sh->turn, 1 - id);
		else
			aba_step_sse(&st, &delta, &sh->turn, 1 - id);

		for (int i = 0; i < 4; i++)
			exp.x87[i] += delta.x87[i];
		for (int r = 0; r < 8; r++)
			for (int q = 0; q < vec_lanes; q++)
				exp.vec[r][q] += delta.vec[r][q];

		if (memcmp(st.x87, exp.x87, sizeof(st.x87)) != 0) {
			atomic_fetch_add(&sh->errors, 1);
			break;
		}
		for (int r = 0; r < 8; r++) {
			for (int q = 0; q < vec_lanes; q++) {
				if (st.vec[r][q] != exp.vec[r][q]) {
					atomic_fetch_add(&sh->errors, 1);
					return NULL;
				}
			}
		}
	}
	return NULL;
}

static int run_fpu_aba_mode(int use_avx, const char *metric_name)
{
	struct aba_shared sh;
	pthread_t th[2];
	struct aba_thread_arg args[2] = {
		{ .sh = &sh, .id = 0 },
		{ .sh = &sh, .id = 1 },
	};

	atomic_init(&sh.turn, 0);
	atomic_init(&sh.ready, 0);
	atomic_init(&sh.errors, 0);
	sh.trips = FPU_ABA_TRIPS;
	sh.use_avx = use_avx;

	long nproc = sysconf(_SC_NPROCESSORS_ONLN);
	pin_to_cpu(0);
	uint64_t t0 = now_ns();
	for (int i = 0; i < 2; i++) {
		if (pthread_create(&th[i], NULL, aba_worker, &args[i]) != 0) {
			restore_all_cpus(nproc);
			printf("RESULT %s 0 ns\n", metric_name);
			return 1;
		}
	}
	restore_all_cpus(nproc);
	for (int i = 0; i < 2; i++)
		pthread_join(th[i], NULL);
	uint64_t dt = now_ns() - t0;

	int errs = atomic_load(&sh.errors);
	printf("RESULT %s %.2f ns\n", metric_name, (double)dt / (double)FPU_ABA_TRIPS);
	printf("RESULT %s_ok %d bool\n", metric_name, errs == 0 ? 1 : 0);
	fflush(stdout);
	return errs == 0 ? 0 : 1;
}

static int run_fpu_aba_bench(int has_avx)
{
	int rc = 0;

	if (run_fpu_aba_mode(0, "fpu_switch_sse_aba_ns") != 0)
		rc = 1;
	if (has_avx) {
		if (run_fpu_aba_mode(1, "fpu_switch_avx_aba_ns") != 0)
			rc = 1;
	} else {
		printf("RESULT fpu_switch_avx_aba_ns SKIP na\n");
	}
	return rc;
}

// ------------------------------------------------------------------
// 5. PR #7 rt_sigreturn checked import test
// ------------------------------------------------------------------

enum sigret_mode {
	SIGRET_VALID = 0,
	SIGRET_BAD_MXCSR = 1,
	SIGRET_BAD_XCOMP_BV = 2,
};

static volatile sig_atomic_t g_sigret_mode;
static volatile sig_atomic_t g_sig_handled;
static int g_has_avx;

struct xstate_sw_reserved {
	uint32_t magic1;
	uint32_t extended_size;
	uint64_t xfeatures;
	uint32_t xstate_size;
	uint32_t padding[7];
};

static void sigusr1_handler(int sig, siginfo_t *si, void *uctx)
{
	(void)sig;
	(void)si;
	ucontext_t *uc = (ucontext_t *)uctx;
	fpregset_t fp = uc->uc_mcontext.fpregs;

	g_sig_handled = 1;
	if (!fp) {
		if (g_sigret_mode == SIGRET_VALID)
			_exit(10);
		return;
	}
	if (g_sigret_mode == SIGRET_VALID) {
		// Benign modification: update xmm0 low 32-bit word in fpregs.
		fp->_xmm[0].element[0] = 0x12345678U;
	} else if (g_sigret_mode == SIGRET_BAD_MXCSR) {
		// Set reserved bit 16 in mxcsr; rt_sigreturn must reject/SIGSEGV safely.
		fp->mxcsr |= (1U << 16);
	} else if (g_sigret_mode == SIGRET_BAD_XCOMP_BV) {
		struct xstate_sw_reserved *sw =
			(struct xstate_sw_reserved *)((uint8_t *)fp + 464);
		if (sw->magic1 == 0x46505853U || ((uc->uc_flags & 1ULL) && g_has_avx)) {
			uint64_t *xsave_hdr = (uint64_t *)((uint8_t *)fp + 512);
			// Set invalid/unsupported feature bits and reserved bit 62 in xcomp_bv.
			xsave_hdr[1] |= (1ULL << 62) | (1ULL << 60);
		} else {
			// Fallback if kernel only emits legacy FXSAVE frame: corrupt mxcsr reserved bit.
			fp->mxcsr |= (1U << 17);
		}
	}
}

static int run_one_sigreturn_subtest(enum sigret_mode mode)
{
	pid_t pid = fork();

	if (pid < 0)
		return 0;
	if (pid == 0) {
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_sigaction = sigusr1_handler;
		sa.sa_flags = SA_SIGINFO;
		sigemptyset(&sa.sa_mask);
		g_sigret_mode = mode;
		g_sig_handled = 0;

		if (sigaction(SIGUSR1, &sa, NULL) != 0)
			_exit(11);
		if (kill(getpid(), SIGUSR1) != 0)
			_exit(12);
		if (!g_sig_handled)
			_exit(13);
		_exit(0);
	}

	int status = 0;
	if (waitpid(pid, &status, 0) < 0)
		return 0;
	if (mode == SIGRET_VALID)
		return WIFEXITED(status) && WEXITSTATUS(status) == 0;
	// Invalid fpregs must be rejected: child terminated by signal (e.g. SIGSEGV) or non-zero exit.
	if (WIFSIGNALED(status))
		return 1;
	if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
		return 1;
	return 0;
}

static int run_rt_sigreturn_test(void)
{
	int v_ok = run_one_sigreturn_subtest(SIGRET_VALID);
	int m_ok = run_one_sigreturn_subtest(SIGRET_BAD_MXCSR);
	int x_ok = run_one_sigreturn_subtest(SIGRET_BAD_XCOMP_BV);

	printf("RESULT rt_sigreturn_valid %d bool\n", v_ok);
	printf("RESULT rt_sigreturn_bad_mxcsr %d bool\n", m_ok);
	printf("RESULT rt_sigreturn_bad_xcomp_bv %d bool\n", x_ok);
	fflush(stdout);
	return (v_ok && m_ok && x_ok) ? 0 : 1;
}

// ------------------------------------------------------------------
// Driver & /init cmdline helper
// ------------------------------------------------------------------

static void ensure_proc_mounted(void)
{
	if (access("/proc/cmdline", R_OK) == 0)
		return;
	mkdir("/proc", 0755);
	if (mount("proc", "/proc", "proc", 0, NULL) != 0 && errno != EBUSY)
		return;
}

static void read_cmdline_suite(char *buf, size_t len)
{
	buf[0] = '\0';
	ensure_proc_mounted();
	int fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0)
		return;
	char raw[1024];
	ssize_t n = read(fd, raw, sizeof(raw) - 1);
	close(fd);
	if (n <= 0)
		return;
	raw[n] = '\0';
	const char *p = strstr(raw, "kernelet_suite=");
	if (!p)
		return;
	p += strlen("kernelet_suite=");
	size_t i = 0;
	while (i + 1 < len && p[i] != '\0' && p[i] != ' ' && p[i] != '\n' && p[i] != '\t') {
		buf[i] = p[i];
		i++;
	}
	buf[i] = '\0';
}

int main(int argc, char **argv)
{
	char suite[64] = "smp-syscall-fpu";

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--suite") == 0 && i + 1 < argc) {
			snprintf(suite, sizeof(suite), "%s", argv[++i]);
		} else if (strncmp(argv[i], "--suite=", 8) == 0) {
			snprintf(suite, sizeof(suite), "%s", argv[i] + 8);
		}
	}
	if (argc == 1) {
		char cmd_suite[64];
		read_cmdline_suite(cmd_suite, sizeof(cmd_suite));
		if (cmd_suite[0] != '\0')
			snprintf(suite, sizeof(suite), "%s", cmd_suite);
	}

	int has_avx = detect_avx_support();
	g_has_avx = has_avx;
	printf("BENCH_INFO suite=%s pid=%d nproc=%ld avx=%d\n",
	       suite, getpid(), sysconf(_SC_NPROCESSORS_ONLN), has_avx);
	fflush(stdout);

	int rc = 0;
	if (strcmp(suite, "smp-syscall-fpu") == 0 || strcmp(suite, "all") == 0) {
		if (run_smp_check() != 0)
			rc = 1;
		if (run_getpid_bench() != 0)
			rc = 1;
		if (run_fpu_getpid_bench(has_avx) != 0)
			rc = 1;
		if (run_fpu_aba_bench(has_avx) != 0)
			rc = 1;
		if (run_rt_sigreturn_test() != 0)
			rc = 1;
	} else if (strcmp(suite, "smp") == 0) {
		rc |= run_smp_check();
	} else if (strcmp(suite, "syscall") == 0) {
		rc |= run_getpid_bench();
	} else if (strcmp(suite, "fpu") == 0) {
		rc |= run_fpu_getpid_bench(has_avx);
		rc |= run_fpu_aba_bench(has_avx);
	} else if (strcmp(suite, "sigreturn") == 0) {
		rc |= run_rt_sigreturn_test();
	} else {
		fprintf(stderr, "unknown suite: %s\n", suite);
		return 2;
	}

	printf("RESULT suite_done %d bool\n", rc == 0 ? 1 : 0);
	fflush(stdout);
	return rc;
}
