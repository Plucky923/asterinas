// SPDX-License-Identifier: GPL-2.0
//
// MM & Exception Safety Suite (Native Linux & Asterinas `/init` compatible).
//
// Tests:
//  1. All 11 forwarded x86-64 user exceptions (#DE, #DB, #BP, #OF, #UD, #SS,
//     #GP, #PF, #MF, #XM, #AC) + RCX/R11/GPR preservation across #PF.
//  2. PROT_NONE (SOFTW2) transitions: RW -> PROT_NONE -> PROT_READ -> RW.
//  3. 2-vCPU concurrent PT allocation/teardown race sharing PGD/PUD/PMD.

#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SZ 4096UL
#define PT_RACE_ROUNDS 1000

static int pin_to_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set) != 0)
		return -1;
	sched_yield();
	if (sched_getcpu() != cpu) {
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 200000L };
		nanosleep(&ts, NULL);
	}
	return 0;
}

static void restore_all_cpus(int nproc)
{
	cpu_set_t set;
	int limit = nproc;

	if (limit < 1)
		limit = 1;
	if (limit > CPU_SETSIZE)
		limit = CPU_SETSIZE;
	CPU_ZERO(&set);
	for (int i = 0; i < limit; i++)
		CPU_SET(i, &set);
	(void)sched_setaffinity(0, sizeof(set), &set);
}

// ------------------------------------------------------------------
// 1. All 11 forwarded user exceptions + RCX/R11 #PF preservation
// ------------------------------------------------------------------

static void child_fault_handler(int sig, siginfo_t *si, void *uctx)
{
	(void)si;
	(void)uctx;
	_exit(100 + sig);
}

static void install_fault_handlers(void)
{
	const int sigs[] = { SIGFPE, SIGTRAP, SIGSEGV, SIGILL, SIGBUS };
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = child_fault_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	for (size_t i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
		sigaction(sigs[i], &sa, NULL);
}

static int expect_exception_sig(const char *name, void (*fn)(void), int expected_sig)
{
	pid_t pid = fork();

	if (pid < 0) {
		perror("fork");
		return 0;
	}
	if (pid == 0) {
		install_fault_handlers();
		fn();
		_exit(1);
	}
	int st = 0;
	if (waitpid(pid, &st, 0) < 0)
		return 0;
	int got_sig = 0;
	if (WIFEXITED(st) && WEXITSTATUS(st) >= 100)
		got_sig = WEXITSTATUS(st) - 100;
	else if (WIFSIGNALED(st))
		got_sig = WTERMSIG(st);

	int ok = (got_sig == expected_sig);
	printf("SAFETY exc_%s got_sig=%d expected=%d ok=%d\n", name, got_sig, expected_sig, ok);
	fflush(stdout);
	return ok;
}

static void trig_de(void)
{
	volatile int z = 0;
	__asm__ __volatile__("xor %%edx, %%edx; mov $1, %%eax; idiv %[z]"
			     :
			     : [z] "r"(z)
			     : "eax", "edx", "cc");
}

static void trig_db(void)
{
	__asm__ __volatile__(
		"pushfq\n\t"
		"orq $0x100, (%%rsp)\n\t"
		"popfq\n\t"
		"nop\n\t"
		"nop\n\t"
		:
		:
		: "cc", "memory");
}

static void trig_bp(void)
{
	__asm__ __volatile__("int3");
}

static void trig_of(void)
{
	__asm__ __volatile__("int $4");
}

static void trig_ud(void)
{
	__asm__ __volatile__("ud2");
}

static void trig_ss(void)
{
	// Non-canonical SS-relative access via %rbp triggers #SS(0) -> SIGBUS.
	__asm__ __volatile__(
		"movabs $0x8000000000000000, %%rbp\n\t"
		"movq (%%rbp), %%rax\n\t"
		:
		:
		: "rax", "rbp");
}

static void trig_gp(void)
{
	__asm__ __volatile__("hlt");
}

static void trig_pf(void)
{
	volatile uint64_t *bad = (volatile uint64_t *)0x1000UL;
	(void)*bad;
}

static void trig_mf(void)
{
	uint16_t cw = 0;

	__asm__ __volatile__(
		"fninit\n\t"
		"fnstcw %[cw]\n\t"
		"andw $0xfffe, %[cw]\n\t" // unmask #IE (invalid operation, bit 0)
		"fldcw %[cw]\n\t"
		"fld1\n\t"
		"fchs\n\t"
		"fsqrt\n\t"
		"fwait\n\t"
		: [cw] "+m"(cw)
		:
		: "st");
}

static void trig_xm(void)
{
	uint32_t mx = 0;
	float one = 1.0f;
	float zero = 0.0f;

	__asm__ __volatile__(
		"stmxcsr %[mx]\n\t"
		"andl $0xfffffdff, %[mx]\n\t" // unmask #ZM (bit 9)
		"ldmxcsr %[mx]\n\t"
		"movss %[one], %%xmm0\n\t"
		"movss %[zero], %%xmm1\n\t"
		"divss %%xmm1, %%xmm0\n\t"
		: [mx] "+m"(mx)
		: [one] "m"(one), [zero] "m"(zero)
		: "xmm0", "xmm1");
}

static void trig_ac(void)
{
	uint8_t buf[32] __attribute__((aligned(16)));

	__asm__ __volatile__(
		"pushfq\n\t"
		"orq $0x40000, (%%rsp)\n\t" // set EFLAGS.AC
		"popfq\n\t"
		"movq 1(%[buf]), %%rax\n\t" // unaligned 8-byte load -> #AC
		:
		: [buf] "r"(buf)
		: "rax", "cc", "memory");
}

static volatile void *g_pf_resume_page;
static volatile sig_atomic_t g_pf_resume_hits;

static void pf_resume_handler(int sig, siginfo_t *si, void *uctx)
{
	(void)sig;
	(void)uctx;
	if (si->si_addr == (void *)g_pf_resume_page) {
		g_pf_resume_hits++;
		if (mprotect((void *)g_pf_resume_page, PAGE_SZ, PROT_READ | PROT_WRITE) != 0)
			_exit(99);
	}
}

struct pf_reg_req {
	uint64_t addr;
	uint64_t out_ptr;
};

__attribute__((noinline))
static void pf_write_preserve_asm(void *page, uint64_t out[14])
{
	struct pf_reg_req req = {
		.addr = (uint64_t)(uintptr_t)page,
		.out_ptr = (uint64_t)(uintptr_t)out,
	};

	__asm__ __volatile__(
		"push %%rbp\n\t"
		"push %%rbx\n\t"
		"mov 8(%%rax), %%rdx\n\t"
		"push %%rdx\n\t"             // [rsp] = out_ptr
		"mov 0(%%rax), %%rdi\n\t"    // rdi = page
		"mov $0x1111222233334400, %%rax\n\t"
		"mov $0x1111222233334401, %%rbx\n\t"
		"mov $0xcafebabedead0002, %%rcx\n\t"
		"mov $0x1111222233334403, %%rdx\n\t"
		"mov $0x1111222233334404, %%rsi\n\t"
		"mov $0x1111222233334405, %%rbp\n\t"
		"mov $0x1111222233334408, %%r8\n\t"
		"mov $0x1111222233334409, %%r9\n\t"
		"mov $0x111122223333440a, %%r10\n\t"
		"mov $0xfeedfacebeef000b, %%r11\n\t"
		"mov $0x111122223333440c, %%r12\n\t"
		"mov $0x111122223333440d, %%r13\n\t"
		"mov $0x111122223333440e, %%r14\n\t"
		"mov $0x111122223333440f, %%r15\n\t"
		"movq %%r10, (%%rdi)\n\t"    // #PF on RO page -> handler makes RW -> resumes!
		"mov (%%rsp), %%rdi\n\t"     // use rdi temporarily as out_ptr (we don't check rdi)
		"mov %%rax,   0(%%rdi)\n\t"
		"mov %%rbx,   8(%%rdi)\n\t"
		"mov %%rcx,  16(%%rdi)\n\t"
		"mov %%rdx,  24(%%rdi)\n\t"
		"mov %%rsi,  32(%%rdi)\n\t"
		"mov %%rbp,  40(%%rdi)\n\t"
		"mov %%r8,   48(%%rdi)\n\t"
		"mov %%r9,   56(%%rdi)\n\t"
		"mov %%r10,  64(%%rdi)\n\t"
		"mov %%r11,  72(%%rdi)\n\t"
		"mov %%r12,  80(%%rdi)\n\t"
		"mov %%r13,  88(%%rdi)\n\t"
		"mov %%r14,  96(%%rdi)\n\t"
		"mov %%r15, 104(%%rdi)\n\t"
		"add $8, %%rsp\n\t"
		"pop %%rbx\n\t"
		"pop %%rbp\n\t"
		:
		: "a"(&req)
		: "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
		  "r12", "r13", "r14", "r15", "cc", "memory");
}

static int test_pf_rcx_r11_preservation(void)
{
	void *page = mmap(NULL, PAGE_SZ, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED)
		return 0;
	*(volatile uint64_t *)page = 0;
	if (mprotect(page, PAGE_SZ, PROT_READ) != 0) {
		munmap(page, PAGE_SZ);
		return 0;
	}

	struct sigaction sa, old_sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = pf_resume_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	g_pf_resume_page = page;
	g_pf_resume_hits = 0;
	sigaction(SIGSEGV, &sa, &old_sa);

	uint64_t out[14];
	memset(out, 0, sizeof(out));
	pf_write_preserve_asm(page, out);
	sigaction(SIGSEGV, &old_sa, NULL);

	const uint64_t exp[14] = {
		0x1111222233334400ULL, // rax
		0x1111222233334401ULL, // rbx
		0xcafebabedead0002ULL, // rcx
		0x1111222233334403ULL, // rdx
		0x1111222233334404ULL, // rsi
		0x1111222233334405ULL, // rbp
		0x1111222233334408ULL, // r8
		0x1111222233334409ULL, // r9
		0x111122223333440aULL, // r10
		0xfeedfacebeef000bULL, // r11
		0x111122223333440cULL, // r12
		0x111122223333440dULL, // r13
		0x111122223333440eULL, // r14
		0x111122223333440fULL, // r15
	};
	int ok = (g_pf_resume_hits == 1) && (*(volatile uint64_t *)page == 0x111122223333440aULL);

	for (int i = 0; i < 14; i++) {
		if (out[i] != exp[i]) {
			fprintf(stderr, "pf_preserve reg[%d] mismatch: got=0x%llx exp=0x%llx\n",
				i, (unsigned long long)out[i], (unsigned long long)exp[i]);
			ok = 0;
		}
	}
	munmap(page, PAGE_SZ);
	printf("SAFETY pf_rcx_r11_preserve %d\n", ok);
	fflush(stdout);
	return ok;
}

static int run_exception_tests(void)
{
	int ok = 1;

	ok &= expect_exception_sig("de", trig_de, SIGFPE);
	ok &= expect_exception_sig("db", trig_db, SIGTRAP);
	ok &= expect_exception_sig("bp", trig_bp, SIGTRAP);
	ok &= expect_exception_sig("of", trig_of, SIGSEGV);
	ok &= expect_exception_sig("ud", trig_ud, SIGILL);
	ok &= expect_exception_sig("ss", trig_ss, SIGBUS);
	ok &= expect_exception_sig("gp", trig_gp, SIGSEGV);
	ok &= expect_exception_sig("pf", trig_pf, SIGSEGV);
	ok &= expect_exception_sig("mf", trig_mf, SIGFPE);
	ok &= expect_exception_sig("xm", trig_xm, SIGFPE);
	ok &= expect_exception_sig("ac", trig_ac, SIGBUS);
	ok &= test_pf_rcx_r11_preservation();
	return ok;
}

// ------------------------------------------------------------------
// 2. PROT_NONE (SOFTW2) transitions
// ------------------------------------------------------------------

static int expect_child_segv_read(volatile uint64_t *ptr)
{
	pid_t pid = fork();
	if (pid < 0)
		return 0;
	if (pid == 0) {
		install_fault_handlers();
		(void)*ptr;
		_exit(1);
	}
	int st = 0;
	waitpid(pid, &st, 0);
	return (WIFEXITED(st) && WEXITSTATUS(st) == 100 + SIGSEGV) ||
	       (WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV);
}

static int expect_child_segv_write(volatile uint64_t *ptr)
{
	pid_t pid = fork();
	if (pid < 0)
		return 0;
	if (pid == 0) {
		install_fault_handlers();
		*ptr = 0x1234ULL;
		_exit(1);
	}
	int st = 0;
	waitpid(pid, &st, 0);
	return (WIFEXITED(st) && WEXITSTATUS(st) == 100 + SIGSEGV) ||
	       (WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV);
}

static int run_prot_none_test(void)
{
	const size_t len = 4 * PAGE_SZ;
	uint8_t *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return 0;

	for (size_t i = 0; i < 4; i++)
		*(volatile uint64_t *)(p + i * PAGE_SZ) = 0xdeadbeefcafebabeULL ^ i;

	int ok = 1;
	if (mprotect(p, len, PROT_NONE) != 0)
		ok = 0;
	ok &= expect_child_segv_read((volatile uint64_t *)(p + PAGE_SZ));
	ok &= expect_child_segv_write((volatile uint64_t *)(p + 2 * PAGE_SZ));

	if (mprotect(p, len, PROT_READ) != 0)
		ok = 0;
	for (size_t i = 0; i < 4; i++) {
		if (*(volatile uint64_t *)(p + i * PAGE_SZ) != (0xdeadbeefcafebabeULL ^ i))
			ok = 0;
	}
	ok &= expect_child_segv_write((volatile uint64_t *)(p + 3 * PAGE_SZ));

	if (mprotect(p, len, PROT_READ | PROT_WRITE) != 0)
		ok = 0;
	for (size_t i = 0; i < 4; i++) {
		*(volatile uint64_t *)(p + i * PAGE_SZ) = 0x1122334455667788ULL + i;
		if (*(volatile uint64_t *)(p + i * PAGE_SZ) != 0x1122334455667788ULL + i)
			ok = 0;
	}

	munmap(p, len);
	printf("SAFETY prot_none_softw2 %d\n", ok);
	fflush(stdout);
	return ok;
}

// ------------------------------------------------------------------
// 3. 2-vCPU concurrent PT allocation race
// ------------------------------------------------------------------

struct pt_race_shared {
	uintptr_t aligned_base;
	int nproc;
	pthread_barrier_t bar;
	atomic_int errors;
};

struct pt_race_arg {
	struct pt_race_shared *sh;
	int id;
};

static void *pt_race_worker(void *arg)
{
	struct pt_race_arg *a = (struct pt_race_arg *)arg;
	struct pt_race_shared *sh = a->sh;
	int id = a->id;

	pin_to_cpu((sh->nproc >= 2) ? id : 0);

	for (int r = 0; r < PT_RACE_ROUNDS; r++) {
		pthread_barrier_wait(&sh->bar);
		// Adjacent 4 KiB slots in the SAME 2 MiB PMD (and PUD/PGD).
		size_t pages = ((r % 64) == 0) ? 16 : 1;
		uintptr_t addr = sh->aligned_base + (size_t)(r % 64) * (32 * PAGE_SZ) +
				 (size_t)id * (16 * PAGE_SZ);
		size_t len = pages * PAGE_SZ;

		void *m = mmap((void *)addr, len, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
		if (m == MAP_FAILED || (uintptr_t)m != addr) {
			atomic_fetch_add(&sh->errors, 1);
			continue;
		}
		for (size_t p = 0; p < pages; p++) {
			volatile uint64_t *slot = (volatile uint64_t *)(addr + p * PAGE_SZ);
			uint64_t val = ((uint64_t)id << 48) ^ ((uint64_t)r << 16) ^ p;
			*slot = val;
			if (*slot != val)
				atomic_fetch_add(&sh->errors, 1);
		}
		if (munmap((void *)addr, len) != 0)
			atomic_fetch_add(&sh->errors, 1);
	}
	return NULL;
}

static int run_pt_race_test(void)
{
	const size_t raw_len = 8UL << 20; // 8 MiB -> guarantees at least one full 2 MiB window
	void *raw = mmap(NULL, raw_len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (raw == MAP_FAILED)
		return 0;
	uintptr_t aligned = ((uintptr_t)raw + (2UL << 20) - 1) & ~((2UL << 20) - 1);

	struct pt_race_shared sh;
	sh.aligned_base = aligned;
	sh.nproc = (int)sysconf(_SC_NPROCESSORS_ONLN);
	if (sh.nproc < 1)
		sh.nproc = 1;
	atomic_init(&sh.errors, 0);
	pthread_barrier_init(&sh.bar, NULL, 2);

	pthread_t th[2];
	struct pt_race_arg args[2] = {
		{ .sh = &sh, .id = 0 },
		{ .sh = &sh, .id = 1 },
	};
	for (int i = 0; i < 2; i++) {
		if (sh.nproc >= 2)
			pin_to_cpu(i);
		if (pthread_create(&th[i], NULL, pt_race_worker, &args[i]) != 0) {
			restore_all_cpus(sh.nproc);
			pthread_barrier_destroy(&sh.bar);
			munmap(raw, raw_len);
			return 0;
		}
	}
	restore_all_cpus(sh.nproc);
	for (int i = 0; i < 2; i++)
		pthread_join(th[i], NULL);

	pthread_barrier_destroy(&sh.bar);
	munmap(raw, raw_len);

	int errs = atomic_load(&sh.errors);
	int ok = (errs == 0);
	printf("SAFETY pt_alloc_race_2vcpu errors=%d ok=%d\n", errs, ok);
	fflush(stdout);
	return ok;
}

// ------------------------------------------------------------------
// 4. Kernel user-copy EFAULT (pipe write/read + read-only mapping)
// ------------------------------------------------------------------

static int run_kernel_efault_test(void)
{
	int p[2];
	int ok = 1;

	if (pipe(p) != 0) {
		perror("pipe");
		return 0;
	}

	// 1. Copy-from-user on unmapped VA must fail with -1 / EFAULT.
	errno = 0;
	ssize_t n1 = write(p[1], (const void *)0x10000UL, 64);
	if (n1 != -1 || errno != EFAULT) {
		fprintf(stderr, "efault write unmapped: ret=%zd errno=%d\n", n1, errno);
		ok = 0;
	}

	// 2. Copy-to-user on unmapped VA must fail with -1 / EFAULT.
	if (write(p[1], "abcdefgh", 8) != 8)
		ok = 0;
	errno = 0;
	ssize_t n2 = read(p[0], (void *)0x10000UL, 8);
	if (n2 != -1 || errno != EFAULT) {
		fprintf(stderr, "efault read unmapped: ret=%zd errno=%d\n", n2, errno);
		ok = 0;
	}

	// 3. Copy-to-user into read-only mapping must fail with -1 / EFAULT.
	void *ro_page = mmap(NULL, PAGE_SZ, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ro_page == MAP_FAILED) {
		ok = 0;
	} else {
		if (write(p[1], "x", 1) != 1)
			ok = 0;
		errno = 0;
		ssize_t n3 = read(p[0], ro_page, 1);
		if (n3 != -1 || errno != EFAULT) {
			fprintf(stderr, "efault read into PROT_READ: ret=%zd errno=%d\n", n3, errno);
			ok = 0;
		}
		munmap(ro_page, PAGE_SZ);
	}

	close(p[0]);
	close(p[1]);
	printf("SAFETY kernel_efault %d\n", ok);
	fflush(stdout);
	return ok;
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	printf("SAFETY_INFO pid=%d nproc=%ld\n", getpid(), sysconf(_SC_NPROCESSORS_ONLN));
	fflush(stdout);

	int ok = 1;
	ok &= run_exception_tests();
	ok &= run_prot_none_test();
	ok &= run_pt_race_test();
	ok &= run_kernel_efault_test();

	printf("SAFETY suite_done %d\n", ok);
	fflush(stdout);
	return ok ? 0 : 1;
}
