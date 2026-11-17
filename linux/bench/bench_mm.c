// SPDX-License-Identifier: GPL-2.0
//
// 64 MiB MM benchmark suite (Native Linux & Asterinas `/init` compatible).
//
// Compiles statically (`gcc -O2 -static -pthread -o bench_mm bench_mm.c`).
// Emits machine-parseable `MM_RESULT <name> <ns_total> <ns_per_page>` lines.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SZ       4096UL
#define REGION_2M     (2UL << 20)
#define REGION_64M    (64UL << 20)
#define PAGES_2M      (REGION_2M / PAGE_SZ)
#define PAGES_64M     (REGION_64M / PAGE_SZ)
#define DEFAULT_ROUNDS 5
#define MAX_ROUNDS    31

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a;
	uint64_t y = *(const uint64_t *)b;

	return (x > y) - (x < y);
}

static uint64_t median_u64(uint64_t *arr, int n)
{
	qsort(arr, (size_t)n, sizeof(uint64_t), cmp_u64);
	return arr[n / 2];
}

static void report_mm(const char *name, uint64_t ns_total, uint64_t pages)
{
	double per_page = pages > 0 ? (double)ns_total / (double)pages : (double)ns_total;

	printf("MM_RESULT %s %llu %.2f\n",
	       name, (unsigned long long)ns_total, per_page);
	fflush(stdout);
}

static uint64_t read_pass(const char *p, size_t len)
{
	volatile uint64_t sum = 0;

	for (size_t off = 0; off < len; off += PAGE_SZ)
		sum += *(const volatile uint64_t *)(p + off);
	return sum;
}

static void write_pass(char *p, size_t len, uint64_t tag)
{
	for (size_t off = 0; off < len; off += PAGE_SZ)
		*(volatile uint64_t *)(p + off) = tag ^ (uint64_t)off;
}

static char *alloc_anon_64m(int populate)
{
	char *p = mmap(NULL, REGION_64M, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (p == MAP_FAILED) {
		perror("mmap anon 64m");
		exit(1);
	}
	(void)madvise(p, REGION_64M, MADV_NOHUGEPAGE);
	if (populate)
		write_pass(p, REGION_64M, 0x55aa55aaULL);
	return p;
}

static void bench_anon_pf(int rounds)
{
	uint64_t samples[MAX_ROUNDS];

	for (int r = 0; r < rounds; r++) {
		char *p = alloc_anon_64m(0);
		uint64_t t0 = now_ns();
		write_pass(p, REGION_64M, (uint64_t)r);
		samples[r] = now_ns() - t0;
		munmap(p, REGION_64M);
	}
	report_mm("anon_pf_1page", median_u64(samples, rounds), PAGES_64M);
}

static void bench_memfd_faultaround(int rounds)
{
	uint64_t samples[MAX_ROUNDS];

	int fd = memfd_create("mm_fa", 0);
	if (fd < 0) {
		perror("memfd_create");
		exit(1);
	}
	if (ftruncate(fd, (off_t)REGION_64M) != 0) {
		perror("ftruncate");
		exit(1);
	}
	char *tmp = mmap(NULL, REGION_64M, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (tmp == MAP_FAILED) {
		perror("mmap memfd prepop");
		exit(1);
	}
	write_pass(tmp, REGION_64M, 0x12345678ULL);
	munmap(tmp, REGION_64M);

	for (int r = 0; r < rounds; r++) {
		char *ro = mmap(NULL, REGION_64M, PROT_READ, MAP_SHARED, fd, 0);
		if (ro == MAP_FAILED) {
			perror("mmap memfd ro");
			exit(1);
		}
		(void)madvise(ro, REGION_64M, MADV_NOHUGEPAGE);
		uint64_t t0 = now_ns();
		(void)read_pass(ro, REGION_64M);
		samples[r] = now_ns() - t0;
		munmap(ro, REGION_64M);
	}
	close(fd);
	report_mm("memfd_faultaround_16p", median_u64(samples, rounds), PAGES_64M);
}

static void bench_mmap_populate(int rounds)
{
	uint64_t map_samples[MAX_ROUNDS];
	uint64_t read_samples[MAX_ROUNDS];

	for (int r = 0; r < rounds; r++) {
		uint64_t t0 = now_ns();
		char *p = mmap(NULL, REGION_64M, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
		uint64_t dt_map = now_ns() - t0;
		if (p == MAP_FAILED) {
			perror("mmap populate");
			exit(1);
		}
		(void)madvise(p, REGION_64M, MADV_NOHUGEPAGE);
		uint64_t t1 = now_ns();
		(void)read_pass(p, REGION_64M);
		uint64_t dt_read = now_ns() - t1;
		munmap(p, REGION_64M);
		map_samples[r] = dt_map;
		read_samples[r] = dt_read;
	}
	report_mm("mmap_populate_64m", median_u64(map_samples, rounds), PAGES_64M);
	report_mm("mmap_populate_read_64m", median_u64(read_samples, rounds), PAGES_64M);
}

static void bench_fork_64m(int rounds)
{
	uint64_t fork_samples[MAX_ROUNDS];
	uint64_t child_samples[MAX_ROUNDS];
	uint64_t parent_samples[MAX_ROUNDS];
	char *p = alloc_anon_64m(1);

	for (int r = 0; r < rounds; r++) {
		int go_pipe[2], done_pipe[2];
		if (pipe(go_pipe) != 0 || pipe(done_pipe) != 0) {
			perror("pipe");
			exit(1);
		}
		(void)read_pass(p, REGION_64M);

		uint64_t t0 = now_ns();
		pid_t pid = fork();
		if (pid < 0) {
			perror("fork");
			exit(1);
		}
		if (pid == 0) {
			char g = 0;
			close(go_pipe[1]);
			close(done_pipe[0]);
			if (read(go_pipe[0], &g, 1) != 1)
				_exit(2);
			uint64_t c0 = now_ns();
			(void)read_pass(p, REGION_64M);
			uint64_t c_dt = now_ns() - c0;
			if (write(done_pipe[1], &c_dt, sizeof(c_dt)) != sizeof(c_dt))
				_exit(3);
			close(go_pipe[0]);
			close(done_pipe[1]);
			_exit(0);
		}
		fork_samples[r] = now_ns() - t0;
		close(go_pipe[0]);
		close(done_pipe[1]);
		if (write(go_pipe[1], "G", 1) != 1) {
			perror("write go_pipe");
			exit(1);
		}
		uint64_t c_dt = 0;
		if (read(done_pipe[0], &c_dt, sizeof(c_dt)) != sizeof(c_dt)) {
			perror("read done_pipe");
			exit(1);
		}
		child_samples[r] = c_dt;
		int st = 0;
		waitpid(pid, &st, 0);
		close(go_pipe[1]);
		close(done_pipe[0]);

		uint64_t p0 = now_ns();
		(void)read_pass(p, REGION_64M);
		parent_samples[r] = now_ns() - p0;
	}
	munmap(p, REGION_64M);
	report_mm("fork_64m", median_u64(fork_samples, rounds), PAGES_64M);
	report_mm("child_read_64m", median_u64(child_samples, rounds), PAGES_64M);
	report_mm("parent_read_64m", median_u64(parent_samples, rounds), PAGES_64M);
}

static void bench_mprotect_ro(int rounds)
{
	uint64_t ro2m[MAX_ROUNDS];
	uint64_t ro64m[MAX_ROUNDS];
	char *p = alloc_anon_64m(1);

	for (int r = 0; r < rounds; r++) {
		if (mprotect(p, REGION_2M, PROT_READ | PROT_WRITE) != 0) {
			perror("mprotect rw 2m");
			exit(1);
		}
		write_pass(p, REGION_2M, (uint64_t)r);
		uint64_t t0 = now_ns();
		if (mprotect(p, REGION_2M, PROT_READ) != 0) {
			perror("mprotect ro 2m");
			exit(1);
		}
		ro2m[r] = now_ns() - t0;
	}

	for (int r = 0; r < rounds; r++) {
		if (mprotect(p, REGION_64M, PROT_READ | PROT_WRITE) != 0) {
			perror("mprotect rw 64m");
			exit(1);
		}
		write_pass(p, REGION_64M, (uint64_t)r + 100);
		uint64_t t0 = now_ns();
		if (mprotect(p, REGION_64M, PROT_READ) != 0) {
			perror("mprotect ro 64m");
			exit(1);
		}
		ro64m[r] = now_ns() - t0;
	}

	munmap(p, REGION_64M);
	report_mm("mprotect_ro_2m", median_u64(ro2m, rounds), PAGES_2M);
	report_mm("mprotect_ro_64m", median_u64(ro64m, rounds), PAGES_64M);
}

static void bench_cow_write(int rounds)
{
	uint64_t cow1[MAX_ROUNDS];
	uint64_t cow2[MAX_ROUNDS];

	// cow_write_1ref: child exits before parent writes, so refcount == 1 (reuse path)
	for (int r = 0; r < rounds; r++) {
		char *p = alloc_anon_64m(1);
		pid_t pid = fork();
		if (pid < 0) {
			perror("fork cow1");
			exit(1);
		}
		if (pid == 0)
			_exit(0);
		int st = 0;
		waitpid(pid, &st, 0);

		uint64_t t0 = now_ns();
		write_pass(p, REGION_64M, (uint64_t)r + 0x1000);
		cow1[r] = now_ns() - t0;
		munmap(p, REGION_64M);
	}

	// cow_write_2ref: child stays alive until parent finishes writes (copy path)
	for (int r = 0; r < rounds; r++) {
		char *p = alloc_anon_64m(1);
		int ready_pipe[2], go_pipe[2];
		if (pipe(ready_pipe) != 0 || pipe(go_pipe) != 0) {
			perror("pipe cow2");
			exit(1);
		}
		pid_t pid = fork();
		if (pid < 0) {
			perror("fork cow2");
			exit(1);
		}
		if (pid == 0) {
			char g = 0;
			close(ready_pipe[0]);
			close(go_pipe[1]);
			if (write(ready_pipe[1], "R", 1) != 1)
				_exit(2);
			(void)read(go_pipe[0], &g, 1);
			close(ready_pipe[1]);
			close(go_pipe[0]);
			_exit(0);
		}
		char ch = 0;
		close(ready_pipe[1]);
		close(go_pipe[0]);
		if (read(ready_pipe[0], &ch, 1) != 1) {
			perror("read ready_pipe");
			exit(1);
		}

		uint64_t t0 = now_ns();
		write_pass(p, REGION_64M, (uint64_t)r + 0x2000);
		cow2[r] = now_ns() - t0;

		if (write(go_pipe[1], "G", 1) != 1) {
			perror("write go_pipe");
			exit(1);
		}
		int st = 0;
		waitpid(pid, &st, 0);
		close(ready_pipe[0]);
		close(go_pipe[1]);
		munmap(p, REGION_64M);
	}

	report_mm("cow_write_1ref", median_u64(cow1, rounds), PAGES_64M);
	report_mm("cow_write_2ref", median_u64(cow2, rounds), PAGES_64M);
}

static void bench_munmap_64m(int rounds)
{
	uint64_t samples[MAX_ROUNDS];

	for (int r = 0; r < rounds; r++) {
		char *p = alloc_anon_64m(1);
		uint64_t t0 = now_ns();
		if (munmap(p, REGION_64M) != 0) {
			perror("munmap");
			exit(1);
		}
		samples[r] = now_ns() - t0;
	}
	report_mm("munmap_64m", median_u64(samples, rounds), PAGES_64M);
}

static uint64_t measure_child_exit(int with_64m)
{
	int ready_pipe[2], go_pipe[2];

	if (pipe(ready_pipe) != 0 || pipe(go_pipe) != 0) {
		perror("pipe exit");
		exit(1);
	}
	pid_t pid = fork();
	if (pid < 0) {
		perror("fork exit");
		exit(1);
	}
	if (pid == 0) {
		char g = 0;
		close(ready_pipe[0]);
		close(go_pipe[1]);
		if (with_64m)
			(void)alloc_anon_64m(1);
		if (write(ready_pipe[1], "R", 1) != 1)
			_exit(2);
		if (read(go_pipe[0], &g, 1) != 1)
			_exit(3);
		close(ready_pipe[1]);
		close(go_pipe[0]);
		_exit(0);
	}
	char ch = 0;
	close(ready_pipe[1]);
	close(go_pipe[0]);
	if (read(ready_pipe[0], &ch, 1) != 1) {
		perror("read ready exit");
		exit(1);
	}
	if (write(go_pipe[1], "G", 1) != 1) {
		perror("write go exit");
		exit(1);
	}
	uint64_t t0 = now_ns();
	int st = 0;
	waitpid(pid, &st, 0);
	uint64_t dt = now_ns() - t0;
	close(ready_pipe[0]);
	close(go_pipe[1]);
	return dt;
}

static void bench_exit(int rounds)
{
	uint64_t empty_samples[MAX_ROUNDS];
	uint64_t full_samples[MAX_ROUNDS];

	for (int r = 0; r < rounds; r++)
		empty_samples[r] = measure_child_exit(0);
	for (int r = 0; r < rounds; r++)
		full_samples[r] = measure_child_exit(1);

	report_mm("exit_empty", median_u64(empty_samples, rounds), 0);
	report_mm("exit_64m", median_u64(full_samples, rounds), PAGES_64M);
}

static void ensure_proc_mounted(void)
{
	if (access("/proc/cmdline", R_OK) == 0)
		return;
	mkdir("/proc", 0755);
	(void)mount("proc", "/proc", "proc", 0, NULL);
}

static int read_cmdline_rounds(void)
{
	ensure_proc_mounted();
	int fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0)
		return 0;
	char raw[1024];
	ssize_t n = read(fd, raw, sizeof(raw) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	raw[n] = '\0';
	const char *p = strstr(raw, "kernelet_rounds=");
	if (!p)
		return 0;
	return atoi(p + strlen("kernelet_rounds="));
}

int main(int argc, char **argv)
{
	int rounds = DEFAULT_ROUNDS;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--rounds") == 0 && i + 1 < argc)
			rounds = atoi(argv[++i]);
	}
	if (argc == 1) {
		int cmd_r = read_cmdline_rounds();
		if (cmd_r > 0)
			rounds = cmd_r;
	}
	if (rounds < 1)
		rounds = 1;
	if (rounds > MAX_ROUNDS)
		rounds = MAX_ROUNDS;

	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(0, &set);
	(void)sched_setaffinity(0, sizeof(set), &set);
	sched_yield();

	printf("MM_BENCH_INFO pid=%d nproc=%ld rounds=%d pages=%lu\n",
	       getpid(), sysconf(_SC_NPROCESSORS_ONLN), rounds, (unsigned long)PAGES_64M);
	fflush(stdout);

	bench_anon_pf(rounds);
	bench_memfd_faultaround(rounds);
	bench_mmap_populate(rounds);
	bench_fork_64m(rounds);
	bench_mprotect_ro(rounds);
	bench_cow_write(rounds);
	bench_munmap_64m(rounds);
	bench_exit(rounds);

	printf("MM_RESULT suite_done 1 1.00\n");
	fflush(stdout);
	return 0;
}
