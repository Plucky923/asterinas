// SPDX-License-Identifier: GPL-2.0
// Measures user-memory access, unmapping, process lifetime, and sparse protection.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAGE_BYTES 4096UL
#define SAMPLES 5
#define ZERO_BYTES ((2UL << 20) + PAGE_BYTES)
#define ZERO_ITERS 64
#define ZERO_SMALL_BYTES (128UL << 10)
#define ZERO_SMALL_ITERS 1024
#define PIPE_BYTES (256UL << 10)
#define PIPE_ITERS 64
#define UNMAP_BYTES (64UL << 20)
#define FORK_ITERS 32
#define SPARSE_PAGES 256UL
#define HOT_PAGES 64UL
#define PROTECT_ITERS 256

static unsigned int sample_cpu;

static void require(int ok, const char *operation)
{
	if (!ok) {
		fprintf(stderr, "%s failed: errno=%d\n", operation, errno);
		exit(EXIT_FAILURE);
	}
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	require(syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts) == 0,
		"clock_gettime");
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void verify_cpu(void)
{
	unsigned int cpu;

	require(syscall(SYS_getcpu, &cpu, NULL, NULL) == 0 && cpu == 0,
		"singleton CPU affinity");
	sample_cpu = cpu;
}

static void warm_cpu(void)
{
	uint64_t until = now_ns() + 100000000ULL;

	// Keep each short window independent of the preceding idle interval.
	do {
		for (unsigned int i = 0; i < 10000; i++)
			require(syscall(SYS_getpid) > 0, "CPU warmup");
	} while (now_ns() < until);
	verify_cpu();
}

static unsigned char *map_bytes(size_t size)
{
	unsigned char *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	require(p != MAP_FAILED, "mmap");
	require(madvise(p, size, MADV_NOHUGEPAGE) == 0, "MADV_NOHUGEPAGE");
	return p;
}

static void report(const char *name, unsigned int sample, uint64_t elapsed,
		   uint64_t operations)
{
	require(elapsed != 0 && operations != 0, "measurement window");
	printf("REVIEW_MM_SAMPLE {\"case\":\"%s\",\"sample\":%u,"
	       "\"iterations\":%llu,\"elapsed_ns\":%llu,\"cpu\":%u,\"valid\":true}\n",
	       name, sample, (unsigned long long)operations,
	       (unsigned long long)elapsed, sample_cpu);
	printf("RESULT %s_s%u %.6f ns/op\n", name, sample,
	       (double)elapsed / (double)operations);
	fflush(stdout);
}

static void check_bytes(const unsigned char *buffer, size_t size,
			unsigned char value, const char *operation)
{
	for (size_t i = 0; i < size; i++)
		require(buffer[i] == value, operation);
}

static void check_partial_zero(ssize_t result, int error, int native_linux)
{
	// `MemFile::Zero` propagates `EFAULT`; Linux returns the completed prefix.
	if (native_linux)
		require(result == (ssize_t)PAGE_BYTES, "Linux zero partial read");
	else
		require(result == -1 && error == EFAULT, "Kernelet zero partial fault");
}

static void check_zero_faults(int native_linux)
{
	const size_t leaf_bytes = 2UL << 20;
	const size_t allocation_bytes = 2 * leaf_bytes;
	unsigned char *allocation = map_bytes(allocation_bytes);
	uintptr_t boundary = ((uintptr_t)allocation + 2 * PAGE_BYTES + leaf_bytes - 1) &
		~(uintptr_t)(leaf_bytes - 1);
	unsigned char *starts[] = {
		(unsigned char *)boundary + PAGE_BYTES,
		(unsigned char *)boundary - PAGE_BYTES,
	};
	const char *names[] = { "same_leaf", "cross_leaf" };
	int fd = open("/dev/zero", O_RDONLY);

	require(fd >= 0, "open zero for fault checks");
	for (size_t position = 0; position < 2; position++) {
		unsigned char *first = starts[position];
		unsigned char *second = first + PAGE_BYTES;
		unsigned char *before = first - PAGE_BYTES;
		unsigned char *after = second + PAGE_BYTES;

		memset(before, 0x7b, 4 * PAGE_BYTES);
		require(mprotect(second, PAGE_BYTES, PROT_READ) == 0,
			"zero read-only page");
		errno = 0;
		ssize_t readonly_result = read(fd, first, 2 * PAGE_BYTES);
		int readonly_error = errno;
		check_partial_zero(readonly_result, readonly_error, native_linux);
		check_bytes(first, PAGE_BYTES, 0, "zero writable prefix");
		check_bytes(second, PAGE_BYTES, 0x7b, "zero read-only contents");
		check_bytes(before, PAGE_BYTES, 0x7b, "zero preceding guard");
		check_bytes(after, PAGE_BYTES, 0x7b, "zero following guard");

		require(mprotect(second, PAGE_BYTES, PROT_READ | PROT_WRITE) == 0,
			"zero restore write permission");
		memset(first, 0x7b, PAGE_BYTES);
		require(read(fd, first, 2 * PAGE_BYTES) == (ssize_t)(2 * PAGE_BYTES),
			"zero read after permission restore");
		check_bytes(first, 2 * PAGE_BYTES, 0, "zero restored contents");
		check_bytes(before, PAGE_BYTES, 0x7b, "zero restored preceding guard");
		check_bytes(after, PAGE_BYTES, 0x7b, "zero restored following guard");

		memset(first, 0x7b, 2 * PAGE_BYTES);
		require(munmap(second, PAGE_BYTES) == 0, "zero remove second page");
		errno = 0;
		ssize_t hole_result = read(fd, first, 2 * PAGE_BYTES);
		int hole_error = errno;
		check_partial_zero(hole_result, hole_error, native_linux);
		check_bytes(first, PAGE_BYTES, 0, "zero prefix before hole");
		check_bytes(before, PAGE_BYTES, 0x7b, "zero hole preceding guard");
		check_bytes(after, PAGE_BYTES, 0x7b, "zero hole following guard");
		errno = 0;
		require(mprotect(second, PAGE_BYTES, PROT_READ) == -1 && errno == ENOMEM,
			"zero hole remains unmapped");

		// `MAP_FIXED` replaces only the hole owned by this single-threaded check.
		require(mmap(second, PAGE_BYTES, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == second,
			"zero remap second page");
		memset(first, 0x7b, PAGE_BYTES);
		require(read(fd, first, 2 * PAGE_BYTES) == (ssize_t)(2 * PAGE_BYTES),
			"zero read after remap");
		check_bytes(first, 2 * PAGE_BYTES, 0, "zero remapped contents");
		check_bytes(before, PAGE_BYTES, 0x7b, "zero remapped preceding guard");
		check_bytes(after, PAGE_BYTES, 0x7b, "zero remapped following guard");
		printf("REVIEW_MM_CHECK {\"case\":\"zero_fault_%s\","
		       "\"native_linux\":%s,\"readonly_result\":%zd,"
		       "\"readonly_errno\":%d,\"hole_result\":%zd,"
		       "\"hole_errno\":%d,\"valid\":true}\n",
		       names[position], native_linux ? "true" : "false", readonly_result,
		       readonly_error, hole_result, hole_error);
		printf("RESULT review_zero_fault_%s 1 bool\n", names[position]);
	}
	require(close(fd) == 0, "close zero fault checks");
	require(munmap(allocation, allocation_bytes) == 0, "unmap zero fault checks");
}

static void bench_zero(const char *name, size_t bytes, unsigned int iterations)
{
	unsigned char *buffer = map_bytes(bytes + PAGE_BYTES);
	int fd = open("/dev/zero", O_RDONLY);

	require(fd >= 0, "open /dev/zero");
	memset(buffer, 0x7b, bytes + PAGE_BYTES);
	require(read(fd, buffer, bytes) == (ssize_t)bytes, "zero warmup");
	for (unsigned int sample = 0; sample < SAMPLES; sample++) {
		warm_cpu();
		uint64_t start = now_ns();

		for (unsigned int i = 0; i < iterations; i++)
			require(read(fd, buffer, bytes) == (ssize_t)bytes,
				"zero read");
		uint64_t elapsed = now_ns() - start;
		verify_cpu();
		for (size_t i = 0; i < bytes; i++)
			require(buffer[i] == 0, "zero contents");
		for (size_t i = bytes; i < bytes + PAGE_BYTES; i++)
			require(buffer[i] == 0x7b, "zero boundary");
		report(name, sample, elapsed, iterations);
	}
	printf("RESULT %s_bytes_per_op %zu bytes\n", name, bytes);
	require(close(fd) == 0, "close zero");
	require(munmap(buffer, bytes + PAGE_BYTES) == 0, "unmap zero");
}

struct pipe_reader {
	int fd;
	unsigned char *buffer;
	pthread_barrier_t ready;
	int error;
};

static int transfer_full(int fd, unsigned char *buffer, size_t size, int writing)
{
	size_t transferred = 0;

	while (transferred < size) {
		ssize_t n = writing ? write(fd, buffer + transferred, size - transferred) :
			read(fd, buffer + transferred, size - transferred);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -1;
		transferred += (size_t)n;
	}
	return 0;
}

static void *read_pipe(void *arg)
{
	struct pipe_reader *reader = arg;
	int status = pthread_barrier_wait(&reader->ready);

	if (status != 0 && status != PTHREAD_BARRIER_SERIAL_THREAD) {
		reader->error = 1;
		return NULL;
	}
	for (unsigned int i = 0; i < PIPE_ITERS; i++) {
		if (transfer_full(reader->fd, reader->buffer, PIPE_BYTES, 0) != 0) {
			reader->error = 1;
			return NULL;
		}
	}
	return NULL;
}

static void bench_pipe(void)
{
	unsigned char *source = map_bytes(PIPE_BYTES);
	unsigned char *destination = map_bytes(PIPE_BYTES);

	for (size_t i = 0; i < PIPE_BYTES; i++)
		source[i] = (unsigned char)(i * 37 + 11);
	memset(destination, 0, PIPE_BYTES);
	for (unsigned int sample = 0; sample < SAMPLES; sample++) {
		int fds[2];
		pthread_t thread;

		require(pipe(fds) == 0, "pipe");
		struct pipe_reader reader = { .fd = fds[0], .buffer = destination };
		require(pthread_barrier_init(&reader.ready, NULL, 2) == 0,
			"pipe barrier init");
		require(pthread_create(&thread, NULL, read_pipe, &reader) == 0,
			"pipe reader create");
		int status = pthread_barrier_wait(&reader.ready);
		require(status == 0 || status == PTHREAD_BARRIER_SERIAL_THREAD,
			"pipe barrier wait");
		warm_cpu();
		uint64_t start = now_ns();

		for (unsigned int i = 0; i < PIPE_ITERS; i++)
			require(transfer_full(fds[1], source, PIPE_BYTES, 1) == 0,
				"pipe write");
		require(pthread_join(thread, NULL) == 0, "pipe reader join");
		uint64_t elapsed = now_ns() - start;
		verify_cpu();
		require(reader.error == 0, "pipe reader result");
		require(memcmp(source, destination, PIPE_BYTES) == 0, "pipe contents");
		report("review_pipe", sample, elapsed, PIPE_ITERS);
		require(pthread_barrier_destroy(&reader.ready) == 0, "pipe barrier destroy");
		require(close(fds[0]) == 0 && close(fds[1]) == 0, "close pipe");
	}
	printf("RESULT review_pipe_bytes_per_op %lu bytes\n", PIPE_BYTES);
	require(munmap(source, PIPE_BYTES) == 0, "unmap pipe source");
	require(munmap(destination, PIPE_BYTES) == 0, "unmap pipe destination");
}

static void bench_unmap(void)
{
	for (unsigned int sample = 0; sample < SAMPLES; sample++) {
		unsigned char *buffer = map_bytes(UNMAP_BYTES);

		for (size_t offset = 0; offset < UNMAP_BYTES; offset += PAGE_BYTES)
			buffer[offset] = (unsigned char)((offset / PAGE_BYTES) ^ 0x5a);
		for (size_t offset = 0; offset < UNMAP_BYTES; offset += PAGE_BYTES)
			require(buffer[offset] == (unsigned char)((offset / PAGE_BYTES) ^ 0x5a),
				"unmap preparation");
		warm_cpu();
		uint64_t start = now_ns();
		int status = munmap(buffer, UNMAP_BYTES);
		uint64_t elapsed = now_ns() - start;
		verify_cpu();
		require(status == 0, "munmap 64 MiB");
		errno = 0;
		require(mprotect(buffer, PAGE_BYTES, PROT_READ) == -1 && errno == ENOMEM,
			"unmapped range");
		report("review_unmap64m", sample, elapsed, 1);
	}
	printf("RESULT review_unmap_pages_per_op %lu pages\n", UNMAP_BYTES / PAGE_BYTES);
}

static void bench_process_lifetime(void)
{
	for (unsigned int sample = 0; sample < SAMPLES; sample++) {
		warm_cpu();
		uint64_t start = now_ns();

		for (unsigned int i = 0; i < FORK_ITERS; i++) {
			pid_t child = fork();
			int status;

			require(child >= 0, "fork");
			if (child == 0)
				_exit(0);
			require(waitpid(child, &status, 0) == child, "waitpid");
			require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child exit");
		}
		uint64_t elapsed = now_ns() - start;
		verify_cpu();
		report("review_fork_exit", sample, elapsed, FORK_ITERS);
	}
}

static uint64_t touch_hot(const unsigned char *hot)
{
	uint64_t sum = 0;

	for (size_t page = 0; page < HOT_PAGES; page++)
		sum += *(const volatile unsigned char *)(hot + page * PAGE_BYTES);
	return sum;
}

static void bench_sparse_protect(void)
{
	const size_t sparse_bytes = SPARSE_PAGES * PAGE_BYTES;
	unsigned char *sparse = map_bytes(sparse_bytes);
	unsigned char *hot = map_bytes(HOT_PAGES * PAGE_BYTES);
	uint64_t expected = 0;

	// One mprotect call covers two resident pages and the untouched gap.
	sparse[0] = 17;
	sparse[sparse_bytes - PAGE_BYTES] = 29;
	for (size_t page = 0; page < HOT_PAGES; page++) {
		hot[page * PAGE_BYTES] = (unsigned char)(page + 1);
		expected += page + 1;
	}
	for (unsigned int sample = 0; sample < SAMPLES; sample++) {
		uint64_t sum = 0;

		require(touch_hot(hot) == expected, "hot page preparation");
		warm_cpu();
		uint64_t start = now_ns();
		for (unsigned int i = 0; i < PROTECT_ITERS; i++) {
			require(mprotect(sparse, sparse_bytes, PROT_READ) == 0,
				"sparse protect read");
			sum += touch_hot(hot);
			require(mprotect(sparse, sparse_bytes, PROT_READ | PROT_WRITE) == 0,
				"sparse protect write");
			sum += touch_hot(hot);
		}
		uint64_t elapsed = now_ns() - start;
		verify_cpu();
		require(sum == expected * 2 * PROTECT_ITERS, "hot page contents");
		require(sparse[0] == 17 && sparse[sparse_bytes - PAGE_BYTES] == 29,
			"sparse page contents");
		report("review_sparse_protect", sample, elapsed, 2 * PROTECT_ITERS);
	}
	require(munmap(sparse, sparse_bytes) == 0, "unmap sparse");
	require(munmap(hot, HOT_PAGES * PAGE_BYTES) == 0, "unmap hot");
}

int main(int argc, char **argv)
{
	cpu_set_t cpus, actual;
	unsigned int cpu;
	int native_linux = 0;

	for (int arg = 1; arg < argc; arg++) {
		if (strcmp(argv[arg], "--native-linux") == 0)
			native_linux = 1;
		else
			require(argv[arg][0] == '\0' || strcmp(argv[arg], "sh") == 0 ||
				strcmp(argv[arg], "-l") == 0,
				"benchmark arguments");
	}
	require(sysconf(_SC_PAGESIZE) == (long)PAGE_BYTES, "4 KiB pages");
	CPU_ZERO(&cpus);
	CPU_SET(0, &cpus);
	require(sched_setaffinity(0, sizeof(cpus), &cpus) == 0, "pin CPU 0");
	require(sched_yield() == 0, "sched_yield");
	require(syscall(SYS_getcpu, &cpu, NULL, NULL) == 0, "getcpu");
	if (cpu != 0) {
		struct timespec delay = { .tv_sec = 0, .tv_nsec = 200000L };

		require(nanosleep(&delay, NULL) == 0, "affinity settling delay");
	}
	require(sched_getaffinity(0, sizeof(actual), &actual) == 0 &&
		CPU_COUNT(&actual) == 1 && CPU_ISSET(0, &actual),
		"singleton CPU 0 affinity");
	verify_cpu();
	check_zero_faults(native_linux);
	bench_zero("review_zero", ZERO_BYTES, ZERO_ITERS);
	bench_zero("review_zero128k", ZERO_SMALL_BYTES, ZERO_SMALL_ITERS);
	bench_pipe();
	bench_unmap();
	bench_process_lifetime();
	bench_sparse_protect();
	printf("RESULT review_mm_done 1 bool\n");
	printf("RESULT suite_done 1 bool\n");
	return EXIT_SUCCESS;
}
