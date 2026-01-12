/*
 * Host Memory Benchmark
 *
 * Usage:
 *   bench_memory [workset_bytes] [repeat] [pattern] [warmup] [random_steps] [do_store]
 *
 *   pattern: 0 = sequential, 1 = random pointer-chase,
 *            2 = page-stride sequential, 3 = page-stride random pointer-chase
 *   warmup:  0 = no warmup, 1 = warmup
 *   do_store: 0 = load-only, 1 = load+store
 *
 * Compile-time options:
 *   -DMEM_USE_STATIC_ARRAY=1  Use static BSS array instead of heap allocation
 *                             (matches FrameVM guest behavior for fair comparison)
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ACCESS_SEQ 0
#define ACCESS_RAND 1
#define ACCESS_PAGE_SEQ 2
#define ACCESS_PAGE_RAND 3

#define PAGE_STRIDE 4096

#ifndef WORKSET_BYTES
#define WORKSET_BYTES (8ULL * 1024 * 1024)
#endif

#ifndef REPEAT
#define REPEAT 16
#endif

#ifndef ACCESS_PATTERN
#define ACCESS_PATTERN ACCESS_SEQ
#endif

#ifndef WARMUP
#define WARMUP 1
#endif

#ifndef RANDOM_STEPS
#define RANDOM_STEPS 0
#endif

#ifndef MEM_DO_STORE
#define MEM_DO_STORE 1
#endif

#ifndef MEM_SEED
#define MEM_SEED 0
#endif

#ifndef MEASURE_RUNS
#define MEASURE_RUNS 1
#endif

#ifndef MEM_FIXED_CONFIG
#define MEM_FIXED_CONFIG 0
#endif

#ifndef MEM_USE_STATIC_ARRAY
#define MEM_USE_STATIC_ARRAY 0
#endif

/*
 * Static array allocation (matches FrameVM guest behavior)
 * When MEM_USE_STATIC_ARRAY=1, uses BSS segment instead of heap
 */
#if MEM_USE_STATIC_ARRAY
#define WORKSET_WORDS (WORKSET_BYTES / 8ULL)
#define WORKSET_PAGES (WORKSET_BYTES / PAGE_STRIDE)
static volatile uint64_t static_data_array[WORKSET_WORDS]
	__attribute__((aligned(4096)));
#if (ACCESS_PATTERN == ACCESS_PAGE_RAND)
static uint32_t static_page_order[WORKSET_PAGES];
#endif
#endif

#if MEM_FIXED_CONFIG
#define IGNORE_DO_STORE() (void)(do_store)
#define MAYBE_STORE(ptr, val)           \
	do {                            \
		if (MEM_DO_STORE)       \
			*(ptr) = (val); \
	} while (0)
#else
#define IGNORE_DO_STORE() \
	do {              \
	} while (0)
#define MAYBE_STORE(ptr, val)           \
	do {                            \
		if (do_store)           \
			*(ptr) = (val); \
	} while (0)
#endif
static volatile uint64_t sink64 = 0;
static volatile uint32_t sink32 = 0;
static uint32_t rand_start = 0;
static uint32_t page_rand_start = 0;
static uint32_t lcg_state = 1;

static inline uint64_t rdtsc(void)
{
	uint32_t lo, hi;
	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtsc_start(void)
{
	__asm__ volatile("lfence" ::: "memory");
	uint64_t t = rdtsc();
	__asm__ volatile("lfence" ::: "memory");
	return t;
}

static inline uint64_t rdtsc_end(void)
{
	__asm__ volatile("lfence" ::: "memory");
	uint64_t t = rdtsc();
	__asm__ volatile("lfence" ::: "memory");
	return t;
}

static uint64_t pick_median(uint64_t *vals, uint32_t n)
{
	for (uint32_t i = 1; i < n; i++) {
		uint64_t key = vals[i];
		uint32_t j = i;
		while (j > 0 && vals[j - 1] > key) {
			vals[j] = vals[j - 1];
			j--;
		}
		vals[j] = key;
	}
	return vals[n / 2];
}

static inline uint32_t lcg_rand(void)
{
	lcg_state = lcg_state * 1664525u + 1013904223u;
	return lcg_state;
}

static void init_seq_data(volatile uint64_t *data, uint64_t words)
{
	for (uint64_t i = 0; i < words; i++) {
		data[i] = i;
	}
}

static void build_random_chain(volatile uint64_t *data, uint32_t n)
{
	for (uint32_t i = 0; i < n; i++) {
		data[i] = i;
	}

	for (uint32_t i = n - 1; i > 0; i--) {
		uint32_t j = lcg_rand() % (i + 1);
		uint64_t tmp = data[i];
		data[i] = data[j];
		data[j] = tmp;
	}

	for (uint32_t pos = 0; pos < n; pos++) {
		uint32_t cur = (uint32_t)(data[pos] & 0xFFFFFFFFULL);
		uint32_t next = (uint32_t)(data[(pos + 1) % n] & 0xFFFFFFFFULL);
		uint64_t entry = data[cur];
		data[cur] = (entry & 0xFFFFFFFFULL) | ((uint64_t)next << 32);
	}

	for (uint32_t i = 0; i < n; i++) {
		data[i] = data[i] >> 32;
	}

	rand_start = lcg_rand() % n;
}

static void init_page_order(uint32_t *order, uint32_t pages, int random)
{
	for (uint32_t i = 0; i < pages; i++)
		order[i] = i;

	if (!random)
		return;

	for (uint32_t i = pages - 1; i > 0; i--) {
		uint32_t j = lcg_rand() % (i + 1);
		uint32_t tmp = order[i];
		order[i] = order[j];
		order[j] = tmp;
	}
}

static void build_page_chain(volatile uint64_t *data, uint32_t *order,
			     uint32_t pages)
{
	volatile uint8_t *base = (volatile uint8_t *)data;
	init_page_order(order, pages, 1);

	for (uint32_t i = 0; i < pages; i++) {
		uint32_t cur = order[i];
		uint32_t next = order[(i + 1) % pages];
		volatile uint64_t *ptr =
			(volatile uint64_t *)(base +
					      (uint64_t)cur * PAGE_STRIDE);
		*ptr = (uint64_t)next;
	}

	page_rand_start = order[lcg_rand() % pages];
}

static void warmup_page(volatile uint8_t *data, const uint32_t *order,
			uint64_t pages, int random, int do_store)
{
	IGNORE_DO_STORE();
	uint64_t acc = 0;
	for (uint64_t i = 0; i < pages; i++) {
		uint64_t idx = random ? order[i] : i;
		volatile uint64_t *ptr =
			(volatile uint64_t *)(data + idx * PAGE_STRIDE);
#if MEM_FIXED_CONFIG
#if MEM_DO_STORE
		/*
		 * Store-first for write-touch mode to avoid read-first zero-page
		 * mapping artifacts in Linux cold-page measurements.
		 */
		uint64_t write_val = idx;
		*ptr = write_val;
		uint64_t val = *ptr;
		acc ^= val;
#else
		uint64_t val = *ptr;
		acc ^= val;
		MAYBE_STORE(ptr, val);
#endif
#else
		if (do_store) {
			uint64_t write_val = idx;
			*ptr = write_val;
			uint64_t val = *ptr;
			acc ^= val;
		} else {
			uint64_t val = *ptr;
			acc ^= val;
		}
#endif
	}
	sink64 = acc;
}

static uint64_t measure_page(volatile uint8_t *data, const uint32_t *order,
			     uint64_t pages, uint64_t repeat, int random,
			     int do_store)
{
	IGNORE_DO_STORE();
	uint64_t acc = 0;
	uint64_t start = rdtsc_start();
	for (uint64_t r = 0; r < repeat; r++) {
		for (uint64_t i = 0; i < pages; i++) {
			uint64_t idx = random ? order[i] : i;
			volatile uint64_t *ptr =
				(volatile uint64_t *)(data + idx * PAGE_STRIDE);
#if MEM_FIXED_CONFIG
#if MEM_DO_STORE
			/*
			 * Store-first avoids read-fault + COW write-fault double
			 * counting on Linux write-touch page-fault probes.
			 */
			uint64_t write_val = idx + r;
			*ptr = write_val;
			uint64_t val = *ptr;
			acc ^= val;
#else
			uint64_t val = *ptr;
			acc ^= val;
			MAYBE_STORE(ptr, val);
#endif
#else
			if (do_store) {
				uint64_t write_val = idx + r;
				*ptr = write_val;
				uint64_t val = *ptr;
				acc ^= val;
			} else {
				uint64_t val = *ptr;
				acc ^= val;
			}
#endif
		}
	}
	uint64_t end = rdtsc_end();
	sink64 = acc;
	return end - start;
}

static void warmup_page_rand(volatile uint64_t *data, const uint32_t *order,
			     uint64_t pages, uint64_t steps, int do_store)
{
	IGNORE_DO_STORE();
	(void)order;
	uint64_t acc = 0;
	uint32_t idx = page_rand_start % (uint32_t)pages;
	volatile uint8_t *base = (volatile uint8_t *)data;
	for (uint64_t i = 0; i < steps; i++) {
		volatile uint64_t *ptr =
			(volatile uint64_t *)(base +
					      (uint64_t)idx * PAGE_STRIDE);
		uint64_t val = *ptr;
		acc ^= val;
		MAYBE_STORE(ptr, val);
		idx = (uint32_t)(val & 0xFFFFFFFFULL);
	}
	sink64 = acc;
	sink32 = idx;
}

static uint64_t measure_page_rand(volatile uint64_t *data,
				  const uint32_t *order, uint64_t pages,
				  uint64_t steps, int do_store)
{
	IGNORE_DO_STORE();
	(void)order;
	uint64_t acc = 0;
	uint32_t idx = page_rand_start % (uint32_t)pages;
	volatile uint8_t *base = (volatile uint8_t *)data;
	uint64_t t_start = rdtsc_start();
	for (uint64_t i = 0; i < steps; i++) {
		volatile uint64_t *ptr =
			(volatile uint64_t *)(base +
					      (uint64_t)idx * PAGE_STRIDE);
		uint64_t val = *ptr;
		acc ^= val;
		MAYBE_STORE(ptr, val);
		idx = (uint32_t)(val & 0xFFFFFFFFULL);
	}
	uint64_t end = rdtsc_end();
	sink64 = acc;
	sink32 = idx;
	return end - t_start;
}

static void warmup_seq(volatile uint64_t *data, uint64_t words, int do_store)
{
	IGNORE_DO_STORE();
	uint64_t acc = 0;
	for (uint64_t i = 0; i < words; i++) {
		uint64_t val = data[i];
		acc ^= val;
		MAYBE_STORE(&data[i], val);
	}
	sink64 = acc;
}

static uint64_t measure_seq(volatile uint64_t *data, uint64_t words,
			    uint64_t repeat, int do_store)
{
	IGNORE_DO_STORE();
	uint64_t acc = 0;
	uint64_t start = rdtsc_start();
	for (uint64_t r = 0; r < repeat; r++) {
		for (uint64_t i = 0; i < words; i++) {
			uint64_t val = data[i];
			acc ^= val;
			MAYBE_STORE(&data[i], val);
		}
	}
	uint64_t end = rdtsc_end();
	sink64 = acc;
	return end - start;
}

static void warmup_rand(volatile uint64_t *data, uint64_t steps, int do_store)
{
	IGNORE_DO_STORE();
	uint32_t idx = rand_start;
	uint64_t acc = 0;
	for (uint64_t i = 0; i < steps; i++) {
		uint64_t val = data[idx];
		acc ^= val;
		MAYBE_STORE(&data[idx], val);
		idx = (uint32_t)(val & 0xFFFFFFFFULL);
	}
	sink64 = acc;
	sink32 = idx;
}

static uint64_t measure_rand(volatile uint64_t *data, uint64_t steps,
			     int do_store)
{
	IGNORE_DO_STORE();
	uint32_t idx = rand_start;
	uint64_t acc = 0;
	uint64_t start = rdtsc_start();
	for (uint64_t i = 0; i < steps; i++) {
		uint64_t val = data[idx];
		acc ^= val;
		MAYBE_STORE(&data[idx], val);
		idx = (uint32_t)(val & 0xFFFFFFFFULL);
	}
	uint64_t end = rdtsc_end();
	sink64 = acc;
	sink32 = idx;
	return end - start;
}

static void print_usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [workset_bytes] [repeat] [pattern] [warmup] [random_steps] [do_store] [--seed N] [--runs N]\n",
		prog);
	fprintf(stderr,
		"  pattern: 0=sequential, 1=random, 2=page-seq, 3=page-rand\n  warmup: 0/1\n  do_store: 0=load-only, 1=load+store\n  seed: 0=auto (rdtsc)\n  runs: >1 uses median of repeated measurements\n");
}

int main(int argc, char *argv[])
{
	uint64_t workset_bytes = WORKSET_BYTES;
	uint64_t repeat = REPEAT;
	int pattern = ACCESS_PATTERN;
	int warmup = WARMUP;
	uint64_t random_steps = RANDOM_STEPS;
	int do_store = MEM_DO_STORE;
	uint32_t seed = MEM_SEED;
	uint32_t runs = MEASURE_RUNS;
#if MEM_FIXED_CONFIG
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0 ||
		    strcmp(argv[i], "-h") == 0) {
			print_usage(argv[0]);
			return 0;
		}
	}
	if (argc > 1) {
		fprintf(stderr,
			"Note: runtime args ignored (MEM_FIXED_CONFIG=1)\n");
	}
#else
	char *pos_args[6];
	int pos_count = 0;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0 ||
		    strcmp(argv[i], "-h") == 0) {
			print_usage(argv[0]);
			return 0;
		}
		if (strcmp(argv[i], "--seed") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr,
					"Error: --seed requires a value\n");
				return 1;
			}
			seed = (uint32_t)strtoul(argv[i + 1], NULL, 10);
			i++;
			continue;
		}
		if (strcmp(argv[i], "--runs") == 0) {
			if (i + 1 >= argc) {
				fprintf(stderr,
					"Error: --runs requires a value\n");
				return 1;
			}
			runs = (uint32_t)strtoul(argv[i + 1], NULL, 10);
			i++;
			continue;
		}
		if (argv[i][0] == '-' && argv[i][1] == '-') {
			fprintf(stderr, "Error: unknown option %s\n", argv[i]);
			print_usage(argv[0]);
			return 1;
		}
		if (pos_count >= 6) {
			print_usage(argv[0]);
			return 1;
		}
		pos_args[pos_count++] = argv[i];
	}

	if (pos_count > 0)
		workset_bytes = strtoull(pos_args[0], NULL, 10);
	if (pos_count > 1)
		repeat = strtoull(pos_args[1], NULL, 10);
	if (pos_count > 2)
		pattern = atoi(pos_args[2]);
	if (pos_count > 3)
		warmup = atoi(pos_args[3]);
	if (pos_count > 4)
		random_steps = strtoull(pos_args[4], NULL, 10);
	if (pos_count > 5)
		do_store = atoi(pos_args[5]);
#endif

	if (workset_bytes == 0 || (workset_bytes % 8ULL) != 0) {
		fprintf(stderr,
			"Error: workset_bytes must be a non-zero multiple of 8\n");
		return 1;
	}
	if (pattern != ACCESS_SEQ && pattern != ACCESS_RAND &&
	    pattern != ACCESS_PAGE_SEQ && pattern != ACCESS_PAGE_RAND) {
		fprintf(stderr, "Error: pattern must be 0, 1, 2, or 3\n");
		return 1;
	}
	if (warmup != 0 && warmup != 1) {
		fprintf(stderr, "Error: warmup must be 0 or 1\n");
		return 1;
	}
	if (do_store != 0 && do_store != 1) {
		fprintf(stderr, "Error: do_store must be 0 or 1\n");
		return 1;
	}
	if (runs == 0) {
		fprintf(stderr, "Error: runs must be > 0\n");
		return 1;
	}
	if (warmup == 0 && runs > 1) {
		fprintf(stderr,
			"Note: warmup=0 forces runs=1 for cold measurement\n");
		runs = 1;
	}

	uint64_t words = 0;
	uint64_t pages = 0;
	if (pattern == ACCESS_SEQ || pattern == ACCESS_RAND) {
		words = workset_bytes / 8ULL;
		if (words == 0 || words > UINT32_MAX) {
			fprintf(stderr, "Error: workset_bytes out of range\n");
			return 1;
		}
	} else {
		if ((workset_bytes % PAGE_STRIDE) != 0) {
			fprintf(stderr,
				"Error: workset_bytes must be a multiple of %d\n",
				PAGE_STRIDE);
			return 1;
		}
		pages = workset_bytes / PAGE_STRIDE;
		if (pages == 0 || pages > UINT32_MAX) {
			fprintf(stderr, "Error: workset_bytes out of range\n");
			return 1;
		}
	}

	if (repeat == 0) {
		fprintf(stderr, "Error: repeat must be > 0\n");
		return 1;
	}

	uint64_t iterations = 0;
	if (pattern == ACCESS_SEQ) {
		if (words > UINT64_MAX / repeat) {
			fprintf(stderr, "Error: iterations overflow\n");
			return 1;
		}
		iterations = words * repeat;
	} else if (pattern == ACCESS_RAND) {
		uint64_t rand_steps = random_steps;
		if (rand_steps == 0) {
			if (words > UINT64_MAX / repeat) {
				fprintf(stderr, "Error: iterations overflow\n");
				return 1;
			}
			rand_steps = words * repeat;
		}
		iterations = rand_steps;
	} else {
		if (pages > UINT64_MAX / repeat) {
			fprintf(stderr, "Error: iterations overflow\n");
			return 1;
		}
		iterations = pages * repeat;
	}

	if (iterations == 0) {
		fprintf(stderr, "Error: iterations must be > 0\n");
		return 1;
	}

	void *raw = NULL;
	volatile uint64_t *data = NULL;
	uint32_t *page_order = NULL;

#if MEM_USE_STATIC_ARRAY
	/* Use static BSS array (matches FrameVM guest behavior) */
	if (workset_bytes != WORKSET_BYTES) {
		fprintf(stderr,
			"Error: MEM_USE_STATIC_ARRAY=1 requires workset_bytes=%llu (compile-time fixed)\n",
			(unsigned long long)WORKSET_BYTES);
		return 1;
	}
	data = static_data_array;
#if (ACCESS_PATTERN == ACCESS_PAGE_RAND)
	page_order = static_page_order;
#endif
#else
	/* Dynamic heap allocation (original behavior) */
	if (workset_bytes > (uint64_t)SIZE_MAX) {
		fprintf(stderr, "Error: workset_bytes too large for host\n");
		return 1;
	}

	int ret = posix_memalign(&raw, 4096, (size_t)workset_bytes);
	if (ret != 0) {
		fprintf(stderr, "posix_memalign failed: %s\n", strerror(ret));
		return 1;
	}

	data = (volatile uint64_t *)raw;
#endif

	if (seed == 0)
		seed = (uint32_t)rdtsc();
	lcg_state = seed;

	if (pattern == ACCESS_SEQ) {
		init_seq_data(data, words);
	} else if (pattern == ACCESS_RAND) {
		build_random_chain(data, (uint32_t)words);
	} else if (pattern == ACCESS_PAGE_RAND) {
#if MEM_USE_STATIC_ARRAY
		/* page_order already points to static array */
#else
		page_order = malloc(pages * sizeof(*page_order));
		if (!page_order) {
			fprintf(stderr, "Error: page_order alloc failed\n");
			free(raw);
			return 1;
		}
#endif
		build_page_chain(data, page_order, (uint32_t)pages);
	}

	if (do_store && iterations > (UINT64_MAX / 2ULL)) {
		fprintf(stderr, "Error: mem_ops overflow\n");
		free(raw);
		return 1;
	}
	uint64_t mem_ops = iterations * (do_store ? 2ULL : 1ULL);

	printf("\n========================================\n");
	printf(" Host Memory Benchmark\n");
	printf("========================================\n");
	printf(" Workset:     %llu bytes\n", (unsigned long long)workset_bytes);
#if MEM_USE_STATIC_ARRAY
	printf(" Allocation:  static (BSS segment)\n");
#else
	printf(" Allocation:  dynamic (heap)\n");
#endif
	printf(" Repeat:      %llu\n", (unsigned long long)repeat);
	printf(" Iterations:  %llu\n", (unsigned long long)iterations);
	printf(" Mem ops:     %llu\n", (unsigned long long)mem_ops);
	if (pattern == ACCESS_SEQ)
		printf(" Pattern:     sequential\n");
	else if (pattern == ACCESS_RAND)
		printf(" Pattern:     random\n");
	else if (pattern == ACCESS_PAGE_SEQ)
		printf(" Pattern:     page-seq\n");
	else
		printf(" Pattern:     page-rand\n");
	if (pattern == ACCESS_RAND || pattern == ACCESS_PAGE_RAND)
		printf(" Seed:        %u\n", seed);
	printf(" Op mode:     %s\n", do_store ? "load+store" : "load-only");
	printf(" Warmup:      %s\n", warmup ? "yes" : "no");
	printf(" Runs:        %u\n", runs);
	if (runs > 1)
		printf(" Aggregate:  median\n");
	printf("----------------------------------------\n");

	uint64_t cycles = 0;
	uint64_t result = 0;
	uint64_t *samples = NULL;
	if (runs > 1) {
		samples = calloc(runs, sizeof(*samples));
		if (!samples) {
			fprintf(stderr, "Error: samples alloc failed\n");
#if MEM_USE_STATIC_ARRAY
			return 1;
#else
			free(page_order);
			free(raw);
			return 1;
#endif
		}
	}
	if (pattern == ACCESS_SEQ) {
		if (warmup)
			warmup_seq(data, words, do_store);
		if (runs == 1) {
			cycles = measure_seq(data, words, repeat, do_store);
		} else {
			for (uint32_t i = 0; i < runs; i++)
				samples[i] = measure_seq(data, words, repeat,
							 do_store);
			cycles = pick_median(samples, runs);
		}
	} else if (pattern == ACCESS_RAND) {
		uint64_t rand_steps = iterations;
		if (warmup) {
			uint64_t warmup_steps = words;
			if (warmup_steps > rand_steps)
				warmup_steps = rand_steps;
			if (warmup_steps != 0)
				warmup_rand(data, warmup_steps, do_store);
		}
		if (runs == 1) {
			cycles = measure_rand(data, rand_steps, do_store);
		} else {
			for (uint32_t i = 0; i < runs; i++)
				samples[i] = measure_rand(data, rand_steps,
							  do_store);
			cycles = pick_median(samples, runs);
		}
	} else if (pattern == ACCESS_PAGE_SEQ) {
		if (warmup)
			warmup_page((volatile uint8_t *)data, NULL, pages, 0,
				    do_store);
		if (runs == 1) {
			cycles = measure_page((volatile uint8_t *)data, NULL,
					      pages, repeat, 0, do_store);
		} else {
			for (uint32_t i = 0; i < runs; i++)
				samples[i] = measure_page(
					(volatile uint8_t *)data, NULL, pages,
					repeat, 0, do_store);
			cycles = pick_median(samples, runs);
		}
	} else {
		uint64_t steps = iterations;
		if (warmup) {
			uint64_t warmup_steps = pages;
			if (warmup_steps > steps)
				warmup_steps = steps;
			if (warmup_steps != 0)
				warmup_page_rand(data, page_order, pages,
						 warmup_steps, do_store);
		}
		if (runs == 1) {
			cycles = measure_page_rand(data, page_order, pages,
						   steps, do_store);
		} else {
			for (uint32_t i = 0; i < runs; i++)
				samples[i] = measure_page_rand(data, page_order,
							       pages, steps,
							       do_store);
			cycles = pick_median(samples, runs);
		}
	}
	if (mem_ops != 0)
		result = cycles / mem_ops;
	printf(" Result:      %llu cycles/op\n", (unsigned long long)result);
	printf("========================================\n\n");

#if MEM_USE_STATIC_ARRAY
	free(samples);
	/* static arrays don't need to be freed */
#else
	free(samples);
	free(page_order);
	free(raw);
#endif
	return 0;
}
