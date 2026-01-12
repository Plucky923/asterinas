/*
 * FrameVM Memory Benchmark (Guest)
 *
 * Compile-time knobs:
 *   -DWORKSET_BYTES=<bytes>   (default: 8MB)
 *   -DREPEAT=<passes>         (default: 16)
 *   -DACCESS_PATTERN=0|1|2|3  (0: sequential, 1: random pointer-chase,
 *                              2: page-stride sequential,
 *                              3: page-stride random pointer-chase)
 *   -DWARMUP=0|1              (0: no warmup, 1: warmup)
 *   -DRANDOM_STEPS=<steps>    (default: 0 => WORKSET_WORDS * REPEAT)
 *   -DMEM_DO_STORE=0|1        (0: load-only, 1: load+store)
 *   -DMEM_SEED=<u32>          (0: seed from rdtsc)
 */

#include "syscalls.h"

#define ACCESS_SEQ  0
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

#ifndef MEASURE_AGGREGATE_MIN
#define MEASURE_AGGREGATE_MIN 0
#endif

#ifndef COLD_MULTI_RUNS
#define COLD_MULTI_RUNS 0
#endif

#define WORKSET_WORDS (WORKSET_BYTES / 8ULL)
#define WORKSET_PAGES (WORKSET_BYTES / PAGE_STRIDE)

#if WORKSET_WORDS == 0
#error WORKSET_BYTES too small
#endif

#if (WORKSET_BYTES % 8ULL) != 0
#error WORKSET_BYTES must be a multiple of 8
#endif

#if WARMUP || COLD_MULTI_RUNS
#define EFFECTIVE_RUNS MEASURE_RUNS
#else
#define EFFECTIVE_RUNS 1
#endif

#if WORKSET_WORDS > 0xFFFFFFFFULL
#error WORKSET_BYTES too large for 32-bit indices
#endif

#if (ACCESS_PATTERN == ACCESS_PAGE_SEQ || ACCESS_PATTERN == ACCESS_PAGE_RAND)
#if (WORKSET_BYTES % PAGE_STRIDE) != 0
#error WORKSET_BYTES must be a multiple of PAGE_STRIDE for page-stride patterns
#endif
#if WORKSET_PAGES == 0
#error WORKSET_BYTES too small for page-stride patterns
#endif
#if WORKSET_PAGES > 0xFFFFFFFFULL
#error WORKSET_BYTES too large for 32-bit page indices
#endif
#endif

#if RANDOM_STEPS != 0
#define RAND_STEPS ((uint64_t)RANDOM_STEPS)
#else
#define RAND_STEPS ((uint64_t)WORKSET_WORDS * (uint64_t)REPEAT)
#endif

#define MAYBE_STORE(ptr, val) \
    do { \
        if (MEM_DO_STORE) { \
            *(ptr) = (val); \
        } \
    } while (0)

static volatile uint64_t data_array[WORKSET_WORDS] __attribute__((aligned(4096)));
static volatile uint64_t sink64 = 0;

#if (ACCESS_PATTERN == ACCESS_RAND || ACCESS_PATTERN == ACCESS_PAGE_RAND)
static uint32_t used_seed = 0;
#endif

#if ACCESS_PATTERN == ACCESS_RAND
static uint32_t rand_start = 0;
#endif

#if ACCESS_PATTERN == ACCESS_PAGE_RAND
static uint32_t page_rand_start = 0;
#endif

#if (ACCESS_PATTERN == ACCESS_RAND || ACCESS_PATTERN == ACCESS_PAGE_RAND)
static volatile uint32_t sink32 = 0;
#endif

#if ACCESS_PATTERN == ACCESS_PAGE_RAND
static uint32_t page_order[WORKSET_PAGES];
#endif

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    asm volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtsc_start(void) {
    asm volatile ("lfence" ::: "memory");
    uint64_t t = rdtsc();
    asm volatile ("lfence" ::: "memory");
    return t;
}

static inline uint64_t rdtsc_end(void) {
    asm volatile ("lfence" ::: "memory");
    uint64_t t = rdtsc();
    asm volatile ("lfence" ::: "memory");
    return t;
}

#if EFFECTIVE_RUNS > 1
static uint64_t run_samples[EFFECTIVE_RUNS];

#if !MEASURE_AGGREGATE_MIN
static uint64_t pick_median(uint64_t *vals, uint32_t n) {
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
#endif

static uint64_t pick_min(const uint64_t *vals, uint32_t n) {
    uint64_t min_val = vals[0];
    for (uint32_t i = 1; i < n; i++) {
        if (vals[i] < min_val) {
            min_val = vals[i];
        }
    }
    return min_val;
}

static uint64_t aggregate_samples(uint64_t *vals, uint32_t n) {
#if MEASURE_AGGREGATE_MIN
    return pick_min(vals, n);
#else
    return pick_median(vals, n);
#endif
}
#endif

#if (ACCESS_PATTERN == ACCESS_RAND || ACCESS_PATTERN == ACCESS_PAGE_RAND)
static uint32_t lcg_state = 1;

static inline uint32_t lcg_rand(void) {
    lcg_state = lcg_state * 1664525u + 1013904223u;
    return lcg_state;
}
#endif

#if ACCESS_PATTERN == ACCESS_RAND
static void build_random_chain(uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        data_array[i] = (uint64_t)i;
    }

    for (uint32_t i = n - 1; i > 0; i--) {
        uint32_t j = lcg_rand() % (i + 1);
        uint64_t tmp = data_array[i];
        data_array[i] = data_array[j];
        data_array[j] = tmp;
    }

    for (uint32_t pos = 0; pos < n; pos++) {
        uint32_t cur = (uint32_t)(data_array[pos] & 0xFFFFFFFFULL);
        uint32_t next = (uint32_t)(data_array[(pos + 1) % n] & 0xFFFFFFFFULL);
        uint64_t entry = data_array[cur];
        data_array[cur] = (entry & 0xFFFFFFFFULL) | ((uint64_t)next << 32);
    }

    for (uint32_t i = 0; i < n; i++) {
        data_array[i] = data_array[i] >> 32;
    }

    rand_start = lcg_rand() % n;
}
#endif

#if ACCESS_PATTERN == ACCESS_PAGE_RAND
static void build_page_chain(uint32_t pages) {
    volatile uint8_t *base = (volatile uint8_t *)data_array;
    for (uint32_t i = 0; i < pages; i++) {
        page_order[i] = i;
    }

    for (uint32_t i = pages - 1; i > 0; i--) {
        uint32_t j = lcg_rand() % (i + 1);
        uint32_t tmp = page_order[i];
        page_order[i] = page_order[j];
        page_order[j] = tmp;
    }

    for (uint32_t i = 0; i < pages; i++) {
        uint32_t cur = page_order[i];
        uint32_t next = page_order[(i + 1) % pages];
        volatile uint64_t *ptr =
            (volatile uint64_t *)(base + (uint64_t)cur * PAGE_STRIDE);
        *ptr = (uint64_t)next;
    }

    page_rand_start = page_order[lcg_rand() % pages];
}
#endif

#if ACCESS_PATTERN == ACCESS_SEQ
static void init_seq_data(uint64_t words) {
    for (uint64_t i = 0; i < words; i++) {
        data_array[i] = i;
    }
}

#if WARMUP
static void warmup_seq(uint64_t words) {
    uint64_t acc = 0;
    for (uint64_t i = 0; i < words; i++) {
        uint64_t val = data_array[i];
        acc ^= val;
#if MEM_DO_STORE
        data_array[i] = val;
#endif
    }
    sink64 = acc;
}
#endif

static uint64_t measure_seq(uint64_t words, uint64_t repeat) {
    uint64_t acc = 0;
    uint64_t start = rdtsc_start();
    for (uint64_t r = 0; r < repeat; r++) {
        for (uint64_t i = 0; i < words; i++) {
            uint64_t val = data_array[i];
            acc ^= val;
#if MEM_DO_STORE
            data_array[i] = val;
#endif
        }
    }
    uint64_t end = rdtsc_end();
    sink64 = acc;
    return end - start;
}
#endif

#if ACCESS_PATTERN == ACCESS_RAND
#if WARMUP
static void warmup_rand(uint64_t steps) {
    uint32_t idx = rand_start;
    uint64_t acc = 0;
    for (uint64_t i = 0; i < steps; i++) {
        uint64_t val = data_array[idx];
        acc ^= val;
#if MEM_DO_STORE
        data_array[idx] = val;
#endif
        idx = (uint32_t)(val & 0xFFFFFFFFULL);
    }
    sink64 = acc;
    sink32 = idx;
}
#endif

static uint64_t measure_rand(uint64_t steps) {
    uint32_t idx = rand_start;
    uint64_t acc = 0;
    uint64_t start = rdtsc_start();
    for (uint64_t i = 0; i < steps; i++) {
        uint64_t val = data_array[idx];
        acc ^= val;
#if MEM_DO_STORE
        data_array[idx] = val;
#endif
        idx = (uint32_t)(val & 0xFFFFFFFFULL);
    }
    uint64_t end = rdtsc_end();
    sink64 = acc;
    sink32 = idx;
    return end - start;
}
#endif

#if ACCESS_PATTERN == ACCESS_PAGE_SEQ
#if WARMUP
static void warmup_page_seq(uint64_t pages) {
    uint64_t acc = 0;
    volatile uint8_t *base = (volatile uint8_t *)data_array;
    for (uint64_t i = 0; i < pages; i++) {
        volatile uint64_t *ptr =
            (volatile uint64_t *)(base + i * PAGE_STRIDE);
#if MEM_DO_STORE
        /*
         * Store-first path for write-touch mode:
         * avoid read-first zero-page mapping on Linux, which can otherwise
         * trigger an extra COW fault on the subsequent write.
         */
        uint64_t write_val = i;
        *ptr = write_val;
        uint64_t val = *ptr;
#else
        uint64_t val = *ptr;
#endif
        acc ^= val;
    }
    sink64 = acc;
}
#endif

static uint64_t measure_page_seq(uint64_t pages, uint64_t repeat) {
    uint64_t acc = 0;
    volatile uint8_t *base = (volatile uint8_t *)data_array;
    uint64_t start = rdtsc_start();
    for (uint64_t r = 0; r < repeat; r++) {
        for (uint64_t i = 0; i < pages; i++) {
            volatile uint64_t *ptr =
                (volatile uint64_t *)(base + i * PAGE_STRIDE);
#if MEM_DO_STORE
            /*
             * Store-first for cold/write path fairness across stacks:
             * count one write-touch fault per page instead of read-fault
             * followed by COW write-fault on Linux.
             */
            uint64_t write_val = i + r;
            *ptr = write_val;
            uint64_t val = *ptr;
#else
            uint64_t val = *ptr;
#endif
            acc ^= val;
        }
    }
    uint64_t end = rdtsc_end();
    sink64 = acc;
    return end - start;
}
#endif

#if ACCESS_PATTERN == ACCESS_PAGE_RAND
#if WARMUP
static void warmup_page_rand(uint64_t steps) {
    uint64_t acc = 0;
    uint32_t idx = page_rand_start % WORKSET_PAGES;
    volatile uint8_t *base = (volatile uint8_t *)data_array;
    for (uint64_t i = 0; i < steps; i++) {
        volatile uint64_t *ptr =
            (volatile uint64_t *)(base + (uint64_t)idx * PAGE_STRIDE);
        uint64_t val = *ptr;
        acc ^= val;
        MAYBE_STORE(ptr, val);
        idx = (uint32_t)(val & 0xFFFFFFFFULL);
    }
    sink64 = acc;
    sink32 = idx;
}
#endif

static uint64_t measure_page_rand(uint64_t steps) {
    uint64_t acc = 0;
    uint32_t idx = page_rand_start % WORKSET_PAGES;
    volatile uint8_t *base = (volatile uint8_t *)data_array;
    uint64_t t_start = rdtsc_start();
    for (uint64_t i = 0; i < steps; i++) {
        volatile uint64_t *ptr =
            (volatile uint64_t *)(base + (uint64_t)idx * PAGE_STRIDE);
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
#endif

void _start(void) {
#if (ACCESS_PATTERN == ACCESS_SEQ || ACCESS_PATTERN == ACCESS_RAND)
    uint64_t words = WORKSET_WORDS;
#endif
#if (ACCESS_PATTERN == ACCESS_PAGE_SEQ || ACCESS_PATTERN == ACCESS_PAGE_RAND)
    uint64_t pages = WORKSET_PAGES;
#endif
    uint64_t cycles = 0;
    uint64_t result = 0;
    uint64_t iterations = 0;
    uint64_t mem_ops = 0;
    uint32_t runs = EFFECTIVE_RUNS;

#if (ACCESS_PATTERN == ACCESS_RAND || ACCESS_PATTERN == ACCESS_PAGE_RAND)
    if (MEM_SEED != 0) {
        used_seed = (uint32_t)MEM_SEED;
    } else {
        used_seed = (uint32_t)rdtsc();
    }
    lcg_state = used_seed;
#endif

    print("\n========================================\n");
    print(" FrameVM Memory Benchmark\n");
    print("========================================\n");
    print(" Workset:     ");
    print_number(WORKSET_BYTES);
    print(" bytes\n");
    print(" Repeat:      ");
    print_number(REPEAT);
    print("\n");
#if ACCESS_PATTERN == ACCESS_SEQ
    iterations = words * (uint64_t)REPEAT;
#elif ACCESS_PATTERN == ACCESS_RAND
    iterations = RAND_STEPS;
#else
    iterations = pages * (uint64_t)REPEAT;
#endif
#if MEM_DO_STORE
    mem_ops = iterations * 2;
#else
    mem_ops = iterations;
#endif
    print(" Iterations:  ");
    print_number(iterations);
    print("\n");
    print(" Mem ops:     ");
    print_number(mem_ops);
    print("\n");
#if ACCESS_PATTERN == ACCESS_SEQ
    print(" Pattern:     sequential\n");
#elif ACCESS_PATTERN == ACCESS_RAND
    print(" Pattern:     random\n");
    print(" Seed:        ");
    print_number(used_seed);
    print("\n");
#elif ACCESS_PATTERN == ACCESS_PAGE_SEQ
    print(" Pattern:     page-seq\n");
#else
    print(" Pattern:     page-rand\n");
    print(" Seed:        ");
    print_number(used_seed);
    print("\n");
#endif
#if MEM_DO_STORE
    print(" Op mode:     load+store\n");
#else
    print(" Op mode:     load-only\n");
#endif
#if WARMUP
    print(" Warmup:      yes\n");
#else
    print(" Warmup:      no\n");
#endif
    print(" Runs:        ");
    print_number(runs);
    print("\n");
#if EFFECTIVE_RUNS > 1
#if MEASURE_AGGREGATE_MIN
    print(" Aggregate:  min\n");
#else
    print(" Aggregate:  median\n");
#endif
#endif
    print("----------------------------------------\n");

#if ACCESS_PATTERN == ACCESS_SEQ
    init_seq_data(words);
#if WARMUP
    warmup_seq(words);
#endif
#if EFFECTIVE_RUNS > 1
    for (uint32_t i = 0; i < EFFECTIVE_RUNS; i++) {
        run_samples[i] = measure_seq(words, REPEAT);
    }
    cycles = aggregate_samples(run_samples, EFFECTIVE_RUNS);
#else
    cycles = measure_seq(words, REPEAT);
#endif
#elif ACCESS_PATTERN == ACCESS_RAND
    build_random_chain((uint32_t)words);
#if WARMUP
    {
        uint64_t warmup_steps = words;
        if (warmup_steps > RAND_STEPS) {
            warmup_steps = RAND_STEPS;
        }
        if (warmup_steps != 0) {
            warmup_rand(warmup_steps);
        }
    }
#endif
#if EFFECTIVE_RUNS > 1
    for (uint32_t i = 0; i < EFFECTIVE_RUNS; i++) {
        run_samples[i] = measure_rand(RAND_STEPS);
    }
    cycles = aggregate_samples(run_samples, EFFECTIVE_RUNS);
#else
    cycles = measure_rand(RAND_STEPS);
#endif
#elif ACCESS_PATTERN == ACCESS_PAGE_SEQ
#if WARMUP
    warmup_page_seq(pages);
#endif
#if EFFECTIVE_RUNS > 1
    for (uint32_t i = 0; i < EFFECTIVE_RUNS; i++) {
        run_samples[i] = measure_page_seq(pages, REPEAT);
    }
    cycles = aggregate_samples(run_samples, EFFECTIVE_RUNS);
#else
    cycles = measure_page_seq(pages, REPEAT);
#endif
#else
    build_page_chain((uint32_t)pages);
#if WARMUP
    warmup_page_rand(pages);
#endif
#if EFFECTIVE_RUNS > 1
    for (uint32_t i = 0; i < EFFECTIVE_RUNS; i++) {
        run_samples[i] = measure_page_rand(iterations);
    }
    cycles = aggregate_samples(run_samples, EFFECTIVE_RUNS);
#else
    cycles = measure_page_rand(iterations);
#endif
#endif
    if (mem_ops != 0) {
        result = cycles / mem_ops;
    }
    print(" Result:      ");
    print_number(result);
    print(" cycles/op\n");
    print("========================================\n");
    print("\n");

    sys_exit(0);
}
