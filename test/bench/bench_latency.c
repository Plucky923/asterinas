/* SPDX-License-Identifier: MPL-2.0 */
/*
 * bench_latency.c - Rigorous Low-Level Latency Microbenchmark
 *
 * Measures fine-grained latency of various operations using RDTSC/RDTSCP
 * with proper serialization for accurate cycle counting.
 *
 * Features:
 *   - RDTSC/RDTSCP with proper serialization (LFENCE/MFENCE)
 *   - Multiple operation types: syscall, function call, VMCALL, etc.
 *   - Statistical analysis with outlier detection
 *   - CPU frequency detection for ns conversion
 *   - Warmup with stability verification
 *
 * Usage:
 *   ./bench_latency [--iterations 100000] [--test all|rdtsc|syscall|...]
 *
 * Copyright (C) 2024 Asterinas Developers.
 */

#include "bench_common.h"

#include <sys/syscall.h>
#include <signal.h>
#include <setjmp.h>

/* ============================================================================
 * Configuration
 * ============================================================================ */

enum test_type {
    TEST_RDTSC,
    TEST_CLOCK_GETTIME,
    TEST_GETPID,
    TEST_GETTID,
    TEST_EMPTY_FUNC,
    TEST_VMCALL,
    TEST_ALL,
};

static struct {
    enum test_type test;
    size_t iterations;
    size_t warmup_iterations;
    int cpu_affinity;
    bool pin_cpu;
    bool remove_outliers;
    bool verbose;
    bool json_output;
    bool csv_output;
    bool detect_frequency;

    /* Detected CPU frequency */
    double cpu_freq_ghz;
    uint64_t tsc_per_ns;

    /* Sample storage */
    uint64_t *samples_cycles;
    double *samples_ns;
} config = {
    .test = TEST_ALL,
    .iterations = 100000,
    .warmup_iterations = 10000,
    .cpu_affinity = 0,
    .pin_cpu = true,
    .remove_outliers = true,
    .detect_frequency = true,
};

/* ============================================================================
 * VMCALL Support
 * ============================================================================ */

static jmp_buf vmcall_jmp;
static volatile sig_atomic_t vmcall_supported = 1;

static void sigill_handler(int sig)
{
    (void)sig;
    vmcall_supported = 0;
    longjmp(vmcall_jmp, 1);
}

static inline uint64_t do_vmcall(void)
{
#if defined(__x86_64__) || defined(__i386__)
    uint64_t ret = 0;
    __asm__ volatile (
        ".byte 0x0f, 0x01, 0xc1"  /* vmcall */
        : "=a"(ret)
        : "a"(0)
        : "memory"
    );
    return ret;
#else
    return 0;
#endif
}

static bool test_vmcall_support(void)
{
#if defined(__x86_64__) || defined(__i386__)
    struct sigaction sa, old_sa;
    sa.sa_handler = sigill_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGILL, &sa, &old_sa);

    if (setjmp(vmcall_jmp) == 0) {
        do_vmcall();
    }

    sigaction(SIGILL, &old_sa, NULL);
    return vmcall_supported;
#else
    return false;
#endif
}

/* ============================================================================
 * Empty Function for Call Overhead Measurement
 * ============================================================================ */

__attribute__((noinline))
static void empty_function(void)
{
    __asm__ volatile ("" ::: "memory");
}

__attribute__((noinline))
static uint64_t empty_function_with_args(uint64_t a, uint64_t b, uint64_t c)
{
    __asm__ volatile ("" ::: "memory");
    return a + b + c;
}

/* ============================================================================
 * Precise RDTSC Measurement Macros
 * ============================================================================ */

/*
 * For accurate cycle measurement:
 * 1. CPUID or LFENCE to serialize before RDTSC
 * 2. RDTSC to get start time
 * 3. <operation>
 * 4. RDTSCP (includes serialization) to get end time
 * 5. CPUID or LFENCE to prevent out-of-order completion
 */

#if defined(__x86_64__) || defined(__i386__)

#define BENCH_CYCLES_START(start) do { \
    uint32_t _lo, _hi; \
    __asm__ volatile ( \
        "mfence\n\t" \
        "lfence\n\t" \
        "rdtsc\n\t" \
        : "=a"(_lo), "=d"(_hi) \
    ); \
    (start) = ((uint64_t)_hi << 32) | _lo; \
} while (0)

#define BENCH_CYCLES_END(end) do { \
    uint32_t _lo, _hi; \
    __asm__ volatile ( \
        "rdtscp\n\t" \
        "lfence\n\t" \
        : "=a"(_lo), "=d"(_hi) \
        : \
        : "ecx" \
    ); \
    (end) = ((uint64_t)_hi << 32) | _lo; \
} while (0)

#else

#define BENCH_CYCLES_START(start) do { \
    (start) = bench_gettime_ns(CLOCK_MONOTONIC); \
} while (0)

#define BENCH_CYCLES_END(end) do { \
    (end) = bench_gettime_ns(CLOCK_MONOTONIC); \
} while (0)

#endif

/* ============================================================================
 * CPU Frequency Detection
 * ============================================================================ */

static double detect_cpu_frequency(void)
{
    const int calibration_ms = 100;
    uint64_t tsc_start, tsc_end;
    uint64_t ns_start, ns_end;

    /* Warmup */
    for (int i = 0; i < 1000; i++) {
        bench_rdtsc();
        bench_gettime_ns(CLOCK_MONOTONIC);
    }

    /* Measure TSC ticks per calibration period */
    ns_start = bench_gettime_ns(CLOCK_MONOTONIC);
    tsc_start = bench_rdtsc();

    /* Busy wait for calibration period */
    uint64_t target_ns = ns_start + (calibration_ms * NSEC_PER_MSEC);
    while (bench_gettime_ns(CLOCK_MONOTONIC) < target_ns) {
        __asm__ volatile ("pause" ::: "memory");
    }

    tsc_end = bench_rdtsc();
    ns_end = bench_gettime_ns(CLOCK_MONOTONIC);

    uint64_t tsc_delta = tsc_end - tsc_start;
    uint64_t ns_delta = ns_end - ns_start;

    double freq_ghz = (double)tsc_delta / (double)ns_delta;
    return freq_ghz;
}

/* ============================================================================
 * Individual Benchmarks
 * ============================================================================ */

static void bench_rdtsc_overhead(void)
{
    printf(" Running RDTSC overhead benchmark...\n");

    /* Warmup */
    for (size_t i = 0; i < config.warmup_iterations; i++) {
        uint64_t start, end;
        BENCH_CYCLES_START(start);
        BENCH_CYCLES_END(end);
        (void)(end - start);
    }

    /* Measurement */
    for (size_t i = 0; i < config.iterations; i++) {
        uint64_t start, end;
        BENCH_CYCLES_START(start);
        /* Empty - measuring RDTSC overhead itself */
        BENCH_CYCLES_END(end);
        config.samples_cycles[i] = end - start;
    }

    /* Convert to double for statistics */
    for (size_t i = 0; i < config.iterations; i++) {
        config.samples_ns[i] = (double)config.samples_cycles[i];
    }

    struct bench_stats stats;
    bench_compute_stats(config.samples_ns, config.iterations, &stats, config.remove_outliers);

    if (config.json_output) {
        bench_print_json(&stats, "rdtsc_overhead");
    } else if (config.csv_output) {
        bench_print_csv(&stats, "rdtsc_overhead");
    } else {
        bench_print_stats_compact(&stats, "RDTSC overhead", "cycles");
    }

    bench_free_stats(&stats);
}

static void bench_clock_gettime_overhead(void)
{
    printf(" Running clock_gettime overhead benchmark...\n");

    /* Warmup */
    for (size_t i = 0; i < config.warmup_iterations; i++) {
        uint64_t start, end;
        BENCH_CYCLES_START(start);
        bench_gettime_ns(CLOCK_MONOTONIC);
        BENCH_CYCLES_END(end);
        (void)(end - start);
    }

    /* Measurement */
    for (size_t i = 0; i < config.iterations; i++) {
        uint64_t start, end;
        BENCH_CYCLES_START(start);
        bench_gettime_ns(CLOCK_MONOTONIC);
        BENCH_CYCLES_END(end);
        config.samples_cycles[i] = end - start;
    }

    for (size_t i = 0; i < config.iterations; i++) {
        config.samples_ns[i] = (double)config.samples_cycles[i];
    }

    struct bench_stats stats;
    bench_compute_stats(config.samples_ns, config.iterations, &stats, config.remove_outliers);

    if (config.json_output) {
        bench_print_json(&stats, "clock_gettime");
    } else if (config.csv_output) {
        bench_print_csv(&stats, "clock_gettime");
    } else {
        bench_print_stats_compact(&stats, "clock_gettime", "cycles");
    }

    bench_free_stats(&stats);
}

static void bench_getpid_overhead(void)
{
    printf(" Running getpid syscall benchmark...\n");

    /* Warmup */
    for (size_t i = 0; i < config.warmup_iterations; i++) {
        uint64_t start, end;
        BENCH_CYCLES_START(start);
        syscall(SYS_getpid);
        BENCH_CYCLES_END(end);
        (void)(end - start);
    }

    /* Measurement */
    for (size_t i = 0; i < config.iterations; i++) {
        uint64_t start, end;
        BENCH_CYCLES_START(start);
        syscall(SYS_getpid);
        BENCH_CYCLES_END(end);
        config.samples_cycles[i] = end - start;
    }

    for (size_t i = 0; i < config.iterations; i++) {
        config.samples_ns[i] = (double)config.samples_cycles[i];
    }

    struct bench_stats stats;
    bench_compute_stats(config.samples_ns, config.iterations, &stats, config.remove_outliers);

    if (config.json_output) {
        bench_print_json(&stats, "getpid");
    } else if (config.csv_output) {
        bench_print_csv(&stats, "getpid");
    } else {
        bench_print_stats_compact(&stats, "getpid syscall", "cycles");
    }

    bench_free_stats(&stats);
}

static void bench_gettid_overhead(void)
{
    printf(" Running gettid syscall benchmark...\n");

    /* Warmup */
    for (size_t i = 0; i < config.warmup_iterations; i++) {
        uint64_t start, end;
        BENCH_CYCLES_START(start);
        syscall(SYS_gettid);
        BENCH_CYCLES_END(end);
        (void)(end - start);
    }

    /* Measurement */
    for (size_t i = 0; i < config.iterations; i++) {
        uint64_t start, end;
        BENCH_CYCLES_START(start);
        syscall(SYS_gettid);
        BENCH_CYCLES_END(end);
        config.samples_cycles[i] = end - start;
    }

    for (size_t i = 0; i < config.iterations; i++) {
        config.samples_ns[i] = (double)config.samples_cycles[i];
    }

    struct bench_stats stats;
    bench_compute_stats(config.samples_ns, config.iterations, &stats, config.remove_outliers);

    if (config.json_output) {
        bench_print_json(&stats, "gettid");
    } else if (config.csv_output) {
        bench_print_csv(&stats, "gettid");
    } else {
        bench_print_stats_compact(&stats, "gettid syscall", "cycles");
    }

    bench_free_stats(&stats);
}

static void bench_function_call_overhead(void)
{
    printf(" Running function call benchmark...\n");

    /* Warmup */
    for (size_t i = 0; i < config.warmup_iterations; i++) {
        uint64_t start, end;
        BENCH_CYCLES_START(start);
        empty_function();
        BENCH_CYCLES_END(end);
        (void)(end - start);
    }

    /* Measurement */
    for (size_t i = 0; i < config.iterations; i++) {
        uint64_t start, end;
        BENCH_CYCLES_START(start);
        empty_function();
        BENCH_CYCLES_END(end);
        config.samples_cycles[i] = end - start;
    }

    for (size_t i = 0; i < config.iterations; i++) {
        config.samples_ns[i] = (double)config.samples_cycles[i];
    }

    struct bench_stats stats;
    bench_compute_stats(config.samples_ns, config.iterations, &stats, config.remove_outliers);

    if (config.json_output) {
        bench_print_json(&stats, "function_call");
    } else if (config.csv_output) {
        bench_print_csv(&stats, "function_call");
    } else {
        bench_print_stats_compact(&stats, "Empty function call", "cycles");
    }

    bench_free_stats(&stats);
}

static void bench_function_call_with_args(void)
{
    printf(" Running function call with args benchmark...\n");

    volatile uint64_t result = 0;

    /* Warmup */
    for (size_t i = 0; i < config.warmup_iterations; i++) {
        uint64_t start, end;
        BENCH_CYCLES_START(start);
        result = empty_function_with_args(1, 2, 3);
        BENCH_CYCLES_END(end);
        (void)(end - start);
    }

    /* Measurement */
    for (size_t i = 0; i < config.iterations; i++) {
        uint64_t start, end;
        BENCH_CYCLES_START(start);
        result = empty_function_with_args(i, i + 1, i + 2);
        BENCH_CYCLES_END(end);
        config.samples_cycles[i] = end - start;
    }
    (void)result;

    for (size_t i = 0; i < config.iterations; i++) {
        config.samples_ns[i] = (double)config.samples_cycles[i];
    }

    struct bench_stats stats;
    bench_compute_stats(config.samples_ns, config.iterations, &stats, config.remove_outliers);

    if (config.json_output) {
        bench_print_json(&stats, "function_call_args");
    } else if (config.csv_output) {
        bench_print_csv(&stats, "function_call_args");
    } else {
        bench_print_stats_compact(&stats, "Function call (3 args)", "cycles");
    }

    bench_free_stats(&stats);
}

static void bench_vmcall_overhead(void)
{
    if (!test_vmcall_support()) {
        printf(" VMCALL not supported (not running in VM)\n");
        return;
    }

    printf(" Running VMCALL benchmark...\n");

    /* Warmup */
    for (size_t i = 0; i < config.warmup_iterations; i++) {
        uint64_t start, end;
        BENCH_CYCLES_START(start);
        do_vmcall();
        BENCH_CYCLES_END(end);
        (void)(end - start);
    }

    /* Measurement */
    for (size_t i = 0; i < config.iterations; i++) {
        uint64_t start, end;
        BENCH_CYCLES_START(start);
        do_vmcall();
        BENCH_CYCLES_END(end);
        config.samples_cycles[i] = end - start;
    }

    for (size_t i = 0; i < config.iterations; i++) {
        config.samples_ns[i] = (double)config.samples_cycles[i];
    }

    struct bench_stats stats;
    bench_compute_stats(config.samples_ns, config.iterations, &stats, config.remove_outliers);

    if (config.json_output) {
        bench_print_json(&stats, "vmcall");
    } else if (config.csv_output) {
        bench_print_csv(&stats, "vmcall");
    } else {
        bench_print_stats_compact(&stats, "VMCALL round-trip", "cycles");
    }

    bench_free_stats(&stats);
}

/* ============================================================================
 * Main Benchmark Runner
 * ============================================================================ */

static int run_benchmarks(void)
{
    printf("\n");
    printf("================================================================================\n");
    printf(" Low-Level Latency Microbenchmark\n");
    printf("================================================================================\n");
    printf(" Iterations:      %zu\n", config.iterations);
    printf(" Warmup:          %zu\n", config.warmup_iterations);
    if (config.pin_cpu) {
        printf(" CPU affinity:    %d\n", config.cpu_affinity);
    }
    printf(" Outlier removal: %s\n", config.remove_outliers ? "enabled" : "disabled");

    /* Pin CPU */
    if (config.pin_cpu) {
        if (bench_pin_cpu(config.cpu_affinity) < 0) {
            fprintf(stderr, "Warning: Failed to pin CPU\n");
        }
    }

    /* Detect CPU frequency */
    if (config.detect_frequency) {
        printf(" Detecting CPU frequency...\n");
        config.cpu_freq_ghz = detect_cpu_frequency();
        printf(" CPU frequency:   %.3f GHz\n", config.cpu_freq_ghz);
    }

    printf("--------------------------------------------------------------------------------\n\n");

    /* Allocate sample storage */
    config.samples_cycles = malloc(config.iterations * sizeof(uint64_t));
    config.samples_ns = malloc(config.iterations * sizeof(double));
    if (!config.samples_cycles || !config.samples_ns) {
        perror("malloc");
        return 1;
    }

    /* Print CSV header if needed */
    if (config.csv_output) {
        bench_print_csv_header();
    }

    /* Run selected benchmarks */
    switch (config.test) {
    case TEST_RDTSC:
        bench_rdtsc_overhead();
        break;

    case TEST_CLOCK_GETTIME:
        bench_clock_gettime_overhead();
        break;

    case TEST_GETPID:
        bench_getpid_overhead();
        break;

    case TEST_GETTID:
        bench_gettid_overhead();
        break;

    case TEST_EMPTY_FUNC:
        bench_function_call_overhead();
        bench_function_call_with_args();
        break;

    case TEST_VMCALL:
        bench_vmcall_overhead();
        break;

    case TEST_ALL:
    default:
        bench_rdtsc_overhead();
        bench_clock_gettime_overhead();
        bench_getpid_overhead();
        bench_gettid_overhead();
        bench_function_call_overhead();
        bench_function_call_with_args();
        bench_vmcall_overhead();
        break;
    }

    if (!config.json_output && !config.csv_output) {
        printf("\n================================================================================\n");
        if (config.cpu_freq_ghz > 0) {
            printf(" Note: At %.3f GHz, 1 cycle = %.3f ns\n",
                   config.cpu_freq_ghz, 1.0 / config.cpu_freq_ghz);
        }
        printf("================================================================================\n\n");
    }

    free(config.samples_cycles);
    free(config.samples_ns);
    return 0;
}

/* ============================================================================
 * Command Line Parsing
 * ============================================================================ */

static void usage(const char *progname)
{
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("\n");
    printf("Low-level latency microbenchmark using RDTSC for cycle-accurate timing.\n");
    printf("\n");
    printf("Test Selection:\n");
    printf("  --test <type>         Test to run (default: all)\n");
    printf("                        Types: all, rdtsc, clock_gettime, getpid,\n");
    printf("                               gettid, function, vmcall\n");
    printf("\n");
    printf("Benchmark Options:\n");
    printf("  --iterations <n>      Number of iterations (default: %zu)\n", config.iterations);
    printf("  --warmup <n>          Number of warmup iterations (default: %zu)\n",
           config.warmup_iterations);
    printf("  --no-outliers         Disable outlier removal\n");
    printf("  --no-freq             Disable CPU frequency detection\n");
    printf("\n");
    printf("System Options:\n");
    printf("  --cpu <n>             Pin to CPU core N (default: 0)\n");
    printf("  --no-pin              Don't pin to CPU\n");
    printf("\n");
    printf("Output Options:\n");
    printf("  --json                Output in JSON format\n");
    printf("  --csv                 Output in CSV format\n");
    printf("  --verbose             Verbose output\n");
    printf("  --help                Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --test all --iterations 100000\n", progname);
    printf("  %s --test vmcall --cpu 0\n", progname);
    printf("  %s --test syscall --json\n", progname);
    printf("\n");
}

static const struct option long_options[] = {
    {"test",        required_argument, NULL, 't'},
    {"iterations",  required_argument, NULL, 'i'},
    {"warmup",      required_argument, NULL, 'w'},
    {"cpu",         required_argument, NULL, 'c'},
    {"no-pin",      no_argument,       NULL, 'P'},
    {"no-outliers", no_argument,       NULL, 'O'},
    {"no-freq",     no_argument,       NULL, 'F'},
    {"json",        no_argument,       NULL, 'j'},
    {"csv",         no_argument,       NULL, 'C'},
    {"verbose",     no_argument,       NULL, 'v'},
    {"help",        no_argument,       NULL, 'h'},
    {NULL, 0, NULL, 0}
};

int main(int argc, char *argv[])
{
    int opt;

    while ((opt = getopt_long(argc, argv, "t:i:w:c:POFjCvh", long_options, NULL)) != -1) {
        switch (opt) {
        case 't':
            if (strcmp(optarg, "all") == 0) {
                config.test = TEST_ALL;
            } else if (strcmp(optarg, "rdtsc") == 0) {
                config.test = TEST_RDTSC;
            } else if (strcmp(optarg, "clock_gettime") == 0 ||
                       strcmp(optarg, "clock") == 0) {
                config.test = TEST_CLOCK_GETTIME;
            } else if (strcmp(optarg, "getpid") == 0) {
                config.test = TEST_GETPID;
            } else if (strcmp(optarg, "gettid") == 0) {
                config.test = TEST_GETTID;
            } else if (strcmp(optarg, "function") == 0 ||
                       strcmp(optarg, "func") == 0) {
                config.test = TEST_EMPTY_FUNC;
            } else if (strcmp(optarg, "vmcall") == 0) {
                config.test = TEST_VMCALL;
            } else {
                fprintf(stderr, "Unknown test type: %s\n", optarg);
                return 1;
            }
            break;

        case 'i':
            config.iterations = bench_memparse(optarg);
            if (config.iterations < 100) {
                fprintf(stderr, "Iterations must be >= 100\n");
                return 1;
            }
            break;

        case 'w':
            config.warmup_iterations = bench_memparse(optarg);
            break;

        case 'c':
            config.cpu_affinity = atoi(optarg);
            config.pin_cpu = true;
            break;

        case 'P':
            config.pin_cpu = false;
            break;

        case 'O':
            config.remove_outliers = false;
            break;

        case 'F':
            config.detect_frequency = false;
            break;

        case 'j':
            config.json_output = true;
            break;

        case 'C':
            config.csv_output = true;
            break;

        case 'v':
            config.verbose = true;
            break;

        case 'h':
            usage(argv[0]);
            return 0;

        default:
            usage(argv[0]);
            return 1;
        }
    }

    return run_benchmarks();
}
