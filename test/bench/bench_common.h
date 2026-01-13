/* SPDX-License-Identifier: MPL-2.0 */
/*
 * bench_common.h - Unified Benchmark Framework
 *
 * A rigorous benchmarking library inspired by Linux vsock_perf.c and
 * academic benchmarking best practices.
 *
 * Features:
 *   - Proper warmup with verification
 *   - Statistical analysis (mean, stddev, variance, percentiles, CI)
 *   - Outlier detection and removal (IQR method)
 *   - CPU affinity pinning
 *   - Memory-aligned buffers
 *   - High-resolution timing with serialization
 *   - Configurable via command-line or compile-time
 *
 * Copyright (C) 2024 Asterinas Developers.
 */

#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <errno.h>
#include <sched.h>
#include <sys/mman.h>
#include <getopt.h>

/* ============================================================================
 * Configuration Constants
 * ============================================================================ */

#define BENCH_VERSION               "1.0.0"

/* Default benchmark parameters */
#define BENCH_DEFAULT_ITERATIONS    10000
#define BENCH_DEFAULT_WARMUP        1000
#define BENCH_DEFAULT_MSG_SIZE      64
#define BENCH_DEFAULT_BUF_SIZE      (128 * 1024)    /* 128 KB */
#define BENCH_DEFAULT_TOTAL_BYTES   (64 * 1024 * 1024ULL)  /* 64 MB */
#define BENCH_DEFAULT_PORT          20000

/* Limits */
#define BENCH_MAX_ITERATIONS        1000000
#define BENCH_MAX_SAMPLES           1000000
#define BENCH_MIN_ITERATIONS        100

/* Time constants */
#define NSEC_PER_SEC                1000000000ULL
#define NSEC_PER_MSEC               1000000ULL
#define NSEC_PER_USEC               1000ULL
#define USEC_PER_SEC                1000000ULL

/* Confidence interval Z-scores */
#define Z_90                        1.645
#define Z_95                        1.960
#define Z_99                        2.576

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * struct bench_stats - Statistical summary of benchmark results
 */
struct bench_stats {
    /* Basic statistics */
    double min;
    double max;
    double mean;
    double median;          /* P50 */
    double stddev;
    double variance;

    /* Percentiles */
    double p1;
    double p5;
    double p10;
    double p25;             /* Q1 */
    double p75;             /* Q3 */
    double p90;
    double p95;
    double p99;
    double p999;

    /* Confidence intervals (95%) */
    double ci_lower;
    double ci_upper;
    double margin_of_error;

    /* Data quality */
    size_t n_samples;
    size_t n_outliers;
    double iqr;             /* Interquartile range */

    /* Raw data reference */
    double *samples;
    size_t n_raw_samples;
};

/**
 * struct bench_config - Benchmark configuration
 */
struct bench_config {
    /* Test parameters */
    size_t iterations;
    size_t warmup_iterations;
    size_t msg_size;
    size_t buf_size;
    uint64_t total_bytes;

    /* Network parameters */
    unsigned int port;
    unsigned int target_cid;
    int socket_fd;

    /* CPU affinity */
    int cpu_affinity;
    bool pin_cpu;

    /* Output options */
    bool verbose;
    bool json_output;
    bool csv_output;
    bool remove_outliers;

    /* Timing */
    clockid_t clock_id;

    /* Internal state */
    double *samples;
    size_t sample_capacity;
    size_t sample_count;
};

/**
 * struct bench_timer - High-resolution timer state
 */
struct bench_timer {
    struct timespec start;
    struct timespec end;
    clockid_t clock_id;
};

/* ============================================================================
 * Inline Timing Functions
 * ============================================================================ */

/**
 * bench_gettime_ns - Get current time in nanoseconds
 */
static inline uint64_t bench_gettime_ns(clockid_t clock_id)
{
    struct timespec ts;
    clock_gettime(clock_id, &ts);
    return (uint64_t)ts.tv_sec * NSEC_PER_SEC + (uint64_t)ts.tv_nsec;
}

/**
 * bench_timer_start - Start high-resolution timer
 */
static inline void bench_timer_start(struct bench_timer *timer, clockid_t clock_id)
{
    timer->clock_id = clock_id;
    clock_gettime(clock_id, &timer->start);
}

/**
 * bench_timer_stop - Stop timer and return elapsed nanoseconds
 */
static inline uint64_t bench_timer_stop(struct bench_timer *timer)
{
    clock_gettime(timer->clock_id, &timer->end);
    return (uint64_t)(timer->end.tv_sec - timer->start.tv_sec) * NSEC_PER_SEC +
           (uint64_t)(timer->end.tv_nsec - timer->start.tv_nsec);
}

/**
 * bench_rdtsc - Read CPU timestamp counter (x86)
 */
static inline uint64_t bench_rdtsc(void)
{
#if defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return bench_gettime_ns(CLOCK_MONOTONIC);
#endif
}

/**
 * bench_rdtscp - Read CPU timestamp counter with serialization (x86)
 */
static inline uint64_t bench_rdtscp(void)
{
#if defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi;
    __asm__ volatile ("rdtscp" : "=a"(lo), "=d"(hi) : : "ecx");
    return ((uint64_t)hi << 32) | lo;
#else
    return bench_gettime_ns(CLOCK_MONOTONIC);
#endif
}

/**
 * bench_serialize - Memory and instruction barrier for accurate timing
 */
static inline void bench_serialize(void)
{
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile ("mfence; lfence" ::: "memory");
#else
    __sync_synchronize();
#endif
}

/* ============================================================================
 * Comparison Functions for qsort
 * ============================================================================ */

static int compare_double(const void *a, const void *b)
{
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

static int compare_uint64(const void *a, const void *b)
{
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    return (ua > ub) - (ua < ub);
}

/* ============================================================================
 * Statistical Functions
 * ============================================================================ */

/**
 * bench_percentile - Calculate percentile from sorted array
 * @sorted: Sorted array of samples
 * @n: Number of samples
 * @p: Percentile (0.0 to 1.0)
 *
 * Uses linear interpolation between nearest ranks.
 */
static inline double bench_percentile(const double *sorted, size_t n, double p)
{
    if (n == 0) return 0.0;
    if (n == 1) return sorted[0];
    if (p <= 0.0) return sorted[0];
    if (p >= 1.0) return sorted[n - 1];

    double rank = p * (n - 1);
    size_t lower = (size_t)rank;
    size_t upper = lower + 1;
    double frac = rank - lower;

    if (upper >= n) return sorted[n - 1];
    return sorted[lower] * (1.0 - frac) + sorted[upper] * frac;
}

/**
 * bench_mean - Calculate arithmetic mean
 */
static inline double bench_mean(const double *samples, size_t n)
{
    if (n == 0) return 0.0;

    double sum = 0.0;
    for (size_t i = 0; i < n; i++) {
        sum += samples[i];
    }
    return sum / n;
}

/**
 * bench_variance - Calculate sample variance
 */
static inline double bench_variance(const double *samples, size_t n, double mean)
{
    if (n < 2) return 0.0;

    double sum_sq = 0.0;
    for (size_t i = 0; i < n; i++) {
        double diff = samples[i] - mean;
        sum_sq += diff * diff;
    }
    return sum_sq / (n - 1);  /* Bessel's correction */
}

/**
 * bench_stddev - Calculate sample standard deviation
 */
static inline double bench_stddev(const double *samples, size_t n, double mean)
{
    return sqrt(bench_variance(samples, n, mean));
}

/**
 * bench_remove_outliers_iqr - Remove outliers using IQR method
 * @samples: Input samples (will be sorted in place)
 * @n: Number of input samples
 * @output: Output buffer for filtered samples
 * @n_outliers: Output parameter for number of outliers removed
 * @multiplier: IQR multiplier (typically 1.5 for mild, 3.0 for extreme)
 *
 * Returns: Number of samples after outlier removal
 *
 * The IQR method marks values as outliers if they are:
 *   - Below Q1 - multiplier * IQR
 *   - Above Q3 + multiplier * IQR
 */
static inline size_t bench_remove_outliers_iqr(
    double *samples, size_t n, double *output, size_t *n_outliers, double multiplier)
{
    if (n < 4) {
        memcpy(output, samples, n * sizeof(double));
        if (n_outliers) *n_outliers = 0;
        return n;
    }

    /* Sort samples */
    qsort(samples, n, sizeof(double), compare_double);

    /* Calculate Q1, Q3, IQR */
    double q1 = bench_percentile(samples, n, 0.25);
    double q3 = bench_percentile(samples, n, 0.75);
    double iqr = q3 - q1;
    double lower_fence = q1 - multiplier * iqr;
    double upper_fence = q3 + multiplier * iqr;

    /* Filter outliers */
    size_t out_count = 0;
    for (size_t i = 0; i < n; i++) {
        if (samples[i] >= lower_fence && samples[i] <= upper_fence) {
            output[out_count++] = samples[i];
        }
    }

    if (n_outliers) *n_outliers = n - out_count;
    return out_count;
}

/**
 * bench_compute_stats - Compute comprehensive statistics
 * @samples: Raw sample array
 * @n: Number of samples
 * @stats: Output statistics structure
 * @remove_outliers: Whether to remove outliers before computing stats
 *
 * Returns: 0 on success, -1 on error
 */
static inline int bench_compute_stats(
    double *samples, size_t n, struct bench_stats *stats, bool remove_outliers)
{
    if (n == 0 || !samples || !stats) {
        return -1;
    }

    memset(stats, 0, sizeof(*stats));
    stats->n_raw_samples = n;

    /* Allocate working buffer */
    double *working = malloc(n * sizeof(double));
    if (!working) {
        return -1;
    }
    memcpy(working, samples, n * sizeof(double));

    double *data = working;
    size_t count = n;

    /* Optionally remove outliers */
    if (remove_outliers && n >= 4) {
        double *filtered = malloc(n * sizeof(double));
        if (filtered) {
            count = bench_remove_outliers_iqr(working, n, filtered, &stats->n_outliers, 1.5);
            free(working);
            working = filtered;
            data = filtered;
        }
    }

    stats->n_samples = count;
    stats->samples = data;

    /* Sort for percentile calculations */
    qsort(data, count, sizeof(double), compare_double);

    /* Basic statistics */
    stats->min = data[0];
    stats->max = data[count - 1];
    stats->mean = bench_mean(data, count);
    stats->median = bench_percentile(data, count, 0.50);
    stats->variance = bench_variance(data, count, stats->mean);
    stats->stddev = sqrt(stats->variance);

    /* Percentiles */
    stats->p1 = bench_percentile(data, count, 0.01);
    stats->p5 = bench_percentile(data, count, 0.05);
    stats->p10 = bench_percentile(data, count, 0.10);
    stats->p25 = bench_percentile(data, count, 0.25);
    stats->p75 = bench_percentile(data, count, 0.75);
    stats->p90 = bench_percentile(data, count, 0.90);
    stats->p95 = bench_percentile(data, count, 0.95);
    stats->p99 = bench_percentile(data, count, 0.99);
    stats->p999 = bench_percentile(data, count, 0.999);

    /* IQR */
    stats->iqr = stats->p75 - stats->p25;

    /* 95% Confidence Interval */
    double se = stats->stddev / sqrt(count);  /* Standard error */
    stats->margin_of_error = Z_95 * se;
    stats->ci_lower = stats->mean - stats->margin_of_error;
    stats->ci_upper = stats->mean + stats->margin_of_error;

    return 0;
}

/**
 * bench_free_stats - Free statistics structure resources
 */
static inline void bench_free_stats(struct bench_stats *stats)
{
    if (stats && stats->samples) {
        free(stats->samples);
        stats->samples = NULL;
    }
}

/* ============================================================================
 * Output Functions
 * ============================================================================ */

/**
 * bench_print_stats - Print statistics to stdout
 */
static inline void bench_print_stats(const struct bench_stats *stats,
                                     const char *name, const char *unit)
{
    printf("\n");
    printf("================================================================================\n");
    printf(" %s Statistics\n", name);
    printf("================================================================================\n");
    printf(" Samples:      %zu", stats->n_samples);
    if (stats->n_outliers > 0) {
        printf(" (%zu outliers removed)", stats->n_outliers);
    }
    printf("\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("                          Value          Unit\n");
    printf("--------------------------------------------------------------------------------\n");
    printf("   Min:           %14.3f    %s\n", stats->min, unit);
    printf("   Max:           %14.3f    %s\n", stats->max, unit);
    printf("   Mean:          %14.3f    %s\n", stats->mean, unit);
    printf("   Median (P50):  %14.3f    %s\n", stats->median, unit);
    printf("   Std Dev:       %14.3f    %s\n", stats->stddev, unit);
    printf("--------------------------------------------------------------------------------\n");
    printf(" Percentiles:\n");
    printf("   P1:            %14.3f    %s\n", stats->p1, unit);
    printf("   P5:            %14.3f    %s\n", stats->p5, unit);
    printf("   P10:           %14.3f    %s\n", stats->p10, unit);
    printf("   P25 (Q1):      %14.3f    %s\n", stats->p25, unit);
    printf("   P75 (Q3):      %14.3f    %s\n", stats->p75, unit);
    printf("   P90:           %14.3f    %s\n", stats->p90, unit);
    printf("   P95:           %14.3f    %s\n", stats->p95, unit);
    printf("   P99:           %14.3f    %s\n", stats->p99, unit);
    printf("   P99.9:         %14.3f    %s\n", stats->p999, unit);
    printf("--------------------------------------------------------------------------------\n");
    printf(" 95%% Confidence Interval:\n");
    printf("   Mean:          %14.3f    %s\n", stats->mean, unit);
    printf("   CI:            [%.3f, %.3f] %s\n", stats->ci_lower, stats->ci_upper, unit);
    printf("   Margin:        +/- %.3f %s\n", stats->margin_of_error, unit);
    printf("================================================================================\n\n");
}

/**
 * bench_print_stats_compact - Print compact one-line statistics
 */
static inline void bench_print_stats_compact(const struct bench_stats *stats,
                                              const char *name, const char *unit)
{
    printf("%-20s  min=%8.2f  mean=%8.2f  p50=%8.2f  p99=%8.2f  stddev=%8.2f  %s  (n=%zu)\n",
           name, stats->min, stats->mean, stats->median, stats->p99, stats->stddev, unit, stats->n_samples);
}

/**
 * bench_print_json - Print statistics in JSON format
 */
static inline void bench_print_json(const struct bench_stats *stats, const char *name)
{
    printf("{\n");
    printf("  \"benchmark\": \"%s\",\n", name);
    printf("  \"samples\": %zu,\n", stats->n_samples);
    printf("  \"outliers_removed\": %zu,\n", stats->n_outliers);
    printf("  \"min\": %.6f,\n", stats->min);
    printf("  \"max\": %.6f,\n", stats->max);
    printf("  \"mean\": %.6f,\n", stats->mean);
    printf("  \"median\": %.6f,\n", stats->median);
    printf("  \"stddev\": %.6f,\n", stats->stddev);
    printf("  \"variance\": %.6f,\n", stats->variance);
    printf("  \"percentiles\": {\n");
    printf("    \"p1\": %.6f,\n", stats->p1);
    printf("    \"p5\": %.6f,\n", stats->p5);
    printf("    \"p10\": %.6f,\n", stats->p10);
    printf("    \"p25\": %.6f,\n", stats->p25);
    printf("    \"p50\": %.6f,\n", stats->median);
    printf("    \"p75\": %.6f,\n", stats->p75);
    printf("    \"p90\": %.6f,\n", stats->p90);
    printf("    \"p95\": %.6f,\n", stats->p95);
    printf("    \"p99\": %.6f,\n", stats->p99);
    printf("    \"p999\": %.6f\n", stats->p999);
    printf("  },\n");
    printf("  \"confidence_interval_95\": {\n");
    printf("    \"lower\": %.6f,\n", stats->ci_lower);
    printf("    \"upper\": %.6f,\n", stats->ci_upper);
    printf("    \"margin_of_error\": %.6f\n", stats->margin_of_error);
    printf("  }\n");
    printf("}\n");
}

/**
 * bench_print_csv_header - Print CSV header
 */
static inline void bench_print_csv_header(void)
{
    printf("benchmark,samples,outliers,min,max,mean,median,stddev,p1,p5,p10,p25,p75,p90,p95,p99,p999,ci_lower,ci_upper\n");
}

/**
 * bench_print_csv - Print statistics as CSV row
 */
static inline void bench_print_csv(const struct bench_stats *stats, const char *name)
{
    printf("%s,%zu,%zu,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f\n",
           name, stats->n_samples, stats->n_outliers,
           stats->min, stats->max, stats->mean, stats->median, stats->stddev,
           stats->p1, stats->p5, stats->p10, stats->p25, stats->p75,
           stats->p90, stats->p95, stats->p99, stats->p999,
           stats->ci_lower, stats->ci_upper);
}

/* ============================================================================
 * System Utility Functions
 * ============================================================================ */

/**
 * bench_pin_cpu - Pin current thread to specific CPU core
 */
static inline int bench_pin_cpu(int cpu)
{
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
        perror("sched_setaffinity");
        return -1;
    }
    return 0;
#else
    (void)cpu;
    fprintf(stderr, "CPU pinning not supported on this platform\n");
    return -1;
#endif
}

/**
 * bench_alloc_aligned - Allocate page-aligned memory
 */
static inline void *bench_alloc_aligned(size_t size)
{
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        return NULL;
    }
    return ptr;
}

/**
 * bench_free_aligned - Free page-aligned memory
 */
static inline void bench_free_aligned(void *ptr, size_t size)
{
    if (ptr && ptr != MAP_FAILED) {
        munmap(ptr, size);
    }
}

/**
 * bench_memparse - Parse memory size with K/M/G suffix
 */
static inline uint64_t bench_memparse(const char *str)
{
    char *endptr;
    uint64_t value = strtoull(str, &endptr, 0);

    switch (*endptr) {
    case 'E': case 'e': value <<= 10; /* fall through */
    case 'P': case 'p': value <<= 10; /* fall through */
    case 'T': case 't': value <<= 10; /* fall through */
    case 'G': case 'g': value <<= 10; /* fall through */
    case 'M': case 'm': value <<= 10; /* fall through */
    case 'K': case 'k': value <<= 10; break;
    }

    return value;
}

/* ============================================================================
 * Configuration and Initialization
 * ============================================================================ */

/**
 * bench_config_init - Initialize configuration with defaults
 */
static inline void bench_config_init(struct bench_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->iterations = BENCH_DEFAULT_ITERATIONS;
    cfg->warmup_iterations = BENCH_DEFAULT_WARMUP;
    cfg->msg_size = BENCH_DEFAULT_MSG_SIZE;
    cfg->buf_size = BENCH_DEFAULT_BUF_SIZE;
    cfg->total_bytes = BENCH_DEFAULT_TOTAL_BYTES;
    cfg->port = BENCH_DEFAULT_PORT;
    cfg->clock_id = CLOCK_MONOTONIC;
    cfg->cpu_affinity = -1;
    cfg->remove_outliers = true;
}

/**
 * bench_config_alloc_samples - Allocate sample storage
 */
static inline int bench_config_alloc_samples(struct bench_config *cfg, size_t capacity)
{
    cfg->samples = malloc(capacity * sizeof(double));
    if (!cfg->samples) {
        return -1;
    }
    cfg->sample_capacity = capacity;
    cfg->sample_count = 0;
    return 0;
}

/**
 * bench_config_free - Free configuration resources
 */
static inline void bench_config_free(struct bench_config *cfg)
{
    if (cfg->samples) {
        free(cfg->samples);
        cfg->samples = NULL;
    }
}

/**
 * bench_record_sample - Record a sample
 */
static inline void bench_record_sample(struct bench_config *cfg, double value)
{
    if (cfg->sample_count < cfg->sample_capacity) {
        cfg->samples[cfg->sample_count++] = value;
    }
}

/* ============================================================================
 * Throughput Utilities
 * ============================================================================ */

/**
 * bench_calc_throughput_gbps - Calculate throughput in Gbits/s
 */
static inline double bench_calc_throughput_gbps(uint64_t bytes, uint64_t ns)
{
    if (ns == 0) return 0.0;
    return ((double)bytes * 8.0 / 1e9) / ((double)ns / 1e9);
}

/**
 * bench_calc_throughput_mbps - Calculate throughput in Mbits/s
 */
static inline double bench_calc_throughput_mbps(uint64_t bytes, uint64_t ns)
{
    if (ns == 0) return 0.0;
    return ((double)bytes * 8.0 / 1e6) / ((double)ns / 1e9);
}

/**
 * bench_format_bytes - Format bytes with appropriate unit
 */
static inline const char *bench_format_bytes(uint64_t bytes, char *buf, size_t buflen)
{
    if (bytes >= 1ULL << 30) {
        snprintf(buf, buflen, "%.2f GB", (double)bytes / (1ULL << 30));
    } else if (bytes >= 1ULL << 20) {
        snprintf(buf, buflen, "%.2f MB", (double)bytes / (1ULL << 20));
    } else if (bytes >= 1ULL << 10) {
        snprintf(buf, buflen, "%.2f KB", (double)bytes / (1ULL << 10));
    } else {
        snprintf(buf, buflen, "%lu B", (unsigned long)bytes);
    }
    return buf;
}

/**
 * bench_format_time - Format time with appropriate unit
 */
static inline const char *bench_format_time(double ns, char *buf, size_t buflen)
{
    if (ns >= 1e9) {
        snprintf(buf, buflen, "%.3f s", ns / 1e9);
    } else if (ns >= 1e6) {
        snprintf(buf, buflen, "%.3f ms", ns / 1e6);
    } else if (ns >= 1e3) {
        snprintf(buf, buflen, "%.3f us", ns / 1e3);
    } else {
        snprintf(buf, buflen, "%.3f ns", ns);
    }
    return buf;
}

/* ============================================================================
 * Warmup Verification
 * ============================================================================ */

/**
 * bench_verify_warmup - Verify that warmup has stabilized measurements
 * @samples: Last N warmup samples
 * @n: Number of samples
 * @threshold: Maximum allowed coefficient of variation (e.g., 0.1 for 10%)
 *
 * Returns: true if warmup is sufficient, false if more warmup needed
 */
static inline bool bench_verify_warmup(const double *samples, size_t n, double threshold)
{
    if (n < 10) return false;

    double mean = bench_mean(samples, n);
    if (mean <= 0) return false;

    double sd = bench_stddev(samples, n, mean);
    double cv = sd / mean;  /* Coefficient of variation */

    return cv <= threshold;
}

/* ============================================================================
 * Progress Reporting
 * ============================================================================ */

/**
 * bench_progress - Print progress indicator
 */
static inline void bench_progress(size_t current, size_t total, const char *phase)
{
    static size_t last_percent = 0;
    size_t percent = (current * 100) / total;

    if (percent != last_percent && percent % 10 == 0) {
        fprintf(stderr, "\r[%s] %3zu%% complete", phase, percent);
        fflush(stderr);
        last_percent = percent;
    }

    if (current == total) {
        fprintf(stderr, "\r[%s] 100%% complete\n", phase);
        last_percent = 0;
    }
}

#endif /* BENCH_COMMON_H */
