/*
 * bench_isolation.c - Isolation Boundary Benchmark (Simple Version)
 *
 * Measures cycle cost using minimal overhead:
 * - RDTSC at start, RDTSCP at end (no extra serialization)
 * - Direct measurement without calibration
 *
 * Compile: gcc -O2 bench_isolation.c -o bench_isolation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define ITERATIONS 100000
#define WARMUP_ITERATIONS 10000

// ============================================================================
// Simple RDTSC measurement
// ============================================================================

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtscp(void) {
    uint32_t lo, hi;
    __asm__ volatile ("rdtscp" : "=a"(lo), "=d"(hi) : : "ecx");
    return ((uint64_t)hi << 32) | lo;
}

// ============================================================================
// VMCALL instruction
// ============================================================================

static inline void vmcall_nop(void) {
    __asm__ volatile (
        ".byte 0x0f, 0x01, 0xc1"  /* vmcall opcode */
        :
        : "a"(0), "b"(0), "c"(0), "d"(0)
        : "memory"
    );
}

// ============================================================================
// Statistics
// ============================================================================

static uint64_t samples[ITERATIONS];

static int compare_uint64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

static void print_stats(const char *name, int count) {
    uint64_t total = 0;
    uint64_t min = UINT64_MAX;
    uint64_t max = 0;

    for (int i = 0; i < count; i++) {
        total += samples[i];
        if (samples[i] < min) min = samples[i];
        if (samples[i] > max) max = samples[i];
    }

    uint64_t avg = total / count;

    qsort(samples, count, sizeof(uint64_t), compare_uint64);
    uint64_t p50 = samples[count / 2];
    uint64_t p90 = samples[(int)(count * 0.90)];
    uint64_t p99 = samples[(int)(count * 0.99)];

    printf("  %-28s min=%5lu  avg=%5lu  p50=%5lu  p90=%5lu  p99=%5lu cycles\n",
           name, min, avg, p50, p90, p99);
}

// ============================================================================
// Benchmarks
// ============================================================================

// RDTSC overhead (back-to-back RDTSC/RDTSCP)
static void bench_rdtsc_overhead(void) {
    // Warmup
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        uint64_t start = rdtsc();
        uint64_t end = rdtscp();
        (void)(end - start);
    }

    // Measure
    for (int i = 0; i < ITERATIONS; i++) {
        uint64_t start = rdtsc();
        uint64_t end = rdtscp();
        samples[i] = end - start;
    }

    print_stats("RDTSC overhead:", ITERATIONS);
}

// Empty function call
__attribute__((noinline))
static void empty_function(void) {
    __asm__ volatile ("" ::: "memory");
}

static void bench_function_call(void) {
    // Warmup
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        uint64_t start = rdtsc();
        empty_function();
        uint64_t end = rdtscp();
        (void)(end - start);
    }

    // Measure
    for (int i = 0; i < ITERATIONS; i++) {
        uint64_t start = rdtsc();
        empty_function();
        uint64_t end = rdtscp();
        samples[i] = end - start;
    }

    print_stats("Empty function call:", ITERATIONS);
}

// VMCALL round-trip (VM-EXIT + VM-ENTRY)
static void bench_vmcall(void) {
    printf("\nMeasuring VMCALL (VM-EXIT + VM-ENTRY round-trip)...\n");
    printf("  NOTE: Will cause 'Illegal instruction' if not inside a VM\n\n");

    // Warmup
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        uint64_t start = rdtsc();
        vmcall_nop();
        uint64_t end = rdtscp();
        (void)(end - start);
    }

    // Measure
    for (int i = 0; i < ITERATIONS; i++) {
        uint64_t start = rdtsc();
        vmcall_nop();
        uint64_t end = rdtscp();
        samples[i] = end - start;
    }

    print_stats("VMCALL round-trip:", ITERATIONS);

    // Calculate estimated one-way costs
    qsort(samples, ITERATIONS, sizeof(uint64_t), compare_uint64);
    uint64_t p50 = samples[ITERATIONS / 2];
    printf("\n  Estimated one-way costs (assuming symmetric):\n");
    printf("    VM-EXIT:  ~%lu cycles\n", p50 / 2);
    printf("    VM-ENTRY: ~%lu cycles\n", p50 / 2);
}

// ============================================================================
// Main
// ============================================================================

int main(void) {
    printf("\n");
    printf("================================================\n");
    printf(" Isolation Boundary Benchmark\n");
    printf("================================================\n");
    printf(" Iterations: %d  Warmup: %d\n", ITERATIONS, WARMUP_ITERATIONS);
    printf("------------------------------------------------\n\n");

    printf("Baseline measurements:\n");
    bench_rdtsc_overhead();
    bench_function_call();

    bench_vmcall();

    printf("\n================================================\n");
    printf(" Benchmark Complete\n");
    printf("================================================\n\n");

    return 0;
}
