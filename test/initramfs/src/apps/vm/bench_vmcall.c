/*
 * bench_vmcall.c - Direct VMCALL instruction benchmark
 *
 * Measures the raw VMCALL instruction cost using RDTSC.
 * Must be run inside a VM (KVM/QEMU).
 *
 * This measures: VM-EXIT + hypervisor handling + VM-ENTRY
 *
 * Compile: gcc -O2 bench_vmcall.c -o bench_vmcall
 * Run inside VM: ./bench_vmcall
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>

#define ITERATIONS 100000
#define WARMUP 10000

static uint64_t samples[ITERATIONS];
static jmp_buf jump_buffer;
static volatile int vmcall_supported = 1;

static void sigill_handler(int sig) {
    vmcall_supported = 0;
    longjmp(jump_buffer, 1);
}

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

/*
 * Inline assembly to measure VMCALL with minimal overhead:
 *
 *   rdtsc           ; start timestamp in EDX:EAX
 *   mov r8d, eax    ; save low bits
 *   mov r9d, edx    ; save high bits
 *   vmcall          ; VM-EXIT -> hypervisor -> VM-ENTRY
 *   rdtscp          ; end timestamp
 *   shl rdx, 32
 *   or rax, rdx     ; RAX = end timestamp
 *   shl r9, 32
 *   or r8, r9       ; R8 = start timestamp
 *   sub rax, r8     ; RAX = cycles
 */
static inline uint64_t measure_vmcall(void) {
    uint64_t cycles;
    __asm__ volatile (
        "rdtsc\n\t"
        "mov %%eax, %%r8d\n\t"
        "mov %%edx, %%r9d\n\t"
        ".byte 0x0f, 0x01, 0xc1\n\t"  /* vmcall */
        "rdtscp\n\t"
        "shl $32, %%rdx\n\t"
        "or %%rdx, %%rax\n\t"
        "shl $32, %%r9\n\t"
        "or %%r9, %%r8\n\t"
        "sub %%r8, %%rax\n\t"
        : "=a"(cycles)
        :
        : "rdx", "rcx", "r8", "r9", "memory"
    );
    return cycles;
}

static int compare_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

static void print_stats(const char *name, int count) {
    uint64_t total = 0, min = UINT64_MAX;
    for (int i = 0; i < count; i++) {
        total += samples[i];
        if (samples[i] < min) min = samples[i];
    }
    qsort(samples, count, sizeof(uint64_t), compare_u64);
    printf("  %-20s min=%5lu  avg=%5lu  p50=%5lu  p99=%5lu cycles\n",
           name, min, total/count, samples[count/2], samples[(int)(count*0.99)]);
}

int main(void) {
    printf("\n================================================\n");
    printf(" VMCALL Instruction Benchmark (raw RDTSC)\n");
    printf("================================================\n");
    printf(" Must run inside a VM (QEMU/KVM)\n");
    printf(" Iterations: %d  Warmup: %d\n", ITERATIONS, WARMUP);
    printf("------------------------------------------------\n\n");

    /* Test if VMCALL works */
    signal(SIGILL, sigill_handler);
    if (setjmp(jump_buffer) == 0) {
        __asm__ volatile (".byte 0x0f, 0x01, 0xc1" ::: "memory");
    }
    signal(SIGILL, SIG_DFL);

    if (!vmcall_supported) {
        printf("ERROR: VMCALL not supported (not running in a VM?)\n\n");
        return 1;
    }

    printf("VMCALL supported, starting benchmark...\n\n");

    /* Warmup */
    for (int i = 0; i < WARMUP; i++) {
        measure_vmcall();
    }

    /* Measure */
    for (int i = 0; i < ITERATIONS; i++) {
        samples[i] = measure_vmcall();
    }

    print_stats("VMCALL round-trip:", ITERATIONS);

    qsort(samples, ITERATIONS, sizeof(uint64_t), compare_u64);
    uint64_t p50 = samples[ITERATIONS / 2];
    printf("\n  This is VM-EXIT + hypervisor + VM-ENTRY total.\n");
    printf("  Estimated per-direction: ~%lu cycles each\n", p50 / 2);

    printf("\n================================================\n\n");
    return 0;
}
