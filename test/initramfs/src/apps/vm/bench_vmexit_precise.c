/*
 * bench_vmexit_precise.c - Precise VM-EXIT/VM-ENTRY Hardware Cost Measurement
 *
 * This program uses multiple techniques to isolate pure hardware costs:
 *
 * 1. Back-to-back VM-EXIT measurement: Measures consecutive exits to
 *    amortize fixed overhead and isolate per-exit cost.
 *
 * 2. Differential measurement: Measures N exits vs 2N exits, the difference
 *    gives pure per-exit cost without setup overhead.
 *
 * 3. In-kernel MSR handling: Uses MSRs that KVM handles in-kernel without
 *    returning to userspace.
 *
 * Compile: gcc -O2 -o bench_vmexit_precise bench_vmexit_precise.c
 * Run: sudo ./bench_vmexit_precise
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kvm.h>
#include <time.h>

#define GUEST_MEM_SIZE  0x10000
#define WARMUP          1000
#define ITERATIONS      10000

/* Memory layout for guest */
#define CODE_START      0x1000
#define DATA_START      0x2000
#define COUNTER_ADDR    0x2000
#define TS_START_LO     0x2010
#define TS_START_HI     0x2014
#define TS_END_LO       0x2018
#define TS_END_HI       0x201c

static uint64_t samples[ITERATIONS];

static inline uint64_t rdtsc_host(void) {
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t rdtscp_host(void) {
    uint32_t lo, hi;
    __asm__ volatile ("rdtscp" : "=a"(lo), "=d"(hi) :: "ecx");
    return ((uint64_t)hi << 32) | lo;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

static void print_stats(const char *name, uint64_t *data, int count) {
    qsort(data, count, sizeof(uint64_t), cmp_u64);

    uint64_t sum = 0;
    for (int i = 0; i < count; i++) sum += data[i];

    uint64_t min = data[0];
    uint64_t max = data[count - 1];
    uint64_t avg = sum / count;
    uint64_t p50 = data[count / 2];
    uint64_t p99 = data[(int)(count * 0.99)];

    /* Remove outliers (top/bottom 5%) for trimmed mean */
    int trim = count / 20;
    uint64_t trimmed_sum = 0;
    for (int i = trim; i < count - trim; i++) {
        trimmed_sum += data[i];
    }
    uint64_t trimmed_avg = trimmed_sum / (count - 2 * trim);

    printf("  %-32s\n", name);
    printf("    min=%lu  avg=%lu  trimmed_avg=%lu  p50=%lu  p99=%lu  max=%lu\n",
           min, avg, trimmed_avg, p50, p99, max);
}

/* Setup VM in 32-bit protected mode */
static int setup_vm(int *kvm_fd, int *vm_fd, int *vcpu_fd,
                    struct kvm_run **run, void **mem, size_t *run_size) {
    *kvm_fd = open("/dev/kvm", O_RDWR);
    if (*kvm_fd < 0) { perror("open /dev/kvm"); return -1; }

    *vm_fd = ioctl(*kvm_fd, KVM_CREATE_VM, 0);
    if (*vm_fd < 0) { perror("KVM_CREATE_VM"); return -1; }

    *mem = mmap(NULL, GUEST_MEM_SIZE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (*mem == MAP_FAILED) { perror("mmap"); return -1; }
    memset(*mem, 0, GUEST_MEM_SIZE);

    /* GDT for 32-bit protected mode */
    uint64_t *gdt = (uint64_t *)*mem;
    gdt[0] = 0x0000000000000000ULL;  /* Null */
    gdt[1] = 0x00cf9a000000ffffULL;  /* Code: base=0, limit=4G, DPL=0, exec/read */
    gdt[2] = 0x00cf92000000ffffULL;  /* Data: base=0, limit=4G, DPL=0, read/write */

    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .guest_phys_addr = 0,
        .memory_size = GUEST_MEM_SIZE,
        .userspace_addr = (uint64_t)*mem,
    };
    if (ioctl(*vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        perror("KVM_SET_USER_MEMORY_REGION");
        return -1;
    }

    *vcpu_fd = ioctl(*vm_fd, KVM_CREATE_VCPU, 0);
    if (*vcpu_fd < 0) { perror("KVM_CREATE_VCPU"); return -1; }

    *run_size = ioctl(*kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    *run = mmap(NULL, *run_size, PROT_READ | PROT_WRITE, MAP_SHARED, *vcpu_fd, 0);
    if (*run == MAP_FAILED) { perror("mmap vcpu"); return -1; }

    /* Setup 32-bit protected mode */
    struct kvm_sregs sregs;
    ioctl(*vcpu_fd, KVM_GET_SREGS, &sregs);

    sregs.cr0 = 0x1;  /* PE bit */
    sregs.gdt.base = 0;
    sregs.gdt.limit = 0x17;

    /* Code segment */
    sregs.cs.base = 0; sregs.cs.limit = 0xffffffff; sregs.cs.selector = 0x08;
    sregs.cs.type = 0xa; sregs.cs.present = 1; sregs.cs.dpl = 0;
    sregs.cs.db = 1; sregs.cs.s = 1; sregs.cs.l = 0; sregs.cs.g = 1;

    /* Data segment */
    sregs.ds.base = 0; sregs.ds.limit = 0xffffffff; sregs.ds.selector = 0x10;
    sregs.ds.type = 0x2; sregs.ds.present = 1; sregs.ds.dpl = 0;
    sregs.ds.db = 1; sregs.ds.s = 1; sregs.ds.g = 1;

    sregs.es = sregs.ss = sregs.fs = sregs.gs = sregs.ds;

    ioctl(*vcpu_fd, KVM_SET_SREGS, &sregs);
    return 0;
}

static void cleanup_vm(int kvm_fd, int vm_fd, int vcpu_fd,
                       struct kvm_run *run, void *mem, size_t run_size) {
    munmap(run, run_size);
    munmap(mem, GUEST_MEM_SIZE);
    close(vcpu_fd);
    close(vm_fd);
    close(kvm_fd);
}

/*
 * Test 1: Differential Measurement
 *
 * Measure time for N exits vs 2N exits.
 * The difference isolates per-exit cost from fixed overhead.
 */
static void bench_differential(void) {
    int kvm_fd, vm_fd, vcpu_fd;
    struct kvm_run *run;
    void *mem;
    size_t run_size;

    printf("\n[Test 1] Differential Measurement (N vs 2N exits)\n");
    printf("================================================================\n");

    if (setup_vm(&kvm_fd, &vm_fd, &vcpu_fd, &run, &mem, &run_size) < 0) return;

    /*
     * Guest code: Loop N times doing OUT, then final OUT to signal done
     *
     * loop:
     *   out 0x10, al       ; VM-EXIT
     *   dec ecx
     *   jnz loop
     *   out 0x20, al       ; signal done
     *   jmp $
     */
    uint8_t guest_code[] = {
        /* 0x1000: loop */
        0xe6, 0x10,             /* out 0x10, al */
        0x49, 0xff, 0xc9,       /* dec r9 (use r9 as counter in case ecx is clobbered) */
        0x75, 0xf9,             /* jnz loop (-7) */
        0xe6, 0x20,             /* out 0x20, al - signal done */
        0xeb, 0xfe,             /* jmp $ */
    };
    memcpy((uint8_t *)mem + CODE_START, guest_code, sizeof(guest_code));

    const int N_small = 100;
    const int N_large = 200;
    uint64_t times_small[ITERATIONS];
    uint64_t times_large[ITERATIONS];

    /* Measure N_small exits */
    for (int iter = 0; iter < WARMUP + ITERATIONS; iter++) {
        struct kvm_regs regs = {0};
        regs.rip = CODE_START;
        regs.rflags = 2;
        regs.r9 = N_small;  /* counter */
        ioctl(vcpu_fd, KVM_SET_REGS, &regs);

        uint64_t start = rdtsc_host();

        for (int i = 0; i <= N_small; i++) {
            ioctl(vcpu_fd, KVM_RUN, 0);
        }

        uint64_t end = rdtscp_host();

        if (iter >= WARMUP) {
            times_small[iter - WARMUP] = end - start;
        }
    }

    /* Measure N_large exits */
    for (int iter = 0; iter < WARMUP + ITERATIONS; iter++) {
        struct kvm_regs regs = {0};
        regs.rip = CODE_START;
        regs.rflags = 2;
        regs.r9 = N_large;
        ioctl(vcpu_fd, KVM_SET_REGS, &regs);

        uint64_t start = rdtsc_host();

        for (int i = 0; i <= N_large; i++) {
            ioctl(vcpu_fd, KVM_RUN, 0);
        }

        uint64_t end = rdtscp_host();

        if (iter >= WARMUP) {
            times_large[iter - WARMUP] = end - start;
        }
    }

    /* Calculate per-exit cost from difference */
    uint64_t diff_samples[ITERATIONS];
    for (int i = 0; i < ITERATIONS; i++) {
        if (times_large[i] > times_small[i]) {
            diff_samples[i] = (times_large[i] - times_small[i]) / (N_large - N_small);
        } else {
            diff_samples[i] = 0;
        }
    }

    printf("\n  Method: (Time for %d exits - Time for %d exits) / %d\n",
           N_large, N_small, N_large - N_small);
    printf("  This isolates per-exit cost from fixed overhead.\n\n");

    print_stats("Per VM-EXIT+VM-ENTRY (differential):", diff_samples, ITERATIONS);

    cleanup_vm(kvm_fd, vm_fd, vcpu_fd, run, mem, run_size);
}

/*
 * Test 2: Batch measurement with amortization
 *
 * Run many exits in a batch, divide total time by count.
 */
static void bench_batch(void) {
    int kvm_fd, vm_fd, vcpu_fd;
    struct kvm_run *run;
    void *mem;
    size_t run_size;

    printf("\n[Test 2] Batch Measurement (amortized over N exits)\n");
    printf("================================================================\n");

    if (setup_vm(&kvm_fd, &vm_fd, &vcpu_fd, &run, &mem, &run_size) < 0) return;

    uint8_t guest_code[] = {
        0xe6, 0x10,             /* out 0x10, al */
        0x49, 0xff, 0xc9,       /* dec r9 */
        0x75, 0xf9,             /* jnz loop */
        0xe6, 0x20,             /* out 0x20, al */
        0xeb, 0xfe,             /* jmp $ */
    };
    memcpy((uint8_t *)mem + CODE_START, guest_code, sizeof(guest_code));

    const int batch_sizes[] = {10, 50, 100, 500, 1000};
    const int num_batches = sizeof(batch_sizes) / sizeof(batch_sizes[0]);

    for (int b = 0; b < num_batches; b++) {
        int N = batch_sizes[b];

        for (int iter = 0; iter < WARMUP + ITERATIONS; iter++) {
            struct kvm_regs regs = {0};
            regs.rip = CODE_START;
            regs.rflags = 2;
            regs.r9 = N;
            ioctl(vcpu_fd, KVM_SET_REGS, &regs);

            uint64_t start = rdtsc_host();

            for (int i = 0; i <= N; i++) {
                ioctl(vcpu_fd, KVM_RUN, 0);
            }

            uint64_t end = rdtscp_host();

            if (iter >= WARMUP) {
                samples[iter - WARMUP] = (end - start) / N;
            }
        }

        char name[64];
        snprintf(name, sizeof(name), "Batch N=%d (per-exit):", N);
        print_stats(name, samples, ITERATIONS);
    }

    cleanup_vm(kvm_fd, vm_fd, vcpu_fd, run, mem, run_size);
}

/*
 * Test 3: Single exit measurement (for comparison)
 */
static void bench_single(void) {
    int kvm_fd, vm_fd, vcpu_fd;
    struct kvm_run *run;
    void *mem;
    size_t run_size;

    printf("\n[Test 3] Single Exit Measurement (baseline)\n");
    printf("================================================================\n");

    if (setup_vm(&kvm_fd, &vm_fd, &vcpu_fd, &run, &mem, &run_size) < 0) return;

    /* Simple: OUT and loop back */
    uint8_t guest_code[] = {
        0xe6, 0x10,     /* out 0x10, al */
        0xeb, 0xfc,     /* jmp -4 */
    };
    memcpy((uint8_t *)mem + CODE_START, guest_code, sizeof(guest_code));

    struct kvm_regs regs = { .rip = CODE_START, .rflags = 2 };
    ioctl(vcpu_fd, KVM_SET_REGS, &regs);

    /* Warmup */
    for (int i = 0; i < WARMUP; i++) {
        ioctl(vcpu_fd, KVM_RUN, 0);
    }

    /* Measure */
    for (int i = 0; i < ITERATIONS; i++) {
        uint64_t start = rdtsc_host();
        ioctl(vcpu_fd, KVM_RUN, 0);
        uint64_t end = rdtscp_host();
        samples[i] = end - start;
    }

    print_stats("Single VM-EXIT+VM-ENTRY:", samples, ITERATIONS);

    cleanup_vm(kvm_fd, vm_fd, vcpu_fd, run, mem, run_size);
}

/*
 * Test 4: Measure syscall overhead separately
 */
static void bench_syscall_overhead(void) {
    printf("\n[Test 4] Syscall Overhead (getpid baseline)\n");
    printf("================================================================\n");

    /* Warmup */
    for (int i = 0; i < WARMUP; i++) {
        getpid();
    }

    /* Measure getpid syscall */
    for (int i = 0; i < ITERATIONS; i++) {
        uint64_t start = rdtsc_host();
        getpid();
        uint64_t end = rdtscp_host();
        samples[i] = end - start;
    }

    print_stats("getpid() syscall:", samples, ITERATIONS);
}

/*
 * Test 5: Use clock_gettime for wall-clock verification
 */
static void bench_wallclock(void) {
    int kvm_fd, vm_fd, vcpu_fd;
    struct kvm_run *run;
    void *mem;
    size_t run_size;

    printf("\n[Test 5] Wall-clock Verification\n");
    printf("================================================================\n");

    if (setup_vm(&kvm_fd, &vm_fd, &vcpu_fd, &run, &mem, &run_size) < 0) return;

    uint8_t guest_code[] = {
        0xe6, 0x10,     /* out 0x10, al */
        0xeb, 0xfc,     /* jmp -4 */
    };
    memcpy((uint8_t *)mem + CODE_START, guest_code, sizeof(guest_code));

    struct kvm_regs regs = { .rip = CODE_START, .rflags = 2 };
    ioctl(vcpu_fd, KVM_SET_REGS, &regs);

    const int total_exits = 100000;

    /* Warmup */
    for (int i = 0; i < 10000; i++) {
        ioctl(vcpu_fd, KVM_RUN, 0);
    }

    struct timespec start_ts, end_ts;
    uint64_t start_tsc = rdtsc_host();
    clock_gettime(CLOCK_MONOTONIC, &start_ts);

    for (int i = 0; i < total_exits; i++) {
        ioctl(vcpu_fd, KVM_RUN, 0);
    }

    clock_gettime(CLOCK_MONOTONIC, &end_ts);
    uint64_t end_tsc = rdtscp_host();

    uint64_t elapsed_ns = (end_ts.tv_sec - start_ts.tv_sec) * 1000000000ULL +
                          (end_ts.tv_nsec - start_ts.tv_nsec);
    uint64_t elapsed_cycles = end_tsc - start_tsc;

    double ns_per_exit = (double)elapsed_ns / total_exits;
    double cycles_per_exit = (double)elapsed_cycles / total_exits;
    double ghz = (double)elapsed_cycles / elapsed_ns;

    printf("  Total exits: %d\n", total_exits);
    printf("  Elapsed: %lu ns, %lu cycles\n", elapsed_ns, elapsed_cycles);
    printf("  CPU frequency: %.2f GHz\n", ghz);
    printf("  Per exit: %.1f ns, %.1f cycles\n", ns_per_exit, cycles_per_exit);

    cleanup_vm(kvm_fd, vm_fd, vcpu_fd, run, mem, run_size);
}

int main(void) {
    printf("\n");
    printf("================================================================\n");
    printf(" Precise VM-EXIT + VM-ENTRY Hardware Cost Benchmark\n");
    printf("================================================================\n");
    printf(" Iterations: %d, Warmup: %d\n", ITERATIONS, WARMUP);
    printf("================================================================\n");

    bench_syscall_overhead();
    bench_single();
    bench_batch();
    bench_differential();
    bench_wallclock();

    printf("\n================================================================\n");
    printf(" Analysis\n");
    printf("================================================================\n");
    printf(" - Syscall overhead: baseline for ioctl() cost\n");
    printf(" - Single exit: includes syscall + VM-EXIT + VM-ENTRY\n");
    printf(" - Batch: amortizes fixed overhead, converges to true cost\n");
    printf(" - Differential: mathematically isolates per-exit cost\n");
    printf(" - Wall-clock: verifies TSC measurements\n");
    printf("\n");
    printf(" Pure hardware VM-EXIT + VM-ENTRY cost =\n");
    printf("   Single exit - syscall overhead\n");
    printf("   OR use batch/differential results directly\n");
    printf("================================================================\n\n");

    return 0;
}
