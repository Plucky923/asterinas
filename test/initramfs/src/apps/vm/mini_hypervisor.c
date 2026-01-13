/*
 * mini_hypervisor.c - VM-EXIT/VM-ENTRY Hardware Cost Benchmark
 *
 * Measures pure hardware VM-EXIT + VM-ENTRY cost using multiple methods:
 * 1. CPUID - causes VM-EXIT, KVM emulates and returns
 * 2. I/O Port - causes VM-EXIT, minimal KVM handling
 * 3. RDMSR - causes VM-EXIT for certain MSRs
 *
 * Compile: gcc -O2 mini_hypervisor.c -o mini_hypervisor
 * Run: sudo ./mini_hypervisor
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

#define ITERATIONS 100000
#define WARMUP_ITERATIONS 10000
#define GUEST_MEM_SIZE 0x10000

#define TS_BEFORE  0x2000
#define TS_AFTER   0x2008

static uint64_t samples[ITERATIONS];

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
    printf("  %-28s min=%5lu  avg=%5lu  p50=%5lu  p99=%5lu cycles\n",
           name, min, total/count, samples[count/2], samples[(int)(count*0.99)]);
}

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
    gdt[0] = 0x0000000000000000ULL;
    gdt[1] = 0x00cf9a000000ffffULL;  /* Code */
    gdt[2] = 0x00cf92000000ffffULL;  /* Data */

    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .guest_phys_addr = 0,
        .memory_size = GUEST_MEM_SIZE,
        .userspace_addr = (uint64_t)*mem,
    };
    ioctl(*vm_fd, KVM_SET_USER_MEMORY_REGION, &region);

    *vcpu_fd = ioctl(*vm_fd, KVM_CREATE_VCPU, 0);
    if (*vcpu_fd < 0) { perror("KVM_CREATE_VCPU"); return -1; }

    *run_size = ioctl(*kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    *run = mmap(NULL, *run_size, PROT_READ | PROT_WRITE, MAP_SHARED, *vcpu_fd, 0);

    /* Setup 32-bit protected mode */
    struct kvm_sregs sregs;
    ioctl(*vcpu_fd, KVM_GET_SREGS, &sregs);
    sregs.cr0 = 0x1;
    sregs.gdt.base = 0;
    sregs.gdt.limit = 0x17;

    sregs.cs.base = 0; sregs.cs.limit = 0xffffffff; sregs.cs.selector = 0x08;
    sregs.cs.type = 0xa; sregs.cs.present = 1; sregs.cs.dpl = 0;
    sregs.cs.db = 1; sregs.cs.s = 1; sregs.cs.l = 0; sregs.cs.g = 1;

    sregs.ds.base = 0; sregs.ds.limit = 0xffffffff; sregs.ds.selector = 0x10;
    sregs.ds.type = 0x2; sregs.ds.present = 1; sregs.ds.dpl = 0;
    sregs.ds.db = 1; sregs.ds.s = 1; sregs.ds.g = 1;

    sregs.es = sregs.ds; sregs.fs = sregs.ds;
    sregs.gs = sregs.ds; sregs.ss = sregs.ds;

    ioctl(*vcpu_fd, KVM_SET_SREGS, &sregs);
    return 0;
}

/*
 * Test 1: CPUID benchmark
 * Guest: rdtsc -> cpuid -> rdtsc -> out
 */
static void bench_cpuid(void) {
    int kvm_fd, vm_fd, vcpu_fd;
    struct kvm_run *run;
    void *mem;
    size_t run_size;

    printf("\n[Test 1] CPUID\n");
    printf("--------------------------------------------------------\n");

    if (setup_vm(&kvm_fd, &vm_fd, &vcpu_fd, &run, &mem, &run_size) < 0) return;

    /*
     * loop:
     *   rdtsc
     *   mov [0x2000], eax
     *   mov [0x2004], edx
     *   xor eax, eax
     *   cpuid                 ; VM-EXIT
     *   rdtsc
     *   mov [0x2008], eax
     *   mov [0x200c], edx
     *   out 0x10, al          ; signal host
     *   jmp loop
     */
    uint8_t guest_code[] = {
        0x0f, 0x31,                         /* rdtsc */
        0xa3, 0x00, 0x20, 0x00, 0x00,       /* mov [0x2000], eax */
        0x89, 0x15, 0x04, 0x20, 0x00, 0x00, /* mov [0x2004], edx */
        0x31, 0xc0,                         /* xor eax, eax */
        0x0f, 0xa2,                         /* cpuid */
        0x0f, 0x31,                         /* rdtsc */
        0xa3, 0x08, 0x20, 0x00, 0x00,       /* mov [0x2008], eax */
        0x89, 0x15, 0x0c, 0x20, 0x00, 0x00, /* mov [0x200c], edx */
        0xe6, 0x10,                         /* out 0x10, al */
        0xeb, 0xe0,                         /* jmp loop */
    };
    memcpy((uint8_t *)mem + 0x1000, guest_code, sizeof(guest_code));

    volatile uint32_t *ts_before_lo = (volatile uint32_t *)((uint8_t *)mem + TS_BEFORE);
    volatile uint32_t *ts_before_hi = (volatile uint32_t *)((uint8_t *)mem + TS_BEFORE + 4);
    volatile uint32_t *ts_after_lo  = (volatile uint32_t *)((uint8_t *)mem + TS_AFTER);
    volatile uint32_t *ts_after_hi  = (volatile uint32_t *)((uint8_t *)mem + TS_AFTER + 4);

    struct kvm_regs regs = { .rip = 0x1000, .rflags = 2 };
    ioctl(vcpu_fd, KVM_SET_REGS, &regs);

    /* Test run */
    ioctl(vcpu_fd, KVM_RUN, 0);
    if (run->exit_reason != KVM_EXIT_IO) {
        printf("  Test failed: exit_reason=%d\n", run->exit_reason);
        goto cleanup;
    }

    /* Warmup */
    for (int i = 0; i < WARMUP_ITERATIONS; i++)
        ioctl(vcpu_fd, KVM_RUN, 0);

    /* Measure */
    for (int i = 0; i < ITERATIONS; i++) {
        ioctl(vcpu_fd, KVM_RUN, 0);
        uint64_t t1 = ((uint64_t)*ts_before_hi << 32) | *ts_before_lo;
        uint64_t t2 = ((uint64_t)*ts_after_hi << 32) | *ts_after_lo;
        samples[i] = t2 - t1;
    }
    print_stats("CPUID:", ITERATIONS);

cleanup:
    munmap(run, run_size);
    munmap(mem, GUEST_MEM_SIZE);
    close(vcpu_fd); close(vm_fd); close(kvm_fd);
}

/*
 * Test 2: I/O port benchmark
 * Guest: rdtsc -> out -> rdtsc -> out
 * This is the cleanest measurement of VM-EXIT + VM-ENTRY
 */
static void bench_io(void) {
    int kvm_fd, vm_fd, vcpu_fd;
    struct kvm_run *run;
    void *mem;
    size_t run_size;

    printf("\n[Test 2] I/O Port (OUT instruction)\n");
    printf("--------------------------------------------------------\n");

    if (setup_vm(&kvm_fd, &vm_fd, &vcpu_fd, &run, &mem, &run_size) < 0) return;

    /*
     * loop:
     *   rdtsc
     *   mov [0x2000], eax
     *   mov [0x2004], edx
     *   out 0x10, al          ; VM-EXIT (timed)
     *   rdtsc
     *   mov [0x2008], eax
     *   mov [0x200c], edx
     *   out 0x20, al          ; VM-EXIT (signal done)
     *   jmp loop
     */
    uint8_t guest_code[] = {
        0x0f, 0x31,                         /* rdtsc */
        0xa3, 0x00, 0x20, 0x00, 0x00,       /* mov [0x2000], eax */
        0x89, 0x15, 0x04, 0x20, 0x00, 0x00, /* mov [0x2004], edx */
        0xe6, 0x10,                         /* out 0x10, al */
        0x0f, 0x31,                         /* rdtsc */
        0xa3, 0x08, 0x20, 0x00, 0x00,       /* mov [0x2008], eax */
        0x89, 0x15, 0x0c, 0x20, 0x00, 0x00, /* mov [0x200c], edx */
        0xe6, 0x20,                         /* out 0x20, al */
        0xeb, 0xe2,                         /* jmp loop */
    };
    memcpy((uint8_t *)mem + 0x1000, guest_code, sizeof(guest_code));

    volatile uint32_t *ts_before_lo = (volatile uint32_t *)((uint8_t *)mem + TS_BEFORE);
    volatile uint32_t *ts_before_hi = (volatile uint32_t *)((uint8_t *)mem + TS_BEFORE + 4);
    volatile uint32_t *ts_after_lo  = (volatile uint32_t *)((uint8_t *)mem + TS_AFTER);
    volatile uint32_t *ts_after_hi  = (volatile uint32_t *)((uint8_t *)mem + TS_AFTER + 4);

    struct kvm_regs regs = { .rip = 0x1000, .rflags = 2 };
    ioctl(vcpu_fd, KVM_SET_REGS, &regs);

    /* Test run */
    ioctl(vcpu_fd, KVM_RUN, 0);  /* First OUT */
    ioctl(vcpu_fd, KVM_RUN, 0);  /* Second OUT */
    if (run->exit_reason != KVM_EXIT_IO) {
        printf("  Test failed: exit_reason=%d\n", run->exit_reason);
        goto cleanup;
    }

    /* Warmup */
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        ioctl(vcpu_fd, KVM_RUN, 0);
        ioctl(vcpu_fd, KVM_RUN, 0);
    }

    /* Measure */
    for (int i = 0; i < ITERATIONS; i++) {
        ioctl(vcpu_fd, KVM_RUN, 0);  /* First OUT (timed) */
        ioctl(vcpu_fd, KVM_RUN, 0);  /* Second OUT (signal) */
        uint64_t t1 = ((uint64_t)*ts_before_hi << 32) | *ts_before_lo;
        uint64_t t2 = ((uint64_t)*ts_after_hi << 32) | *ts_after_lo;
        samples[i] = t2 - t1;
    }
    print_stats("I/O Port:", ITERATIONS);

cleanup:
    munmap(run, run_size);
    munmap(mem, GUEST_MEM_SIZE);
    close(vcpu_fd); close(vm_fd); close(kvm_fd);
}

/*
 * Test 3: Host-side measurement (for comparison)
 * Measures ioctl(KVM_RUN) round-trip from host perspective
 */
static void bench_host_side(void) {
    int kvm_fd, vm_fd, vcpu_fd;
    struct kvm_run *run;
    void *mem;
    size_t run_size;

    printf("\n[Test 3] Host-side ioctl measurement\n");
    printf("--------------------------------------------------------\n");

    if (setup_vm(&kvm_fd, &vm_fd, &vcpu_fd, &run, &mem, &run_size) < 0) return;

    /* Simple: just OUT and loop */
    uint8_t guest_code[] = {
        0xe6, 0x10,     /* out 0x10, al */
        0xeb, 0xfc,     /* jmp -4 */
    };
    memcpy((uint8_t *)mem + 0x1000, guest_code, sizeof(guest_code));

    struct kvm_regs regs = { .rip = 0x1000, .rflags = 2 };
    ioctl(vcpu_fd, KVM_SET_REGS, &regs);

    /* Test */
    ioctl(vcpu_fd, KVM_RUN, 0);
    if (run->exit_reason != KVM_EXIT_IO) {
        printf("  Test failed: exit_reason=%d\n", run->exit_reason);
        goto cleanup;
    }

    /* Warmup */
    for (int i = 0; i < WARMUP_ITERATIONS; i++)
        ioctl(vcpu_fd, KVM_RUN, 0);

    /* Measure from host side */
    for (int i = 0; i < ITERATIONS; i++) {
        uint32_t lo1, hi1, lo2, hi2;
        __asm__ volatile ("rdtsc" : "=a"(lo1), "=d"(hi1));
        ioctl(vcpu_fd, KVM_RUN, 0);
        __asm__ volatile ("rdtscp" : "=a"(lo2), "=d"(hi2) : : "ecx");
        uint64_t t1 = ((uint64_t)hi1 << 32) | lo1;
        uint64_t t2 = ((uint64_t)hi2 << 32) | lo2;
        samples[i] = t2 - t1;
    }
    print_stats("Host ioctl:", ITERATIONS);

cleanup:
    munmap(run, run_size);
    munmap(mem, GUEST_MEM_SIZE);
    close(vcpu_fd); close(vm_fd); close(kvm_fd);
}

int main(void) {
    printf("\n========================================================\n");
    printf(" VM-EXIT + VM-ENTRY Hardware Cost Benchmark\n");
    printf("========================================================\n");
    printf(" Iterations: %d, Warmup: %d\n", ITERATIONS, WARMUP_ITERATIONS);

    bench_cpuid();
    bench_io();
    bench_host_side();

    printf("\n========================================================\n");
    printf(" Summary\n");
    printf("========================================================\n");
    printf(" CPUID:      Guest measures CPUID round-trip\n");
    printf("             (includes KVM CPUID emulation)\n");
    printf(" I/O Port:   Guest measures OUT round-trip\n");
    printf("             (minimal KVM handling)\n");
    printf(" Host ioctl: Host measures ioctl(KVM_RUN) round-trip\n");
    printf("             (includes syscall + KVM + hardware)\n");
    printf("\n");
    printf(" I/O Port result is closest to pure VM-EXIT + VM-ENTRY.\n");
    printf("========================================================\n\n");

    return 0;
}
