/* SPDX-License-Identifier: MPL-2.0 */

/*
 * rdtsc_timing.h - Shared rdtsc timing utilities for throughput benchmarks
 *
 * This header provides consistent cycle-accurate timing across all throughput
 * benchmarks (pipe, unix socket, vsock, framevsock) to enable fair comparison.
 *
 * Usage:
 *   #include "../rdtsc_timing.h"  // or appropriate relative path
 *
 *   uint64_t start = rdtsc_fenced();
 *   // ... work ...
 *   uint64_t end = rdtsc_fenced();
 *   double gbps = cycles_to_gbps(bytes, end - start);
 */

#ifndef RDTSC_TIMING_H
#define RDTSC_TIMING_H

#include <stdint.h>

#ifndef CPU_MHZ
#define CPU_MHZ 2600
#endif

/* Read Time Stamp Counter */
static inline uint64_t rdtsc(void)
{
	uint32_t lo, hi;
	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
}

/* Read TSC with serializing fence for accurate measurement */
static inline uint64_t rdtsc_fenced(void)
{
	__asm__ volatile("lfence" ::: "memory");
	return rdtsc();
}

/*
 * Convert cycles to Gbits/s throughput
 *
 * Formula: Gbps = bytes * 8 bits/byte * CPU_MHZ MHz / cycles / 1000
 *        = bytes * 8 * CPU_MHZ / cycles / 1000
 *
 * This matches the calculation in guest_receiver.c
 */
static inline double cycles_to_gbps(uint64_t bytes, uint64_t cycles)
{
	if (cycles == 0)
		return 0.0;
	return (double)(bytes * 8ULL) * (double)CPU_MHZ / (double)cycles /
	       1000.0;
}

#endif /* RDTSC_TIMING_H */
