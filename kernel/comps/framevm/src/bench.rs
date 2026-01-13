// SPDX-License-Identifier: MPL-2.0

//! FrameVisor Benchmark Module
//!
//! This module provides detailed benchmarking for various FrameVisor operations:
//! - RDTSC overhead (baseline measurement)
//! - Empty function call (baseline)
//! - FrameVisor call (cross-domain call overhead)
//! - RRef create (remote reference allocation)
//! - RRef transfer (ownership transfer)
//! - RRef drop (deallocation)
//! - ensure_stack overhead (no switch vs force switch)
//!
//! # Usage
//!
//! Call `run_all_benchmarks()` to execute all benchmarks and print results.

use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, Ordering};

use aster_framevisor::{
    bench as fv_bench,
    println, DomainId, RRef,
    vsock::set_guest_vsock_active,
};

// ============================================================================
// Configuration
// ============================================================================

/// Number of warmup iterations
const WARMUP_ITERATIONS: usize = 1000;

/// Number of measurement iterations
const BENCH_ITERATIONS: usize = 10000;

// ============================================================================
// Use TSC functions from FrameVisor
// ============================================================================

use fv_bench::{rdtsc_start, rdtsc_end};

// ============================================================================
// Statistics
// ============================================================================

/// Benchmark statistics
#[derive(Debug, Clone)]
pub struct BenchStats {
    pub min: u64,
    pub max: u64,
    pub avg: u64,
    pub p50: u64,
    pub p90: u64,
    pub p99: u64,
    pub samples: usize,
}

impl BenchStats {
    /// Compute statistics from samples
    pub fn from_samples(samples: &mut [u64]) -> Self {
        if samples.is_empty() {
            return Self {
                min: 0,
                max: 0,
                avg: 0,
                p50: 0,
                p90: 0,
                p99: 0,
                samples: 0,
            };
        }

        // Sort for percentiles
        samples.sort_unstable();

        let n = samples.len();
        let sum: u64 = samples.iter().sum();

        Self {
            min: samples[0],
            max: samples[n - 1],
            avg: sum / (n as u64),
            p50: samples[n / 2],
            p90: samples[(n * 90) / 100],
            p99: samples[(n * 99) / 100],
            samples: n,
        }
    }

    /// Print statistics in compact format
    pub fn print(&self, name: &str) {
        println!(
            " {:<22} min={:<4} avg={:<4} p50={:<4} cycles",
            name, self.min, self.avg, self.p50
        );
    }
}

// ============================================================================
// Empty Functions for Baseline Measurements
// ============================================================================

/// Empty function - baseline for function call overhead
#[inline(never)]
fn empty_function() {
    compiler_fence(Ordering::SeqCst);
}

// ============================================================================
// Benchmark Implementations
// ============================================================================

/// Benchmark RDTSC overhead (baseline)
pub fn bench_rdtsc_overhead() -> BenchStats {
    let mut samples = Vec::with_capacity(BENCH_ITERATIONS);

    // Warmup
    for _ in 0..WARMUP_ITERATIONS {
        let start = rdtsc_start();
        let end = rdtsc_end();
        core::hint::black_box(end - start);
    }

    // Measurement
    for _ in 0..BENCH_ITERATIONS {
        let start = rdtsc_start();
        // Empty - measuring RDTSC overhead itself
        let end = rdtsc_end();
        samples.push(end - start);
    }

    BenchStats::from_samples(&mut samples)
}

/// Benchmark empty function call overhead
pub fn bench_empty_function_call() -> BenchStats {
    let mut samples = Vec::with_capacity(BENCH_ITERATIONS);

    // Warmup
    for _ in 0..WARMUP_ITERATIONS {
        let start = rdtsc_start();
        empty_function();
        let end = rdtsc_end();
        core::hint::black_box(end - start);
    }

    // Measurement
    for _ in 0..BENCH_ITERATIONS {
        let start = rdtsc_start();
        empty_function();
        let end = rdtsc_end();
        samples.push(end - start);
    }

    BenchStats::from_samples(&mut samples)
}

/// Benchmark FrameVisor call (cross-domain call)
/// This measures the overhead of calling a FrameVisor API from FrameVM
pub fn bench_framevisor_call() -> BenchStats {
    let mut samples = Vec::with_capacity(BENCH_ITERATIONS);

    // Warmup - use a simple FrameVisor API call
    for _ in 0..WARMUP_ITERATIONS {
        let start = rdtsc_start();
        // Call a simple FrameVisor API that does minimal work
        // set_guest_vsock_active is a simple atomic store wrapped with ensure_stack
        set_guest_vsock_active(true);
        let end = rdtsc_end();
        core::hint::black_box(end - start);
    }

    // Measurement
    for _ in 0..BENCH_ITERATIONS {
        let start = rdtsc_start();
        set_guest_vsock_active(true);
        let end = rdtsc_end();
        samples.push(end - start);
    }

    BenchStats::from_samples(&mut samples)
}

/// Benchmark RRef creation
pub fn bench_rref_create() -> BenchStats {
    let mut samples = Vec::with_capacity(BENCH_ITERATIONS);

    // Warmup
    for i in 0..WARMUP_ITERATIONS {
        let start = rdtsc_start();
        let rref = RRef::new(i as u64);
        let end = rdtsc_end();
        core::hint::black_box(&rref);
        core::hint::black_box(end - start);
        drop(rref);
    }

    // Measurement
    for i in 0..BENCH_ITERATIONS {
        let start = rdtsc_start();
        let rref = RRef::new(i as u64);
        let end = rdtsc_end();
        core::hint::black_box(&rref);
        samples.push(end - start);
        drop(rref); // Drop outside measurement
    }

    BenchStats::from_samples(&mut samples)
}

/// Benchmark RRef transfer (ownership transfer)
pub fn bench_rref_transfer() -> BenchStats {
    let mut samples = Vec::with_capacity(BENCH_ITERATIONS);

    // Pre-create RRefs for transfer test
    let mut rrefs: Vec<RRef<u64>> = (0..BENCH_ITERATIONS)
        .map(|i| RRef::new(i as u64))
        .collect();

    // Warmup with some extra RRefs
    let mut warmup_rrefs: Vec<RRef<u64>> = (0..WARMUP_ITERATIONS)
        .map(|i| RRef::new(i as u64))
        .collect();

    for rref in warmup_rrefs.drain(..) {
        let start = rdtsc_start();
        let transferred = rref.transfer_to(DomainId::Host);
        let end = rdtsc_end();
        core::hint::black_box(&transferred);
        core::hint::black_box(end - start);
        drop(transferred);
    }

    // Measurement
    for rref in rrefs.drain(..) {
        let start = rdtsc_start();
        let transferred = rref.transfer_to(DomainId::Host);
        let end = rdtsc_end();
        core::hint::black_box(&transferred);
        samples.push(end - start);
        drop(transferred);
    }

    BenchStats::from_samples(&mut samples)
}

/// Benchmark RRef drop
pub fn bench_rref_drop() -> BenchStats {
    let mut samples = Vec::with_capacity(BENCH_ITERATIONS);

    // Pre-create RRefs for drop test
    let mut rrefs: Vec<Option<RRef<u64>>> = (0..(BENCH_ITERATIONS + WARMUP_ITERATIONS))
        .map(|i| Some(RRef::new(i as u64)))
        .collect();

    // Warmup
    for i in 0..WARMUP_ITERATIONS {
        let rref = rrefs[i].take().unwrap();
        let start = rdtsc_start();
        drop(rref);
        let end = rdtsc_end();
        core::hint::black_box(end - start);
    }

    // Measurement
    for i in 0..BENCH_ITERATIONS {
        let rref = rrefs[WARMUP_ITERATIONS + i].take().unwrap();
        let start = rdtsc_start();
        drop(rref);
        let end = rdtsc_end();
        samples.push(end - start);
    }

    BenchStats::from_samples(&mut samples)
}

// ============================================================================
// ensure_stack Overhead Benchmarks
// ============================================================================

/// Benchmark noop function (no ensure_stack) - baseline
pub fn bench_ensure_stack_noop() -> BenchStats {
    let mut samples = Vec::with_capacity(BENCH_ITERATIONS);

    // Warmup
    for _ in 0..WARMUP_ITERATIONS {
        let start = rdtsc_start();
        let result = fv_bench::bench_noop();
        let end = rdtsc_end();
        core::hint::black_box(result);
        core::hint::black_box(end - start);
    }

    // Measurement
    for _ in 0..BENCH_ITERATIONS {
        let start = rdtsc_start();
        let result = fv_bench::bench_noop();
        let end = rdtsc_end();
        core::hint::black_box(result);
        samples.push(end - start);
    }

    BenchStats::from_samples(&mut samples)
}

/// Benchmark ensure_stack - fast path (no stack switch)
pub fn bench_ensure_stack_no_switch() -> BenchStats {
    let mut samples = Vec::with_capacity(BENCH_ITERATIONS);

    // Warmup
    for _ in 0..WARMUP_ITERATIONS {
        let start = rdtsc_start();
        let result = fv_bench::bench_ensure_stack_no_switch();
        let end = rdtsc_end();
        core::hint::black_box(result);
        core::hint::black_box(end - start);
    }

    // Measurement
    for _ in 0..BENCH_ITERATIONS {
        let start = rdtsc_start();
        let result = fv_bench::bench_ensure_stack_no_switch();
        let end = rdtsc_end();
        core::hint::black_box(result);
        samples.push(end - start);
    }

    BenchStats::from_samples(&mut samples)
}

/// Benchmark ensure_stack - slow path (force stack switch)
pub fn bench_ensure_stack_force_switch() -> BenchStats {
    let mut samples = Vec::with_capacity(BENCH_ITERATIONS);

    // Warmup
    for _ in 0..WARMUP_ITERATIONS {
        let start = rdtsc_start();
        let result = fv_bench::bench_ensure_stack_force_switch();
        let end = rdtsc_end();
        core::hint::black_box(result);
        core::hint::black_box(end - start);
    }

    // Measurement
    for _ in 0..BENCH_ITERATIONS {
        let start = rdtsc_start();
        let result = fv_bench::bench_ensure_stack_force_switch();
        let end = rdtsc_end();
        core::hint::black_box(result);
        samples.push(end - start);
    }

    BenchStats::from_samples(&mut samples)
}

// ============================================================================
// Main Benchmark Runner
// ============================================================================

/// Run all benchmarks and print results
pub fn run_all_benchmarks() {
    println!(
        "\n================================================================================"
    );
    println!(" FrameVisor Microbenchmark Suite");
    println!(
        "================================================================================"
    );
    println!(" Warmup iterations:      {}", WARMUP_ITERATIONS);
    println!(" Measurement iterations: {}", BENCH_ITERATIONS);
    println!(
        "--------------------------------------------------------------------------------\n"
    );

    // Baseline measurements
    println!(" Baseline Measurements:");
    println!(" ----------------------");

    let rdtsc_stats = bench_rdtsc_overhead();
    rdtsc_stats.print("RDTSC overhead");

    let empty_call_stats = bench_empty_function_call();
    empty_call_stats.print("Empty function call");

    // FrameVisor call overhead
    println!("\n FrameVisor Call Overhead:");
    println!(" -------------------------");

    let fv_call_stats = bench_framevisor_call();
    fv_call_stats.print("FrameVisor call");

    // RRef operations
    println!("\n RRef Operations:");
    println!(" ----------------");

    let rref_create_stats = bench_rref_create();
    rref_create_stats.print("RRef create");

    let rref_transfer_stats = bench_rref_transfer();
    rref_transfer_stats.print("RRef transfer");

    let rref_drop_stats = bench_rref_drop();
    rref_drop_stats.print("RRef drop");

    // ensure_stack overhead
    println!("\n ensure_stack Overhead:");
    println!(" ----------------------");

    let noop_stats = bench_ensure_stack_noop();
    noop_stats.print("No ensure_stack");

    let no_switch_stats = bench_ensure_stack_no_switch();
    no_switch_stats.print("ensure_stack (no switch)");

    let force_switch_stats = bench_ensure_stack_force_switch();
    force_switch_stats.print("ensure_stack (switch)");

    // Summary
    println!(
        "\n================================================================================"
    );
    println!(" Summary (overhead in cycles, lower is better)");
    println!(
        "================================================================================"
    );
    println!(
        " RDTSC overhead:       min={:<4} avg={:<4} p50={:<4} cycles",
        rdtsc_stats.min, rdtsc_stats.avg, rdtsc_stats.p50
    );
    println!(
        " Empty function call:  min={:<4} avg={:<4} p50={:<4} cycles",
        empty_call_stats.min, empty_call_stats.avg, empty_call_stats.p50
    );
    println!(
        " FrameVisor call:      min={:<4} avg={:<4} p50={:<4} cycles",
        fv_call_stats.min, fv_call_stats.avg, fv_call_stats.p50
    );
    println!(
        " RRef create:          min={:<4} avg={:<4} p50={:<4} cycles",
        rref_create_stats.min, rref_create_stats.avg, rref_create_stats.p50
    );
    println!(
        " RRef transfer:        min={:<4} avg={:<4} p50={:<4} cycles",
        rref_transfer_stats.min, rref_transfer_stats.avg, rref_transfer_stats.p50
    );
    println!(
        " RRef drop:            min={:<4} avg={:<4} p50={:<4} cycles",
        rref_drop_stats.min, rref_drop_stats.avg, rref_drop_stats.p50
    );
    println!(
        "--------------------------------------------------------------------------------"
    );
    println!(
        " ensure_stack (no switch):  min={:<4} avg={:<4} p50={:<4} cycles",
        no_switch_stats.min, no_switch_stats.avg, no_switch_stats.p50
    );
    println!(
        " ensure_stack (switch):     min={:<4} avg={:<4} p50={:<4} cycles",
        force_switch_stats.min, force_switch_stats.avg, force_switch_stats.p50
    );
    println!(
        "================================================================================\n"
    );
}
