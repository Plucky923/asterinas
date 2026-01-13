// SPDX-License-Identifier: MPL-2.0

//! Benchmark utilities for FrameVisor
//!
//! This module provides:
//! 1. TSC reading functions (safe wrappers using ostd::arch::read_tsc)
//! 2. Test functions with different `ensure_stack` configurations

use core::sync::atomic::{compiler_fence, Ordering};

// ============================================================================
// TSC Reading Functions (Safe Wrappers)
// ============================================================================

/// Read TSC with serialization for start of measurement.
/// Uses compiler_fence to prevent reordering around the TSC read.
#[inline(always)]
pub fn rdtsc_start() -> u64 {
    // Use compiler fence to prevent reordering before TSC read
    compiler_fence(Ordering::SeqCst);
    let tsc = ostd::arch::read_tsc();
    compiler_fence(Ordering::SeqCst);
    tsc
}

/// Read TSC with serialization for end of measurement.
/// Uses compiler_fence to prevent reordering around the TSC read.
#[inline(always)]
pub fn rdtsc_end() -> u64 {
    // Use compiler fence to prevent reordering before TSC read
    compiler_fence(Ordering::SeqCst);
    let tsc = ostd::arch::read_tsc();
    compiler_fence(Ordering::SeqCst);
    tsc
}

// ============================================================================
// Test Functions for ensure_stack Benchmarking
// ============================================================================

/// Empty function without ensure_stack (baseline)
#[inline(never)]
pub fn bench_noop() -> u64 {
    compiler_fence(Ordering::SeqCst);
    42
}

/// Function with ensure_stack requiring 4KB (fast path - no switch expected)
#[ostd::ensure_stack(4096)]
pub fn bench_ensure_stack_no_switch() -> u64 {
    compiler_fence(Ordering::SeqCst);
    42
}

/// Function with ensure_stack requiring 60KB (slow path - will trigger switch)
/// Since typical task stack is 64KB, requesting 60KB will almost certainly
/// trigger a stack switch to the service stack.
#[ostd::ensure_stack(61440)]
pub fn bench_ensure_stack_force_switch() -> u64 {
    compiler_fence(Ordering::SeqCst);
    42
}

// ============================================================================
// Functions with Arguments
// ============================================================================

/// Function with args, no ensure_stack
#[inline(never)]
pub fn bench_noop_with_args(a: u64, b: u64, c: u64) -> u64 {
    compiler_fence(Ordering::SeqCst);
    a.wrapping_add(b).wrapping_add(c)
}

/// Function with args and ensure_stack 4KB (fast path)
#[ostd::ensure_stack(4096)]
pub fn bench_ensure_stack_4k_with_args(a: u64, b: u64, c: u64) -> u64 {
    compiler_fence(Ordering::SeqCst);
    a.wrapping_add(b).wrapping_add(c)
}
