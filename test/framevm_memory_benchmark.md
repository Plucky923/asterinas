# FrameVM Memory Benchmark Method

This document describes how to run the FrameVM memory benchmark used by
`kernel/comps/framevm/test/bench_memory.c` and how to map it to the four
scenarios in `kernel/comps/framevm/test/Memory_test.md`.

For a copy-paste end-to-end execution and quantification procedure of the Linux
nested stack (`L0 -> L1 Linux -> L2 Linux`), see
`test/framevm_linux_stack_runbook.md`.

For host bare-metal execution (no guest VM layer), see
`test/framevm_baremetal_memory_runbook.md`.

## 1. Benchmark summary

- Pattern: sequential scan, random pointer-chase, or page-stride (one word per page).
  Page-rand uses a page-level pointer-chase to serialize accesses.
- Operation mode: load-only or load+store (store writes the same value back).
- Warmup: optional extra pass after initialization.
- Output: one canonical metric `Result` (`cycles/op`, median-based when runs > 1).

## 2. Build and run (FrameVM guest)

Build the guest binaries:

```bash
cd kernel/comps/framevm/test
make compare_all
```

Scenario binaries:

- `bench_memory_page_seq_cold`
- `bench_memory_page_seq_warm`
- `bench_memory_page_rand_warm`
- `bench_memory_word_seq_warm`

Workset sweep targets:

- `bench_memory_page_rand_warm_<size>` (64k..64m)

FrameVM loads the binary via:
`kernel/comps/framevm/src/main.rs` (include_bytes for
`bench_memory_page_seq_cold` by default for memory cold-fault tests).

Boot the system and start FrameVM (1 vCPU example):

```bash
echo 1 > /proc/framevm
```

## 2b. Build and run (Host initramfs)

Host benchmark sources live in `test/initramfs/src/apps/memory/`.
The initramfs build installs binaries under `/test/memory/`.

Build host binaries:

```bash
cd test/initramfs/src/apps
make memory
```

Or build specific targets:

```bash
make -C test/initramfs/src/apps/memory bench_memory_page_seq_cold
make -C test/initramfs/src/apps/memory bench_memory_page_rand_warm
```

Run on host (examples):

```bash
cd /test/memory
./bench_memory_page_seq_warm
./bench_memory_page_rand_warm
./bench_memory_word_seq_warm
```

## 3. Parameters

- `MEM_WORKSET_BYTES`: working set size in bytes (must be multiple of 8).
- `MEM_REPEAT`: repeat count for sequential scans.
- `MEM_ACCESS_PATTERN`:
  - `0`: sequential
  - `1`: random pointer-chase
  - `2`: page-stride sequential
  - `3`: page-stride random (page-level pointer-chase)
- `MEM_WARMUP`:
  - `1`: one warmup pass
  - `0`: no warmup pass
- `MEM_RANDOM_STEPS`:
  - `0`: defaults to `WORKSET_WORDS * MEM_REPEAT`
  - `>0`: use this explicit step count
- `MEM_DO_STORE`:
  - `1`: load+store (store writes the same value back)
  - `0`: load-only
- `MEM_SEED`:
  - `0`: seed from `rdtsc`
  - `>0`: fixed seed for reproducible random chain
- `MEASURE_RUNS`:
  - `1`: single measurement (default)
  - `>1`: take the median of repeated measurements

Host binary also accepts `--seed N` and `--runs N` at runtime.

Note: the Makefiles default `MEM_SEED` to `12345` for reproducibility. Override
with `MEM_SEED=0` if you want a randomized chain per build.

## 4. Warmup semantics (explicit)

Warmup is a separate pass executed after initialization:

- Sequential: one full pass over all elements (`WORKSET_WORDS` iterations).
- Random: one full pointer-chase cycle
  (`min(WORKSET_WORDS, MEM_RANDOM_STEPS)` iterations).
- Page-stride: one full pass over all pages (`WORKSET_BYTES / 4096` iterations).

If `MEM_WARMUP=0`, the benchmark skips this extra pass.

Note: random pointer-chase and page-rand build their chains during
initialization and touch every page, so they cannot be used to measure cold
page faults. FrameVM maps file-backed pages eagerly, but BSS pages are lazily
mapped, so `page_seq_cold` is used as the cold page-fault probe.

## 5. EPT page fault and TLB miss modes

To expose translation costs, use the page-stride patterns (2/3):

- Page fault cost (cold first-touch, write path): `MEM_ACCESS_PATTERN=2`, `MEM_WARMUP=0`,
  `MEM_REPEAT=1`, `MEM_DO_STORE=1` (`bench_memory_page_seq_cold`).
- TLB miss + two-stage translation (no page fault): `MEM_ACCESS_PATTERN=3`,
  `MEM_WARMUP=1`, `MEM_DO_STORE=0` (`bench_memory_page_rand_warm`).

Override `MEM_COMPARE_WORKSET_BYTES` and `MEM_COMPARE_RUNS` via make variables
as needed (use `MEASURE_RUNS>1` for noisy setups).

## 6. Mapping to four scenarios (Experiment 2.2)

Fix `MEM_WORKSET_BYTES` and run:

1. Page-seq + cold:
   - `MEM_ACCESS_PATTERN=2`, `MEM_WARMUP=0`, `MEM_DO_STORE=1`
     (`bench_memory_page_seq_cold`)
2. Page-seq + warm:
   - `MEM_ACCESS_PATTERN=2`, `MEM_WARMUP=1`, `MEM_DO_STORE=1`
     (`bench_memory_page_seq_warm`)
3. Page-rand + warm:
   - `MEM_ACCESS_PATTERN=3`, `MEM_WARMUP=1` (`bench_memory_page_rand_warm`)
4. Word-seq + warm:
   - `MEM_ACCESS_PATTERN=0`, `MEM_WARMUP=1` (`bench_memory_word_seq_warm`)

Keep `MEM_DO_STORE=1` for the `page-seq` pair (`cold`/`warm`) when quantifying
page-fault cost, and keep `MEM_DO_STORE=0` for `page-rand` and `word-seq`.

## 7. Workset sweep (Experiment 2.1)

Hold all parameters constant and sweep `MEM_WORKSET_BYTES` (for example:
64K, 256K, 1M, 4M, 16M, 64M) under page-rand + warmup:

- `MEM_ACCESS_PATTERN=3`
- `MEM_WARMUP=1`
- `MEM_DO_STORE=0` (recommended)

Plot `Result` (cycles/op, median-of-runs) vs. working set size.

Convenience targets (built by default):

- `bench_memory_page_rand_warm_<size>` (page-rand sweep, load-only by default)

## 8. Output interpretation

- `Iterations`: loop iterations executed.
- `Mem ops`: memory operations (load or load+store).
- `Result`: canonical metric used by the benchmark (`cycles/op`, median-of-runs).
- `Runs`: number of measurements; when >1, `Result` is based on the median.

For cross-system comparisons, use the same parameters and report `Result`.
