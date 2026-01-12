# FrameVM Linux Nested Memory Quantification Runbook

This runbook is the single source of truth for memory-overhead comparison in the nested Linux stack:

`L0 Linux host -> L1 Linux (QEMU/KVM) -> L2 Linux (QEMU/KVM nested)`

It focuses on *quantification* (not just boot success):

1. Fixed-workset scenario overhead (`cycles/op`)
2. Workset-growth TLB/page-walk overhead (`cycles/page`)
3. Nested overhead (`L2 - L1`, `L2 / L1`)

Last updated: 2026-02-28

## 1. Scope and metrics

### 1.1 Scenario set (fixed workset)

Use the following binaries at fixed workset (`MEM_COMPARE_WORKSET_BYTES`):

1. `bench_memory_page_seq_cold`
2. `bench_memory_page_seq_warm`
3. `bench_memory_page_rand_warm`
4. `bench_memory_word_seq_warm`

### 1.2 Workset sweep

Use page-random warm sweep binaries:

1. `bench_memory_page_rand_warm_64k`
2. `bench_memory_page_rand_warm_128k`
3. `bench_memory_page_rand_warm_256k`
4. `bench_memory_page_rand_warm_512k`
5. `bench_memory_page_rand_warm_1m`
6. `bench_memory_page_rand_warm_2m`
7. `bench_memory_page_rand_warm_4m`
8. `bench_memory_page_rand_warm_8m`
9. `bench_memory_page_rand_warm_16m`
10. `bench_memory_page_rand_warm_32m`
11. `bench_memory_page_rand_warm_64m`

### 1.3 Quantification outputs

From analysis script `test/initramfs/src/benchmark/common/analyze_memory_overhead_metrics.sh`:

1. `nested_fixed_summary.csv`
2. `nested_sweep_by_size.csv`
3. `nested_sweep_summary.csv`

Core formulas:

1. `delta = L2 - L1`
2. `ratio = L2 / L1`
3. `pf_proxy = page_seq_cold - page_seq_warm`
4. `tlb_walk_proxy = page_rand_warm - word_seq_warm`

## 2. Strict parity contract

Use identical benchmark knobs in L1 and L2:

1. same workset bytes
2. same seed
3. same warm scenario runs
4. same load/store mode for each binary

Recommended baseline knobs:

1. `MEM_COMPARE_WORKSET_BYTES=536870912`
2. `MEM_COMPARE_RUNS=5`
3. `MEM_COMPARE_SEED=12345`
4. `MEM_COMPARE_DO_STORE=0`
5. `MEM_PAGE_RAND_RUNS=10000`
6. `MEM_PAGE_RAND_SEED=12345`
7. `MEM_PAGE_RAND_DO_STORE=0`
8. `PIN_HOST_CPU=2` (L0 affinity for QEMU process)
9. `PIN_GUEST_CPU=0` (L1/L2 affinity for benchmark commands)

Note:
`bench_memory_page_seq_cold` and `bench_memory_page_seq_warm` are baked as
write-path tests (`MEM_DO_STORE=1`) to quantify first-touch page-fault cost.
`MEM_COMPARE_DO_STORE` affects the other compare targets.

`page_rand_warm` and `page_rand_warm_*` policy:

1. run each binary 20 times at outer level
2. pick the minimum `Result` as the single value written into CSV

Linux cmdline (L1 and L2):

`mitigations=off hugepages=0 transparent_hugepage=never`

## 3. Host preflight (L0)

Run:

```bash
bash test/initramfs/src/benchmark/common/check_nested_linux_stack.sh
```

Must pass:

1. host has `vmx` or `svm`
2. `/dev/kvm` is rw for current user
3. required tools exist
4. `taskset` exists on host

## 4. Build artifacts with benchmark parameters baked in

Important: benchmark parameters must be passed through `make -C test/initramfs ...` so they are baked into initramfs binaries.

### 4.1 Export benchmark knobs once

```bash
export MEM_COMPARE_WORKSET_BYTES=536870912
export MEM_COMPARE_RUNS=5
export MEM_COMPARE_SEED=12345
export MEM_COMPARE_DO_STORE=0
export MEM_PAGE_RAND_RUNS=10000
export MEM_PAGE_RAND_SEED=12345
export MEM_PAGE_RAND_DO_STORE=0
export PIN_HOST_CPU=2
export PIN_GUEST_CPU=0

command -v taskset
```

### 4.2 Build L1 full initramfs and ext2

```bash
make -C test/initramfs \
  ENABLE_BASIC_TEST=true \
  ENABLE_NESTED_QEMU=true \
  MEM_COMPARE_WORKSET_BYTES=${MEM_COMPARE_WORKSET_BYTES} \
  MEM_COMPARE_RUNS=${MEM_COMPARE_RUNS} \
  MEM_COMPARE_SEED=${MEM_COMPARE_SEED} \
  MEM_COMPARE_DO_STORE=${MEM_COMPARE_DO_STORE} \
  MEM_PAGE_RAND_RUNS=${MEM_PAGE_RAND_RUNS} \
  MEM_PAGE_RAND_SEED=${MEM_PAGE_RAND_SEED} \
  MEM_PAGE_RAND_DO_STORE=${MEM_PAGE_RAND_DO_STORE} -j$(nproc)

cp -Lf test/initramfs/build/initramfs.cpio.gz test/initramfs/build/initramfs.l1.cpio.gz
```

### 4.3 Build L2 slim initramfs (same benchmark knobs)

```bash
make -C test/initramfs -B framevm_initramfs \
  ENABLE_BASIC_TEST=true \
  ENABLE_NESTED_QEMU=false \
  MEM_COMPARE_WORKSET_BYTES=${MEM_COMPARE_WORKSET_BYTES} \
  MEM_COMPARE_RUNS=${MEM_COMPARE_RUNS} \
  MEM_COMPARE_SEED=${MEM_COMPARE_SEED} \
  MEM_COMPARE_DO_STORE=${MEM_COMPARE_DO_STORE} \
  MEM_PAGE_RAND_RUNS=${MEM_PAGE_RAND_RUNS} \
  MEM_PAGE_RAND_SEED=${MEM_PAGE_RAND_SEED} \
  MEM_PAGE_RAND_DO_STORE=${MEM_PAGE_RAND_DO_STORE} -j$(nproc)

cp -Lf test/initramfs/build/initramfs.cpio.gz test/initramfs/build/initramfs.l2.cpio.gz
```

### 4.4 Build FrameVM guest-side binaries (for FrameVM parity runs)

```bash
make -C kernel/comps/framevm/test compare_all page_rand_warm_sweep \
  MEM_COMPARE_WORKSET_BYTES=${MEM_COMPARE_WORKSET_BYTES} \
  MEM_COMPARE_RUNS=${MEM_COMPARE_RUNS} \
  MEM_COMPARE_SEED=${MEM_COMPARE_SEED} \
  MEM_COMPARE_DO_STORE=${MEM_COMPARE_DO_STORE} \
  MEM_PAGE_RAND_RUNS=${MEM_PAGE_RAND_RUNS} \
  MEM_PAGE_RAND_SEED=${MEM_PAGE_RAND_SEED} \
  MEM_PAGE_RAND_DO_STORE=${MEM_PAGE_RAND_DO_STORE} -j$(nproc)
```

## 5. Prepare L2 kernel/initrd in ext2 image

Prepare cached Linux kernel:

```bash
bash -lc 'source test/initramfs/src/benchmark/common/prepare_host.sh && prepare_libs'
```

Inject L2 artifacts:

```bash
bash test/initramfs/src/benchmark/common/prepare_l2_boot_artifacts.sh \
  --ext2 test/initramfs/build/ext2.img \
  --kernel /opt/linux_binary_cache/vmlinuz \
  --initrd test/initramfs/build/initramfs.l2.cpio.gz \
  --l2-dir /l2
```

## 6. Boot L1 from L0

```bash
taskset -c ${PIN_HOST_CPU} qemu-system-x86_64 \
  --no-reboot \
  -smp 1 \
  -m 8G \
  -machine q35,kernel-irqchip=split \
  -accel kvm \
  -cpu host,+x2apic,+vmx \
  -nographic \
  -serial chardev:mux \
  -monitor chardev:mux \
  -chardev stdio,id=mux,mux=on,signal=off,logfile=l1-linux.log \
  -drive if=none,format=raw,id=x0,file=test/initramfs/build/ext2.img \
  -device virtio-blk-pci,bus=pcie.0,addr=0x6,drive=x0,serial=vext2,disable-legacy=on,disable-modern=off \
  -device virtio-serial-pci,disable-legacy=on,disable-modern=off \
  -device virtconsole,chardev=mux \
  -kernel /opt/linux_binary_cache/vmlinuz \
  -initrd test/initramfs/build/initramfs.l1.cpio.gz \
  -append "console=hvc0 rdinit=/bin/sh mitigations=off hugepages=0 transparent_hugepage=never"
```

## 7. L1 init and gate checks

Inside L1:

```bash
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /ext2
mount -t ext2 /dev/vda /ext2 || mount -t ext2 /dev/sda /ext2
```

Check nested prerequisites:

```bash
grep -E 'vmx|svm' /proc/cpuinfo | head -n 1
ls -l /dev/kvm
ls -lh /ext2/l2
ls -l /test/nested_l2_qemu.sh
```

Validate benchmark binaries exist in L1 initramfs:

```bash
ls /test/memory/bench_memory_page_seq_cold
ls /test/memory/bench_memory_page_seq_warm
ls /test/memory/bench_memory_page_rand_warm
ls /test/memory/bench_memory_word_seq_warm
```

Check CPU affinity tools/state in L1:

```bash
command -v taskset
nproc
```

## 8. Collect L1 benchmark logs

Inside L1:

```bash
mkdir -p /tmp/mem_l1
cd /test/memory
PIN_GUEST_CPU=0

# cold paths are single-run by design; run multiple outer samples for robustness.
for i in $(seq 1 15); do taskset -c ${PIN_GUEST_CPU} ./bench_memory_page_seq_cold | tee /tmp/mem_l1/page_seq_cold.${i}.log; done

taskset -c ${PIN_GUEST_CPU} ./bench_memory_page_seq_warm | tee /tmp/mem_l1/page_seq_warm.log
taskset -c ${PIN_GUEST_CPU} ./bench_memory_word_seq_warm | tee /tmp/mem_l1/word_seq_warm.log

for i in $(seq 1 20); do
  taskset -c ${PIN_GUEST_CPU} ./bench_memory_page_rand_warm | tee /tmp/mem_l1/page_rand_warm.${i}.log
done

for s in 64k 128k 256k 512k 1m 2m 4m 8m 16m 32m 64m; do
  for i in $(seq 1 20); do
    taskset -c ${PIN_GUEST_CPU} ./bench_memory_page_rand_warm_${s} | tee /tmp/mem_l1/page_rand_warm_${s}.${i}.log
  done
done
```

## 9. Boot L2 from L1

Inside L1:

```bash
PIN_GUEST_CPU=0
L2_SMP=1 L2_MEM=2G L2_CPU=host \
  taskset -c ${PIN_GUEST_CPU} \
  sh /test/nested_l2_qemu.sh /ext2/l2/bzImage /ext2/l2/initramfs.cpio.gz
```

Inside L2 shell:

```bash
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
cat /proc/cmdline
ls /test/memory/bench_memory_page_seq_cold
command -v taskset
nproc
```

## 10. Collect L2 benchmark logs

Inside L2:

```bash
mkdir -p /tmp/mem_l2
cd /test/memory
PIN_GUEST_CPU=0

for i in $(seq 1 15); do taskset -c ${PIN_GUEST_CPU} ./bench_memory_page_seq_cold | tee /tmp/mem_l2/page_seq_cold.${i}.log; done

taskset -c ${PIN_GUEST_CPU} ./bench_memory_page_seq_warm | tee /tmp/mem_l2/page_seq_warm.log
taskset -c ${PIN_GUEST_CPU} ./bench_memory_word_seq_warm | tee /tmp/mem_l2/word_seq_warm.log

for i in $(seq 1 20); do
  taskset -c ${PIN_GUEST_CPU} ./bench_memory_page_rand_warm | tee /tmp/mem_l2/page_rand_warm.${i}.log
done

for s in 64k 128k 256k 512k 1m 2m 4m 8m 16m 32m 64m; do
  for i in $(seq 1 20); do
    taskset -c ${PIN_GUEST_CPU} ./bench_memory_page_rand_warm_${s} | tee /tmp/mem_l2/page_rand_warm_${s}.${i}.log
  done
done
```

## 11. Build raw CSV on L0

Create CSV header once (use one real log path):

```bash
bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh \
  --stack linux_l1 \
  --scenario page_seq_cold \
  --input /path/to/l1/page_seq_cold.1.log \
  --header > /tmp/metrics_raw.csv
```

Append all logs for L1 and L2:

```bash
min_result_log() {
  pattern="$1"
  best_file=""
  best_value=""

  for f in ${pattern}; do
    [ -f "${f}" ] || continue
    value="$(awk '/Result:/ {print $2}' "${f}" | tail -n 1)"
    [ -n "${value}" ] || continue
    if [ -z "${best_value}" ] || awk "BEGIN { exit !(${value} < ${best_value}) }"; then
      best_value="${value}"
      best_file="${f}"
    fi
  done

  [ -n "${best_file}" ] || { echo "No valid Result in ${pattern}" >&2; return 1; }
  echo "${best_file}"
}

# L1 cold samples
for i in $(seq 1 15); do
  bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh \
    --stack linux_l1 --scenario page_seq_cold \
    --input /path/to/l1/page_seq_cold.${i}.log >> /tmp/metrics_raw.csv
done

# L1 warm scenarios
bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh --stack linux_l1 --scenario page_seq_warm --input /path/to/l1/page_seq_warm.log >> /tmp/metrics_raw.csv
bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh --stack linux_l1 --scenario page_rand_warm --input "$(min_result_log '/path/to/l1/page_rand_warm.*.log')" >> /tmp/metrics_raw.csv
bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh --stack linux_l1 --scenario word_seq_warm --input /path/to/l1/word_seq_warm.log >> /tmp/metrics_raw.csv

for s in 64k 128k 256k 512k 1m 2m 4m 8m 16m 32m 64m; do
  min_log="$(min_result_log "/path/to/l1/page_rand_warm_${s}.*.log")"
  bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh \
    --stack linux_l1 --scenario page_rand_warm_${s} \
    --input "${min_log}" >> /tmp/metrics_raw.csv
done

# Repeat same pattern for linux_l2 logs
for i in $(seq 1 15); do
  bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh \
    --stack linux_l2 --scenario page_seq_cold \
    --input /path/to/l2/page_seq_cold.${i}.log >> /tmp/metrics_raw.csv
done

bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh --stack linux_l2 --scenario page_seq_warm --input /path/to/l2/page_seq_warm.log >> /tmp/metrics_raw.csv
bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh --stack linux_l2 --scenario page_rand_warm --input "$(min_result_log '/path/to/l2/page_rand_warm.*.log')" >> /tmp/metrics_raw.csv
bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh --stack linux_l2 --scenario word_seq_warm --input /path/to/l2/word_seq_warm.log >> /tmp/metrics_raw.csv

for s in 64k 128k 256k 512k 1m 2m 4m 8m 16m 32m 64m; do
  min_log="$(min_result_log "/path/to/l2/page_rand_warm_${s}.*.log")"
  bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh \
    --stack linux_l2 --scenario page_rand_warm_${s} \
    --input "${min_log}" >> /tmp/metrics_raw.csv
done
```

Optional consistency check:

```bash
bash test/initramfs/src/benchmark/common/validate_bench_memory_matrix.sh \
  --input /tmp/metrics_raw.csv
```

## 12. Run quantification

```bash
bash test/initramfs/src/benchmark/common/analyze_memory_overhead_metrics.sh \
  --input /tmp/metrics_raw.csv \
  --output-dir /tmp/memory_nested_report \
  --nested-l1-system linux_l1 \
  --nested-l2-system linux_l2
```

Primary outputs for nested comparison:

1. `/tmp/memory_nested_report/nested_fixed_summary.csv`
2. `/tmp/memory_nested_report/nested_sweep_by_size.csv`
3. `/tmp/memory_nested_report/nested_sweep_summary.csv`

## 13. Interpretation checklist

Use `nested_fixed_summary.csv`:

1. `page_seq_cold` delta/ratio: nested cold first-touch fault amplification
2. `pf_proxy` delta/ratio: nested PF path overhead proxy
3. `tlb_walk_proxy` delta/ratio: nested page-walk overhead proxy
4. `word_seq_warm` delta/ratio: baseline translation-path overhead

Use `nested_sweep_summary.csv`:

1. `growth_ratio_64m_over_64k`: scale-up sensitivity in L1 vs L2
2. `tlb_knee_size_bytes`: where latency starts accelerating
3. `auc_tlb_walk_proxy`: aggregate walk-cost level over sweep
4. `avg_delta_result` and `peak_delta_result`: nested overhead magnitude

## 14. Frequent failure cases

1. `/proc/cpuinfo` missing in shell
Run `mount -t proc proc /proc`.

2. `/dev/kvm` missing in L1
Run `mount -t devtmpfs devtmpfs /dev` and confirm L1 booted with `-cpu host,+vmx`.

3. L2 panic `unknown-block(0,0)`
Verify `/ext2/l2/initramfs.cpio.gz` integrity and use slim L2 initramfs.

4. Benchmark knobs not matching expectation
In L1/L2, run one benchmark and verify printed header fields:
`Workset`, `Runs`, `Op mode`, `Warmup`.

5. `page_seq_cold` noise too high
Use outer repeated samples (`15+`) and aggregate by median (already supported by analysis pipeline).
