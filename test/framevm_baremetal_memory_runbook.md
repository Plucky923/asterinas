# Bare-Metal Memory Test Runbook (Strict Parity, Commands Only)

## 0. Workspace

```bash
cd /path/to/asterinas
```

## 1. Variables

```bash
export BARE_BUILD_DIR=/tmp/asterinas_baremem_build
export BARE_BIN_DIR="${BARE_BUILD_DIR}/initramfs/test/memory"
export BARE_BUILD_DIR_STORE=/tmp/asterinas_baremem_build_store
export BARE_BIN_DIR_STORE="${BARE_BUILD_DIR_STORE}/initramfs/test/memory"
export PIN_CPU=2
export IRQ_CPU=0
export MEM_COMPARE_WORKSET_BYTES=536870912
export MEM_COMPARE_RUNS=5
export MEM_COMPARE_SEED=12345
export MEM_COMPARE_DO_STORE=0
export MEM_PAGE_RAND_RUNS=10000
export MEM_PAGE_RAND_SEED=12345
export MEM_PAGE_RAND_DO_STORE=0
```

## 2. Tool Checks

```bash
command -v taskset
command -v cpupower
```

## 3. System Snapshot (Before)

```bash
mkdir -p /tmp/mem_host_sys

{
  echo "=== uname -a ==="
  uname -a
  echo "=== /proc/cmdline ==="
  cat /proc/cmdline
  echo "=== THP enabled ==="
  cat /sys/kernel/mm/transparent_hugepage/enabled
  echo "=== THP defrag ==="
  cat /sys/kernel/mm/transparent_hugepage/defrag
  echo "=== governor cpu${PIN_CPU} ==="
  cat /sys/devices/system/cpu/cpu${PIN_CPU}/cpufreq/scaling_governor || true
  echo "=== nproc ==="
  nproc
} | tee /tmp/mem_host_sys/before.txt
```

## 4. System Parity Setup

```bash
sudo cpupower frequency-set -g performance || true
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
echo never | sudo tee /sys/kernel/mm/transparent_hugepage/defrag

for f in /proc/irq/*/smp_affinity_list; do
  [ -f "$f" ] || continue
  echo "${IRQ_CPU}" | sudo tee "$f" >/dev/null || true
done
```

## 5. System Snapshot (After)

```bash
{
  echo "=== /proc/cmdline ==="
  cat /proc/cmdline
  echo "=== THP enabled ==="
  cat /sys/kernel/mm/transparent_hugepage/enabled
  echo "=== THP defrag ==="
  cat /sys/kernel/mm/transparent_hugepage/defrag
  echo "=== governor cpu${PIN_CPU} ==="
  cat /sys/devices/system/cpu/cpu${PIN_CPU}/cpufreq/scaling_governor || true
  echo "=== IRQ affinity sample ==="
  grep . /proc/irq/*/smp_affinity_list 2>/dev/null | head -n 40
} | tee /tmp/mem_host_sys/after.txt
```

## 6. Build (Load Group + Store Group)

```bash
make -C test/initramfs/src/apps/memory compare_all \
  BUILD_DIR="${BARE_BUILD_DIR}" \
  MEM_COMPARE_WORKSET_BYTES=${MEM_COMPARE_WORKSET_BYTES} \
  MEM_COMPARE_RUNS=${MEM_COMPARE_RUNS} \
  MEM_COMPARE_SEED=${MEM_COMPARE_SEED} \
  MEM_COMPARE_DO_STORE=${MEM_COMPARE_DO_STORE}

make -C test/initramfs/src/apps/memory page_rand_warm_sweep \
  BUILD_DIR="${BARE_BUILD_DIR}" \
  MEM_PAGE_RAND_RUNS=${MEM_PAGE_RAND_RUNS} \
  MEM_PAGE_RAND_SEED=${MEM_PAGE_RAND_SEED} \
  MEM_PAGE_RAND_DO_STORE=${MEM_PAGE_RAND_DO_STORE}

make -C test/initramfs/src/apps/memory bench_memory_page_rand_warm \
  BUILD_DIR="${BARE_BUILD_DIR_STORE}" \
  MEM_COMPARE_WORKSET_BYTES=${MEM_COMPARE_WORKSET_BYTES} \
  MEM_COMPARE_RUNS=${MEM_COMPARE_RUNS} \
  MEM_COMPARE_SEED=${MEM_COMPARE_SEED} \
  MEM_COMPARE_DO_STORE=1

make -C test/initramfs/src/apps/memory page_rand_warm_sweep \
  BUILD_DIR="${BARE_BUILD_DIR_STORE}" \
  MEM_PAGE_RAND_RUNS=${MEM_PAGE_RAND_RUNS} \
  MEM_PAGE_RAND_SEED=${MEM_PAGE_RAND_SEED} \
  MEM_PAGE_RAND_DO_STORE=1

ls -lh "${BARE_BIN_DIR}"/bench_memory_*
ls -lh "${BARE_BIN_DIR_STORE}"/bench_memory_page_rand_warm*
```

## 7. Run Fixed-Workset Scenarios

```bash
mkdir -p /tmp/mem_host
cd "${BARE_BIN_DIR}"

for i in $(seq 1 15); do taskset -c "${PIN_CPU}" ./bench_memory_page_seq_cold_store | tee /tmp/mem_host/page_seq_cold_store.${i}.log; done
taskset -c "${PIN_CPU}" ./bench_memory_page_seq_warm  | tee /tmp/mem_host/page_seq_warm.log
taskset -c "${PIN_CPU}" ./bench_memory_page_rand_warm | tee /tmp/mem_host/page_rand_warm.log
taskset -c "${PIN_CPU}" "${BARE_BIN_DIR_STORE}/bench_memory_page_rand_warm" | tee /tmp/mem_host/page_rand_warm_store.log
taskset -c "${PIN_CPU}" ./bench_memory_word_seq_warm  | tee /tmp/mem_host/word_seq_warm.log
```

## 8. Run Workset Sweep (Load + Store)

```bash
mkdir -p /tmp/mem_host_sweep
cd "${BARE_BIN_DIR}"

for s in 64k 128k 256k 512k 1m 2m 4m 8m 16m 32m 64m; do
  taskset -c "${PIN_CPU}" ./bench_memory_page_rand_warm_${s} | tee /tmp/mem_host_sweep/page_rand_warm_${s}.log
  taskset -c "${PIN_CPU}" "${BARE_BIN_DIR_STORE}/bench_memory_page_rand_warm_${s}" | tee /tmp/mem_host_sweep/page_rand_warm_${s}_store.log
done
```

## 9. Extract Result CSV

```bash
echo "stack,scenario,workset_bytes,runs,result,timestamp,input_file" > /tmp/metrics_host_raw.csv

for i in $(seq 1 15); do
  bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh \
    --stack host_baremetal \
    --scenario page_seq_cold_store \
    --input "/tmp/mem_host/page_seq_cold_store.${i}.log" >> /tmp/metrics_host_raw.csv
done

bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh \
  --stack host_baremetal \
  --scenario page_seq_warm \
  --input /tmp/mem_host/page_seq_warm.log >> /tmp/metrics_host_raw.csv

bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh \
  --stack host_baremetal \
  --scenario page_rand_warm \
  --input /tmp/mem_host/page_rand_warm.log >> /tmp/metrics_host_raw.csv

bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh \
  --stack host_baremetal \
  --scenario page_rand_warm_store \
  --input /tmp/mem_host/page_rand_warm_store.log >> /tmp/metrics_host_raw.csv

bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh \
  --stack host_baremetal \
  --scenario word_seq_warm \
  --input /tmp/mem_host/word_seq_warm.log >> /tmp/metrics_host_raw.csv

for s in 64k 128k 256k 512k 1m 2m 4m 8m 16m 32m 64m; do
  bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh \
    --stack host_baremetal \
    --scenario "page_rand_warm_${s}" \
    --input "/tmp/mem_host_sweep/page_rand_warm_${s}.log" >> /tmp/metrics_host_raw.csv
  bash test/initramfs/src/benchmark/common/extract_bench_memory_metrics.sh \
    --stack host_baremetal \
    --scenario "page_rand_warm_${s}_store" \
    --input "/tmp/mem_host_sweep/page_rand_warm_${s}_store.log" >> /tmp/metrics_host_raw.csv
done
```

## 10. Validate and Analyze

```bash
bash test/initramfs/src/benchmark/common/validate_bench_memory_matrix.sh \
  --input /tmp/metrics_host_raw.csv

bash test/initramfs/src/benchmark/common/analyze_memory_overhead_metrics.sh \
  --input /tmp/metrics_host_raw.csv \
  --output-dir /tmp/memory_host_report \
  --host-system host_baremetal \
  --guest-system host_baremetal \
  --container-system host_baremetal \
  --framevm-system host_baremetal
```

## 11. Merge with Nested CSV (Optional)

```bash
cat /tmp/metrics_host_raw.csv /tmp/metrics_l1_l2_raw.csv > /tmp/metrics_all_raw.csv

bash test/initramfs/src/benchmark/common/analyze_memory_overhead_metrics.sh \
  --input /tmp/metrics_all_raw.csv \
  --output-dir /tmp/memory_all_report \
  --host-system host_baremetal \
  --nested-l1-system linux_l1 \
  --nested-l2-system linux_l2
```

## 12. Output Files

```bash
ls -lh /tmp/memory_host_report
```
