# Virtio vsock 5-Stage RTT Quantification Toolkit

This toolkit decomposes virtio-vsock RTT into 5 stages in both directions:

1. sender user -> sender kernel
2. sender kernel processing
3. sender kernel -> receiver kernel
4. receiver kernel processing
5. receiver kernel -> receiver user

## Components

1. User benchmark binaries:
`test/initramfs/src/apps/vsock/vsock_rtt_seq_client.c`
`test/initramfs/src/apps/vsock/vsock_rtt_seq_server.c`
2. Kernel collectors:
`tools/vsock_quant/collect_kernel_events.sh` (bpftrace-based)
`tools/vsock_quant/collect_kernel_events_tracefs.sh` (tracefs-based, no bpftrace runtime)
`tools/vsock_quant/probe_map.sh` (probe/symbol audit)
`tools/vsock_quant/run_guest_round.sh` (guest one-command capture)
`tools/vsock_quant/run_host_round.sh` (host one-command capture with auto fallback)
`tools/vsock_quant/post_analyze_round.sh` (host one-command post analyze)
3. Analysis:
`tools/vsock_quant/analysis/parse_tracefs_events.py` (tracefs raw -> CSV)
`tools/vsock_quant/analysis/analyze_segments.py` (5-stage decomposition + stats)

## Prerequisites

1. Root permission for tracing.
2. tracefs/debugfs mounted on host/guest.
3. Python 3 on analysis machine (typically host).
4. Isolated benchmark environment (single vsock benchmark flow).
5. One in-flight ping-pong pattern (seq client/server default).
6. At least 100 request/response samples in the same run (for clock fitting).

## Recommended Workflow (tracefs raw mode)

For a strict copy-paste runbook, see:
`docs/virtio-vsock-rtt-5stage-quantification.md`

Minimal command flow after guest ext2 preparation:

1. In guest:
`/ext2/tools/vsock_quant/run_guest_round.sh --seconds 240`
2. In host:
`tools/vsock_quant/run_host_round.sh --run-dir /tmp/vsock_quant_run --no-syscall-pid-filter`
3. In host (after guest poweroff):
`tools/vsock_quant/post_analyze_round.sh --run-dir /tmp/vsock_quant_run`

If guest userspace is minimal, copy the collector into your guest-visible disk
before boot:

```bash
sudo mkdir -p /mnt/vsock_ext2
sudo mount -o loop test/initramfs/build/ext2.img /mnt/vsock_ext2
sudo mkdir -p /mnt/vsock_ext2/tools/vsock_quant/analysis
sudo install -m 0755 tools/vsock_quant/collect_kernel_events_tracefs.sh /mnt/vsock_ext2/tools/vsock_quant/collect_kernel_events_tracefs.sh
sudo install -m 0755 tools/vsock_quant/analysis/parse_tracefs_events.py /mnt/vsock_ext2/tools/vsock_quant/analysis/parse_tracefs_events.py
sudo umount /mnt/vsock_ext2
```

Also copy seq RTT binaries into ext2 so guest can run them even if initramfs is
not refreshed:

```bash
SEQ_BIN_DIR=/tmp/asterinas-apps-build/initramfs/test/vsock
test -x "${SEQ_BIN_DIR}/vsock_rtt_seq_server"
test -x "${SEQ_BIN_DIR}/vsock_rtt_seq_client"

STATIC_BIN_DIR=/tmp/vsock_quant_static
mkdir -p "${STATIC_BIN_DIR}"
gcc -O2 -static -o "${STATIC_BIN_DIR}/vsock_rtt_seq_server" test/initramfs/src/apps/vsock/vsock_rtt_seq_server.c
gcc -O2 -static -o "${STATIC_BIN_DIR}/vsock_rtt_seq_client" test/initramfs/src/apps/vsock/vsock_rtt_seq_client.c
file "${STATIC_BIN_DIR}/vsock_rtt_seq_server" | grep -q "statically linked"
file "${STATIC_BIN_DIR}/vsock_rtt_seq_client" | grep -q "statically linked"

sudo mkdir -p /mnt/vsock_ext2
sudo mount -o loop test/initramfs/build/ext2.img /mnt/vsock_ext2
sudo mkdir -p /mnt/vsock_ext2/vsock_bin
sudo install -m 0755 "${STATIC_BIN_DIR}/vsock_rtt_seq_server" /mnt/vsock_ext2/vsock_bin/vsock_rtt_seq_server
sudo install -m 0755 "${STATIC_BIN_DIR}/vsock_rtt_seq_client" /mnt/vsock_ext2/vsock_bin/vsock_rtt_seq_client
sudo umount /mnt/vsock_ext2
```

## 1) Build seq benchmarks

```bash
make -C test/initramfs/src/apps/vsock BUILD_DIR=/tmp/asterinas-apps-build
```

## 2) Audit probe availability

```bash
sudo tools/vsock_quant/probe_map.sh
```

## 3) Collect host and guest kernel events as raw trace

Host:

```bash
sudo tools/vsock_quant/collect_kernel_events_tracefs.sh \
  --pid <client_pid> --side host --seconds 40 \
  --out /tmp/host_kernel.raw --no-parse
```

If host syscall events are zero in containerized environments (PID namespace
mismatch), rerun host collection with:

```bash
sudo tools/vsock_quant/collect_kernel_events_tracefs.sh \
  --pid <client_pid> --side host --seconds 40 \
  --out /tmp/host_kernel.raw --no-parse --no-syscall-pid-filter
```

Guest:

```bash
sudo tools/vsock_quant/collect_kernel_events_tracefs.sh \
  --pid <server_pid> --side guest --seconds 40 \
  --out /tmp/guest_kernel.raw --no-parse
```

`--no-parse` is the default recommendation for minimal guests that do not have
`python3` or `bpftrace`.

## 4) Parse raw trace to kernel CSV

```bash
python3 tools/vsock_quant/analysis/parse_tracefs_events.py \
  --in /tmp/host_kernel.raw --out /tmp/host_kernel.csv --side host

python3 tools/vsock_quant/analysis/parse_tracefs_events.py \
  --in /tmp/guest_kernel.raw --out /tmp/guest_kernel.csv --side guest
```

## 5) Analyze and decompose

```bash
python3 tools/vsock_quant/analysis/analyze_segments.py \
  --client-csv /tmp/client_user.csv \
  --server-csv /tmp/server_user.csv \
  --host-kernel-csv /tmp/host_kernel.csv \
  --guest-kernel-csv /tmp/guest_kernel.csv \
  --out-dir /tmp/vsock_quant_out
```

Outputs:

1. `/tmp/vsock_quant_out/segments_seq.csv`
2. `/tmp/vsock_quant_out/segments_summary.csv`
3. `/tmp/vsock_quant_out/quality_report.txt`

## Data Model

`segments_seq.csv` row fields:

1. `direction` (`host_to_guest` / `guest_to_host`)
2. `T1_ns..T5_ns`
3. `T_total_ns`
4. `RTT_user_ns`
5. `residual_ns`

## Notes

1. Host/guest clock mapping uses NTP-like offset estimation from user events.
2. Quality report includes drift/offset fit and event pairing diagnostics.
3. Negative segments beyond tolerance are filtered and counted.
4. kprobe-based `TX_OUT`/`RX_IN` may include unrelated traffic; isolate workload.
5. The collector filters PID only for syscall events; TX/RX are intentionally not
PID-filtered so events emitted in softirq/worker context are preserved.
6. Syscall capture supports both `sendto/recvfrom` and `sendmsg/recvmsg` paths.
