# FrameVM Test Runner

FrameVM runtime tests use the same selection style as kernel run tests:

```sh
make run_framevm AUTO_TEST=<case>
```

`MEM` controls the outer Host QEMU. `FRAMEVM_MEMORY_LIMIT` controls the
private heap limit passed to inner FrameVM instances and defaults to `8G`.
The memory-specific target deliberately uses a small inner limit while keeping
the Host at a normal size:

```sh
make run_framevm_memory
```

Supported cases:

| `AUTO_TEST` | Init path | Success marker | Coverage | Cost |
| --- | --- | --- | --- | --- |
| unset | `/test/framevm/shell.sh` | none | Interactive Asterinas host shell for hand-driven `framevmm` demos. | QEMU/KVM interactive |
| `load` | `/test/framevm/load.sh` | `FRAMEVM_LOAD_OK` | Load smoke path. | QEMU/KVM smoke |
| `boot` | `/test/framevm/boot.sh` | `FRAMEVM_BOOT_OK` | Build/reuse FrameVM artifacts, boot the host kernel, start FrameVM through `framevmm`, and observe load success. | QEMU/KVM smoke |
| `regression` | `/test/framevm/regression.sh` | `FRAMEVM_REGRESSION_OK` | FrameVM regression script placeholder for guest-service regression coverage. | QEMU/KVM medium |
| `device` | `/test/framevm/device.sh` | `FRAMEVM_DEVICE_OK` | FrameV device coverage, including migrated FrameV sock guest/host traffic. | QEMU/KVM medium |
| `nvme-passthrough` | `/test/framevm/nvme_passthrough.sh` | `FRAMEVM_NVME_PASSTHROUGH_OK` | Boot-reserved QEMU NVMe assignment through the unchanged driver, multi-segment read/write/flush, BIO-local failure, owner-fd loss, and immediate reassignment. | QEMU/KVM long |
| `memory` | `/test/framevm/memory.sh` | `FRAMEVM_MEMORY_OK` | Starts with an explicit inner cap, allocates and releases a bounded private buffer, then boots a sibling with a distinct FrameV Sock CID. Exact OOM admission and rollback are covered by FrameVisor kernel tests. | QEMU/KVM medium |
| `allocator` | `/test/framevm/allocator.sh` | `FRAMEVM_ALLOCATOR_OK` | Starts two FrameVM instances concurrently with distinct CIDs; each exercises the service heap and page-backed mappings, then requires independent terminal success and allocator markers. | QEMU/KVM medium |
| `rootfs` | `/test/framevm/rootfs.sh` | `FRAMEVM_ROOTFS_OK` | Raw ext2 rootfs path through a copied `/framevm/rootfs.ext2` drive image and three sequential FrameVM starts. | QEMU/KVM medium |
| `lifecycle` | `/test/framevm/lifecycle.sh` | `FRAMEVM_LIFECYCLE_OK` | Terminal-status coverage for guest success, guest failure, restart requests, missing marker, console EOF before terminal status, and host stop. | QEMU/KVM long |
| `net` | `/test/framevm/net.sh` | `FRAMEV_NET_OK` | FrameV-owned RX through ARP, TCP setup, HTTP transfer, and teardown against the Rust/smoltcp datagram peer. | QEMU/KVM medium |
| `application` | `/test/framevm/application.sh` | `FRAMEVM_APPLICATION_OK` | Runs a bounded pinned SQLite workload and restart integrity gate on FrameV-blk, then retrieves the deterministic Nginx page through FrameV-net and requires clean shutdown. | QEMU/KVM medium |
| `placement` | `/test/framevm/placement.sh` | `FRAMEVM_PLACEMENT_OK` | Changes a two-vCPU FrameVM's captured Host cpuset while idle and busy; verifies empty-set blocking, wakeup after restoration, continued progress, stable virtual CPU identity, and absence of a cgroupfs node for the hidden scheduler group. | QEMU/KVM medium |
| `smp` | `/test/framevm/smp.sh` | `FRAMEVM_SMP_OK` | Runs two- and four-vCPU identity, concurrency, and lifecycle coverage. | QEMU/KVM long |
| `fairness` | `/test/framevm/fairness.sh` | `FRAMEVM_FAIRNESS_OK` | Runs synchronized pairs of CPU-bound FrameVMs on one Host CPU; checks equal-share progress, a broad 2:1..8:1 bound for 256:1024 shares, creator movement, hidden-group absence, and captured-parent CPU accounting. | QEMU/KVM long |
| `all` | `/test/framevm/all.sh` | `FRAMEVM_CASE_RESULT case=all result=pass` | Runs the non-PCI service, storage, lifecycle, networking, placement, fairness, and shell cases sequentially in one Host boot. | QEMU/KVM long |

Positive runtime cases require the FrameVM artifact set produced by OSDK and a
host initramfs carrier containing `/framevm/rootfs.ext2.gz`. The helper
validates decompression into the sole writable case-local
`/tmp/framevm-<case>-rootfs.ext2`, then passes it to the QEMU-shaped
`framevmm -drive` fixture. Tests do not mutate the packaged baseline image, and
the carrier no longer materializes a second uncompressed copy in host memory.

`make check` runs only the fast static FrameVM architecture gate
`framevm_service_check`. QEMU/KVM runtime cases remain explicit
`make run_framevm AUTO_TEST=<case>` runs.

The OSDK accepts a case only after the host script emits both
`FRAMEVM_CASE_RESULT case=<case> result=pass` and a FrameVM terminal status.
QEMU is allowed to exit naturally after the case result;
the OSDK rereads the completed log before deciding success. Use
`make run_framevm_no_build AUTO_TEST=<case>` only after a matching regular run,
and `make run_framevm_smoke` to exercise build and no-build paths together.

`make run_framevm_full` runs the non-PCI supported cases as separate
sequential Host boots, avoiding shared `qemu.log` and temporary-drive
ownership. Run `make run_framevm AUTO_TEST=nvme-passthrough` separately when
the reserved NVMe function and IOMMU prerequisites are available.

The FrameVM application case reuses the SQLite and Nginx derivations already
covered by the Host benchmark suite instead of rebuilding or patching either
application. It defaults to `sqlite-speedtest1 --size 25`: enough to exercise
tables, indexes, writes, and restart integrity without turning each FrameVM
application check into a Host performance benchmark. `FRAMEVM_SQLITE_SIZE`
may select a value from 1 through 100 for an explicit heavier validation.
When a FrameVM failure needs performance comparison against the Host kernel,
rerun the corresponding existing coverage:

```sh
./test/initramfs/src/benchmark/bench_linux_and_aster.sh sqlite/ext2_benchmarks
./test/initramfs/src/benchmark/bench_linux_and_aster.sh nginx/http_file16KB_bw
```

Temporary drives, logs, and child helper processes are cleaned by
`common.sh` traps on success, failure, timeout, and signal exit. Set
`FRAMEVM_KEEP_ARTIFACTS=1` to keep temporary drives and logs for debugging.

The current non-co-designed service teardown deliberately retains opaque
service-owned frames and their FrameV Sock CID until a future service-side
teardown protocol can release them safely. `common.sh` therefore assigns a
fresh CID to each `framevmm` invocation in one Host test. Aggregate children
receive separate CID ranges; tests that launch `framevmm` directly use the
same allocator before starting it.

## Migrated Coverage

| Previous entrypoint | Current owner |
| --- | --- |
| `/test/framevm_load.sh` | `AUTO_TEST=load` and `AUTO_TEST=boot` via `/test/framevm/load.sh` and `/test/framevm/boot.sh` |
| `/test/framev_vsock_test.sh` | `make run_framevm AUTO_TEST=device` via `/test/framevm/device.sh` |
| long-term `make framev_vsock_test` target | removed; device coverage runs through `AUTO_TEST=device` |
| OSDK default FrameVM load action | `/test/framevm/shell.sh` |
| `/dev/framevm`, `framevmm`, and ioctl validation | normal kernel regression target `test/initramfs/src/regression/device/framevm.c` |

Host-control regression remains in the normal kernel regression suite because
it validates the host `/dev/framevm` device and userspace `framevmm` ABI,
not guest service behavior inside a loaded FrameVM.
