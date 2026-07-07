# FrameVM Test Runner

FrameVM runtime tests use the same selection style as kernel run tests:

```sh
make run_framevm AUTO_TEST=<case>
```

Supported cases:

| `AUTO_TEST` | Init path | Success marker | Coverage | Cost |
| --- | --- | --- | --- | --- |
| unset | `/test/framevm/shell.sh` | none | Interactive Asterinas host shell for hand-driven `framevmctl` demos. | QEMU/KVM interactive |
| `load` | `/test/framevm/load.sh` | `FRAMEVM_LOAD_OK` | Load smoke path. | QEMU/KVM smoke |
| `boot` | `/test/framevm/boot.sh` | `FRAMEVM_BOOT_OK` | Build/reuse FrameVM artifacts, boot the host kernel, start FrameVM through `framevmctl`, and observe load success. | QEMU/KVM smoke |
| `regression` | `/test/framevm/regression.sh` | `FRAMEVM_REGRESSION_OK` | FrameVM regression script placeholder for guest-service regression coverage. | QEMU/KVM medium |
| `device` | `/test/framevm/device.sh` | `FRAMEVM_DEVICE_OK` | FrameV device coverage, including migrated FrameV sock guest/host traffic. | QEMU/KVM medium |
| `rootfs` | `/test/framevm/rootfs.sh` | `FRAMEVM_ROOTFS_OK` | Raw ext2 rootfs path through a copied `/framevm/rootfs.ext2` drive image. | QEMU/KVM medium |
| `lifecycle` | `/test/framevm/lifecycle.sh` | `FRAMEVM_LIFECYCLE_OK` | Terminal-status coverage for guest success, guest failure, restart-requested, missing marker, console EOF before terminal status, and host stop. | QEMU/KVM long |
| `all` | `/test/framevm/all.sh` | child case markers | Runs `boot`, `regression`, `device`, and `rootfs` as child cases. | QEMU/KVM long |

Positive runtime cases require the FrameVM artifact set produced by OSDK and a
host initramfs carrier containing `/framevm/rootfs.ext2`. The helper copies
that image to a case-local `/tmp/framevm-<case>-rootfs.ext2` and passes the
copy to `framevmctl --drive file=...`, so tests do not mutate the packaged
baseline image.

`make check` runs only the fast static FrameVM architecture gate
`framevm_service_check`. QEMU/KVM runtime cases remain explicit
`make run_framevm AUTO_TEST=<case>` runs.

Temporary drives, logs, and child helper processes are cleaned by
`common.sh` traps on success, failure, timeout, and signal exit. Set
`FRAMEVM_KEEP_ARTIFACTS=1` to keep temporary drives and logs for debugging.

## Migrated Coverage

| Previous entrypoint | Current owner |
| --- | --- |
| `/test/framevm_load.sh` | `AUTO_TEST=load` and `AUTO_TEST=boot` via `/test/framevm/load.sh` and `/test/framevm/boot.sh` |
| `/test/framev_vsock_test.sh` | `make run_framevm AUTO_TEST=device` via `/test/framevm/device.sh` |
| long-term `make framev_vsock_test` target | removed; device coverage runs through `AUTO_TEST=device` |
| OSDK default FrameVM load action | `/test/framevm/shell.sh` |
| `/dev/framevm`, `framevmctl`, and ioctl validation | normal kernel regression target `test/initramfs/src/regression/device/framevm.c` |

Host-control regression remains in the normal kernel regression suite because
it validates the host `/dev/framevm` device and userspace `framevmctl` ABI,
not guest service behavior inside a loaded FrameVM.
