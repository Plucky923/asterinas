# FrameVM Control Device

FrameVM exposes a Host-side control device at `/dev/framevm`. User space opens
this device to create an immutable-version VM draft, configures resources on
the returned VM file descriptor, and commits the draft with `FRAMEVM_START`.

The current management ABI version is `2`. All request structures use fixed C
layouts. Unknown flags and nonzero reserved fields are rejected with `EINVAL`.

## Create Request

`FRAMEVM_CREATE_VM` takes the following 24-byte, 4-byte-aligned structure and
returns a VM fd:

```c
struct framevm_create_vm {
    uint32_t api_version;
    uint32_t vcpu_count;
    uint32_t share;
    uint32_t flags;
    uint32_t memory_limit_bytes[2];
};
```

For version 2, `api_version` is `2`, `flags` is zero, and
`memory_limit_bytes` contains the requested byte limit as a little-endian
64-bit value split into low and high 32-bit words. The limit must be nonzero
and page-aligned. `vcpu_count` is between 1 and 4, and `share` is between 2
and 262144. Creation does not start the VM and does not acquire physical
devices.

## Ioctls

All FrameVM ioctls use magic byte `F`.

| Command | Type | Number | File descriptor | Description |
|---------|------|--------|-----------------|-------------|
| `FRAMEVM_CREATE_VM` | `_IOW` | `0x01` | `/dev/framevm` | Creates a versioned VM draft and returns a VM fd. |
| `FRAMEVM_START` | `_IO` | `0x02` | VM fd | Atomically commits the draft and starts the VM. |
| `FRAMEVM_STOP` | `_IO` | `0x03` | VM fd | Stops the VM. |
| `FRAMEVM_GET_CONSOLE_FD` | `_IO` | `0x04` | VM fd | Returns an independent nonblocking console fd. |
| `FRAMEVM_GET_STATUS` | `_IOR` | `0x06` | VM fd | Writes the current lifecycle status. |
| `FRAMEVM_GET_MEMORY_STATUS` | `_IOR` | `0x0f` | VM fd | Writes the VM memory-accounting snapshot. |
| `FRAMEVM_SET_CMDLINE` | `_IOW` | `0x07` | VM fd | Stores a validated guest command-line suffix. |
| `FRAMEVM_ADD_BLOCK` | `_IOW` | `0x0b` | VM fd | Captures the root block-image fd. |
| `FRAMEVM_ASSIGN_PCI` | `_IOW` | `0x0e` | VM fd | Stages one boot-reserved PCI function for assignment at start. |

Calling a VM-only command on `/dev/framevm`, calling `FRAMEVM_CREATE_VM` on a
VM fd, or using an unknown command fails with `ENOTTY`.

## Draft Configuration

Configuration operations are append-only and are accepted only in the created
state. A concurrent start or stop returns `EBUSY`; configuration after a
terminal state returns `EINVAL`. Request values are copied at ioctl entry.
Resource fds are resolved and retained by the kernel, so closing or reusing the
caller fd after a successful ioctl does not change the draft.

`FRAMEVM_SET_CMDLINE` accepts this 16-byte, 8-byte-aligned structure:

```c
struct framevm_cmdline {
    uint64_t ptr;
    uint32_t len;
    uint32_t flags;
};
```

The copied suffix is at most 4096 bytes, is ASCII without NUL bytes, and uses
`flags == 0`. It may not override `kernel.realtime_base_ns`,
`kernel.monotonic_base_ns`, or `ostd.vcpu_count`. Invalid data returns
`EINVAL`; an invalid pointer returns `EFAULT`. A second cmdline request returns
`EEXIST`.

`FRAMEVM_ADD_BLOCK` accepts this 16-byte, 4-byte-aligned structure:

```c
struct framevm_block {
    int32_t fd;
    uint32_t device_id;
    uint32_t flags;
    uint32_t reserved;
};
```

Version 1 supports only `device_id == 0`. `FRAMEVM_BLOCK_READ_ONLY` (`1 << 0`)
is the only flag. The fd must identify a readable regular file whose nonzero
size is 512-byte aligned; writable mode also requires a writable fd. A root
block image is required to start a VM.

`FRAMEVM_ASSIGN_PCI` accepts this 16-byte, 8-byte-aligned structure:

```c
struct framevm_assigned_pci {
    uint16_t segment;
    uint8_t bus;
    uint8_t device_function;
    uint32_t flags;
    uint64_t reserved;
};
```

`device_function` encodes the device in bits 7:3 and function in bits 2:0.
Version 1 supports segment 0, function 0, no flags, and at most one staged PCI
function. The function must have been reserved with `framevm.pci_reserve`.
Staging a BDF grants no hardware authority: `FRAMEVM_START` revalidates and
claims the complete requester group, DMA domain, BAR access, and interrupt
routes as one rollback-capable transaction.

## Status and Lifecycle

`FRAMEVM_GET_STATUS` writes this 8-byte, 4-byte-aligned structure:

```c
struct framevm_status {
    uint32_t state;
    int32_t code;
};
```

The state is `CREATED`, `STARTING`, `RUNNING`, or `EXITED`. The `code` field is
zero for a successful exit and otherwise carries the guest or Host exit code.
The control device does not expose the internal VM identity or scheduler
state.

A VM fd starts in the created state. `FRAMEVM_START` is the sole commit point.
Starting an already running VM returns `EALREADY`; starting a terminal VM
returns `EINVAL`. A start failure is terminal after the start transaction has
been committed; cleanup completes before the terminal status is published.

`FRAMEVM_STOP` is idempotent for created and exited VMs. Closing the final VM
fd performs the corresponding stop before releasing the VM. A guest restart
request is reported as an exited status with its exit code; version 2 does not
restart the same VM fd.

`FRAMEVM_GET_MEMORY_STATUS` writes this 56-byte, 8-byte-aligned structure:

```c
struct framevm_memory_status {
    uint64_t limit_bytes;
    uint64_t committed_bytes;
    uint64_t reserved_bytes;
    uint64_t reusable_bytes;
    uint64_t active_bytes;
    uint64_t oom_count;
    uint64_t reclaim_count;
};
```

The snapshot reports the configured limit together with VM-local committed,
reserved, reusable, and active bytes. The two counters record allocation
pressure and reclaim activity.

## Console FD

`FRAMEVM_GET_CONSOLE_FD` returns an fd backed by the FrameVM console. Multiple
console fds have independent cursors beginning at the output tail observed at
creation. The console is non-seekable. Nonblocking reads and writes return
`EAGAIN` when no input or output space is available.
