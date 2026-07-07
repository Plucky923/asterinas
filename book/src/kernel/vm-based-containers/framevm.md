# FrameVM Control Device

FrameVM exposes a host-side control device at `/dev/framevm`.
User space opens this device to create a VM file descriptor,
then drives that VM through ioctls on the returned descriptor.

## Create Request

`FRAMEVM_CREATE_VM` takes the following C layout:

```c
struct framevm_create_vm {
    uint32_t vcpu_count;
    uint32_t share;
    uint32_t flags;
    uint32_t reserved;
};
```

The structure size is 16 bytes and its alignment is 4 bytes.
The `flags` and `reserved` fields must be zero.

Valid creation ranges are:

- `vcpu_count`: 1 to 4
- `share`: 2 to 262144

Invalid ranges or nonzero reserved fields fail with `EINVAL`.

## Ioctls

All FrameVM ioctls use magic byte `F`.

| Command | Type | Number | File descriptor | Description |
|---------|------|--------|-----------------|-------------|
| `FRAMEVM_CREATE_VM` | `_IOW` | `0x01` | `/dev/framevm` | Creates a VM and returns a VM fd. |
| `FRAMEVM_START` | `_IO` | `0x02` | VM fd | Starts a created VM. |
| `FRAMEVM_STOP` | `_IO` | `0x03` | VM fd | Stops the VM. |
| `FRAMEVM_GET_CONSOLE_FD` | `_IO` | `0x04` | VM fd | Returns a console fd for the VM. |

Calling VM-only commands on `/dev/framevm`, or calling
`FRAMEVM_CREATE_VM` on a VM fd, fails with `ENOTTY`.
Unknown FrameVM ioctls also fail with `ENOTTY`.

## Lifecycle

A VM fd starts in the created state.
`FRAMEVM_START` transitions it to running.
If a lifecycle transition is already in progress,
the ioctl fails with `EBUSY`.
Starting an already running VM fails with `EALREADY`.
Starting a stopped VM fails with `EINVAL`.

`FRAMEVM_STOP` is idempotent for created and stopped VMs.
Closing a VM fd stops a running VM before releasing the file.

## Console FD

`FRAMEVM_GET_CONSOLE_FD` returns an fd backed by the FrameVM console.
It is valid while the VM is created or running.
The console fd starts reading from the current console tail offset,
so multiple console fds can read independently from the point at which
they were created.

The console is non-seekable.
When no input or output space is available,
nonblocking console operations return `EAGAIN`.
