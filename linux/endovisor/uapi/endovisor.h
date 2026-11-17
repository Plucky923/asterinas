/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Endovisor defines ioctls on `/dev/endovisor` and its sandbox
// descriptors for launching SMP Asterinas kernelets on Linux.

#ifndef UAPI_ENDOVISOR_H
#define UAPI_ENDOVISOR_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define IOC_MAGIC		'K'

#define MAX_VCPUS		64
#define MAX_GRANT_MB	512
#define DEFAULT_MAX_TASKS	256
#define CMDLINE_MAX		1744
#define INITRAMFS_MAX	(128UL << 20)
#define IMAGE_MAX		(256UL << 20)

#define PT_MODE_DIRECT	0
#define PT_MODE_VMA		1

// Argument to `KIND_REGISTER`.
//
// `elf_ptr` and `elf_len` describe a self-contained x86-64 `ET_DYN` PIE image.
// On success, the ioctl stores the assigned identifier in `kind_id` and
// returns 0.
struct kind_register {
	__u64 elf_ptr;		// `const void *`, user pointer to ELF image
	__u64 elf_len;		// byte length of ELF image
	__u32 flags;		// must be 0
	__u32 kind_id;		// out: registered kind identifier
};

// Argument to `SANDBOX_CREATE`.
//
// `grant_mb` is rounded up to a 2 MiB grain multiple (max `MAX_GRANT_MB`).
// `max_tasks` defaults to `DEFAULT_MAX_TASKS` (256) when `0`.
// `max_tasks + nr_vcpus + 1` must fit in `u32` after applying the default.
// `pt_mode` selects `PT_MODE_DIRECT` (0) or `PT_MODE_VMA` (1).
// Returns a sandbox file descriptor on success.
struct sandbox_create {
	__u32 kind_id;		// registered kind identifier
	__u32 nr_vcpus;		// 1..MAX_VCPUS
	__u32 grant_mb;		// grant size in MiB (up to 512; 0 defaults to 64)
	__u32 max_tasks;	// 0 uses DEFAULT_MAX_TASKS (256)
	__u32 pt_mode;		// PT_MODE_DIRECT (0) or PT_MODE_VMA (1)
	__u32 flags;		// must be 0
	__u64 cmdline_ptr;	// `const char *`, user pointer
	__u64 cmdline_len;	// byte length without trailing NUL
	__u64 initramfs_ptr;	// `const void *`, user pointer (or 0)
	__u64 initramfs_len;	// byte length (or 0)
};

// Sandbox exit and diagnostic statistics returned by `SANDBOX_STATS`.
struct sandbox_stats {
	__u32 exit_kind;	// `0`: exit; `1`: panic; `2`: stack overflow; `3`: killed
	__u32 exit_code;	// image exit code or signal/reason, not a `wait(2)` status
	char exit_msg[256];	// NUL-terminated exit or panic message
	__u64 fpu_saves;
	__u64 fpu_restores;
	__u64 vm_creates;
	__u64 vm_destroys;
	__u64 vm_flushes;
	__u64 vm_maps;
	__u64 vm_protects;
	__u64 vm_unmaps;
	__u64 exceptions;
	__u64 page_faults;
	__u64 virqs;
	__u64 forced_yields;
	// Syscall returns failing the SYSRET precheck before Linux exit work.
	// This does not observe the final return instruction; `~0ULL` means unobserved.
	__u64 non_sysret;
	__u64 bench_vm_apply_cycles;
	// Observed syscall entries; `~0ULL` means auditing was disabled.
	__u64 syscalls;
	__u64 image_load_base;
	__u64 grant_grains_allocated;
	__u64 grant_grains_freed;
};

// The ioctl for registering a raw x86-64 kernelet ELF image.
//
// Takes `struct kind_register` and copies its image bytes before validation.
// Returns `0` and writes `kind_id` only when registration succeeds.
// Invalid arguments or images return `EINVAL` or `ENOEXEC`;
// inaccessible buffers return `EFAULT`, and a full registry returns `ENOSPC`.
// Allocation failures return `ENOMEM`.
//
// # Security
// Requires `CAP_SYS_MODULE` and enabled module loading.
// Linux LSM load-data hooks must permit the supplied bytes.
// This raw-image interface rejects enforced signatures and module lockdown.
#define KIND_REGISTER	_IOWR(IOC_MAGIC, 0x01, struct kind_register)

// The ioctl for creating a sandbox from a registered image kind.
//
// Takes `struct sandbox_create` and returns an `O_CLOEXEC` sandbox descriptor.
// `flags` must be `0`; the argument limits and defaults are defined above.
// Invalid arguments return `EINVAL`, an absent kind returns `ENOENT`,
// and exhausted registry or memory resources return `ENOSPC` or `ENOMEM`.
// Invalid command-line or initramfs buffers return `EFAULT`.
// Closing the last descriptor requests sandbox termination.
#define SANDBOX_CREATE	_IOW(IOC_MAGIC, 0x02, struct sandbox_create)

// The ioctl for unregistering an image kind.
//
// Takes a pointer to a `u32` kind identifier and returns `0` on success.
// A missing kind returns `ENOENT`; a kind still used by a live sandbox
// returns `EBUSY`; an invalid identifier or pointer returns `EINVAL` or `EFAULT`.
//
// # Security
// Requires `CAP_SYS_MODULE` and enabled module loading.
#define KIND_UNREGISTER	_IOW(IOC_MAGIC, 0x03, __u32)

// The ioctl for obtaining an executable descriptor for one virtual CPU.
//
// Takes a pointer to its `u32` index and returns an `O_CLOEXEC` descriptor
// that can be passed to `execveat` with `AT_EMPTY_PATH`.
// An invalid index returns `EINVAL`, an already claimed vCPU returns `EBUSY`,
// and a stopping sandbox returns `ESRCH`.
// Descriptor allocation and user-pointer errors are propagated.
#define SANDBOX_GET_VCPU_FD	_IOW(IOC_MAGIC, 0x10, __u32)

// The ioctl for converting the calling task into a virtual CPU carrier.
//
// Takes a pointer to its `u32` index.
// The caller must be single-threaded and own unshared descriptor and signal-handler tables.
// Success discards the caller's user mappings and enters the kernelet;
// the original user program does not resume.
// Conversion releases the caller's Linux userspace registrations as on `exec`.
// Invalid indices or shared task state return `EINVAL`; an occupied vCPU
// returns `EBUSY`, and a stopping sandbox returns `ESRCH`.
// Failures before conversion preserve the original userspace context.
// Failures after conversion terminate the carrier.
#define SANDBOX_ATTACH_VCPU	_IOW(IOC_MAGIC, 0x11, __u32)

// The ioctl for reading a sandbox's current exit information and counters.
//
// Writes `struct sandbox_stats` and returns `0`, or `EFAULT` for an invalid buffer.
// While the sandbox runs this is a live snapshot.
// Use `read` or wait for descriptor readability to obtain completed-exit statistics.
#define SANDBOX_STATS	_IOR(IOC_MAGIC, 0x12, struct sandbox_stats)

// The ioctl for requesting termination of all sandbox carriers.
//
// Takes no argument and returns `0`; repeated requests are harmless.
// The first termination reason is retained.
// Descriptor readability reports completion; this operation only requests it.
#define SANDBOX_KILL	_IO(IOC_MAGIC, 0x13)

#define ENDOVISOR_PROF_MAX_FRAMES	24

// One captured instruction-pointer callchain sample from isolated `profile_hz` mode.
struct sandbox_prof_sample {
	__u32 nr_frames;	// valid entries in `frames` (leaf first at index 0)
	__u32 vcpu;		// carrier vCPU index
	__u64 frames[ENDOVISOR_PROF_MAX_FRAMES];
};

// Arguments for `SANDBOX_PROF_DUMP`.
struct sandbox_prof_dump {
	__u64 buf_ptr;		// `struct sandbox_prof_sample *` user buffer
	__u32 capacity;		// max samples writable to `buf_ptr`
	__u32 count;		// out: samples copied (or total available if `capacity == 0`)
	__u64 dropped;		// out: samples dropped due to ring capacity
};

// The ioctl for draining captured stack samples after isolated `profile_hz` runs.
//
// Writes up to `capacity` `struct sandbox_prof_sample` entries to `buf_ptr`,
// populates `count` and `dropped`, and returns `0`, or `EFAULT`/`EINVAL`.
#define SANDBOX_PROF_DUMP	_IOWR(IOC_MAGIC, 0x14, struct sandbox_prof_dump)

#endif // UAPI_ENDOVISOR_H
