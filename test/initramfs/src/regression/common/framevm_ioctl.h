/* SPDX-License-Identifier: MPL-2.0 */

#ifndef ASTERINAS_FRAMEVM_IOCTL_H
#define ASTERINAS_FRAMEVM_IOCTL_H

#include <stdint.h>
#include <sys/ioctl.h>

#define FRAMEVM_IOCTL_MAGIC 'F'
#define FRAMEVM_DEFAULT_SHARE 1024U
#define FRAMEVM_MIN_VCPU_COUNT 1U
#define FRAMEVM_MAX_VCPU_COUNT 4U
#define FRAMEVM_MIN_SHARE 2U
#define FRAMEVM_MAX_SHARE 262144U
#define FRAMEVM_CREATE_HAS_DRIVE (1U << 0)
#define FRAMEVM_CREATE_DRIVE_READONLY (1U << 1)
#define FRAMEVM_STATUS_VM_ID_NONE UINT64_MAX
#define FRAMEVM_CMDLINE_MAX_LEN 4096U

#define FRAMEVM_STATE_CREATED 0U
#define FRAMEVM_STATE_STARTING 1U
#define FRAMEVM_STATE_RUNNING 2U
#define FRAMEVM_STATE_EXITED_SUCCESS 3U
#define FRAMEVM_STATE_EXITED_FAILURE 4U
#define FRAMEVM_STATE_RESTART_REQUESTED 5U
#define FRAMEVM_STATE_STOPPED_BY_HOST 6U
#define FRAMEVM_STATE_PANIC_FAILURE 7U
#define FRAMEVM_STATE_DESTROYED 8U

#define FRAMEVM_TERMINAL_NONE 0U
#define FRAMEVM_TERMINAL_GUEST_EXIT 1U
#define FRAMEVM_TERMINAL_POWEROFF 2U
#define FRAMEVM_TERMINAL_RESTART 3U
#define FRAMEVM_TERMINAL_HOST_STOP 4U
#define FRAMEVM_TERMINAL_FD_CLOSE 5U
#define FRAMEVM_TERMINAL_PANIC 6U
#define FRAMEVM_TERMINAL_SETUP_FAILED 7U

#define FRAMEVM_FAILURE_NONE 0U
#define FRAMEVM_FAILURE_GUEST_EXIT_CODE 1U
#define FRAMEVM_FAILURE_PANIC 2U
#define FRAMEVM_FAILURE_SETUP 3U
#define FRAMEVM_FAILURE_HOST_STOP 4U

struct framevm_create_vm {
	uint32_t vcpu_count;
	uint32_t share;
	uint32_t flags;
	uint32_t reserved;
};

struct framevm_cmdline {
	uint64_t ptr;
	uint32_t len;
	uint32_t flags;
};

struct framevm_status {
	uint32_t state;
	uint32_t terminal_reason;
	int32_t status_code;
	uint32_t failure_class;
	uint64_t vm_id;
	uint64_t reserved;
};

#define FRAMEVM_CREATE_VM \
	_IOW(FRAMEVM_IOCTL_MAGIC, 0x01, struct framevm_create_vm)
#define FRAMEVM_START _IO(FRAMEVM_IOCTL_MAGIC, 0x02)
#define FRAMEVM_STOP _IO(FRAMEVM_IOCTL_MAGIC, 0x03)
#define FRAMEVM_GET_CONSOLE_FD _IO(FRAMEVM_IOCTL_MAGIC, 0x04)
#define FRAMEVM_GET_STATUS \
	_IOR(FRAMEVM_IOCTL_MAGIC, 0x06, struct framevm_status)
#define FRAMEVM_SET_CMDLINE \
	_IOW(FRAMEVM_IOCTL_MAGIC, 0x07, struct framevm_cmdline)

_Static_assert(sizeof(struct framevm_create_vm) == 16,
	       "framevm_create_vm must stay ABI-stable");
_Static_assert(_Alignof(struct framevm_create_vm) == 4,
	       "framevm_create_vm alignment must stay ABI-stable");
_Static_assert(sizeof(struct framevm_cmdline) == 16,
	       "framevm_cmdline must stay ABI-stable");
_Static_assert(_Alignof(struct framevm_cmdline) == 8,
	       "framevm_cmdline alignment must stay ABI-stable");
_Static_assert(sizeof(struct framevm_status) == 32,
	       "framevm_status must stay ABI-stable");
_Static_assert(_Alignof(struct framevm_status) == 8,
	       "framevm_status alignment must stay ABI-stable");
_Static_assert(FRAMEVM_CREATE_VM == _IOW('F', 0x01, struct framevm_create_vm),
	       "FRAMEVM_CREATE_VM command must stay ABI-stable");
_Static_assert(FRAMEVM_START == _IO('F', 0x02),
	       "FRAMEVM_START command must stay ABI-stable");
_Static_assert(FRAMEVM_STOP == _IO('F', 0x03),
	       "FRAMEVM_STOP command must stay ABI-stable");
_Static_assert(FRAMEVM_GET_CONSOLE_FD == _IO('F', 0x04),
	       "FRAMEVM_GET_CONSOLE_FD command must stay ABI-stable");
_Static_assert(FRAMEVM_GET_STATUS ==
		       _IOR('F', 0x06, struct framevm_status),
	       "FRAMEVM_GET_STATUS command must stay ABI-stable");
_Static_assert(FRAMEVM_SET_CMDLINE ==
		       _IOW('F', 0x07, struct framevm_cmdline),
	       "FRAMEVM_SET_CMDLINE command must stay ABI-stable");

#endif /* ASTERINAS_FRAMEVM_IOCTL_H */
