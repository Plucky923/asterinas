/* SPDX-License-Identifier: MPL-2.0 */

#ifndef ASTERINAS_FRAMEVM_IOCTL_H
#define ASTERINAS_FRAMEVM_IOCTL_H

#include <stdint.h>
#include <sys/ioctl.h>

#define FRAMEVM_IOCTL_MAGIC 'F'
#define FRAMEVM_API_VERSION 2U
#define FRAMEVM_DEFAULT_MEMORY_LIMIT_BYTES \
	(UINT64_C(8) * UINT64_C(1024) * UINT64_C(1024) * UINT64_C(1024))
#define FRAMEVM_DEFAULT_SHARE 1024U
#define FRAMEVM_MIN_VCPU_COUNT 1U
#define FRAMEVM_MAX_VCPU_COUNT 4U
#define FRAMEVM_MIN_SHARE 2U
#define FRAMEVM_MAX_SHARE 262144U
#define FRAMEVM_BLOCK_READ_ONLY (1U << 0)
#define FRAMEVM_CMDLINE_MAX_LEN 4096U

#define FRAMEVM_STATE_CREATED 0U
#define FRAMEVM_STATE_STARTING 1U
#define FRAMEVM_STATE_RUNNING 2U
#define FRAMEVM_STATE_EXITED 3U

struct framevm_create_vm {
	uint32_t api_version;
	uint32_t vcpu_count;
	uint32_t share;
	uint32_t flags;
	uint32_t memory_limit_bytes[2];
};

struct framevm_cmdline {
	uint64_t ptr;
	uint32_t len;
	uint32_t flags;
};

struct framevm_resource_fd {
	int32_t fd;
	uint32_t flags;
	uint64_t reserved;
};

struct framevm_status {
	uint32_t state;
	int32_t code;
};

struct framevm_memory_status {
	uint64_t limit_bytes;
	uint64_t committed_bytes;
	uint64_t reserved_bytes;
	uint64_t reusable_bytes;
	uint64_t active_bytes;
	uint64_t oom_count;
	uint64_t reclaim_count;
};

struct framevm_block {
	int32_t fd;
	uint32_t device_id;
	uint32_t flags;
	uint32_t reserved;
};

struct framevm_sock {
	uint32_t guest_cid;
	uint32_t flags;
	uint64_t guest_connect_host_ports_ptr;
	uint64_t host_connect_guest_ports_ptr;
	uint32_t guest_connect_host_ports_len;
	uint32_t host_connect_guest_ports_len;
	uint64_t reserved[2];
};

struct framevm_net {
	int32_t fd;
	uint8_t mac_address[6];
	uint16_t mtu;
	uint32_t flags;
	uint32_t reserved;
};

struct framevm_assigned_pci {
	uint16_t segment;
	uint8_t bus;
	uint8_t device_function;
	uint32_t flags;
	uint64_t reserved;
};

#define FRAMEVM_CREATE_VM \
	_IOW(FRAMEVM_IOCTL_MAGIC, 0x01, struct framevm_create_vm)
#define FRAMEVM_START _IO(FRAMEVM_IOCTL_MAGIC, 0x02)
#define FRAMEVM_STOP _IO(FRAMEVM_IOCTL_MAGIC, 0x03)
#define FRAMEVM_GET_CONSOLE_FD _IO(FRAMEVM_IOCTL_MAGIC, 0x04)
#define FRAMEVM_GET_STATUS \
	_IOR(FRAMEVM_IOCTL_MAGIC, 0x06, struct framevm_status)
#define FRAMEVM_GET_MEMORY_STATUS \
	_IOR(FRAMEVM_IOCTL_MAGIC, 0x0f, struct framevm_memory_status)
#define FRAMEVM_SET_CMDLINE \
	_IOW(FRAMEVM_IOCTL_MAGIC, 0x07, struct framevm_cmdline)
#define FRAMEVM_SET_ARTIFACT \
	_IOW(FRAMEVM_IOCTL_MAGIC, 0x08, struct framevm_resource_fd)
#define FRAMEVM_ADD_CONSOLE _IO(FRAMEVM_IOCTL_MAGIC, 0x09)
#define FRAMEVM_ADD_RNG _IO(FRAMEVM_IOCTL_MAGIC, 0x0a)
#define FRAMEVM_ADD_BLOCK _IOW(FRAMEVM_IOCTL_MAGIC, 0x0b, struct framevm_block)
#define FRAMEVM_ADD_SOCK _IOW(FRAMEVM_IOCTL_MAGIC, 0x0c, struct framevm_sock)
#define FRAMEVM_ADD_NET _IOW(FRAMEVM_IOCTL_MAGIC, 0x0d, struct framevm_net)
#define FRAMEVM_ASSIGN_PCI \
	_IOW(FRAMEVM_IOCTL_MAGIC, 0x0e, struct framevm_assigned_pci)

_Static_assert(sizeof(struct framevm_create_vm) == 24,
	       "framevm_create_vm must stay ABI-stable");
_Static_assert(_Alignof(struct framevm_create_vm) == 4,
	       "framevm_create_vm alignment must stay ABI-stable");
_Static_assert(sizeof(struct framevm_cmdline) == 16,
	       "framevm_cmdline must stay ABI-stable");
_Static_assert(_Alignof(struct framevm_cmdline) == 8,
	       "framevm_cmdline alignment must stay ABI-stable");
_Static_assert(sizeof(struct framevm_resource_fd) == 16,
	       "framevm_resource_fd must stay ABI-stable");
_Static_assert(_Alignof(struct framevm_resource_fd) == 8,
	       "framevm_resource_fd alignment must stay ABI-stable");
_Static_assert(sizeof(struct framevm_status) == 8,
	       "framevm_status must stay ABI-stable");
_Static_assert(_Alignof(struct framevm_status) == 4,
	       "framevm_status alignment must stay ABI-stable");
_Static_assert(sizeof(struct framevm_memory_status) == 56,
	       "framevm_memory_status must stay ABI-stable");
_Static_assert(_Alignof(struct framevm_memory_status) == 8,
	       "framevm_memory_status alignment must stay ABI-stable");
_Static_assert(sizeof(struct framevm_block) == 16,
	       "framevm_block must stay ABI-stable");
_Static_assert(_Alignof(struct framevm_block) == 4,
	       "framevm_block alignment must stay ABI-stable");
_Static_assert(sizeof(struct framevm_sock) == 48,
	       "framevm_sock must stay ABI-stable");
_Static_assert(_Alignof(struct framevm_sock) == 8,
	       "framevm_sock alignment must stay ABI-stable");
_Static_assert(sizeof(struct framevm_net) == 20,
	       "framevm_net must stay ABI-stable");
_Static_assert(_Alignof(struct framevm_net) == 4,
	       "framevm_net alignment must stay ABI-stable");
_Static_assert(sizeof(struct framevm_assigned_pci) == 16,
	       "framevm_assigned_pci must stay ABI-stable");
_Static_assert(_Alignof(struct framevm_assigned_pci) == 8,
	       "framevm_assigned_pci alignment must stay ABI-stable");
_Static_assert(FRAMEVM_CREATE_VM == _IOW('F', 0x01, struct framevm_create_vm),
	       "FRAMEVM_CREATE_VM command must stay ABI-stable");
_Static_assert(FRAMEVM_START == _IO('F', 0x02),
	       "FRAMEVM_START command must stay ABI-stable");
_Static_assert(FRAMEVM_STOP == _IO('F', 0x03),
	       "FRAMEVM_STOP command must stay ABI-stable");
_Static_assert(FRAMEVM_GET_CONSOLE_FD == _IO('F', 0x04),
	       "FRAMEVM_GET_CONSOLE_FD command must stay ABI-stable");
_Static_assert(FRAMEVM_GET_STATUS == _IOR('F', 0x06, struct framevm_status),
	       "FRAMEVM_GET_STATUS command must stay ABI-stable");
_Static_assert(FRAMEVM_GET_MEMORY_STATUS ==
		       _IOR('F', 0x0f, struct framevm_memory_status),
	       "FRAMEVM_GET_MEMORY_STATUS command must stay ABI-stable");
_Static_assert(FRAMEVM_SET_CMDLINE == _IOW('F', 0x07, struct framevm_cmdline),
	       "FRAMEVM_SET_CMDLINE command must stay ABI-stable");
_Static_assert(FRAMEVM_SET_ARTIFACT ==
		       _IOW('F', 0x08, struct framevm_resource_fd),
	       "FRAMEVM_SET_ARTIFACT command must stay ABI-stable");
_Static_assert(FRAMEVM_ADD_CONSOLE == _IO('F', 0x09),
	       "FRAMEVM_ADD_CONSOLE command must stay ABI-stable");
_Static_assert(FRAMEVM_ADD_RNG == _IO('F', 0x0a),
	       "FRAMEVM_ADD_RNG command must stay ABI-stable");
_Static_assert(FRAMEVM_ADD_BLOCK == _IOW('F', 0x0b, struct framevm_block),
	       "FRAMEVM_ADD_BLOCK command must stay ABI-stable");
_Static_assert(FRAMEVM_ADD_SOCK == _IOW('F', 0x0c, struct framevm_sock),
	       "FRAMEVM_ADD_SOCK command must stay ABI-stable");
_Static_assert(FRAMEVM_ADD_NET == _IOW('F', 0x0d, struct framevm_net),
	       "FRAMEVM_ADD_NET command must stay ABI-stable");
_Static_assert(FRAMEVM_ASSIGN_PCI ==
		       _IOW('F', 0x0e, struct framevm_assigned_pci),
	       "FRAMEVM_ASSIGN_PCI command must stay ABI-stable");

#endif /* ASTERINAS_FRAMEVM_IOCTL_H */
