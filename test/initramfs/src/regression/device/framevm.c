// SPDX-License-Identifier: MPL-2.0

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "../common/test.h"
#include "../common/framevm_ioctl.h"

#define FRAMEVM_PATH "/dev/framevm"
#define FRAMEVM_PROC_PATH "/proc/framevm"
#define FRAMEVMM_PATH "/bin/framevmm"
#define FRAMEVM_SET_SHARE _IOW(FRAMEVM_IOCTL_MAGIC, 0x05, uint32_t)
#define FRAMEVM_UNKNOWN_IOCTL _IO(FRAMEVM_IOCTL_MAGIC, 0x7f)

static int controller_fd;

static struct framevm_create_vm valid_create_request(void)
{
	return (struct framevm_create_vm){
		.api_version = FRAMEVM_API_VERSION,
		.vcpu_count = 1,
		.share = FRAMEVM_DEFAULT_SHARE,
		.flags = 0,
		.memory_limit_bytes = {
			(uint32_t)(FRAMEVM_DEFAULT_MEMORY_LIMIT_BYTES & UINT64_C(0xffffffff)),
			(uint32_t)(FRAMEVM_DEFAULT_MEMORY_LIMIT_BYTES >> 32),
		},
	};
}

static int create_vm_fd(struct framevm_create_vm request)
{
	return ioctl(controller_fd, FRAMEVM_CREATE_VM, &request);
}

static struct framevm_cmdline cmdline_request(const char *text)
{
	return (struct framevm_cmdline){
		.ptr = (uint64_t)(uintptr_t)text,
		.len = (uint32_t)strlen(text),
		.flags = 0,
	};
}

static int fdinfo_contains(int fd, const char *expected_line)
{
	char path[64];
	char line[256];

	if (snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd) < 0) {
		return 0;
	}

	FILE *fdinfo = fopen(path, "r");
	if (fdinfo == NULL) {
		return 0;
	}

	while (fgets(line, sizeof(line), fdinfo) != NULL) {
		if (strcmp(line, expected_line) == 0) {
			fclose(fdinfo);
			return 1;
		}
	}

	fclose(fdinfo);
	return 0;
}

FN_SETUP(open_controller)
{
	controller_fd = CHECK(open(FRAMEVM_PATH, O_RDWR));
}
END_SETUP()

FN_TEST(node_metadata)
{
	struct stat stat_buf;

	TEST_RES(stat(FRAMEVM_PATH, &stat_buf),
		 S_ISCHR(stat_buf.st_mode) &&
			 stat_buf.st_rdev == makedev(10, 0x7c) &&
			 (stat_buf.st_mode & 0777) == 0600);
	TEST_ERRNO(stat(FRAMEVM_PROC_PATH, &stat_buf), ENOENT);
	TEST_ERRNO(open(FRAMEVM_PROC_PATH, O_RDWR), ENOENT);
	TEST_RES(stat(FRAMEVMM_PATH, &stat_buf),
		 S_ISREG(stat_buf.st_mode) && (stat_buf.st_mode & 0111) != 0);
}
END_TEST()

FN_TEST(controller_io_is_invalid)
{
	char byte = 0;
	struct pollfd poll_fd = {
		.fd = controller_fd,
		.events = POLLIN | POLLOUT,
	};

	TEST_ERRNO(read(controller_fd, &byte, sizeof(byte)), EINVAL);
	TEST_ERRNO(write(controller_fd, &byte, sizeof(byte)), EINVAL);
	TEST_RES(poll(&poll_fd, 1, 0), _ret == 0 && poll_fd.revents == 0);
}
END_TEST()

FN_TEST(create_vm_validation)
{
	struct framevm_create_vm request = valid_create_request();
	int vm_fd = TEST_RES(create_vm_fd(request), _ret >= 0);
	if (vm_fd >= 0) {
		close(vm_fd);
	}

	request = valid_create_request();
	request.share = FRAMEVM_MIN_SHARE;
	vm_fd = TEST_RES(create_vm_fd(request), _ret >= 0);
	if (vm_fd >= 0) {
		close(vm_fd);
	}

	request = valid_create_request();
	request.share = FRAMEVM_MAX_SHARE;
	vm_fd = TEST_RES(create_vm_fd(request), _ret >= 0);
	if (vm_fd >= 0) {
		close(vm_fd);
	}

	request = valid_create_request();
	request.vcpu_count = 0;
	TEST_ERRNO(create_vm_fd(request), EINVAL);

	request = valid_create_request();
	request.vcpu_count = 5;
	TEST_ERRNO(create_vm_fd(request), EINVAL);

	request = valid_create_request();
	request.share = 1;
	TEST_ERRNO(create_vm_fd(request), EINVAL);

	request = valid_create_request();
	request.share = 262145;
	TEST_ERRNO(create_vm_fd(request), EINVAL);

	request = valid_create_request();
	request.flags = 1U << 31;
	TEST_ERRNO(create_vm_fd(request), EINVAL);

	request = valid_create_request();
	request.api_version = FRAMEVM_API_VERSION + 1;
	TEST_ERRNO(create_vm_fd(request), EINVAL);

	request = valid_create_request();
	request.memory_limit_bytes[0] = 1;
	TEST_ERRNO(create_vm_fd(request), EINVAL);

	request = valid_create_request();
	request.memory_limit_bytes[0] = 0;
	request.memory_limit_bytes[1] = 0;
	TEST_ERRNO(create_vm_fd(request), EINVAL);
}
END_TEST()

FN_TEST(create_vm_captures_request_values)
{
	struct framevm_create_vm request = valid_create_request();
	request.vcpu_count = 2;
	request.share = 2048;

	int vm_fd = TEST_RES(create_vm_fd(request), _ret >= 0);
	if (vm_fd < 0) {
		return;
	}

	request.vcpu_count = 4;
	request.share = 4096;
	TEST_RES(fdinfo_contains(vm_fd, "vcpu_count:\t2\n"), _ret == 1);
	TEST_RES(fdinfo_contains(vm_fd, "share:\t2048\n"), _ret == 1);

	close(vm_fd);
}
END_TEST()

FN_TEST(duplicated_vm_fd_preserves_one_vm_object)
{
	int vm_fd = TEST_RES(create_vm_fd(valid_create_request()), _ret >= 0);
	if (vm_fd < 0) {
		return;
	}

	int duplicate_fd = TEST_RES(dup(vm_fd), _ret >= 0);
	if (duplicate_fd < 0) {
		close(vm_fd);
		return;
	}

	TEST_RES(close(vm_fd), _ret == 0);
	TEST_RES(fdinfo_contains(duplicate_fd, "vcpu_count:\t1\n"), _ret == 1);
	TEST_RES(fdinfo_contains(duplicate_fd, "share:\t1024\n"), _ret == 1);
	TEST_RES(ioctl(duplicate_fd, FRAMEVM_STOP), _ret == 0);

	close(duplicate_fd);
}
END_TEST()

FN_TEST(framevmm_rejects_unsupported_cli)
{
	TEST_RES(access(FRAMEVMM_PATH, X_OK), _ret == 0);
	TEST_RES(system(FRAMEVMM_PATH " -m 512M >/dev/null 2>&1"), _ret != 0);
	TEST_RES(system(FRAMEVMM_PATH " -smp 0 >/dev/null 2>&1"), _ret != 0);
	TEST_RES(system(FRAMEVMM_PATH
			" -smp 1 -kernel /tmp/missing -nographic "
			"-drive file=/tmp/a,id=root,format=qcow2 "
			"-device framev-blk,drive=root,root=on "
			"-device framev-sock,guest-cid=3 >/dev/null 2>&1"),
		 _ret != 0);
}
END_TEST()

FN_TEST(ioctl_role_errors)
{
	struct framevm_create_vm request = valid_create_request();
	int vm_fd = TEST_RES(create_vm_fd(request), _ret >= 0);
	if (vm_fd < 0) {
		return;
	}

	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_START), ENOTTY);
	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_STOP), ENOTTY);
	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_GET_CONSOLE_FD), ENOTTY);
	struct framevm_status status = { 0 };
	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_GET_STATUS, &status), ENOTTY);
	struct framevm_cmdline cmdline = cmdline_request("init=/bin/sh");
	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_SET_CMDLINE, &cmdline), ENOTTY);
	struct framevm_resource_fd artifact = { 0 };
	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_SET_ARTIFACT, &artifact),
		   ENOTTY);
	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_ADD_CONSOLE), ENOTTY);
	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_ADD_RNG), ENOTTY);
	struct framevm_block block = { 0 };
	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_ADD_BLOCK, &block), ENOTTY);
	struct framevm_sock sock = { 0 };
	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_ADD_SOCK, &sock), ENOTTY);
	struct framevm_net net = { 0 };
	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_ADD_NET, &net), ENOTTY);
	struct framevm_assigned_pci assigned_pci = { 0 };
	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_ASSIGN_PCI, &assigned_pci),
		   ENOTTY);
	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_SET_SHARE, &request.share),
		   ENOTTY);
	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_UNKNOWN_IOCTL), ENOTTY);

	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_CREATE_VM, &request), ENOTTY);
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_SET_SHARE, &request.share), ENOTTY);
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_UNKNOWN_IOCTL), ENOTTY);

	close(vm_fd);
}
END_TEST()

FN_TEST(typed_resource_validation)
{
	int vm_fd = TEST_RES(create_vm_fd(valid_create_request()), _ret >= 0);
	if (vm_fd < 0) {
		return;
	}

	struct framevm_block block = {
		.fd = -1,
		.device_id = 0,
		.flags = 0,
		.reserved = 0,
	};
	struct framevm_resource_fd artifact = {
		.fd = -1,
		.flags = 0,
		.reserved = 0,
	};
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_SET_ARTIFACT, &artifact), EBADF);
	artifact.fd = controller_fd;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_SET_ARTIFACT, &artifact), EINVAL);
	artifact.flags = 1U << 31;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_SET_ARTIFACT, &artifact), EINVAL);
	artifact.flags = 0;
	artifact.reserved = 1;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_SET_ARTIFACT, &artifact), EINVAL);

	TEST_RES(ioctl(vm_fd, FRAMEVM_ADD_CONSOLE), _ret == 0);
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ADD_CONSOLE), EEXIST);
	TEST_RES(ioctl(vm_fd, FRAMEVM_ADD_RNG), _ret == 0);
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ADD_RNG), EEXIST);

	struct framevm_sock sock = {
		.guest_cid = 3,
		.flags = 1U << 31,
		.reserved = { 0, 0 },
	};
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ADD_SOCK, &sock), EINVAL);
	sock.flags = 0;
	sock.reserved[0] = 1;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ADD_SOCK, &sock), EINVAL);
	sock.reserved[0] = 0;
	sock.guest_cid = 2;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ADD_SOCK, &sock), EINVAL);
	sock.guest_cid = 3;
	sock.guest_connect_host_ports_ptr = 1;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ADD_SOCK, &sock), EINVAL);
	sock.guest_connect_host_ports_ptr = 0;
	TEST_RES(ioctl(vm_fd, FRAMEVM_ADD_SOCK, &sock), _ret == 0);
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ADD_SOCK, &sock), EEXIST);

	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ADD_BLOCK, &block), EBADF);
	block.fd = controller_fd;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ADD_BLOCK, &block), EINVAL);
	block.flags = 1U << 31;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ADD_BLOCK, &block), EINVAL);
	block.flags = 0;
	block.reserved = 1;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ADD_BLOCK, &block), EINVAL);

	struct framevm_assigned_pci assigned_pci = {
		.segment = 0,
		.bus = 0,
		.device_function = (1U << 3),
		.flags = 0,
		.reserved = 0,
	};
	assigned_pci.segment = 1;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ASSIGN_PCI, &assigned_pci), EINVAL);
	assigned_pci.segment = 0;
	assigned_pci.device_function |= 1;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ASSIGN_PCI, &assigned_pci), EINVAL);
	assigned_pci.device_function &= ~7U;
	TEST_RES(ioctl(vm_fd, FRAMEVM_ASSIGN_PCI, &assigned_pci), _ret == 0);
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ASSIGN_PCI, &assigned_pci), EEXIST);
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_START), EINVAL);
	assigned_pci.flags = 1U << 31;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ASSIGN_PCI, &assigned_pci), EINVAL);
	assigned_pci.flags = 0;
	assigned_pci.reserved = 1;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ASSIGN_PCI, &assigned_pci), EINVAL);

	close(vm_fd);
}
END_TEST()

FN_TEST(block_configuration_captures_file)
{
	char path[64];
	TEST_RES(snprintf(path, sizeof(path), "/tmp/framevm-drive-%d",
			  getpid()),
		 _ret > 0 && (size_t)_ret < sizeof(path));

	int drive_fd = TEST_RES(open(path, O_CREAT | O_EXCL | O_RDWR, 0600),
				_ret >= 0);
	if (drive_fd < 0) {
		return;
	}
	TEST_RES(ftruncate(drive_fd, 4096), _ret == 0);

	int vm_fd = TEST_RES(create_vm_fd(valid_create_request()), _ret >= 0);
	if (vm_fd < 0) {
		close(drive_fd);
		unlink(path);
		return;
	}

	struct framevm_block block = {
		.fd = drive_fd,
		.device_id = 0,
		.flags = 0,
		.reserved = 0,
	};
	TEST_RES(ioctl(vm_fd, FRAMEVM_ADD_BLOCK, &block), _ret == 0);
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_ADD_BLOCK, &block), EEXIST);
	block.device_id = 1;
	block.flags = FRAMEVM_BLOCK_READ_ONLY;
	TEST_RES(ioctl(vm_fd, FRAMEVM_ADD_BLOCK, &block), _ret == 0);
	TEST_RES(close(drive_fd), _ret == 0);
	TEST_RES(unlink(path), _ret == 0);
	TEST_RES(fdinfo_contains(vm_fd, "drive[0]:\twritable,access=O_RDWR\n"),
		 _ret == 1);
	TEST_RES(fdinfo_contains(vm_fd, "drive[1]:\treadonly,access=O_RDWR\n"),
		 _ret == 1);

	close(vm_fd);
}
END_TEST()

FN_TEST(cmdline_append_validation)
{
	struct framevm_create_vm request = valid_create_request();
	int vm_fd = TEST_RES(create_vm_fd(request), _ret >= 0);
	if (vm_fd < 0) {
		return;
	}

	struct framevm_cmdline cmdline = cmdline_request("init=/bin/sh");
	TEST_RES(ioctl(vm_fd, FRAMEVM_SET_CMDLINE, &cmdline), _ret == 0);

	cmdline.ptr = 0;
	cmdline.len = 0;
	cmdline.flags = 0;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_SET_CMDLINE, &cmdline), EEXIST);

	cmdline = cmdline_request(
		"init=/bin/framevm-test-runner framevm.test=boot");
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_SET_CMDLINE, &cmdline), EEXIST);

	cmdline = cmdline_request("init=/bin/sh");
	cmdline.flags = 1;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_SET_CMDLINE, &cmdline), EINVAL);

	cmdline = cmdline_request("init=/bin/sh");
	cmdline.ptr = 0;
	cmdline.len = 1;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_SET_CMDLINE, &cmdline), EFAULT);

	static char long_cmdline[FRAMEVM_CMDLINE_MAX_LEN + 1];
	memset(long_cmdline, 'a', sizeof(long_cmdline));
	cmdline.ptr = (uint64_t)(uintptr_t)long_cmdline;
	cmdline.len = sizeof(long_cmdline);
	cmdline.flags = 0;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_SET_CMDLINE, &cmdline), EINVAL);

	char nul_cmdline[] = { 'i', 'n', 'i', 't', '=', 0, 'x' };
	cmdline.ptr = (uint64_t)(uintptr_t)nul_cmdline;
	cmdline.len = sizeof(nul_cmdline);
	cmdline.flags = 0;
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_SET_CMDLINE, &cmdline), EINVAL);

	cmdline = cmdline_request("ostd.vcpu_count=2");
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_SET_CMDLINE, &cmdline), EINVAL);

	TEST_RES(ioctl(vm_fd, FRAMEVM_STOP), _ret == 0);
	cmdline = cmdline_request("init=/bin/sh");
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_SET_CMDLINE, &cmdline), EINVAL);

	close(vm_fd);
}
END_TEST()

FN_TEST(vm_fd_state_errors)
{
	struct framevm_create_vm request = valid_create_request();
	int vm_fd = TEST_RES(create_vm_fd(request), _ret >= 0);
	struct pollfd poll_fd = {
		.fd = vm_fd,
		.events = POLLIN | POLLHUP,
	};
	struct framevm_status status = { 0 };
	struct framevm_memory_status memory_status = { 0 };
	if (vm_fd < 0) {
		return;
	}

	TEST_RES(ioctl(vm_fd, FRAMEVM_GET_MEMORY_STATUS, &memory_status),
		 _ret == 0);
	TEST_RES(memory_status.limit_bytes ==
				 FRAMEVM_DEFAULT_MEMORY_LIMIT_BYTES &&
			 memory_status.committed_bytes == 0 &&
			 memory_status.reserved_bytes == 0 &&
			 memory_status.reusable_bytes == 0 &&
			 memory_status.active_bytes == 0 &&
			 memory_status.oom_count == 0 &&
			 memory_status.reclaim_count == 0,
		 _ret);

	TEST_RES(ioctl(vm_fd, FRAMEVM_GET_STATUS, &status), _ret == 0);
	TEST_RES(status.state == FRAMEVM_STATE_CREATED && status.code == 0,
			 _ret);
	TEST_RES(poll(&poll_fd, 1, 0), _ret == 0 && poll_fd.revents == 0);

	TEST_RES(ioctl(vm_fd, FRAMEVM_STOP), _ret == 0);
	TEST_RES(ioctl(vm_fd, FRAMEVM_GET_STATUS, &status), _ret == 0);
	TEST_RES(status.state == FRAMEVM_STATE_EXITED && status.code == 0,
			 _ret);
	poll_fd.revents = 0;
	TEST_RES(poll(&poll_fd, 1, 0),
		 _ret == 1 && (poll_fd.revents & (POLLIN | POLLHUP)) != 0);
	TEST_RES(ioctl(vm_fd, FRAMEVM_STOP), _ret == 0);
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_START), EINVAL);

	close(vm_fd);
}
END_TEST()

FN_TEST(console_fd_created_state)
{
	struct framevm_create_vm request = valid_create_request();
	int vm_fd = TEST_RES(create_vm_fd(request), _ret >= 0);
	if (vm_fd < 0) {
		return;
	}

	int console_fd =
		TEST_RES(ioctl(vm_fd, FRAMEVM_GET_CONSOLE_FD), _ret >= 0);
	if (console_fd < 0) {
		close(vm_fd);
		return;
	}

	char byte = 0;
	struct pollfd poll_fd = {
		.fd = console_fd,
		.events = POLLIN | POLLOUT | POLLHUP,
	};

	TEST_RES(poll(&poll_fd, 1, 0), _ret == 0 && poll_fd.revents == 0);
	TEST_ERRNO(read(console_fd, &byte, sizeof(byte)), EAGAIN);
	TEST_ERRNO(write(console_fd, &byte, sizeof(byte)), EAGAIN);

	close(console_fd);
	close(vm_fd);
}
END_TEST()

FN_TEST(multiple_console_fds_are_independent)
{
	struct framevm_create_vm request = valid_create_request();
	int vm_fd = TEST_RES(create_vm_fd(request), _ret >= 0);
	if (vm_fd < 0) {
		return;
	}

	int first_console =
		TEST_RES(ioctl(vm_fd, FRAMEVM_GET_CONSOLE_FD), _ret >= 0);
	int second_console =
		TEST_RES(ioctl(vm_fd, FRAMEVM_GET_CONSOLE_FD), _ret >= 0);
	if (first_console < 0 || second_console < 0) {
		if (first_console >= 0) {
			close(first_console);
		}
		if (second_console >= 0) {
			close(second_console);
		}
		close(vm_fd);
		return;
	}

	char byte = 0;
	TEST_ERRNO(read(first_console, &byte, sizeof(byte)), EAGAIN);
	TEST_ERRNO(read(second_console, &byte, sizeof(byte)), EAGAIN);
	TEST_ERRNO(write(first_console, &byte, sizeof(byte)), EAGAIN);
	TEST_ERRNO(write(second_console, &byte, sizeof(byte)), EAGAIN);

	close(first_console);
	TEST_ERRNO(read(second_console, &byte, sizeof(byte)), EAGAIN);
	close(second_console);
	TEST_RES(ioctl(vm_fd, FRAMEVM_STOP), _ret == 0);
	close(vm_fd);
}
END_TEST()

FN_TEST(controller_close_does_not_destroy_vm_fd)
{
	int second_controller = TEST_RES(open(FRAMEVM_PATH, O_RDWR), _ret >= 0);
	if (second_controller < 0) {
		return;
	}

	int vm_fd = TEST_RES(create_vm_fd(valid_create_request()), _ret >= 0);
	if (vm_fd < 0) {
		close(second_controller);
		return;
	}

	TEST_RES(close(controller_fd), _ret == 0);
	controller_fd = -1;
	TEST_RES(ioctl(vm_fd, FRAMEVM_STOP), _ret == 0);

	close(vm_fd);
	controller_fd = second_controller;
}
END_TEST()

FN_SETUP(close_controller)
{
	if (controller_fd >= 0) {
		CHECK(close(controller_fd));
	}
}
END_SETUP()
