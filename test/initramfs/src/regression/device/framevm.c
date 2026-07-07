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
#define FRAMEVMCTL_PATH "/bin/framevmctl"
#define FRAMEVM_SET_SHARE _IOW(FRAMEVM_IOCTL_MAGIC, 0x05, uint32_t)
#define FRAMEVM_UNKNOWN_IOCTL _IO(FRAMEVM_IOCTL_MAGIC, 0x7f)

static int controller_fd;

static struct framevm_create_vm valid_create_request(void)
{
	return (struct framevm_create_vm){
		.vcpu_count = 1,
		.share = FRAMEVM_DEFAULT_SHARE,
		.flags = 0,
		.reserved = 0,
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
	TEST_RES(stat(FRAMEVMCTL_PATH, &stat_buf),
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
	request.reserved = 1;
	TEST_ERRNO(create_vm_fd(request), EINVAL);

	request = valid_create_request();
	request.flags = FRAMEVM_CREATE_DRIVE_READONLY;
	TEST_ERRNO(create_vm_fd(request), EINVAL);

	request = valid_create_request();
	request.flags = FRAMEVM_CREATE_HAS_DRIVE;
	request.reserved = 9999;
	TEST_ERRNO(create_vm_fd(request), EBADF);
}
END_TEST()

FN_TEST(framevmctl_basic_cli)
{
	TEST_RES(access(FRAMEVMCTL_PATH, X_OK), _ret == 0);
	TEST_RES(system(FRAMEVMCTL_PATH " --help >/dev/null"), _ret == 0);
	TEST_RES(system(FRAMEVMCTL_PATH " run --vcpus 0 >/dev/null 2>&1"),
		 _ret != 0);
	TEST_RES(system(FRAMEVMCTL_PATH
			" run --vcpus 1 --share 1 >/dev/null 2>&1"),
		 _ret != 0);
	TEST_RES(system(FRAMEVMCTL_PATH
			" run --vcpus 1 --drive file=/tmp/a "
			"--drive file=/tmp/b >/dev/null 2>&1"),
		 _ret != 0);
	TEST_RES(system(FRAMEVMCTL_PATH
			" run --vcpus 1 --drive "
			"file=/tmp/a,readonly,readonly >/dev/null 2>&1"),
		 _ret != 0);
	TEST_RES(system(FRAMEVMCTL_PATH
			" run --vcpus 1 --drive "
			"file=/tmp/a,readonly,writable >/dev/null 2>&1"),
		 _ret != 0);
	TEST_RES(system(FRAMEVMCTL_PATH
			" run --vcpus 1 --drive "
			"file=/tmp/a,format=qcow2 >/dev/null 2>&1"),
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
	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_SET_SHARE, &request.share),
		   ENOTTY);
	TEST_ERRNO(ioctl(controller_fd, FRAMEVM_UNKNOWN_IOCTL), ENOTTY);

	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_CREATE_VM, &request), ENOTTY);
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_SET_SHARE, &request.share), ENOTTY);
	TEST_ERRNO(ioctl(vm_fd, FRAMEVM_UNKNOWN_IOCTL), ENOTTY);

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
	TEST_RES(ioctl(vm_fd, FRAMEVM_SET_CMDLINE, &cmdline), _ret == 0);

	cmdline = cmdline_request("init=/bin/framevm-test-runner framevm.test=boot");
	TEST_RES(ioctl(vm_fd, FRAMEVM_SET_CMDLINE, &cmdline), _ret == 0);

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

	cmdline = cmdline_request("framev.devices=bad");
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
	if (vm_fd < 0) {
		return;
	}

	TEST_RES(ioctl(vm_fd, FRAMEVM_GET_STATUS, &status), _ret == 0);
	TEST_RES(status.state == FRAMEVM_STATE_CREATED &&
			 status.terminal_reason == FRAMEVM_TERMINAL_NONE &&
			 status.status_code == 0 &&
			 status.failure_class == FRAMEVM_FAILURE_NONE &&
			 status.vm_id == FRAMEVM_STATUS_VM_ID_NONE,
		 _ret);
	TEST_RES(poll(&poll_fd, 1, 0), _ret == 0 && poll_fd.revents == 0);

	TEST_RES(ioctl(vm_fd, FRAMEVM_STOP), _ret == 0);
	TEST_RES(ioctl(vm_fd, FRAMEVM_GET_STATUS, &status), _ret == 0);
	TEST_RES(status.state == FRAMEVM_STATE_STOPPED_BY_HOST &&
			 status.terminal_reason == FRAMEVM_TERMINAL_HOST_STOP &&
			 status.failure_class == FRAMEVM_FAILURE_HOST_STOP,
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
