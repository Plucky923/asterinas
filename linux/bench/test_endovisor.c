// SPDX-License-Identifier: GPL-2.0
// Validate Endovisor ownership and failure paths with a real audited image.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../endovisor/uapi/endovisor.h"

#define REQUIRE(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "%s:%d: %s (errno=%d)\n", __func__, __LINE__, #condition, errno); \
		exit(1); \
	} \
} while (0)

static void wait_success(pid_t child)
{
	int status;
	pid_t result;
	do {
		result = waitpid(child, &status, 0);
	} while (result < 0 && errno == EINTR);
	REQUIRE(result == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static int sandbox_create(int device, uint32_t kind)
{
	struct sandbox_create request = {
		.kind_id = kind, .nr_vcpus = 1, .grant_mb = 2, .max_tasks = 8,
	};
	int fd = ioctl(device, SANDBOX_CREATE, &request);
	REQUIRE(fd >= 0);
	return fd;
}

static void finish_sandbox(int fd)
{
	struct sandbox_stats stats;
	REQUIRE(ioctl(fd, SANDBOX_KILL) == 0);
	REQUIRE(read(fd, &stats, sizeof(stats)) == sizeof(stats));
	REQUIRE(stats.exit_kind == 3 && stats.exit_code == SIGKILL);
	REQUIRE(stats.vm_creates == stats.vm_destroys);
	REQUIRE(close(fd) == 0);
}

static int reject_shared_state(void *arg)
{
	int fd = *(int *)arg;
	uint32_t vcpu = 0;
	errno = 0;
	int result = ioctl(fd, SANDBOX_ATTACH_VCPU, &vcpu);
	_exit(result == -1 && errno == EINVAL ? 0 : 11);
}

static void check_attach(int device, uint32_t kind)
{
	int fd = sandbox_create(device, kind);
	void *memory = mmap(NULL, 131072, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	REQUIRE(memory != MAP_FAILED);
	for (int mode = 0; mode < 2; mode++) {
		int flags = mode == 0 ? CLONE_FILES : CLONE_VM | CLONE_SIGHAND;
		pid_t child = clone(reject_shared_state, (char *)memory + 131072,
				    flags | SIGCHLD, &fd);
		REQUIRE(child >= 0);
		wait_success(child);
	}
	REQUIRE(munmap(memory, 131072) == 0);
	finish_sandbox(fd);
	printf("RESULT attach_requires_private_state 1 bool\n");

	fd = sandbox_create(device, kind);
	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		struct rlimit limit = { .rlim_cur = 64, .rlim_max = 64 };
		if (setrlimit(RLIMIT_NOFILE, &limit) != 0)
			_exit(12);
		while (open("/dev/null", O_RDONLY) >= 0)
			;
		if (errno != EMFILE)
			_exit(13);
		uint32_t vcpu = 0;
		errno = 0;
		int result = ioctl(fd, SANDBOX_ATTACH_VCPU, &vcpu);
		_exit(result == -1 && errno == EMFILE ? 0 : 14);
	}
	wait_success(child);
	finish_sandbox(fd);
	printf("RESULT attach_descriptor_exhaustion 1 bool\n");
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(60);
	const char *path = argc > 1 ? argv[1] : "/images/test-image.elf";
	int image_fd = open(path, O_RDONLY);
	REQUIRE(image_fd >= 0);
	struct stat image_stat;
	REQUIRE(fstat(image_fd, &image_stat) == 0);
	void *image = mmap(NULL, image_stat.st_size, PROT_READ, MAP_PRIVATE, image_fd, 0);
	REQUIRE(image != MAP_FAILED);
	int device = open("/dev/endovisor", O_RDWR);
	REQUIRE(device >= 0);
	struct kind_register registration = {
		.elf_ptr = (uintptr_t)image, .elf_len = image_stat.st_size,
	};

	struct kind_register *readonly = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
					     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	REQUIRE(readonly != MAP_FAILED);
	*readonly = registration;
	REQUIRE(mprotect(readonly, 4096, PROT_READ) == 0);
	errno = 0;
	REQUIRE(ioctl(device, KIND_REGISTER, readonly) == -1 && errno == EFAULT);
	REQUIRE(munmap(readonly, 4096) == 0);
	printf("RESULT register_readonly_output 1 bool\n");

	uint32_t kinds[128];
	unsigned int count = 0;
	while (count < sizeof(kinds) / sizeof(kinds[0])) {
		if (ioctl(device, KIND_REGISTER, &registration) != 0)
			break;
		kinds[count++] = registration.kind_id;
	}
	REQUIRE(count > 0 && count < 128 && errno == ENOSPC);
	for (unsigned int i = 1; i < count; i++)
		REQUIRE(ioctl(device, KIND_UNREGISTER, &kinds[i]) == 0);
	printf("RESULT register_capacity_rollback 1 bool\n");

	pid_t child = fork();
	REQUIRE(child >= 0);
	if (child == 0) {
		if (setuid(65534) != 0)
			_exit(15);
		errno = 0;
		int result = ioctl(device, KIND_UNREGISTER, &kinds[0]);
		_exit(result == -1 && errno == EPERM ? 0 : 16);
	}
	wait_success(child);
	printf("RESULT unregister_privilege 1 bool\n");

	struct sandbox_create invalid = {
		.kind_id = kinds[0], .nr_vcpus = 1, .grant_mb = 2, .max_tasks = UINT32_MAX,
	};
	errno = 0;
	REQUIRE(ioctl(device, SANDBOX_CREATE, &invalid) == -1 && errno == EINVAL);
	invalid.max_tasks--;
	errno = 0;
	REQUIRE(ioctl(device, SANDBOX_CREATE, &invalid) == -1 && errno == EINVAL);
	printf("RESULT task_capacity_overflow 1 bool\n");

	check_attach(device, kinds[0]);
	for (int round = 0; round < 8; round++)
		finish_sandbox(sandbox_create(device, kinds[0]));
	REQUIRE(ioctl(device, KIND_UNREGISTER, &kinds[0]) == 0);
	REQUIRE(close(device) == 0);
	REQUIRE(munmap(image, image_stat.st_size) == 0);
	REQUIRE(close(image_fd) == 0);
	printf("RESULT repeated_cleanup 1 bool\n");
	printf("RESULT suite_done 1 bool\n");
	return 0;
}
