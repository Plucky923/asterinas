// SPDX-License-Identifier: MPL-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/capability.h>

int set_capcability(__u32 target_pid)
{
	struct __user_cap_header_struct capheader;
	struct __user_cap_data_struct capdata[2];

	capheader.version = _LINUX_CAPABILITY_VERSION_3;
	capheader.pid = target_pid;

	memset(&capdata, 0, sizeof(capdata));

	// try to set CAP_NET_RAW and CAP_NET_ADMIN
	capdata[0].effective = capdata[0].permitted = (1 << CAP_NET_RAW) |
						      (1 << CAP_NET_ADMIN);
	capdata[0].inheritable = 0;

	if (syscall(SYS_capset, &capheader, &capdata) < 0) {
		perror("capset failed");
		return 1;
	}
	printf("Process capabilities set successfully.\n");

	return 0;
}

int check_capability(__u32 cap, __u32 target_pid)
{
	struct __user_cap_header_struct capheader;
	struct __user_cap_data_struct capdata[2];

	memset(&capheader, 0, sizeof(capheader));
	memset(&capdata, 0, sizeof(capdata));

	capheader.version = _LINUX_CAPABILITY_VERSION_3;
	capheader.pid = target_pid;

	if (syscall(SYS_capget, &capheader, &capdata) == -1) {
		perror("capget failed");
		exit(EXIT_FAILURE);
	}
	printf("Process capabilities retrieved successfully.\n");

	// Check if a specific capability is in the permitted and effective sets.
	return (capdata[0].permitted & cap) && (capdata[0].effective & cap);
}

int main(void)
{
	// get/set current process's CAPs.
	__u32 target_pid = getpid();
	printf("Process Pid: %u.\n", target_pid);

	// set CAP_NET_RAW & CAP_NET_ADMIN
	set_capcability(target_pid);

	// check CAP_NET_RAW
	if (check_capability(1 << CAP_NET_RAW, target_pid)) {
		printf("Process has CAP_NET_RAW capability.\n");
	} else {
		printf("Process does NOT have CAP_NET_RAW capability.\n");
	}

	// check CAP_NET_ADMIN
	if (check_capability(1 << CAP_NET_ADMIN, target_pid)) {
		printf("Process has CAP_NET_ADMIN capability.\n");
	} else {
		printf("Process does NOT have CAP_NET_ADMIN capability.\n");
	}

	return 0;
}
