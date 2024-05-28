// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <string.h>

void print_cpumask(cpu_set_t *mask)
{
	size_t size = sizeof(cpu_set_t) / sizeof(unsigned long);
	for (size_t i = 0; i < size; i++) {
		printf("%lu ", ((unsigned long *)mask)[i]);
	}
	printf("\n");
}

int main()
{
	cpu_set_t mask;
	long nproc, i;

	// Get the number of CPUs available in the system
	nproc = sysconf(_SC_NPROCESSORS_ONLN);
	if (nproc < 0) {
		perror("sysconf(_SC_NPROCESSORS_ONLN) failed");
		return EXIT_FAILURE;
	}

	// Clear CPU set to ensure it's empty before using it
	CPU_ZERO(&mask);

	// Perform the system call to get the CPU affinity mask for the current process
	if (sched_getaffinity(0, sizeof(mask), &mask) == -1) {
		perror("sched_getaffinity");
		return EXIT_FAILURE;
	}

	printf("CPU Affinity mask: ");
	for (i = 0; i < nproc; i++) {
		// Check if the CPU 'i' is in the set (i.e., if the process can run on CPU 'i')
		if (CPU_ISSET(i, &mask)) {
			printf("%ld ", i);
		}
	}
	printf("\n");

	return EXIT_SUCCESS;
}