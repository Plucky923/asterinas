// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/wait.h>

static void *check_inherited_affinity(void *unused)
{
	(void)unused;
	cpu_set_t mask;
	CPU_ZERO(&mask);
	unsigned cpu;
	if (sched_getaffinity(0, sizeof(mask), &mask) != 0 ||
	    syscall(SYS_getcpu, &cpu, NULL, NULL) != 0 ||
	    CPU_COUNT(&mask) != 1 || !CPU_ISSET(0, &mask) || cpu != 0) {
		fputs("Child did not inherit CPU 0 affinity and placement\n", stderr);
		return (void *)1;
	}
	return NULL;
}


int main()
{
	pid_t pid = getpid();
	cpu_set_t mask;

	// Get current affinity mask
	if (sched_getaffinity(pid, sizeof(cpu_set_t), &mask) == -1) {
		perror("sched_getaffinity");
		exit(EXIT_FAILURE);
	}

	printf("Current CPU affinity:");
	int cur_cpu_count = 0;
	for (int i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, &mask)) {
			printf(" %d", i);
			cur_cpu_count++;
		}
	}
	printf("\n");
	if (cur_cpu_count == 0) {
		printf("Error: No CPU affinity set\n");
		exit(EXIT_FAILURE);
	}

	// Set the process to run on CPU 0 only
	CPU_ZERO(&mask);
	CPU_SET(0, &mask);
	if (sched_setaffinity(pid, sizeof(cpu_set_t), &mask) == -1) {
		perror("sched_setaffinity");
		exit(EXIT_FAILURE);
	}
	printf("Set CPU affinity to CPU 0\n");

	// Verify the new CPU affinity
	if (sched_getaffinity(pid, sizeof(cpu_set_t), &mask) == -1) {
		perror("sched_getaffinity");
		exit(EXIT_FAILURE);
	}

	printf("New CPU affinity:");
	cur_cpu_count = 0;
	for (int i = 0; i < CPU_SETSIZE; i++) {
		if (CPU_ISSET(i, &mask)) {
			printf(" %d", i);
			cur_cpu_count++;
			if (i != 0) {
				printf("Error: CPU affinity not set to CPU 0\n");
				exit(EXIT_FAILURE);
			}
		}
	}
	printf("\n");
	if (cur_cpu_count != 1) {
		printf("Error: CPU affinity not set to CPU 0\n");
		exit(EXIT_FAILURE);
	}

	/* A new process and a new POSIX thread must inherit the restricted mask. */
	pid_t child = fork();
	if (child < 0) {
		perror("fork");
		return EXIT_FAILURE;
	}
	if (child == 0)
		_exit(check_inherited_affinity(NULL) != NULL);
	int status;
	if (waitpid(child, &status, 0) != child ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return EXIT_FAILURE;
	pthread_t thread;
	void *result;
	if (pthread_create(&thread, NULL, check_inherited_affinity, NULL) != 0 ||
	    pthread_join(thread, &result) != 0 || result != NULL)
		return EXIT_FAILURE;
	puts("cpu_affinity inheritance: PASS");

	return 0;
}
