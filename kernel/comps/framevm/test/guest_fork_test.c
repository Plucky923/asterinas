/*
 * SPDX-License-Identifier: MPL-2.0
 *
 * FrameVM clone/fork smoke test (thread semantics).
 */

#include "syscalls.h"

#define STACK_SIZE (64 * 1024)

static char child_stack[STACK_SIZE];

void _start(void) {
    print("before fork\n");
    print("pid=");
    print_number((uint64_t)sys_getpid());
    print(" tid=");
    print_number((uint64_t)sys_gettid());
    print("\n");

    char *stack_top = child_stack + sizeof(child_stack);
    long child_tid = sys_clone(CLONE_VM | CLONE_FILES, stack_top, 0, 0, 0);

    if (child_tid < 0) {
        print("clone failed: ");
        print_number((uint64_t)(-child_tid));
        print("\n");
        sys_exit(1);
    }

    if (child_tid == 0) {
        print("after fork: Hello from child\n");
        print("child tid=");
        print_number((uint64_t)sys_gettid());
        print("\n");
        sys_exit(0);
    } else {
        print("after fork: Hello from parent\n");
        print("parent tid=");
        print_number((uint64_t)sys_gettid());
        print(" child tid=");
        print_number((uint64_t)child_tid);
        print("\n");
    }

    for (volatile int i = 0; i < 1000000; i++) {
    }
    sys_exit(0);
}
