// SPDX-License-Identifier: MPL-2.0

// Functional fixture: invokes the real image kernel socket and block APIs.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static int run(const char *command) {
  int fd = open("/proc/kernelet_shared_io_test", O_RDWR);
  if (fd < 0) {
    perror("open shared I/O test");
    return -1;
  }
  size_t len = strlen(command);
  if (write(fd, command, len) != (ssize_t)len) {
    perror(command);
    close(fd);
    return -1;
  }
  if (lseek(fd, 0, SEEK_SET) < 0) {
    perror("seek result");
    close(fd);
    return -1;
  }
  char result[1024];
  ssize_t count = read(fd, result, sizeof(result) - 1);
  close(fd);
  if (count <= 0) {
    perror("read shared I/O result");
    return -1;
  }
  result[count] = 0;
  printf("SHARED_IO_RESULT %s", result);
  fflush(stdout);
  return 0;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mkdir("/proc", 0755);
  if (mount("proc", "/proc", "proc", 0, NULL) < 0 && errno != EBUSY) {
    perror("mount proc");
    return 1;
  }
  const char *role = getenv("SHARED_ROLE");
  if (!role || (strcmp(role, "send") && strcmp(role, "receive"))) {
    fprintf(stderr, "missing SHARED_ROLE\n");
    return 1;
  }
  if (!strcmp(role, "send") && run("block") < 0)
    return 1;
  if (run(role) < 0)
    return 1;
  printf("SHARED_IO_IMAGE_PASS role=%s\n", role);
  return 0;
}
