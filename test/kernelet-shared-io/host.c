// SPDX-License-Identifier: MPL-2.0

// Runs inside Asterinas against the real /dev/kernelet and VirtIO block device.
#define _GNU_SOURCE
#include "kernelet-abi.h"
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct instance {
  int fd;
  int console;
  int log;
  bool finished;
};

static void fail(const char *operation) {
  fprintf(stderr, "SHARED_IO_HOST_FAIL %s: errno=%d %s\n", operation, errno,
          strerror(errno));
  fflush(NULL);
  reboot(RB_POWER_OFF);
  _exit(1);
}

static void checked_ioctl(int fd, unsigned long request, void *arg,
                          const char *operation) {
  if (ioctl(fd, request, arg) < 0)
    fail(operation);
}

static int endpoint(int fd, unsigned kind) {
  struct KERNELET_EndpointArgs args = {.kind = kind};
  int result = ioctl(fd, KERNELET_ENDPOINT, &args);
  if (result < 0)
    fail("endpoint");
  if (fcntl(result, F_SETFL, O_NONBLOCK) < 0)
    fail("nonblocking endpoint");
  return result;
}

static void attach(int fd, unsigned kind, int backing, unsigned flags) {
  struct KERNELET_AttachArgs args = {
      .kind = kind,
      .backing_fd = backing,
      .flags = flags,
  };
  checked_ioctl(fd, KERNELET_ATTACH, &args, "attach");
  if ((kind == KERNELET_BLOCK || kind == KERNELET_ZERO_COPY_BLOCK) &&
      args.out_index != 0)
    fail("independent block index");
}

static struct instance start(int control, const char *role) {
  char command[256];
  snprintf(
      command, sizeof(command),
      "root=/dev/vda rootfstype=ext2 ro init=/init SHARED_ROLE=%s loglevel=3",
      role);
  struct KERNELET_CreateArgs args = {
      .num_vcpus = 1,
      .initial_grains = 32,
      .max_grains = 128,
      .max_meta_sections = 128,
      .oops_budget = 0,
      .log_bytes_per_sec = 65536,
      .max_tasks = 64,
      .cmdline_ptr = (uintptr_t)command,
      .cmdline_len = strlen(command),
  };
  struct instance instance = {.fd = ioctl(control, KERNELET_CREATE, &args)};
  if (instance.fd < 0)
    fail("create");
  instance.console = endpoint(instance.fd, KERNELET_CONSOLE);
  instance.log = endpoint(instance.fd, KERNELET_LOG);
  int root = open("/image-root.ext2", O_RDONLY);
  if (root < 0)
    fail("open image root");
  attach(instance.fd, KERNELET_BLOCK, root, KERNELET_BLOCK_READ_ONLY);
  if (!strcmp(role, "send")) {
    struct KERNELET_AttachArgs invalid = {
        .kind = KERNELET_ZERO_COPY_BLOCK,
        .backing_fd = root,
        .flags = KERNELET_BLOCK_READ_ONLY,
    };
    errno = 0;
    if (ioctl(instance.fd, KERNELET_ATTACH, &invalid) != -1 ||
        errno != EOPNOTSUPP)
      fail("buffered backend must reject zero-copy attachment");
    int device = open("/dev/vda", O_RDWR);
    if (device < 0)
      fail("open physical VirtIO block");
    attach(instance.fd, KERNELET_ZERO_COPY_BLOCK, device, 0);
    close(device);
  }
  close(root);
  attach(instance.fd, KERNELET_CONSOLE, instance.console, 0);
  checked_ioctl(instance.fd, KERNELET_START, NULL, "start");
  printf("SHARED_IO_STARTED role=%s cid=%u\n", role, args.out_cid);
  return instance;
}

static void drain(int fd, unsigned index, const char *kind) {
  char bytes[4096];
  ssize_t count;
  while ((count = read(fd, bytes, sizeof(bytes))) > 0) {
    printf("[image %u %s] ", index, kind);
    fwrite(bytes, 1, count, stdout);
  }
  if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    fail("drain endpoint");
}

static void rejected_connection(int fd,
                                struct KERNELET_SharedBufferConnectArgs args,
                                int expected) {
  errno = 0;
  if (ioctl(fd, KERNELET_SHARED_BUFFER_CONNECT, &args) != -1 ||
      errno != expected)
    fail("invalid shared connection must reject without mutation");
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mkdir("/dev", 0755);
  mkdir("/proc", 0755);
  if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) < 0 && errno != EBUSY)
    fail("mount devtmpfs");
  if (mount("proc", "/proc", "proc", 0, NULL) < 0 && errno != EBUSY)
    fail("mount proc");
  int control = open("/dev/kernelet", O_RDWR);
  if (control < 0)
    fail("open control");
  struct instance instances[2] = {start(control, "send"),
                                  start(control, "receive")};
  rejected_connection(instances[0].fd,
                      (struct KERNELET_SharedBufferConnectArgs){.peer_fd = -1},
                      EBADF);
  rejected_connection(
      instances[0].fd,
      (struct KERNELET_SharedBufferConnectArgs){.peer_fd = control}, EBADF);
  rejected_connection(instances[0].fd,
                      (struct KERNELET_SharedBufferConnectArgs){
                          .peer_fd = instances[1].fd, .flags = 1},
                      EINVAL);
  rejected_connection(instances[0].fd,
                      (struct KERNELET_SharedBufferConnectArgs){
                          .peer_fd = instances[1].fd, .out_connection = 1},
                      EINVAL);
  int alias = dup(instances[0].fd);
  if (alias < 0)
    fail("dup sandbox capability");
  rejected_connection(
      instances[0].fd,
      (struct KERNELET_SharedBufferConnectArgs){.peer_fd = alias}, EINVAL);
  close(alias);
  struct KERNELET_SharedBufferConnectArgs connection = {.peer_fd =
                                                            instances[1].fd};
  checked_ioctl(instances[0].fd, KERNELET_SHARED_BUFFER_CONNECT, &connection,
                "connect shared buffers");
  if (!connection.out_connection ||
      connection.out_connection != connection.out_peer_connection)
    fail("connection identity");
  struct KERNELET_SharedBufferConnectArgs duplicate = {.peer_fd =
                                                           instances[1].fd};
  checked_ioctl(instances[0].fd, KERNELET_SHARED_BUFFER_CONNECT, &duplicate,
                "duplicate connection");
  if (duplicate.out_connection != connection.out_connection)
    fail("connection must be idempotent");
  pid_t child = fork();
  if (child < 0)
    fail("fork capability holder");
  if (child == 0) {
    struct KERNELET_SharedBufferConnectArgs transferred = {.peer_fd =
                                                               instances[1].fd};
    if (setuid(51001) < 0 ||
        ioctl(instances[0].fd, KERNELET_SHARED_BUFFER_CONNECT, &transferred) <
            0 ||
        transferred.out_connection != connection.out_connection)
      _exit(1);
    _exit(0);
  }
  int child_status = 0;
  if (waitpid(child, &child_status, 0) != child || !WIFEXITED(child_status) ||
      WEXITSTATUS(child_status) != 0)
    fail("delegated capability authorization");
  printf("SHARED_IO_CONNECTED id=%llu\n",
         (unsigned long long)connection.out_connection);
  time_t deadline = time(NULL) + 60;
  unsigned finished = 0;
  while (finished < 2 && time(NULL) < deadline) {
    for (unsigned index = 0; index < 2; ++index) {
      struct instance *instance = &instances[index];
      drain(instance->console, index, "console");
      drain(instance->log, index, "log");
      if (instance->finished)
        continue;
      struct KERNELET_StatusRaw status = {0};
      checked_ioctl(instance->fd, KERNELET_STATUS, &status, "status");
      if (status.state == KERNELET_STATE_EXITED) {
        if (status.reason != KERNELET_STATUS_REASON_EXITED ||
            status.code != 0) {
          fprintf(stderr, "image=%u reason=%u code=%u message=%.*s\n", index,
                  status.reason, status.code, status.message_len,
                  status.message);
          fail("image exited unsuccessfully");
        }
        instance->finished = true;
        ++finished;
      }
    }
    usleep(1000);
  }
  if (finished != 2)
    fail("image deadline");
  for (unsigned index = 0; index < 2; ++index) {
    drain(instances[index].console, index, "console");
    checked_ioctl(instances[index].fd, KERNELET_DESTROY, NULL, "destroy");
    time_t destroy_deadline = time(NULL) + 10;
    for (;;) {
      struct KERNELET_StatusRaw status = {0};
      checked_ioctl(instances[index].fd, KERNELET_STATUS, &status,
                    "destroy status");
      if (status.state == KERNELET_STATE_DESTROYED)
        break;
      if (time(NULL) >= destroy_deadline)
        fail("destroy deadline");
      usleep(1000);
    }
    close(instances[index].fd);
    close(instances[index].console);
    close(instances[index].log);
  }
  close(control);
  puts("SHARED_IO_HOST_PASS real_virtio_dma=1 network_round_trips=4");
  reboot(RB_POWER_OFF);
  return 0;
}
