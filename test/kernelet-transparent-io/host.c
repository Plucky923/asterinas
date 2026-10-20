// SPDX-License-Identifier: MPL-2.0

#define _GNU_SOURCE
#include "kernelet-abi.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void fail(const char *what) {
  fprintf(stderr, "TRANSPARENT_HOST_FAIL %s errno=%d %s\n", what, errno,
          strerror(errno));
  fflush(NULL);
  reboot(RB_POWER_OFF);
  _exit(1);
}

static void checked(int fd, unsigned long request, void *arg,
                    const char *what) {
  if (ioctl(fd, request, arg) < 0)
    fail(what);
}

static void echo_server(int datagram, int ready) {
  int listener = socket(AF_INET, datagram ? SOCK_DGRAM : SOCK_STREAM, 0);
  if (listener < 0) {
    perror("Host server socket");
    _exit(2);
  }
  struct sockaddr_in local = {.sin_family = AF_INET,
                              .sin_port = htons(datagram ? 10081 : 10080)};
  if (inet_pton(AF_INET, "10.0.2.16", &local.sin_addr) != 1)
    _exit(3);
  int one = 1;
  if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
    perror("Host server reuseaddr");
    _exit(3);
  }
  if (bind(listener, (struct sockaddr *)&local, sizeof(local))) {
    perror("Host server bind");
    _exit(3);
  }
  if (!datagram && listen(listener, 4)) {
    perror("Host server listen");
    _exit(3);
  }
  if (write(ready, "R", 1) != 1)
    _exit(4);
  close(ready);
  char bytes[8192];
  for (;;) {
    if (datagram) {
      struct sockaddr_in peer;
      socklen_t len = sizeof(peer);
      ssize_t count = recvfrom(listener, bytes, sizeof(bytes), 0,
                               (struct sockaddr *)&peer, &len);
      if (count <= 0 || sendto(listener, bytes, count, 0,
                               (struct sockaddr *)&peer, len) != count)
        _exit(5);
    } else {
      int stream = accept(listener, NULL, NULL);
      if (stream < 0)
        _exit(6);
      ssize_t count;
      while ((count = read(stream, bytes, sizeof(bytes))) > 0) {
        size_t offset = 0;
        while (offset < (size_t)count) {
          ssize_t done = write(stream, bytes + offset, count - offset);
          if (done <= 0)
            _exit(7);
          offset += done;
        }
      }
      close(stream);
    }
  }
}

static pid_t start_server(int datagram) {
  int ready[2];
  if (pipe(ready))
    fail("server pipe");
  pid_t child = fork();
  if (child < 0)
    fail("server fork");
  if (!child) {
    close(ready[0]);
    echo_server(datagram, ready[1]);
    _exit(8);
  }
  close(ready[1]);
  char byte;
  ssize_t count = read(ready[0], &byte, 1);
  if (count != 1 || byte != 'R') {
    int status = 0;
    pid_t waited = waitpid(child, &status, WNOHANG);
    fprintf(stderr, "server datagram=%d readiness=%zd waited=%d status=%d\n",
            datagram, count, waited, status);
    fail("server readiness");
  }
  close(ready[0]);
  return child;
}

static int endpoint(int sandbox, unsigned kind) {
  struct KERNELET_EndpointArgs args = {.kind = kind};
  int fd = ioctl(sandbox, KERNELET_ENDPOINT, &args);
  if (fd < 0 || fcntl(fd, F_SETFL, O_NONBLOCK))
    fail("endpoint");
  return fd;
}

static void drain(int fd, const char *mode, const char *name) {
  char bytes[4096];
  ssize_t count;
  while ((count = read(fd, bytes, sizeof(bytes))) > 0) {
    printf("[image %s %s] ", mode, name);
    fwrite(bytes, 1, count, stdout);
  }
  if (count < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    fail("drain endpoint");
}

static void run_image(int control, bool shared) {
  const char *mode = shared ? "shared" : "copy";
  char command[256];
  snprintf(command, sizeof(command),
           "root=/dev/vda rootfstype=ext2 rw init=/init IO_MODE=%s loglevel=3",
           mode);
  struct KERNELET_CreateArgs create = {
      .num_vcpus = 1,
      .initial_grains = 32,
      .max_grains = 128,
      .max_meta_sections = 128,
      .max_tasks = 64,
      .log_bytes_per_sec = 65536,
      .cmdline_ptr = (uintptr_t)command,
      .cmdline_len = strlen(command),
  };
  int sandbox = ioctl(control, KERNELET_CREATE, &create);
  if (sandbox < 0)
    fail("create");
  int console = endpoint(sandbox, KERNELET_CONSOLE);
  int log = endpoint(sandbox, KERNELET_LOG);
  int disk = open(shared ? "/dev/vdb" : "/dev/vda", O_RDWR);
  if (disk < 0)
    fail("open dedicated root disk");
  struct KERNELET_AttachArgs block = {
      .kind = shared ? KERNELET_BORROWED_BLOCK : KERNELET_BLOCK,
      .backing_fd = disk,
  };
  checked(sandbox, KERNELET_ATTACH, &block, "attach root disk");
  close(disk);
  struct KERNELET_AttachArgs terminal = {
      .kind = KERNELET_CONSOLE,
      .backing_fd = console,
  };
  checked(sandbox, KERNELET_ATTACH, &terminal, "attach console");
  int network = endpoint(sandbox, KERNELET_NET);
  struct KERNELET_NetConfigArgs config = {.host_resolver = {10, 0, 2, 3}};
  checked(network, KERNELET_NET_CONFIG, &config, "configure NAT");
  struct KERNELET_AttachArgs net = {
      .kind = shared ? KERNELET_SHARED_NET : KERNELET_NET,
      .backing_fd = network,
      .arg = UINT64_C(0x010044000002) + ((uint64_t)shared << 32),
  };
  checked(sandbox, KERNELET_ATTACH, &net, "attach network");
  close(network);
  checked(sandbox, KERNELET_START, NULL, "start");
  printf("TRANSPARENT_STARTED mode=%s cid=%u\n", mode, create.out_cid);
  time_t deadline = time(NULL) + 120;
  for (;;) {
    drain(console, mode, "console");
    drain(log, mode, "log");
    struct KERNELET_StatusRaw status = {0};
    checked(sandbox, KERNELET_STATUS, &status, "status");
    if (status.state == KERNELET_STATE_EXITED) {
      if (status.reason != KERNELET_STATUS_REASON_EXITED || status.code) {
        fprintf(stderr, "mode=%s reason=%u code=%u message=%.*s\n", mode,
                status.reason, status.code, status.message_len, status.message);
        fail("image exit");
      }
      break;
    }
    if (time(NULL) >= deadline)
      fail("image deadline");
    usleep(1000);
  }
  drain(console, mode, "console");
  struct KERNELET_IoPathStatsRaw paths = {0};
  checked(sandbox, KERNELET_IO_PATH_STATS, &paths, "I/O path counters");
  printf(
      "TRANSPARENT_PATHS mode=%s block_devices=%llu requests=%llu bytes=%llu "
      "identity=%llu block_copy=%llu net_devices=%llu tx=%llu tx_bytes=%llu "
      "rx=%llu rx_bytes=%llu net_copy=%llu fallback=%llu fallback_bytes=%llu "
      "allocations=%llu reuses=%llu\n",
      mode, (unsigned long long)paths.borrowed_block_devices,
      (unsigned long long)paths.borrowed_block_requests,
      (unsigned long long)paths.borrowed_block_bytes,
      (unsigned long long)paths.borrowed_block_identity_checks,
      (unsigned long long)paths.borrowed_block_copy_bytes,
      (unsigned long long)paths.shared_net_devices,
      (unsigned long long)paths.shared_net_tx_packets,
      (unsigned long long)paths.shared_net_tx_bytes,
      (unsigned long long)paths.shared_net_rx_packets,
      (unsigned long long)paths.shared_net_rx_bytes,
      (unsigned long long)paths.shared_net_payload_copy_bytes,
      (unsigned long long)paths.shared_net_native_fallback_packets,
      (unsigned long long)paths.shared_net_native_fallback_bytes,
      (unsigned long long)paths.shared_net_allocations,
      (unsigned long long)paths.shared_net_reuses);
  if (shared &&
      (paths.borrowed_block_devices != 1 || !paths.borrowed_block_requests ||
       paths.borrowed_block_bytes < 2097152 ||
       !paths.borrowed_block_identity_checks ||
       paths.borrowed_block_copy_bytes || paths.shared_net_devices != 1 ||
       paths.shared_net_tx_bytes < 2097152 ||
       paths.shared_net_rx_bytes < 2097152 ||
       paths.shared_net_payload_copy_bytes ||
       paths.shared_net_native_fallback_packets ||
       paths.shared_net_native_fallback_bytes || !paths.shared_net_reuses))
    fail("zero-copy coverage");
  if (!shared && (paths.borrowed_block_devices || paths.shared_net_devices))
    fail("copy device identity");
  struct KERNELET_StatsRaw stats = {0};
  checked(sandbox, KERNELET_STATS, &stats, "statistics");
  printf("TRANSPARENT_COST mode=%s services=%llu mmio=%llu irq=%llu "
         "host_bytes=%llu\n",
         mode, (unsigned long long)stats.service_calls,
         (unsigned long long)stats.mmio_accesses,
         (unsigned long long)stats.irqs_raised,
         (unsigned long long)stats.host_bytes_charged);
  checked(sandbox, KERNELET_DESTROY, NULL, "destroy");
  deadline = time(NULL) + 15;
  for (;;) {
    struct KERNELET_StatusRaw status = {0};
    checked(sandbox, KERNELET_STATUS, &status, "destroy status");
    if (status.state == KERNELET_STATE_DESTROYED)
      break;
    if (time(NULL) >= deadline)
      fail("destroy deadline");
    usleep(1000);
  }
  close(sandbox);
  close(console);
  close(log);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mkdir("/dev", 0755);
  mkdir("/proc", 0755);
  if ((mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) && errno != EBUSY) ||
      (mount("proc", "/proc", "proc", 0, NULL) && errno != EBUSY))
    fail("mount");
  pid_t tcp = start_server(0), udp = start_server(1);
  int control = open("/dev/kernelet", O_RDWR);
  if (control < 0)
    fail("control");
  run_image(control, false);
  run_image(control, true);
  close(control);
  kill(tcp, SIGTERM);
  kill(udp, SIGTERM);
  waitpid(tcp, NULL, 0);
  waitpid(udp, NULL, 0);
  puts("TRANSPARENT_HOST_PASS file=1 mmap=1 tcp=1 udp=1 zero_copy=1");
  reboot(RB_POWER_OFF);
  return 0;
}
