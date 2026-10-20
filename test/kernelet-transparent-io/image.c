// SPDX-License-Identifier: MPL-2.0

// Ordinary file and socket operations; no kernelet-specific I/O interface.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define FILE_BYTES (1024 * 1024)
#define TCP_ROUNDS 256
#define UDP_ROUNDS 128

static void fail(const char *what) {
  perror(what);
  exit(1);
}

static uint64_t nanoseconds(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now))
    fail("clock_gettime");
  return (uint64_t)now.tv_sec * 1000000000 + now.tv_nsec;
}

static void transfer(int fd, void *buffer, size_t len, int writing) {
  char *bytes = buffer;
  while (len) {
    ssize_t done = writing ? write(fd, bytes, len) : read(fd, bytes, len);
    if (done <= 0)
      fail(writing ? "write" : "read");
    bytes += done;
    len -= done;
  }
}

static unsigned char pattern(size_t index, unsigned salt) {
  return (unsigned char)(index * 13 + salt);
}

static void file_test(void) {
  unsigned char bytes[4096];
  int fd = open("/seed.bin", O_RDONLY);
  if (fd < 0)
    fail("open seed");
  for (size_t offset = 0; offset < FILE_BYTES; offset += sizeof(bytes)) {
    transfer(fd, bytes, sizeof(bytes), 0);
    for (size_t i = 0; i < sizeof(bytes); ++i)
      if (bytes[i] != pattern(offset + i, 7))
        fail("seed differs");
  }
  close(fd);
  fd = open("/written.bin", O_CREAT | O_TRUNC | O_RDWR, 0644);
  if (fd < 0)
    fail("create file");
  for (size_t offset = 0; offset < FILE_BYTES; offset += sizeof(bytes)) {
    for (size_t i = 0; i < sizeof(bytes); ++i)
      bytes[i] = pattern(offset + i, 91);
    transfer(fd, bytes, sizeof(bytes), 1);
  }
  if (fsync(fd))
    fail("fsync file");
  unsigned char *mapping =
      mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (mapping == MAP_FAILED)
    fail("mmap file");
  memcpy(mapping + 31, "shared-file-map", 15);
  if (msync(mapping, 4096, MS_SYNC) || munmap(mapping, 4096) || fsync(fd))
    fail("persist mapping");
  if (lseek(fd, 0, SEEK_SET))
    fail("seek file");
  for (size_t offset = 0; offset < FILE_BYTES; offset += sizeof(bytes)) {
    transfer(fd, bytes, sizeof(bytes), 0);
    for (size_t i = 0; i < sizeof(bytes); ++i) {
      size_t at = offset + i;
      unsigned char expected = at >= 31 && at < 46
                                   ? (unsigned char)"shared-file-map"[at - 31]
                                   : pattern(at, 91);
      if (bytes[i] != expected)
        fail("file readback differs");
    }
  }
  close(fd);
  sync();
}

static int socket_to_host(int type, unsigned port) {
  int fd = socket(AF_INET, type, 0);
  if (fd < 0)
    fail("socket");
  struct timeval timeout = {.tv_sec = 15};
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
      setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
    fail("socket timeout");
  struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
  if (inet_pton(AF_INET, "10.0.2.16", &address.sin_addr) != 1 ||
      connect(fd, (struct sockaddr *)&address, sizeof(address)))
    fail("connect Host");
  return fd;
}

static void network_test(void) {
  unsigned char bytes[8192], actual[8192];
  int fd = socket_to_host(SOCK_STREAM, 10080);
  for (unsigned round = 0; round < TCP_ROUNDS; ++round) {
    for (size_t i = 0; i < sizeof(bytes); ++i)
      bytes[i] = pattern(i, round);
    transfer(fd, bytes, sizeof(bytes), 1);
    transfer(fd, actual, sizeof(actual), 0);
    if (memcmp(bytes, actual, sizeof(bytes)))
      fail("TCP echo differs");
  }
  close(fd);
  fd = socket_to_host(SOCK_DGRAM, 10081);
  const size_t sizes[] = {1, 64, 512, 1200};
  for (unsigned round = 0; round < UDP_ROUNDS; ++round) {
    size_t len = sizes[round % 4];
    for (size_t i = 0; i < len; ++i)
      bytes[i] = pattern(i, round + 17);
    if (send(fd, bytes, len, 0) != (ssize_t)len ||
        recv(fd, actual, sizeof(actual), 0) != (ssize_t)len ||
        memcmp(bytes, actual, len))
      fail("UDP echo differs");
  }
  close(fd);
}

static void report_paths(void) {
  if (mount("proc", "/proc", "proc", 0, NULL) && errno != EBUSY)
    fail("mount diagnostics");
  int fd = open("/proc/kernelet_shared_io_test", O_RDWR);
  if (fd < 0 || write(fd, "paths", 5) != 5 || lseek(fd, 0, SEEK_SET))
    fail("packet copy counters");
  char result[512];
  ssize_t len = read(fd, result, sizeof(result) - 1);
  if (len <= 0)
    fail("read packet counters");
  result[len] = 0;
  printf("TRANSPARENT_PACKET_PATHS %s", result);
  close(fd);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  const char *mode = getenv("IO_MODE");
  if (!mode)
    fail("missing IO_MODE");
  uint64_t started = nanoseconds();
  file_test();
  uint64_t files_done = nanoseconds();
  printf("TRANSPARENT_FILE_PASS mode=%s bytes=%u elapsed_ns=%llu\n", mode,
         FILE_BYTES, (unsigned long long)(files_done - started));
  network_test();
  printf("TRANSPARENT_NET_PASS mode=%s tcp_bytes=%u udp_rounds=%u "
         "elapsed_ns=%llu\n",
         mode, TCP_ROUNDS * 8192, UDP_ROUNDS,
         (unsigned long long)(nanoseconds() - files_done));
  report_paths();
  printf("TRANSPARENT_IMAGE_PASS mode=%s\n", mode);
  return 0;
}
