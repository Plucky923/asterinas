/* SPDX-License-Identifier: MPL-2.0 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "../regression/common/framevm_ioctl.h"

#define FRAMEVM_DEVICE_PATH "/dev/framevm"
#define FRAMEVMCTL_POLL_TIMEOUT_MS 50
#define FRAMEVMCTL_TERMINAL_DRAIN_MS 250
#define FRAMEVMCTL_IO_CHUNK 4096
#define FRAMEVMCTL_PENDING_CAPACITY 8192
#define FRAMEVMCTL_SCRIPT_INPUT_LIMIT 65536
#define FRAMEVM_GUEST_CID_BASE 3ULL

static volatile sig_atomic_t should_exit;
static struct termios saved_termios;
static int raw_mode_enabled;

static void handle_signal(int signal_number) {
  (void)signal_number;
  should_exit = 1;
}

static int install_signal_handlers(void) {
  struct sigaction action;

  memset(&action, 0, sizeof(action));
  action.sa_handler = handle_signal;
  sigemptyset(&action.sa_mask);

  if (sigaction(SIGINT, &action, NULL) < 0 ||
      sigaction(SIGTERM, &action, NULL) < 0) {
    perror("sigaction");
    return -1;
  }
  return 0;
}

static int enable_raw_mode_if_tty(void) {
  struct termios raw_termios;

  if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
    return 0;
  }
  if (tcgetattr(STDIN_FILENO, &saved_termios) < 0) {
    perror("tcgetattr");
    return -1;
  }

  raw_termios = saved_termios;
  cfmakeraw(&raw_termios);
  if (tcsetattr(STDIN_FILENO, TCSANOW, &raw_termios) < 0) {
    perror("tcsetattr");
    return -1;
  }

  raw_mode_enabled = 1;
  return 0;
}

static void restore_raw_mode(void) {
  if (raw_mode_enabled) {
    (void)tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
    raw_mode_enabled = 0;
  }
}

static int parse_u32(const char *text, uint32_t *value) {
  char *end = NULL;
  unsigned long parsed;

  errno = 0;
  parsed = strtoul(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || parsed > UINT32_MAX) {
    return -1;
  }

  *value = (uint32_t)parsed;
  return 0;
}

static int write_all(int fd, const void *buffer, size_t length) {
  const char *cursor = buffer;

  while (length > 0) {
    ssize_t written = write(fd, cursor, length);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (written == 0) {
      errno = EIO;
      return -1;
    }
    cursor += written;
    length -= (size_t)written;
  }

  return 0;
}

struct pending_write {
  char bytes[FRAMEVMCTL_PENDING_CAPACITY];
  size_t offset;
  size_t length;
};

struct scripted_input {
  char *bytes;
  size_t length;
};

struct drive_config {
  const char *path;
  int readonly;
  int present;
  int fd;
};

static int pending_write_empty(const struct pending_write *pending) {
  return pending->offset == pending->length;
}

static void pending_write_clear(struct pending_write *pending) {
  pending->offset = 0;
  pending->length = 0;
}

static int pending_write_fill(struct pending_write *pending, const char *buffer,
                              size_t length) {
  if (length > sizeof(pending->bytes)) {
    errno = EMSGSIZE;
    return -1;
  }

  memcpy(pending->bytes, buffer, length);
  pending->offset = 0;
  pending->length = length;
  return 0;
}

static int flush_pending_console_write(int console_fd,
                                       struct pending_write *pending) {
  while (pending->offset < pending->length) {
    ssize_t written = write(console_fd, pending->bytes + pending->offset,
                            pending->length - pending->offset);
    if (written < 0) {
      if (errno == EINTR || errno == EAGAIN) {
        return 0;
      }
      return -1;
    }
    if (written == 0) {
      errno = EIO;
      return -1;
    }
    pending->offset += (size_t)written;
  }

  pending_write_clear(pending);
  return 0;
}

static void free_scripted_input(struct scripted_input *input) {
  free(input->bytes);
  input->bytes = NULL;
  input->length = 0;
}

static int append_scripted_input(struct scripted_input *input,
                                 const char *buffer, size_t length) {
  char *new_bytes;

  if (length > FRAMEVMCTL_SCRIPT_INPUT_LIMIT - input->length) {
    fprintf(stderr, "scripted FrameVM console input is too large\n");
    errno = EMSGSIZE;
    return -1;
  }

  new_bytes = realloc(input->bytes, input->length + length);
  if (new_bytes == NULL) {
    perror("realloc");
    return -1;
  }
  memcpy(new_bytes + input->length, buffer, length);
  input->bytes = new_bytes;
  input->length += length;
  return 0;
}

static int read_scripted_stdin(struct scripted_input *input) {
  char buffer[FRAMEVMCTL_IO_CHUNK];

  if (isatty(STDIN_FILENO)) {
    return 0;
  }

  for (;;) {
    ssize_t read_len = read(STDIN_FILENO, buffer, sizeof(buffer));
    if (read_len < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("read stdin");
      return -1;
    }
    if (read_len == 0) {
      return 0;
    }
    if (append_scripted_input(input, buffer, (size_t)read_len) < 0) {
      return -1;
    }
  }
}

static int bridge_console(int console_fd) {
  char buffer[FRAMEVMCTL_IO_CHUNK];
  struct pending_write pending_stdin = {0};
  int stdin_open = 1;

  if (install_signal_handlers() < 0 || enable_raw_mode_if_tty() < 0) {
    return 1;
  }

  while (!should_exit) {
    struct pollfd poll_fds[2];
    nfds_t poll_count = 0;

    if (stdin_open && pending_write_empty(&pending_stdin)) {
      poll_fds[poll_count].fd = STDIN_FILENO;
      poll_fds[poll_count].events = POLLIN | POLLHUP;
      poll_fds[poll_count].revents = 0;
      poll_count++;
    }
    poll_fds[poll_count].fd = console_fd;
    poll_fds[poll_count].events = POLLIN | POLLHUP | POLLERR;
    if (!pending_write_empty(&pending_stdin)) {
      poll_fds[poll_count].events |= POLLOUT;
    }
    poll_fds[poll_count].revents = 0;
    poll_count++;

    int ready = poll(poll_fds, poll_count, FRAMEVMCTL_POLL_TIMEOUT_MS);
    if (ready < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("poll");
      restore_raw_mode();
      return 1;
    }
    if (ready == 0) {
      if (!pending_write_empty(&pending_stdin) &&
          flush_pending_console_write(console_fd, &pending_stdin) < 0) {
        perror("write console");
        restore_raw_mode();
        return 1;
      }
      continue;
    }

    nfds_t stdin_index = 0;
    nfds_t console_index =
        (stdin_open && pending_write_empty(&pending_stdin)) ? 1 : 0;
    if (stdin_open && pending_write_empty(&pending_stdin) &&
        (poll_fds[stdin_index].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
      ssize_t read_len = read(STDIN_FILENO, buffer, sizeof(buffer));
      if (read_len < 0) {
        if (errno == EINTR || errno == EAGAIN) {
          continue;
        }
        perror("read stdin");
        restore_raw_mode();
        return 1;
      }
      if (read_len == 0) {
        stdin_open = 0;
      } else if (pending_write_fill(&pending_stdin, buffer,
                                    (size_t)read_len) < 0) {
        perror("buffer stdin");
        restore_raw_mode();
        return 1;
      }
    }

    if (!pending_write_empty(&pending_stdin) &&
        flush_pending_console_write(console_fd, &pending_stdin) < 0) {
      perror("write console");
      restore_raw_mode();
      return 1;
    }
    if ((poll_fds[console_index].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
      ssize_t read_len = read(console_fd, buffer, sizeof(buffer));
      if (read_len < 0) {
        if (errno == EINTR || errno == EAGAIN) {
          continue;
        }
        perror("read console");
        restore_raw_mode();
        return 1;
      }
      if (read_len == 0) {
        break;
      }
      if (write_all(STDOUT_FILENO, buffer, (size_t)read_len) < 0) {
        perror("write stdout");
        restore_raw_mode();
        return 1;
      }
      if (!pending_write_empty(&pending_stdin) &&
          flush_pending_console_write(console_fd, &pending_stdin) < 0) {
        perror("write console");
        restore_raw_mode();
        return 1;
      }
    }
  }

  restore_raw_mode();
  return should_exit ? 130 : 0;
}

static int wait_for_bridge_start_signal(int fd) {
  char byte;

  for (;;) {
    ssize_t read_len = read(fd, &byte, sizeof(byte));
    if (read_len < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("read bridge start signal");
      close(fd);
      return 1;
    }
    close(fd);
    return read_len == 1 ? 0 : 1;
  }
}

static int signal_bridge_start(int fd) {
  char byte = 0;

  if (write_all(fd, &byte, sizeof(byte)) < 0) {
    perror("write bridge start signal");
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

static void usage(FILE *stream) {
  fprintf(stream,
          "usage: framevmctl run --vcpus N [--share X] "
          "[--drive file=PATH[,readonly|writable]] "
          "[--append CMDLINE]\n"
                  "       framevmctl --help\n");
}

static int parse_drive(const char *text, struct drive_config *drive) {
  char *copy;
  char *token;
  char *saveptr = NULL;
  int saw_file = 0;
  int saw_readonly = 0;
  int saw_writable = 0;

  if (drive->present) {
    fprintf(stderr, "multiple --drive options are not supported\n");
    return -1;
  }

  copy = strdup(text);
  if (copy == NULL) {
    perror("strdup");
    return -1;
  }

  for (token = strtok_r(copy, ",", &saveptr); token != NULL;
       token = strtok_r(NULL, ",", &saveptr)) {
    if (strncmp(token, "file=", 5) == 0) {
      if (saw_file || token[5] == '\0') {
        fprintf(stderr, "invalid --drive file token\n");
        free(copy);
        return -1;
      }
      drive->path = strdup(token + 5);
      if (drive->path == NULL) {
        perror("strdup");
        free(copy);
        return -1;
      }
      saw_file = 1;
    } else if (strcmp(token, "readonly") == 0) {
      if (saw_readonly || saw_writable) {
        fprintf(stderr, "conflicting or duplicate --drive mode\n");
        free((void *)drive->path);
        drive->path = NULL;
        free(copy);
        return -1;
      }
      saw_readonly = 1;
      drive->readonly = 1;
    } else if (strcmp(token, "writable") == 0) {
      if (saw_readonly || saw_writable) {
        fprintf(stderr, "conflicting or duplicate --drive mode\n");
        free((void *)drive->path);
        drive->path = NULL;
        free(copy);
        return -1;
      }
      saw_writable = 1;
      drive->readonly = 0;
    } else {
      fprintf(stderr, "unsupported --drive token: %s\n", token);
      free((void *)drive->path);
      drive->path = NULL;
      free(copy);
      return -1;
    }
  }

  free(copy);
  if (!saw_file) {
    fprintf(stderr, "--drive requires file=PATH\n");
    return -1;
  }
  drive->present = 1;
  return 0;
}

static int open_drive(struct drive_config *drive,
                      struct framevm_create_vm *request) {
  int flags;

  if (!drive->present) {
    return 0;
  }

  flags = drive->readonly ? O_RDONLY : O_RDWR;
#ifdef O_CLOEXEC
  flags |= O_CLOEXEC;
#endif
  drive->fd = open(drive->path, flags);
  if (drive->fd < 0) {
    perror("open --drive file");
    return -1;
  }

  request->flags |= FRAMEVM_CREATE_HAS_DRIVE;
  if (drive->readonly) {
    request->flags |= FRAMEVM_CREATE_DRIVE_READONLY;
  }
  request->reserved = (uint32_t)drive->fd;
  return 0;
}

static void close_drive(struct drive_config *drive) {
  if (drive->fd >= 0) {
    close(drive->fd);
    drive->fd = -1;
  }
  free((void *)drive->path);
  drive->path = NULL;
}

static int set_guest_cmdline(int vm_fd, const char *append) {
  struct framevm_cmdline request;
  size_t length;

  if (append == NULL) {
    return 0;
  }

  length = strlen(append);
  if (length > FRAMEVM_CMDLINE_MAX_LEN) {
    fprintf(stderr, "FrameVM guest cmdline append is too long\n");
    return -1;
  }

  request.ptr = (uint64_t)(uintptr_t)append;
  request.len = (uint32_t)length;
  request.flags = 0;
  if (ioctl(vm_fd, FRAMEVM_SET_CMDLINE, &request) < 0) {
    perror("FRAMEVM_SET_CMDLINE");
    return -1;
  }
  return 0;
}

static const char *framevm_state_name(uint32_t state) {
  switch (state) {
  case FRAMEVM_STATE_CREATED:
    return "created";
  case FRAMEVM_STATE_STARTING:
    return "starting";
  case FRAMEVM_STATE_RUNNING:
    return "running";
  case FRAMEVM_STATE_EXITED_SUCCESS:
    return "exited-success";
  case FRAMEVM_STATE_EXITED_FAILURE:
    return "exited-failure";
  case FRAMEVM_STATE_RESTART_REQUESTED:
    return "restart-requested";
  case FRAMEVM_STATE_STOPPED_BY_HOST:
    return "stopped-by-host";
  case FRAMEVM_STATE_PANIC_FAILURE:
    return "panic-failure";
  case FRAMEVM_STATE_DESTROYED:
    return "destroyed";
  default:
    return "unknown";
  }
}

static int framevm_status_is_terminal(const struct framevm_status *status) {
  return status->state == FRAMEVM_STATE_EXITED_SUCCESS ||
         status->state == FRAMEVM_STATE_EXITED_FAILURE ||
         status->state == FRAMEVM_STATE_RESTART_REQUESTED ||
         status->state == FRAMEVM_STATE_STOPPED_BY_HOST ||
         status->state == FRAMEVM_STATE_PANIC_FAILURE ||
         status->state == FRAMEVM_STATE_DESTROYED;
}

static int get_framevm_status(int vm_fd, struct framevm_status *status) {
  memset(status, 0, sizeof(*status));
  if (ioctl(vm_fd, FRAMEVM_GET_STATUS, status) < 0) {
    perror("FRAMEVM_GET_STATUS");
    return -1;
  }
  return 0;
}

static int print_framevm_identity(int vm_fd) {
  struct framevm_status status;

  if (get_framevm_status(vm_fd, &status) < 0) {
    return -1;
  }
  if (status.vm_id == FRAMEVM_STATUS_VM_ID_NONE) {
    fprintf(stderr, "FrameVM identity is unavailable after start\n");
    return -1;
  }

  printf("FRAMEVM_VM_ID=%llu\n", (unsigned long long)status.vm_id);
  printf("FRAMEVM_GUEST_CID=%llu\n",
         (unsigned long long)(status.vm_id + FRAMEVM_GUEST_CID_BASE));
  fflush(stdout);
  return 0;
}

static void print_framevm_status_on_failure(int vm_fd, const char *operation) {
  struct framevm_status status;

  if (get_framevm_status(vm_fd, &status) < 0) {
    return;
  }
  fprintf(stderr, "%s failure status: %s vm_id=%llu code=%d reason=%u class=%u\n",
          operation, framevm_state_name(status.state),
          (unsigned long long)status.vm_id, status.status_code,
          status.terminal_reason, status.failure_class);
}

static int framevm_status_exit_code(const struct framevm_status *status) {
  switch (status->state) {
  case FRAMEVM_STATE_EXITED_SUCCESS:
    return status->status_code == 0 ? 0 : 1;
  case FRAMEVM_STATE_EXITED_FAILURE:
    if (status->status_code > 0 && status->status_code < 126) {
      return status->status_code;
    }
    return 1;
  case FRAMEVM_STATE_RESTART_REQUESTED:
  case FRAMEVM_STATE_STOPPED_BY_HOST:
  case FRAMEVM_STATE_PANIC_FAILURE:
  case FRAMEVM_STATE_DESTROYED:
    return 1;
  default:
    return 1;
  }
}

static int reap_bridge_if_exited(pid_t bridge_pid, int *bridge_waited,
                                 int *bridge_status) {
  int wait_status;
  pid_t ret;

  if (*bridge_waited) {
    return 0;
  }

  ret = waitpid(bridge_pid, &wait_status, WNOHANG);
  if (ret == 0) {
    return 0;
  }
  if (ret < 0) {
    if (errno == ECHILD) {
      *bridge_waited = 1;
      return 0;
    }
    perror("waitpid");
    return -1;
  }

  *bridge_waited = 1;
  if (WIFSIGNALED(wait_status)) {
    *bridge_status = 128 + WTERMSIG(wait_status);
  } else if (WIFEXITED(wait_status)) {
    *bridge_status = WEXITSTATUS(wait_status);
  } else {
    *bridge_status = 1;
  }
  return 0;
}

static void drain_bridge_after_terminal(pid_t bridge_pid, int *bridge_waited) {
  int bridge_status = 0;
  int elapsed_ms = 0;

  while (!*bridge_waited && elapsed_ms < FRAMEVMCTL_TERMINAL_DRAIN_MS) {
    if (reap_bridge_if_exited(bridge_pid, bridge_waited, &bridge_status) < 0) {
      return;
    }
    if (*bridge_waited) {
      return;
    }
    usleep(FRAMEVMCTL_POLL_TIMEOUT_MS * 1000);
    elapsed_ms += FRAMEVMCTL_POLL_TIMEOUT_MS;
  }
}

static int wait_for_vm_terminal(int vm_fd, pid_t bridge_pid,
                                int *bridge_waited,
                                struct framevm_status *status) {
  int bridge_status = 0;

  for (;;) {
    struct pollfd poll_fd = {
        .fd = vm_fd,
        .events = POLLIN | POLLHUP | POLLERR,
        .revents = 0,
    };

    if (should_exit) {
      return 130;
    }

    if (get_framevm_status(vm_fd, status) < 0) {
      return 1;
    }
    if (framevm_status_is_terminal(status)) {
      return framevm_status_exit_code(status);
    }

    if (reap_bridge_if_exited(bridge_pid, bridge_waited, &bridge_status) < 0) {
      return 1;
    }
    if (*bridge_waited && bridge_status != 0) {
      return bridge_status;
    }

    int ready = poll(&poll_fd, 1, FRAMEVMCTL_POLL_TIMEOUT_MS);
    if (ready < 0) {
      if (errno == EINTR) {
        if (should_exit) {
          return 130;
        }
        continue;
      }
      perror("poll vm");
      return 1;
    }
    if (should_exit) {
      return 130;
    }
  }
}

static int run_framevm(int argc, char **argv) {
  struct framevm_create_vm request = {
      .vcpu_count = 0,
      .share = FRAMEVM_DEFAULT_SHARE,
      .flags = 0,
      .reserved = 0,
  };
  int controller_fd;
  int vm_fd;
  int console_fd;
  int bridge_start_pipe[2] = {-1, -1};
  pid_t bridge_pid = -1;
  int bridge_waited = 0;
  int status = 0;
  struct framevm_status vm_status;
  struct scripted_input scripted_input = {
      .bytes = NULL,
      .length = 0,
  };
  struct drive_config drive = {
      .path = NULL,
      .readonly = 0,
      .present = 0,
      .fd = -1,
  };
  const char *guest_cmdline_append = NULL;

  for (int i = 2; i < argc; i++) {
    if (strcmp(argv[i], "--vcpus") == 0 && i + 1 < argc) {
      if (parse_u32(argv[++i], &request.vcpu_count) < 0) {
        fprintf(stderr, "invalid --vcpus value\n");
        return 2;
      }
    } else if (strcmp(argv[i], "--share") == 0 && i + 1 < argc) {
      if (parse_u32(argv[++i], &request.share) < 0) {
        fprintf(stderr, "invalid --share value\n");
        return 2;
      }
    } else if (strcmp(argv[i], "--drive") == 0 && i + 1 < argc) {
      if (parse_drive(argv[++i], &drive) < 0) {
        close_drive(&drive);
        return 2;
      }
    } else if (strcmp(argv[i], "--append") == 0 && i + 1 < argc) {
      if (guest_cmdline_append != NULL) {
        fprintf(stderr, "multiple --append options are not supported\n");
        close_drive(&drive);
        return 2;
      }
      guest_cmdline_append = argv[++i];
    } else {
      usage(stderr);
      close_drive(&drive);
      return 2;
    }
  }

  if (request.vcpu_count < FRAMEVM_MIN_VCPU_COUNT ||
      request.vcpu_count > FRAMEVM_MAX_VCPU_COUNT ||
      request.share < FRAMEVM_MIN_SHARE || request.share > FRAMEVM_MAX_SHARE) {
    usage(stderr);
    close_drive(&drive);
    return 2;
  }

  if (read_scripted_stdin(&scripted_input) < 0) {
    close_drive(&drive);
    free_scripted_input(&scripted_input);
    return 1;
  }

  if (open_drive(&drive, &request) < 0) {
    close_drive(&drive);
    free_scripted_input(&scripted_input);
    return 1;
  }

  controller_fd = open(FRAMEVM_DEVICE_PATH, O_RDWR);
  if (controller_fd < 0) {
    perror("open /dev/framevm");
    close_drive(&drive);
    free_scripted_input(&scripted_input);
    return 1;
  }

  vm_fd = ioctl(controller_fd, FRAMEVM_CREATE_VM, &request);
  close_drive(&drive);
  if (vm_fd < 0) {
    perror("FRAMEVM_CREATE_VM");
    close(controller_fd);
    free_scripted_input(&scripted_input);
    return 1;
  }

  if (set_guest_cmdline(vm_fd, guest_cmdline_append) < 0) {
    close(vm_fd);
    close(controller_fd);
    free_scripted_input(&scripted_input);
    return 1;
  }

  console_fd = ioctl(vm_fd, FRAMEVM_GET_CONSOLE_FD);
  if (console_fd < 0) {
    perror("FRAMEVM_GET_CONSOLE_FD");
    close(vm_fd);
    close(controller_fd);
    free_scripted_input(&scripted_input);
    return 1;
  }

  if (pipe(bridge_start_pipe) < 0) {
    perror("pipe");
    status = 1;
  } else if (install_signal_handlers() < 0) {
    status = 1;
  } else if ((bridge_pid = fork()) < 0) {
    perror("fork");
    status = 1;
  } else if (bridge_pid == 0) {
    close(bridge_start_pipe[1]);
    close(vm_fd);
    close(controller_fd);
    if (wait_for_bridge_start_signal(bridge_start_pipe[0]) != 0) {
      close(console_fd);
      return 1;
    }
    return bridge_console(console_fd);
  } else {
    close(bridge_start_pipe[0]);
    bridge_start_pipe[0] = -1;
  }

  if (status == 0 && ioctl(vm_fd, FRAMEVM_START) < 0 && errno != EINTR) {
    perror("FRAMEVM_START");
    print_framevm_status_on_failure(vm_fd, "FRAMEVM_START");
    status = 1;
  }

  if (status == 0 && bridge_pid > 0) {
    if (signal_bridge_start(bridge_start_pipe[1]) < 0) {
      status = 1;
    }
    bridge_start_pipe[1] = -1;
  }

  if (status == 0 && bridge_pid > 0 && print_framevm_identity(vm_fd) < 0) {
    status = 1;
  }

  if (status == 0 && scripted_input.length != 0 &&
      write_all(console_fd, scripted_input.bytes, scripted_input.length) < 0) {
    perror("write scripted console input");
    status = 1;
  }
  free_scripted_input(&scripted_input);

  if (status == 0 && bridge_pid > 0) {
    status = wait_for_vm_terminal(vm_fd, bridge_pid, &bridge_waited,
                                  &vm_status);
    if (status != 130) {
      drain_bridge_after_terminal(bridge_pid, &bridge_waited);
      fprintf(stderr, "FrameVM terminal status: %s code=%d reason=%u\n",
              framevm_state_name(vm_status.state), vm_status.status_code,
              vm_status.terminal_reason);
    }
  }

  (void)ioctl(vm_fd, FRAMEVM_STOP);
  if (bridge_pid > 0 && !bridge_waited) {
    kill(bridge_pid, SIGTERM);
    if (waitpid(bridge_pid, NULL, 0) < 0 && errno != ECHILD) {
      perror("waitpid");
      status = 1;
    }
  }
  if (bridge_start_pipe[0] >= 0) {
    close(bridge_start_pipe[0]);
  }
  if (bridge_start_pipe[1] >= 0) {
    close(bridge_start_pipe[1]);
  }
  close(console_fd);
  close(vm_fd);
  close(controller_fd);
  free_scripted_input(&scripted_input);

  if (should_exit && status == 0) {
    status = 130;
  }
  return status;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--help") == 0) {
    usage(stdout);
    return 0;
  }
  if (argc >= 2 && strcmp(argv[1], "run") == 0) {
    return run_framevm(argc, argv);
  }

  usage(stderr);
  return 2;
}
