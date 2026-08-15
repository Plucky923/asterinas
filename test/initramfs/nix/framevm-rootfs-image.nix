{ stdenvNoCC, pkgsBuildBuild, pkgsStatic, busybox, closureInfo, nginx, sqlite
, sqliteSpeedtest1 }:
let
  framevVsockEcho = builtins.path {
    name = "framev-vsock-echo.c";
    path = ./../src/regression/network/vsock/framev_vsock_echo.c;
  };
  applicationClosure = closureInfo {
    rootPaths = [ nginx sqlite sqliteSpeedtest1 ];
  };
in stdenvNoCC.mkDerivation {
  name = "framevm-rootfs.ext2";
  nativeBuildInputs = (with pkgsBuildBuild; [ e2fsprogs nix ]) ++ [ pkgsStatic.stdenv.cc ];
  buildCommand = ''
    root=$(mktemp -d)
    mkdir -p "$root"/{bin,dev,etc,nix/store,proc,srv/framevm-demo,sys,tmp,var/lib/framevm,var/lib/nginx,var/log/nginx,var/run}

    manifest="$root/etc/framevm-application-manifest"
    : > "$manifest"
    while IFS= read -r store_path; do
      relative_path="''${store_path#/}"
      cp -a "$store_path" "$root/nix/store/"
      source_hash=$(nix-hash --type sha256 --base32 "$store_path")
      copied_hash=$(nix-hash --type sha256 --base32 "$root/$relative_path")
      if [ "$source_hash" != "$copied_hash" ]; then
        echo "FrameVM closure copy changed $store_path" >&2
        exit 1
      fi
      printf '%s  %s\n' "$source_hash" "$store_path" >> "$manifest"
    done < ${applicationClosure}/store-paths

    ln -s ${sqliteSpeedtest1}/bin/sqlite-speedtest1 "$root/bin/sqlite-speedtest1"
    ln -s ${sqlite}/bin/sqlite3 "$root/bin/sqlite3"
    ln -s ${nginx}/bin/nginx "$root/bin/nginx"

    printf '%s\n' \
      'FrameVM Nginx demo' \
      'served by Nginx inside an isolated FrameVM' \
      'request completed over FrameV-net' \
      > "$root/srv/framevm-demo/index.html"
    page_prefix_bytes=$(wc -c < "$root/srv/framevm-demo/index.html")
    head -c $((16384 - page_prefix_bytes)) /dev/zero | tr '\0' 'F' \
      >> "$root/srv/framevm-demo/index.html"
    page_hash=$(sha256sum "$root/srv/framevm-demo/index.html" | cut -d ' ' -f 1)
    printf '%s  %s  %s\n' "$page_hash" 16384 /srv/framevm-demo/index.html \
      > "$root/etc/framevm-http-manifest"

    cat > framevm-init.c <<'EOF'
    #include <errno.h>
    #include <fcntl.h>
    #include <stdio.h>
    #include <sys/ioctl.h>
    #include <sys/mount.h>
    #include <sys/stat.h>
    #include <sys/time.h>
    #include <termios.h>
    #include <unistd.h>

    static char *const envp[] = {
        "PATH=/bin",
        "HOME=/",
        "TERM=linux",
        "USER=root",
        "LOGNAME=root",
        "PS1=~ # ",
        NULL
    };

    static int setup_console(void) {
        if (setsid() < 0 && errno != EPERM) {
            perror("setsid");
            return errno == 0 ? 127 : errno;
        }

        int console_fd = open("/dev/console", O_RDWR);
        if (console_fd < 0) {
            perror("open /dev/console");
            return errno == 0 ? 127 : errno;
        }

        if (ioctl(console_fd, TIOCSCTTY, 0) < 0 && errno != EPERM) {
            perror("TIOCSCTTY");
            close(console_fd);
            return errno == 0 ? 127 : errno;
        }

        for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
            if (dup2(console_fd, fd) < 0) {
                perror("dup2 /dev/console");
                close(console_fd);
                return errno == 0 ? 127 : errno;
            }
        }
        if (console_fd > STDERR_FILENO) {
            close(console_fd);
        }

        return 0;
    }

    static void mount_proc_if_available(void) {
        mkdir("/proc", 0555);
        if (mount("proc", "/proc", "proc", 0, NULL) < 0 &&
            errno != EBUSY && errno != ENODEV && errno != ENOSYS) {
            perror("mount /proc");
        }
    }

    int main(void) {
        int ret = setup_console();
        if (ret != 0) {
            return ret;
        }

        mount_proc_if_available();

        char *const argv[] = { "/bin/sh", "-i", NULL };
        execve("/bin/sh", argv, envp);
        perror("execve /bin/sh");
        return errno == 0 ? 127 : errno;
    }
    EOF
    $CC -O2 -static -o "$root/init" framevm-init.c
    cat > framevm-test-runner.c <<'EOF'
    #define _GNU_SOURCE

    #include <errno.h>
    #include <fcntl.h>
    #include <stdint.h>
    #include <sched.h>
    #include <stdatomic.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <sys/ioctl.h>
    #include <sys/mount.h>
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <sys/uio.h>
    #include <sys/wait.h>
    #include <termios.h>
    #include <time.h>
    #include <unistd.h>

    extern int __clone(int (*start_fn)(void *), void *stack, int flags,
        void *argument, int *parent_tid, void *tls, int *child_tid);

    static char *const envp[] = {
        "PATH=/bin",
        "HOME=/",
        "TERM=linux",
        "USER=root",
        "LOGNAME=root",
        "PS1=~ # ",
        NULL
    };

    struct smp_worker {
        int expected_cpu;
        int worker_count;
        atomic_int *ready_count;
        atomic_int *running_count;
        atomic_int *failed;
        atomic_int *done_count;
        int start_fd;
        int ready_fd;
        int done_fd;
    };

    static void run_smp_worker(struct smp_worker *worker) {
        if (sched_getcpu() != worker->expected_cpu) {
            atomic_store(worker->failed, 1);
        }
        atomic_fetch_add(worker->ready_count, 1);
        int attempts = 0;
        while (atomic_load(worker->ready_count) != worker->worker_count &&
            attempts++ < 1000) {
            sched_yield();
        }
        if (atomic_load(worker->ready_count) != worker->worker_count) {
            atomic_store(worker->failed, 1);
            return;
        }

        atomic_fetch_add(worker->running_count, 1);
        attempts = 0;
        while (atomic_load(worker->running_count) != worker->worker_count &&
            attempts++ < 1000) {
            int observed_cpu = sched_getcpu();
            if (observed_cpu != worker->expected_cpu) {
                atomic_store(worker->failed, 1);
            }
        }
        if (atomic_load(worker->running_count) != worker->worker_count) {
            atomic_store(worker->failed, 1);
            return;
        }

        if (sched_getcpu() != worker->expected_cpu) {
            atomic_store(worker->failed, 1);
        }
    }

    static int read_pipe_token(int pipe_fd, char *token) {
        ssize_t result;
        do {
            result = read(pipe_fd, token, sizeof(*token));
        } while (result < 0 && errno == EINTR);
        return result == sizeof(*token) ? 0 : -1;
    }

    static int write_pipe_token(int pipe_fd, char token) {
        ssize_t result;
        do {
            result = write(pipe_fd, &token, sizeof(token));
        } while (result < 0 && errno == EINTR);
        return result == sizeof(token) ? 0 : -1;
    }

    static int finish_smp_worker(struct smp_worker *worker, int result) {
        atomic_fetch_add(worker->done_count, 1);
        if (write_pipe_token(worker->done_fd, 1) != 0) {
            dprintf(STDOUT_FILENO, "FRAMEVM_SMP_WORKER_%d_DONE_FAILED errno=%d\n",
                worker->expected_cpu, errno);
            atomic_store(worker->failed, 1);
            return 1;
        }
        return result;
    }

    static int start_smp_worker(void *argument) {
        struct smp_worker *worker = argument;
        char token = 1;
        if (write_pipe_token(worker->ready_fd, token) != 0) {
            dprintf(STDOUT_FILENO, "FRAMEVM_SMP_WORKER_%d_READY_FAILED errno=%d\n",
                worker->expected_cpu, errno);
            atomic_store(worker->failed, 1);
            return finish_smp_worker(worker, 1);
        }
        if (read_pipe_token(worker->start_fd, &token) != 0) {
            dprintf(STDOUT_FILENO, "FRAMEVM_SMP_WORKER_%d_START_FAILED errno=%d\n",
                worker->expected_cpu, errno);
            atomic_store(worker->failed, 1);
            return finish_smp_worker(worker, 1);
        }

        dprintf(STDOUT_FILENO, "FRAMEVM_SMP_WORKER_%d_RUNNING cpu=%d\n",
            worker->expected_cpu, sched_getcpu());
        run_smp_worker(worker);
        dprintf(STDOUT_FILENO, "FRAMEVM_SMP_WORKER_%d_DONE cpu=%d\n",
            worker->expected_cpu, sched_getcpu());
        return finish_smp_worker(worker, 0);
    }

    static int run_smp_test(void) {
        const char *count_text = getenv("FRAMEVM_VCPUS");
        int worker_count = count_text == NULL ? 0 : atoi(count_text);
        if (worker_count != 2 && worker_count != 4) {
            fprintf(stderr, "FRAMEVM_VCPUS must be 2 or 4 for the SMP test\n");
            return 1;
        }
        dprintf(STDOUT_FILENO, "FRAMEVM_SMP_GUEST_%d_START\n", worker_count);

        cpu_set_t parent_affinity;
        CPU_ZERO(&parent_affinity);
        CPU_SET(0, &parent_affinity);
        if (sched_setaffinity(0, sizeof(parent_affinity), &parent_affinity) != 0) {
            perror("sched_setaffinity SMP parent");
            return 1;
        }

        struct smp_worker workers[4];
        atomic_int shared_state[4];
        atomic_init(&shared_state[0], 0);
        atomic_init(&shared_state[1], 0);
        atomic_init(&shared_state[2], 0);
        atomic_init(&shared_state[3], 0);

        const size_t worker_stack_size = 256 * 1024;
        void *worker_stacks[4];
        int start_pipes[4][2];
        int ready_pipes[4][2];
        int done_pipes[4][2];
        for (int cpu = 0; cpu < worker_count; cpu++) {
            cpu_set_t worker_affinity;
            CPU_ZERO(&worker_affinity);
            CPU_SET(cpu, &worker_affinity);
            if (sched_setaffinity(0, sizeof(worker_affinity), &worker_affinity) != 0) {
                perror("set SMP worker affinity");
                return 1;
            }
            if (pipe(start_pipes[cpu]) != 0 || pipe(ready_pipes[cpu]) != 0 ||
                pipe(done_pipes[cpu]) != 0) {
                perror("pipe SMP worker");
                return 1;
            }
            workers[cpu] = (struct smp_worker) {
                .expected_cpu = cpu,
                .worker_count = worker_count,
                .ready_count = &shared_state[0],
                .running_count = &shared_state[1],
                .failed = &shared_state[2],
                .done_count = &shared_state[3],
                .start_fd = start_pipes[cpu][0],
                .ready_fd = ready_pipes[cpu][1],
                .done_fd = done_pipes[cpu][1],
            };
            worker_stacks[cpu] = mmap(NULL, worker_stack_size,
                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (worker_stacks[cpu] == MAP_FAILED) {
                perror("mmap SMP worker stack");
                return 1;
            }
            void *stack_top = (char *)worker_stacks[cpu] + worker_stack_size;
            int clone_flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                CLONE_THREAD | CLONE_SYSVSEM;
            if (__clone(start_smp_worker, stack_top, clone_flags, &workers[cpu],
                    NULL, NULL, NULL) < 0) {
                perror("clone SMP worker");
                return 1;
            }
        }
        if (sched_setaffinity(0, sizeof(parent_affinity), &parent_affinity) != 0) {
            perror("restore SMP parent affinity");
            return 1;
        }
        dprintf(STDOUT_FILENO, "FRAMEVM_SMP_GUEST_%d_WORKERS_SPAWNED\n", worker_count);
        for (int cpu = 0; cpu < worker_count; cpu++) {
            char token = 0;
            if (read_pipe_token(ready_pipes[cpu][0], &token) != 0) {
                perror("wait for ready SMP worker");
                return 1;
            }
        }
        dprintf(STDOUT_FILENO, "FRAMEVM_SMP_GUEST_%d_WORKERS_READY\n", worker_count);

        // A pipe retains an early start token until its worker reaches the
        // blocking read, so readiness is sufficient to release the workload.
        // Each worker exercises repeated `sched_yield` calls below.
        for (int cpu = 0; cpu < worker_count; cpu++) {
            char token = 1;
            if (write_pipe_token(start_pipes[cpu][1], token) != 0) {
                perror("start SMP worker");
                return 1;
            }
        }
        dprintf(STDOUT_FILENO, "FRAMEVM_SMP_GUEST_%d_WORKERS_RELEASED\n", worker_count);
        for (int cpu = 0; cpu < worker_count; cpu++) {
            char token = 0;
            if (read_pipe_token(done_pipes[cpu][0], &token) != 0) {
                perror("wait for completed SMP worker");
                return 1;
            }
        }
        if (atomic_load(&shared_state[3]) != worker_count) {
            dprintf(STDOUT_FILENO, "SMP workers did not complete: %d/%d\n",
                atomic_load(&shared_state[3]), worker_count);
            return 1;
        }
        for (int cpu = 0; cpu < worker_count; cpu++) {
            close(start_pipes[cpu][0]);
            close(start_pipes[cpu][1]);
            close(ready_pipes[cpu][0]);
            close(ready_pipes[cpu][1]);
            close(done_pipes[cpu][0]);
            close(done_pipes[cpu][1]);
        }
        // A completion token is written before the clone trampoline returns,
        // so the process keeps worker stacks mapped until exit.
        int failed = atomic_load(&shared_state[2]);
        if (failed != 0) {
            dprintf(STDOUT_FILENO,
                "FrameVM vCPU identity changed during the SMP workload\n");
            return 1;
        }

        dprintf(STDOUT_FILENO, "FRAMEVM_SMP_GUEST_%d_DONE\n", worker_count);
        return 0;
    }

    static int expect_cpuset_command(int expected_command) {
        int command;
        do {
            command = getchar();
        } while (command == '\n' || command == '\r');
        if (command != expected_command) {
            dprintf(STDERR_FILENO,
                "unexpected FrameVM cpuset command: expected=%c actual=%d\n",
                expected_command, command);
            return -1;
        }
        return 0;
    }

    static int run_cpuset_test(void) {
        cpu_set_t affinity;
        CPU_ZERO(&affinity);
        CPU_SET(0, &affinity);
        if (sched_setaffinity(0, sizeof(affinity), &affinity) != 0) {
            perror("sched_setaffinity cpuset workload");
            return 1;
        }

        puts("FRAMEVM_CPUSET_IDLE_READY");
        fflush(stdout);
        if (expect_cpuset_command('i') != 0) {
            return 1;
        }
        puts("FRAMEVM_CPUSET_READY");
        fflush(stdout);

        const char commands[] = { 'b', 's', 'e', 'r' };
        const char *const markers[] = {
            "FRAMEVM_CPUSET_BASELINE",
            "FRAMEVM_CPUSET_SHRUNK",
            "FRAMEVM_CPUSET_EXPANDED",
            "FRAMEVM_CPUSET_RESTORED",
        };
        volatile unsigned long progress = 0;
        for (size_t stage = 0; stage < sizeof(commands); stage++) {
            if (expect_cpuset_command(commands[stage]) != 0) {
                return 1;
            }
            for (unsigned long iteration = 0; iteration < 100000000UL; iteration++) {
                progress += iteration;
            }
            if (sched_getcpu() != 0) {
                dprintf(STDERR_FILENO,
                    "FrameVM virtual CPU identity changed during Host migration\n");
                return 1;
            }
            puts(markers[stage]);
            fflush(stdout);
        }

        if (expect_cpuset_command('f') != 0) {
            return 1;
        }
        puts("FRAMEVM_CPUSET_DONE");
        return 0;
    }

    static int run_share_test(void) {
        const char *limit_text = getenv("FRAMEVM_SHARE_PROGRESS_LIMIT");
        uint64_t progress_limit = 0;
        if (limit_text != NULL && limit_text[0] != '\0') {
            char *end = NULL;
            errno = 0;
            progress_limit = strtoull(limit_text, &end, 10);
            if (errno != 0 || end == limit_text || *end != '\0' ||
                progress_limit == 0) {
                fprintf(stderr, "FRAMEVM_SHARE_PROGRESS_LIMIT must be a positive integer\n");
                return 1;
            }
        }
        puts("FRAMEVM_SHARE_READY");
        fflush(stdout);
        if (expect_cpuset_command('s') != 0) {
            fputs("FrameVM share workload did not receive its start token\n", stderr);
            return 1;
        }
        volatile uint64_t value = 1;
        for (uint64_t startup_work = 0; startup_work < 10000;
            startup_work++) {
            value = value * 6364136223846793005ULL + 1;
        }
        puts("FRAMEVM_SHARE_STARTED");
        fflush(stdout);
        #if defined(__x86_64__)
        unsigned long rflags;
        __asm__ volatile("pushfq; popq %0" : "=r"(rflags));
        if ((rflags & (1UL << 9)) == 0) {
            fputs("FrameVM share workload entered user mode with interrupts disabled\n", stderr);
            return 1;
        }
        #endif
        unsigned int progress_batches = 0;
        uint64_t completed_progress = 0;
        for (;;) {
            for (int batch = 0; batch < 4096; batch++) {
                value = value * 6364136223846793005ULL + 1;
            }
            progress_batches++;
            if (progress_batches == 256) {
                puts("FRAMEVM_SHARE_PROGRESS");
                fflush(stdout);
                progress_batches = 0;
                completed_progress++;
                if (completed_progress == progress_limit) {
                    puts("FRAMEVM_SHARE_DONE");
                    return 0;
                }
            }
        }
    }

    static int setup_console(void) {
        if (setsid() < 0 && errno != EPERM) {
            perror("setsid");
            return errno == 0 ? 127 : errno;
        }

        int console_fd = open("/dev/console", O_RDWR);
        if (console_fd < 0) {
            perror("open /dev/console");
            return errno == 0 ? 127 : errno;
        }

        if (ioctl(console_fd, TIOCSCTTY, 0) < 0 && errno != EPERM) {
            perror("TIOCSCTTY");
            close(console_fd);
            return errno == 0 ? 127 : errno;
        }

        for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
            if (dup2(console_fd, fd) < 0) {
                perror("dup2 /dev/console");
                close(console_fd);
                return errno == 0 ? 127 : errno;
            }
        }
        if (console_fd > STDERR_FILENO) {
            close(console_fd);
        }

        return 0;
    }

    static void mount_proc_if_available(void) {
        mkdir("/proc", 0555);
        if (mount("proc", "/proc", "proc", 0, NULL) < 0 &&
            errno != EBUSY && errno != ENODEV && errno != ENOSYS) {
            perror("mount /proc");
        }
    }

    static int run_shell_command(const char *command) {
        pid_t child = fork();
        if (child < 0) {
            perror("fork /bin/sh");
            return 1;
        }
        if (child == 0) {
            char *const argv[] = { "/bin/sh", "-c", (char *)command, NULL };
            execve("/bin/sh", argv, envp);
            perror("execve /bin/sh");
            _exit(127);
        }

        int status;
        if (waitpid(child, &status, 0) != child) {
            perror("waitpid /bin/sh");
            return 1;
        }
        return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    }

    static int run_vsock_client(const char *payload_len) {
        pid_t child = fork();
        if (child < 0) {
            perror("fork framev_vsock_echo");
            return 1;
        }
        if (child == 0) {
            char *const argv[] = {
                "/bin/framev_vsock_echo", "client", "2", "1234",
                (char *)payload_len, "shutdown", NULL
            };
            execve(argv[0], argv, envp);
            perror("execve framev_vsock_echo client");
            _exit(127);
        }

        int status;
        if (waitpid(child, &status, 0) != child) {
            perror("waitpid framev_vsock_echo");
            return 1;
        }
        return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
    }

    static int run_device_test(void) {
        puts("FRAMEV_VSOCK_GUEST_CLIENT_SMALL_START");
        fflush(stdout);
        if (run_vsock_client("4096") != 0) {
            puts("FRAMEV_VSOCK_FAILED");
            return 1;
        }
        puts("FRAMEV_VSOCK_GUEST_CLIENT_SMALL_DONE");
        puts("FRAMEV_VSOCK_GUEST_CLIENT_LARGE_START");
        fflush(stdout);
        if (run_vsock_client("131072") != 0) {
            puts("FRAMEV_VSOCK_FAILED");
            return 1;
        }
        puts("FRAMEV_VSOCK_GUEST_CLIENT_LARGE_DONE");
        puts("FRAMEV_VSOCK_GUEST_CLIENT_DONE");
        puts("FRAMEV_VSOCK_GUEST_SERVER_START");
        fflush(stdout);

        char *const argv[] = {
            "/bin/framev_vsock_echo", "server", "any", "4321", "2",
            "FRAMEV_VSOCK_GUEST_SERVER_DONE", NULL
        };
        execve(argv[0], argv, envp);
        perror("execve framev_vsock_echo server");
        puts("FRAMEV_VSOCK_FAILED");
        return 127;
    }

    static int run_network_test(void) {
        int result = run_shell_command(
            "wget -q -O /tmp/framev-net-http http://192.0.2.1/ && "
            "grep -qx 'FrameV-net HTTP OK' /tmp/framev-net-http");
        if (result != 0) {
            puts("FRAMEV_NET_HTTP_FAILED");
            return result;
        }
        puts("FRAMEV_NET_HTTP_OK");
        return 0;
    }

    static int run_wall_clock_test(void) {
        const time_t earliest_supported_time = 1577836800;
        struct timespec realtime;

        if (clock_gettime(CLOCK_REALTIME, &realtime) != 0) {
            perror("clock_gettime CLOCK_REALTIME");
            return 1;
        }
        if (realtime.tv_sec < earliest_supported_time) {
            fprintf(stderr, "FrameVM wall clock precedes 2020-01-01: %lld\n",
                (long long)realtime.tv_sec);
            return 1;
        }

        puts("FRAMEVM_WALL_CLOCK_OK");
        return 0;
    }

    static int run_memory_test(void) {
        enum { CHUNK_SIZE = 1024 * 1024, FRAMEVM_PAGE_BYTES = 4096 };

        puts("FRAMEVM_MEMORY_BOUNDED_ALLOC_START");
        fflush(stdout);
        void *chunk = mmap(NULL, CHUNK_SIZE, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (chunk == MAP_FAILED) {
            dprintf(STDERR_FILENO,
                "FRAMEVM_MEMORY_ALLOC_FAILED errno=%d\n", errno);
            return 1;
        }

        volatile unsigned char *bytes = chunk;
        for (size_t offset = 0; offset < CHUNK_SIZE;
            offset += FRAMEVM_PAGE_BYTES) {
            bytes[offset] = (unsigned char)(offset / FRAMEVM_PAGE_BYTES);
        }
        if (munmap(chunk, CHUNK_SIZE) != 0) {
            dprintf(STDERR_FILENO,
                "FRAMEVM_MEMORY_RELEASE_FAILED errno=%d\n", errno);
            return 1;
        }

        puts("FRAMEVM_MEMORY_BOUNDED_ALLOC_OK");
        return 0;
    }

    static int run_allocator_test(void) {
        enum {
            HEAP_BYTES = 256 * 1024,
            PAGE_BYTES = 4096,
            PAGE_COUNT = 512,
        };
        const char *instance = getenv("FRAMEVM_ALLOCATOR_INSTANCE");
        if (instance == NULL || (instance[0] != 'A' && instance[0] != 'B') ||
            instance[1] != '\0') {
            fputs("FRAMEVM_ALLOCATOR_INSTANCE must be A or B\n", stderr);
            return 1;
        }

        printf("FRAMEVM_ALLOCATOR_INSTANCE=%s\n", instance);
        fflush(stdout);

        puts("FRAMEVM_ALLOCATOR_HEAP_START");
        unsigned char *heap = malloc(HEAP_BYTES);
        if (heap == NULL) {
            perror("malloc allocator heap");
            return 1;
        }
        for (size_t offset = 0; offset < HEAP_BYTES; offset += PAGE_BYTES) {
            heap[offset] = (unsigned char)(offset / PAGE_BYTES);
        }
        if (heap[HEAP_BYTES - PAGE_BYTES] !=
            (unsigned char)((HEAP_BYTES - PAGE_BYTES) / PAGE_BYTES)) {
            fputs("FrameVM allocator heap data changed\n", stderr);
            free(heap);
            return 1;
        }
        free(heap);
        puts("FRAMEVM_ALLOCATOR_HEAP_OK");

        puts("FRAMEVM_ALLOCATOR_PAGES_START");
        void *pages = mmap(NULL, PAGE_COUNT * PAGE_BYTES,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (pages == MAP_FAILED) {
            perror("mmap allocator pages");
            return 1;
        }
        volatile unsigned char *page_bytes = pages;
        for (size_t page = 0; page < PAGE_COUNT; page++) {
            page_bytes[page * PAGE_BYTES] = (unsigned char)page;
        }
        if (page_bytes[(PAGE_COUNT - 1) * PAGE_BYTES] !=
            (unsigned char)(PAGE_COUNT - 1)) {
            fputs("FrameVM allocator page data changed\n", stderr);
            munmap(pages, PAGE_COUNT * PAGE_BYTES);
            return 1;
        }
        if (munmap(pages, PAGE_COUNT * PAGE_BYTES) != 0) {
            perror("munmap allocator pages");
            return 1;
        }
        puts("FRAMEVM_ALLOCATOR_PAGES_OK");
        return 0;
    }

    static int run_sqlite_workload(void) {
        const char *size_value = getenv("FRAMEVM_SQLITE_SIZE");
        char *size_end = NULL;
        long size = size_value == NULL ? 25 : strtol(size_value, &size_end, 10);
        if (size < 1 || size > 100 ||
            (size_value != NULL &&
             (size_end == size_value || *size_end != '\0'))) {
            dprintf(STDERR_FILENO,
                "invalid FRAMEVM_SQLITE_SIZE=%s\n",
                size_value == NULL ? "" : size_value);
            return 1;
        }

        char size_arg[16];
        int size_arg_len = snprintf(size_arg, sizeof(size_arg), "%ld", size);
        if (size_arg_len < 0 || (size_t)size_arg_len >= sizeof(size_arg)) {
            fputs("SQLite size exceeds its fixed buffer\n", stderr);
            return 1;
        }

        pid_t child = fork();
        if (child < 0) {
            perror("fork sqlite-speedtest1");
            return 1;
        }
        if (child == 0) {
            char *const argv[] = {
                "/bin/sqlite-speedtest1", "--size", size_arg,
                "/var/lib/framevm/sqlite-speedtest1.db", NULL
            };
            execve(argv[0], argv, envp);
            perror("execve sqlite-speedtest1");
            _exit(127);
        }

        // The host runner owns the deadline because it can bound a stuck
        // FrameVM. Avoid an in-guest shell and timeout process tree here.
        int status;
        if (waitpid(child, &status, 0) != child) {
            perror("waitpid sqlite-speedtest1");
            return 1;
        }
        int result = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
        if (result != 0) {
            dprintf(STDERR_FILENO,
                "FRAMEVM_APPLICATION_FAILED stage=sqlite-workload status=%d\n",
                result);
            return result;
        }
        puts("FRAMEVM_SQLITE_SYNC_START");
        fflush(stdout);
        sync();
        puts("FRAMEVM_SQLITE_SYNC_DONE");
        puts("FRAMEVM_SQLITE_WORKLOAD_OK");
        return 0;
    }

    static int run_sqlite_integrity_check(void) {
        int result = run_shell_command(
            "/bin/sqlite3 /var/lib/framevm/sqlite-speedtest1.db "
            "'PRAGMA quick_check;' > /tmp/framevm-sqlite-check && "
            "cat /tmp/framevm-sqlite-check && "
            "test \"$(wc -l < /tmp/framevm-sqlite-check)\" -eq 1 && "
            "grep -qx ok /tmp/framevm-sqlite-check");
        if (result != 0) {
            dprintf(STDERR_FILENO,
                "FRAMEVM_APPLICATION_FAILED stage=sqlite-integrity status=%d\n",
                result);
            return result;
        }
        puts("FRAMEVM_SQLITE_INTEGRITY_OK");
        return 0;
    }

    static int run_nginx(void) {
        int result = run_shell_command(
            ": > /tmp/framevm-nginx-access.log; "
            "/bin/nginx -p /var/lib/nginx -c /etc/framevm-nginx.conf & "
            "nginx_pid=$!; "
            "elapsed=0; "
            "while ! test -s /tmp/framevm-nginx-access.log; do "
            "kill -0 \"$nginx_pid\" || "
            "{ wait \"$nginx_pid\"; exit $?; }; "
            "test \"$elapsed\" -lt 60 || "
            "{ kill -TERM \"$nginx_pid\"; wait \"$nginx_pid\"; exit 124; }; "
            "sleep 1; elapsed=$((elapsed + 1)); done; "
            "kill -TERM \"$nginx_pid\" && wait \"$nginx_pid\"");
        if (result != 0) {
            dprintf(STDERR_FILENO,
                "FRAMEVM_APPLICATION_FAILED stage=nginx-lifecycle status=%d\n",
                result);
            return result;
        }
        puts("FRAMEVM_NGINX_GUEST_OK");
        return 0;
    }

    static int run_shell_parity_test(void) {
        if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
            fprintf(stderr, "standard streams are not attached to a TTY\n");
            return 1;
        }

        int tty_fd = open("/dev/tty", O_RDWR);
        if (tty_fd < 0) {
            perror("open /dev/tty");
            return errno == 0 ? 127 : errno;
        }
        close(tty_fd);

        int ret = system("ps >/tmp/framevm-ps.out && grep -q framevm-test-runner /tmp/framevm-ps.out");
        if (ret != 0) {
            fprintf(stderr, "guest ps did not report framevm-test-runner\n");
            return 1;
        }

        puts("FRAMEVM_SHELL_OK");
        return 0;
    }

    static int run_nvme_passthrough_test(int hold_after_io) {
        enum { CHUNK_SIZE = 4096, CHUNK_COUNT = 2 };
        const off_t offset = 128 * 1024 * 1024;
        unsigned char write_bytes[CHUNK_COUNT][CHUNK_SIZE];
        unsigned char read_bytes[CHUNK_COUNT][CHUNK_SIZE] = {{0}};
        struct iovec write_iov[CHUNK_COUNT];
        struct iovec read_iov[CHUNK_COUNT];

        for (size_t chunk = 0; chunk < CHUNK_COUNT; chunk++) {
            for (size_t index = 0; index < CHUNK_SIZE; index++) {
                write_bytes[chunk][index] =
                    (unsigned char)(0x5aU ^ (chunk * 0x33U) ^ (index & 0xffU));
            }
            write_iov[chunk].iov_base = write_bytes[chunk];
            write_iov[chunk].iov_len = CHUNK_SIZE;
            read_iov[chunk].iov_base = read_bytes[chunk];
            read_iov[chunk].iov_len = CHUNK_SIZE;
        }

        puts("FRAMEVM_NVME_STEP=open");
        int fd = open("/dev/nvme0n1", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            perror("open /dev/nvme0n1");
            return 1;
        }
        puts("FRAMEVM_NVME_STEP=write");
        ssize_t written = pwritev(fd, write_iov, CHUNK_COUNT, offset);
        if (written != CHUNK_COUNT * CHUNK_SIZE) {
            perror("pwritev /dev/nvme0n1");
            close(fd);
            return 1;
        }
        puts("FRAMEVM_NVME_STEP=flush");
        if (fsync(fd) != 0) {
            perror("fsync /dev/nvme0n1");
            close(fd);
            return 1;
        }
        puts("FRAMEVM_NVME_STEP=read");
        ssize_t read_len = preadv(fd, read_iov, CHUNK_COUNT, offset);
        if (read_len != CHUNK_COUNT * CHUNK_SIZE) {
            perror("preadv /dev/nvme0n1");
            close(fd);
            return 1;
        }
        close(fd);

        if (memcmp(write_bytes, read_bytes, sizeof(write_bytes)) != 0) {
            fprintf(stderr, "NVMe passthrough payload mismatch\n");
            return 1;
        }
        puts("FRAMEVM_NVME_PASSTHROUGH_GUEST_OK");
        if (hold_after_io) {
            puts("FRAMEVM_NVME_HOLD_READY");
            fflush(stdout);
            for (;;) {
                pause();
            }
        }
        return 0;
    }

    static int run_nvme_local_failure_test(void) {
        unsigned char byte = 0xa5;

        puts("FRAMEVM_NVME_STEP=open-for-local-failure");
        int fd = open("/dev/nvme0n1", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            perror("open /dev/nvme0n1");
            return 1;
        }

        off_t capacity = lseek(fd, 0, SEEK_END);
        if (capacity <= 0) {
            perror("lseek /dev/nvme0n1");
            close(fd);
            return 1;
        }

        // A write beginning at the exact end of the namespace must fail as a
        // normal guest I/O error. It must not be reclassified as an assignment
        // infrastructure failure by the Host.
        puts("FRAMEVM_NVME_STEP=out-of-range-write");
        if (pwrite(fd, &byte, sizeof(byte), capacity) >= 0) {
            fprintf(stderr, "out-of-range NVMe write unexpectedly succeeded\n");
            close(fd);
            return 1;
        }
        close(fd);

        puts("FRAMEVM_NVME_LOCAL_FAILURE_OK");
        return 0;
    }

    int main(int argc, char **argv) {
        const char *test = getenv("FRAMEVM_TEST");
        if ((test == NULL || test[0] == '\0') && argc > 1) {
            test = argv[1];
        }
        if (test == NULL || test[0] == '\0') {
            fprintf(stderr, "FRAMEVM_TEST is required\n");
            return 127;
        }

        // The FrameVM first-process setup has already attached descriptors
        // 0-2 to `/dev/console`. Scheduler/device cases deliberately avoid
        // creating a controlling terminal because session/TTY behavior is
        // outside these tests and can block during concurrent startup.
        if (strcmp(test, "smp") == 0) {
            return run_smp_test();
        }
        if (strcmp(test, "device") == 0) {
            return run_device_test();
        }
        if (strcmp(test, "cpuset-resume") == 0) {
            return run_cpuset_test();
        }
        if (strcmp(test, "share") == 0) {
            return run_share_test();
        }

        int ret = setup_console();
        if (ret != 0) {
            return ret;
        }

        if (strcmp(test, "nvme-passthrough") == 0) {
            return run_nvme_passthrough_test(0);
        }
        if (strcmp(test, "nvme-passthrough-hold") == 0) {
            return run_nvme_passthrough_test(1);
        }
        if (strcmp(test, "nvme-passthrough-local-failure") == 0) {
            return run_nvme_local_failure_test();
        }
        mount_proc_if_available();

        if (strcmp(test, "load") == 0) {
            puts("FRAMEVM_LOAD_OK");
            return 0;
        }
        if (strcmp(test, "boot") == 0) {
            puts("FRAMEVM_BOOT_OK");
            return 0;
        }
        if (strcmp(test, "regression") == 0) {
            puts("FRAMEVM_REGRESSION_OK");
            return 0;
        }
        if (strcmp(test, "exit-zero") == 0 || strcmp(test, "marker-missing") == 0) {
            return 0;
        }
        if (strcmp(test, "exit-nonzero") == 0) {
            return 7;
        }
        if (strcmp(test, "restart-requested") == 0) {
            char *const reboot_argv[] = { "/bin/framevm_reboot", "restart", NULL };
            execve("/bin/framevm_reboot", reboot_argv, envp);
            perror("execve /bin/framevm_reboot");
            return errno == 0 ? 127 : errno;
        }
        if (strcmp(test, "lifecycle-hold") == 0) {
            puts("FRAMEVM_LIFECYCLE_READY");
            fflush(stdout);
            for (;;) {
                pause();
            }
        }
        if (strcmp(test, "rootfs-write") == 0) {
            puts("FRAMEVM_ROOTFS_WRITE_STAGE stage=write-sync state=start");
            int result = run_shell_command(
                "{ printf 'framevm-rootfs-1111\\n'; head -c 131072 /dev/zero; } "
                "> /tmp/framevm-persist && sync");
            if (result == 0) {
                puts("FRAMEVM_ROOTFS_WRITE_STAGE stage=write-sync state=done");
            }
            return result;
        }
        if (strcmp(test, "rootfs") == 0) {
            puts("FRAMEVM_ROOTFS_OK");
            return 0;
        }
        if (strcmp(test, "net") == 0) {
            return run_network_test();
        }
        if (strcmp(test, "wall-clock") == 0) {
            return run_wall_clock_test();
        }
        if (strcmp(test, "memory") == 0) {
            return run_memory_test();
        }
        if (strcmp(test, "allocator") == 0) {
            return run_allocator_test();
        }
        if (strcmp(test, "application-sqlite-run") == 0) {
            return run_sqlite_workload();
        }
        if (strcmp(test, "application-sqlite-check") == 0) {
            return run_sqlite_integrity_check();
        }
        if (strcmp(test, "application-nginx") == 0) {
            return run_nginx();
        }
        if (strcmp(test, "shell") == 0) {
            return run_shell_parity_test();
        }

        fprintf(stderr, "unknown FRAMEVM_TEST=%s\n", test);
        return 127;
    }
    EOF
    $CC -O2 -static -o "$root/bin/framevm-test-runner" framevm-test-runner.c
    $CC -O2 -static -o "$root/bin/framev_vsock_echo" ${framevVsockEcho}
    cat > framevm-reboot.c <<'EOF'
    #include <linux/reboot.h>
    #include <stdio.h>
    #include <string.h>
    #include <sys/syscall.h>
    #include <unistd.h>

    int main(int argc, char **argv) {
        int command = LINUX_REBOOT_CMD_RESTART;
        if (argc > 1 && strcmp(argv[1], "poweroff") == 0) {
            command = LINUX_REBOOT_CMD_POWER_OFF;
        } else if (argc > 1 && strcmp(argv[1], "halt") == 0) {
            command = LINUX_REBOOT_CMD_HALT;
        }

        long ret = syscall(SYS_reboot, LINUX_REBOOT_MAGIC1,
                           LINUX_REBOOT_MAGIC2, command, 0);
        perror("reboot");
        return ret == 0 ? 0 : 1;
    }
    EOF
    $CC -O2 -static -o "$root/bin/framevm_reboot" framevm-reboot.c

    cp ${busybox}/bin/busybox "$root/bin/busybox"
    ln -s /bin "$root/linkbin"
    ln -s /tmp "$root/linktmp"
    ln -s /init "$root/bin/init"
    ln -s busybox "$root/bin/sh"
    for applet in \
      ash cat chmod cp cut date dd echo env false grep head kill ln ls \
      mkdir mount mv printf ps pwd rm rmdir sed sh sleep sort sync tail test \
      timeout touch true umount uname wc wget; do
    ln -sf busybox "$root/bin/$applet"
    done
    printf 'framevm-rootfs-0000\n' > "$root/tmp/framevm-persist"

    chmod 0755 "$root/bin/busybox" "$root/bin/framev_vsock_echo" \
      "$root/bin/framevm-test-runner" "$root/bin/framevm_reboot" "$root/init"
    chmod 1777 "$root/tmp"

    cat > "$root/etc/framevm-nginx.conf" <<'EOF'
    daemon off;
    master_process on;
    worker_processes 1;
    error_log stderr notice;
    pid /var/run/nginx.pid;

    events {
        worker_connections 64;
    }

    http {
        access_log /tmp/framevm-nginx-access.log;
        client_body_temp_path /var/lib/nginx/client_body;
        proxy_temp_path /var/lib/nginx/proxy;
        fastcgi_temp_path /var/lib/nginx/fastcgi;
        uwsgi_temp_path /var/lib/nginx/uwsgi;
        scgi_temp_path /var/lib/nginx/scgi;
        sendfile on;

        server {
            listen 192.0.2.2:8080;
            server_name framevm.test;

            location = /index.html {
                root /srv/framevm-demo;
            }
        }
    }
    EOF
    cat > "$root/etc/passwd" <<'EOF'
    root:x:0:0:root:/:/bin/sh
    nobody:x:65534:65534:nobody:/:/bin/false
    EOF
    cat > "$root/etc/group" <<'EOF'
    root:x:0:
    nogroup:x:65534:
    EOF
    mkdir -p "$root/var/lib/nginx"/{client_body,fastcgi,proxy,scgi,uwsgi}

    content_bytes=$(du -sb "$root" | cut -f 1)
    # The pinned `--size 1000` workload materializes a large database, and
    # `VACUUM` needs transient replacement space. Reserve their measured
    # bounded workspace before applying the filesystem free-space requirements.
    runtime_content_bytes=$((480 * 1024 * 1024))
    occupied_bytes=$((content_bytes + runtime_content_bytes))
    required_by_ratio=$(( (occupied_bytes * 4 + 2) / 3 ))
    required_by_writable=$(( occupied_bytes + 128 * 1024 * 1024 ))
    if [ "$required_by_ratio" -gt "$required_by_writable" ]; then
      image_bytes=$required_by_ratio
    else
      image_bytes=$required_by_writable
    fi
    alignment=$((16 * 1024 * 1024))
    image_bytes=$(( (image_bytes + alignment - 1) / alignment * alignment ))

    while true; do
      truncate -s "$image_bytes" "$out"
      mkfs.ext2 -q -F -b 4096 -d "$root" "$out"
      block_count=$(dumpe2fs -h "$out" 2>/dev/null | sed -n 's/^Block count:[[:space:]]*//p')
      free_blocks=$(dumpe2fs -h "$out" 2>/dev/null | sed -n 's/^Free blocks:[[:space:]]*//p')
      free_bytes=$((free_blocks * 4096))
      minimum_ratio_free=$((image_bytes / 4))
      minimum_free=$((128 * 1024 * 1024))
      if [ "$minimum_ratio_free" -gt "$minimum_free" ]; then
        minimum_free=$minimum_ratio_free
      fi
      if [ "$free_bytes" -ge "$minimum_free" ] && \
         [ $((block_count * 4096)) -eq "$image_bytes" ]; then
        break
      fi
      image_bytes=$((image_bytes + alignment))
    done
  '';
}
