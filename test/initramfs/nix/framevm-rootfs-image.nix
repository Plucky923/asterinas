{ stdenvNoCC, pkgsBuildBuild, pkgsStatic, busybox }:
stdenvNoCC.mkDerivation {
  name = "framevm-rootfs.cpio.gz";
  nativeBuildInputs = (with pkgsBuildBuild; [ cpio gzip ]) ++ [ pkgsStatic.stdenv.cc ];
  buildCommand = ''
    root=$(mktemp -d)
    mkdir -p "$root"/{bin,dev,etc,proc,sys,tmp}

    cat > cpu-burn.c <<'EOF'
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <time.h>

    static uint64_t elapsed_ms(const struct timespec *start, const struct timespec *now) {
        uint64_t start_ms = (uint64_t)start->tv_sec * 1000 + (uint64_t)start->tv_nsec / 1000000;
        uint64_t now_ms = (uint64_t)now->tv_sec * 1000 + (uint64_t)now->tv_nsec / 1000000;
        return now_ms - start_ms;
    }

    int main(int argc, char **argv) {
        uint64_t duration_ms = 3000;
        const char *label = "cpu-burn";
        if (argc > 1) {
            duration_ms = strtoull(argv[1], NULL, 10);
        }
        if (argc > 2) {
            label = argv[2];
        }

        struct timespec start;
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
            return 2;
        }

        volatile uint64_t value = 0x9e3779b97f4a7c15ULL;
        uint64_t loops = 0;
        do {
            for (uint64_t i = 0; i < 4096; i++) {
                value = value * 2862933555777941757ULL + i + loops;
            }
            loops++;
            if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
                return 3;
            }
        } while (elapsed_ms(&start, &now) < duration_ms);

        printf("%s loops=%llu checksum=%llu duration_ms=%llu\n",
               label,
               (unsigned long long)loops,
               (unsigned long long)value,
               (unsigned long long)duration_ms);
        return 0;
    }
    EOF
    $CC -O2 -static -o "$root/bin/cpu-burn" cpu-burn.c

    cat > fd-probe.c <<'EOF'
    #include <errno.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>

    int main(int argc, char **argv) {
        if (argc != 3) {
            return 64;
        }

        int fd = atoi(argv[1]);
        int expect_open = argv[2][0] == 'o';
        char byte = 0;
        errno = 0;
        ssize_t ret = read(fd, &byte, 1);

        if (expect_open) {
            return ret == 1 ? 0 : 65;
        }

        return ret == -1 && errno == EBADF ? 0 : 66;
    }
    EOF
    $CC -O2 -static -o "$root/bin/fd-probe" fd-probe.c

    cat > vsock-probe.c <<'EOF'
    #include <errno.h>
    #include <stdio.h>
    #include <string.h>
    #include <sys/socket.h>
    #include <unistd.h>

    #ifndef AF_VSOCK
    #define AF_VSOCK 40
    #endif

    #ifndef VMADDR_CID_HOST
    #define VMADDR_CID_HOST 2U
    #endif

    struct sockaddr_vm_probe {
        unsigned short svm_family;
        unsigned short svm_reserved1;
        unsigned int svm_port;
        unsigned int svm_cid;
        unsigned char svm_zero[4];
    };

    static int expect_errno(const char *name, int ret, int expected_errno) {
        if (ret != -1 || errno != expected_errno) {
            printf("%s failed: ret=%d errno=%d expected=%d\n",
                   name, ret, errno, expected_errno);
            return 1;
        }
        return 0;
    }

    int main(void) {
        int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
        if (fd < 0) {
            printf("socket AF_VSOCK failed: errno=%d\n", errno);
            return 1;
        }

        char byte = 0;
        errno = 0;
        if (expect_errno("read unconnected AF_VSOCK", (int)read(fd, &byte, 1), ENOTCONN) != 0) {
            return 2;
        }

        errno = 0;
        if (expect_errno("write unconnected AF_VSOCK", (int)write(fd, "x", 1), ENOTCONN) != 0) {
            return 3;
        }

        struct sockaddr_vm_probe addr;
        memset(&addr, 0, sizeof(addr));
        addr.svm_family = AF_VSOCK;
        addr.svm_cid = VMADDR_CID_HOST;
        addr.svm_port = 1024;

        errno = 0;
        if (expect_errno(
                "connect AF_VSOCK without transport",
                connect(fd, (const struct sockaddr *)&addr, sizeof(addr)),
                ECONNREFUSED) != 0) {
            return 4;
        }
        close(fd);

        printf("vsock-probe passed\n");
        return 0;
    }
    EOF
    $CC -O2 -static -o "$root/bin/vsock-probe" vsock-probe.c


    cat > framevm-init.c <<'EOF'
    #include <errno.h>
    #include <stdio.h>
    #include <unistd.h>

    int main(void) {
        char *const argv[] = { "/bin/sh", "-i", NULL };
        char *const envp[] = { "PATH=/bin", "HOME=/", "TERM=linux", NULL };
        execve("/bin/sh", argv, envp);
        perror("execve /bin/sh");
        return errno == 0 ? 127 : errno;
    }
    EOF
    $CC -O2 -static -o "$root/init" framevm-init.c

    cp ${busybox}/bin/busybox "$root/bin/busybox"
    ln -s /bin "$root/linkbin"
    ln -s /tmp "$root/linktmp"
    ln -s busybox "$root/bin/sh"
    for applet in \
      ash cat chmod cp cut date dd echo env false grep head ln ls mkdir \
      mount mv printf ps pwd rm rmdir sed sh sleep sort tail test touch \
      true umount uname wc; do
      ln -sf busybox "$root/bin/$applet"
    done
    touch "$root/dev/console" "$root/dev/tty" "$root/dev/ttyS0"

    chmod 0755 "$root/bin/busybox" "$root/bin/cpu-burn" "$root/bin/fd-probe" "$root/bin/vsock-probe" "$root/init"
    chmod 1777 "$root/tmp"

    pushd "$root"
    find . -print0 | cpio -o -H newc --null | gzip -n > "$out"
    popd
  '';
}
