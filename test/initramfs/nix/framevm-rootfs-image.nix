{ stdenvNoCC, pkgsBuildBuild, pkgsStatic, busybox }:
let
  framevVsockEcho = builtins.path {
    name = "framev-vsock-echo.c";
    path = ./../src/regression/network/vsock/framev_vsock_echo.c;
  };
in stdenvNoCC.mkDerivation {
  name = "framevm-rootfs.ext2";
  nativeBuildInputs = (with pkgsBuildBuild; [ e2fsprogs ]) ++ [ pkgsStatic.stdenv.cc ];
  buildCommand = ''
    root=$(mktemp -d)
    mkdir -p "$root"/{bin,dev,etc,proc,sys,tmp}

    cat > framevm-init.c <<'EOF'
    #include <errno.h>
    #include <fcntl.h>
    #include <stdio.h>
    #include <string.h>
    #include <time.h>
    #include <unistd.h>

    static char *const envp[] = { "PATH=/bin", "HOME=/", "TERM=linux", NULL };

    static int write_all(int fd, const char *buf, ssize_t len) {
        while (len > 0) {
            ssize_t written = write(fd, buf, len);
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
            buf += written;
            len -= written;
        }
        return 0;
    }

    static int sleep_for_initial_input(void) {
        const struct timespec delay = {
            .tv_sec = 0,
            .tv_nsec = 50 * 1000 * 1000,
        };

        for (;;) {
            if (nanosleep(&delay, NULL) == 0) {
                return 0;
            }
            if (errno != EINTR) {
                perror("nanosleep");
                return errno == 0 ? 127 : errno;
            }
        }
    }

    static int run_initial_script_from_stdin(void) {
        static const char script_path[] = "/tmp/framevm-init-script";
        char buf[4096];
        ssize_t total = 0;
        int old_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
        if (old_flags < 0) {
            perror("fcntl stdin");
            return errno == 0 ? 127 : errno;
        }
        if (fcntl(STDIN_FILENO, F_SETFL, old_flags | O_NONBLOCK) < 0) {
            perror("fcntl stdin nonblock");
            return errno == 0 ? 127 : errno;
        }

        int script_fd = open(script_path, O_WRONLY | O_CREAT | O_TRUNC, 0700);
        if (script_fd < 0) {
            perror("open init script");
            fcntl(STDIN_FILENO, F_SETFL, old_flags);
            return errno == 0 ? 127 : errno;
        }

        for (int idle_rounds = 0; idle_rounds < 30;) {
            ssize_t read_len = read(STDIN_FILENO, buf, sizeof(buf));
            if (read_len < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    if (total != 0) {
                        break;
                    }
                    int ret = sleep_for_initial_input();
                    if (ret != 0) {
                        close(script_fd);
                        fcntl(STDIN_FILENO, F_SETFL, old_flags);
                        return ret;
                    }
                    idle_rounds++;
                    continue;
                }
                perror("read stdin");
                close(script_fd);
                fcntl(STDIN_FILENO, F_SETFL, old_flags);
                return errno == 0 ? 127 : errno;
            }
            if (read_len == 0) {
                break;
            }
            idle_rounds = 0;
            if (write_all(script_fd, buf, read_len) < 0) {
                perror("write init script");
                close(script_fd);
                fcntl(STDIN_FILENO, F_SETFL, old_flags);
                return errno == 0 ? 127 : errno;
            }
            total += read_len;
        }

        if (fcntl(STDIN_FILENO, F_SETFL, old_flags) < 0) {
            perror("fcntl stdin restore");
            close(script_fd);
            return errno == 0 ? 127 : errno;
        }
        if (total == 0) {
            close(script_fd);
            return 0;
        }
        if (write_all(script_fd, "\n", 1) < 0) {
            perror("write init script terminator");
            close(script_fd);
            return errno == 0 ? 127 : errno;
        }
        close(script_fd);

        char *const argv[] = { "/bin/sh", (char *)script_path, NULL };
        execve("/bin/sh", argv, envp);
        perror("execve /bin/sh script");
        return errno == 0 ? 127 : errno;
    }

    int main(void) {
        int ret = run_initial_script_from_stdin();
        if (ret != 0) {
            return ret;
        }

        char *const argv[] = { "/bin/sh", NULL };
        execve("/bin/sh", argv, envp);
        perror("execve /bin/sh");
        return errno == 0 ? 127 : errno;
    }
    EOF
    $CC -O2 -static -o "$root/init" framevm-init.c
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
      timeout touch true umount uname wc; do
    ln -sf busybox "$root/bin/$applet"
    done
    printf 'framevm-rootfs-0000\n' > "$root/tmp/framevm-persist"

    chmod 0755 "$root/bin/busybox" "$root/bin/framev_vsock_echo" \
      "$root/bin/framevm_reboot" "$root/init"
    chmod 1777 "$root/tmp"

    dd if=/dev/zero of="$out" bs=1M count=32 status=none
    mkfs.ext2 -q -F -b 4096 -d "$root" "$out"
  '';
}
