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
    #include <sys/ioctl.h>
    #include <sys/mount.h>
    #include <sys/stat.h>
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
    #include <errno.h>
    #include <fcntl.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <sys/ioctl.h>
    #include <sys/mount.h>
    #include <sys/stat.h>
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

    static int run_shell_command(const char *command) {
        char *const argv[] = { "/bin/sh", "-c", (char *)command, NULL };
        execve("/bin/sh", argv, envp);
        perror("execve /bin/sh");
        return errno == 0 ? 127 : errno;
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

    int main(int argc, char **argv) {
        int ret = setup_console();
        if (ret != 0) {
            return ret;
        }
        mount_proc_if_available();

        const char *test = getenv("FRAMEVM_TEST");
        if ((test == NULL || test[0] == '\0') && argc > 1) {
            test = argv[1];
        }
        if (test == NULL || test[0] == '\0') {
            fprintf(stderr, "FRAMEVM_TEST is required\n");
            return 127;
        }

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
        if (strcmp(test, "rootfs-write") == 0) {
            return run_shell_command("printf 'framevm-rootfs-1111\\n' > /tmp/framevm-persist && sync");
        }
        if (strcmp(test, "rootfs") == 0) {
            puts("FRAMEVM_ROOTFS_OK");
            return 0;
        }
        if (strcmp(test, "device") == 0) {
            return run_shell_command("echo FRAMEV_VSOCK_GUEST_CLIENT_SMALL_START && /bin/framev_vsock_echo client 2 1234 4096 shutdown && echo FRAMEV_VSOCK_GUEST_CLIENT_SMALL_DONE && echo FRAMEV_VSOCK_GUEST_CLIENT_LARGE_START && /bin/framev_vsock_echo client 2 1234 131072 shutdown && echo FRAMEV_VSOCK_GUEST_CLIENT_LARGE_DONE && echo FRAMEV_VSOCK_GUEST_CLIENT_DONE && echo FRAMEV_VSOCK_GUEST_SERVER_START && /bin/framev_vsock_echo server any 4321 2 FRAMEV_VSOCK_GUEST_SERVER_DONE || echo FRAMEV_VSOCK_FAILED");
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
      timeout touch true umount uname wc; do
    ln -sf busybox "$root/bin/$applet"
    done
    printf 'framevm-rootfs-0000\n' > "$root/tmp/framevm-persist"

    chmod 0755 "$root/bin/busybox" "$root/bin/framev_vsock_echo" \
      "$root/bin/framevm-test-runner" "$root/bin/framevm_reboot" "$root/init"
    chmod 1777 "$root/tmp"

    dd if=/dev/zero of="$out" bs=1M count=32 status=none
    mkfs.ext2 -q -F -b 4096 -d "$root" "$out"
  '';
}
