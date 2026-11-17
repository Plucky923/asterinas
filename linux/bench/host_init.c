// SPDX-License-Identifier: GPL-2.0
//
// Minimal PID 1 init for host-initramfs.cpio.gz.
//
// Mounts /proc, /sys, /sys/fs/cgroup (creating /sys/fs/cgroup/sandbox), /dev;
// loads /modules/*.ko; runs either the cmdline-selected `kernelet_mode=...`
// workload or /tests/*; unloads modules; and powers off the VM.

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define MODULE_DIR "/modules"
#define TEST_DIR   "/tests"
#define MAX_ITEMS  64
#define NAME_MAX_LEN 256

static void out(const char *s)
{
	size_t len = strlen(s);

	while (len > 0) {
		ssize_t n = write(1, s, len);
		if (n <= 0)
			return;
		s += n;
		len -= (size_t)n;
	}
	tcdrain(1);
}

__attribute__((format(printf, 1, 2)))
static void outf(const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n <= 0)
		return;
	if ((size_t)n >= sizeof(buf))
		buf[sizeof(buf) - 1] = '\0';
	out(buf);
}

static int finit_module(int fd, const char *args, int flags)
{
	return (int)syscall(SYS_finit_module, fd, args, flags);
}

static int delete_module(const char *name, int flags)
{
	return (int)syscall(SYS_delete_module, name, flags);
}

static void mount_one(const char *src, const char *target, const char *type)
{
	mkdir(target, 0755);
	if (mount(src, target, type, 0, NULL) != 0 && errno != EBUSY)
		outf("INIT: mount %s on %s failed: %s\n", type, target, strerror(errno));
}

static void ensure_console(void)
{
	if (fcntl(1, F_GETFD) >= 0)
		return;
	int fd = open("/dev/console", O_RDWR);
	if (fd < 0)
		return;
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	if (fd > 2)
		close(fd);
}

static char mod_files[MAX_ITEMS][NAME_MAX_LEN];
static char mod_args[MAX_ITEMS][NAME_MAX_LEN];
static int  mod_count;
static char loaded[MAX_ITEMS][NAME_MAX_LEN];
static int  loaded_count;

static int ends_with_ko(const char *name)
{
	size_t len = strlen(name);

	return len > 3 && strcmp(name + len - 3, ".ko") == 0;
}

static void module_name(const char *file, char *buf, size_t buflen)
{
	size_t len = strlen(file);

	if (len > 3)
		len -= 3;
	if (len >= buflen)
		len = buflen - 1;
	for (size_t i = 0; i < len; i++)
		buf[i] = file[i] == '-' ? '_' : file[i];
	buf[len] = '\0';
}

static void add_module(const char *file, const char *args)
{
	if (mod_count >= MAX_ITEMS)
		return;
	snprintf(mod_files[mod_count], NAME_MAX_LEN, "%s", file);
	snprintf(mod_args[mod_count], NAME_MAX_LEN, "%s", args ? args : "");
	mod_count++;
}

static int read_mod_order(void)
{
	FILE *f = fopen(MODULE_DIR "/order", "re");
	char line[NAME_MAX_LEN];

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		char *p = line;
		while (*p == ' ' || *p == '\t')
			p++;
		char *end = p + strlen(p);
		while (end > p && (end[-1] == '\n' || end[-1] == '\r' ||
				   end[-1] == ' ' || end[-1] == '\t'))
			*--end = '\0';
		if (*p == '\0' || *p == '#')
			continue;
		char *args = strpbrk(p, " \t");
		if (args) {
			*args++ = '\0';
			while (*args == ' ' || *args == '\t')
				args++;
		}
		if (ends_with_ko(p))
			add_module(p, args);
	}
	fclose(f);
	return 1;
}

static void scan_modules(void)
{
	DIR *d = opendir(MODULE_DIR);
	struct dirent *de;

	if (!d)
		return;
	while ((de = readdir(d)) != NULL) {
		if (ends_with_ko(de->d_name))
			add_module(de->d_name, "");
	}
	closedir(d);
}

static void load_modules(const char *extra_args)
{
	char path[NAME_MAX_LEN * 2];

	for (int i = 0; i < mod_count; i++) {
		char combined[NAME_MAX_LEN * 2 + 128];
		if (strcmp(mod_files[i], "endovisor.ko") == 0 &&
		    extra_args && extra_args[0] != '\0') {
			snprintf(combined, sizeof(combined), "%.*s %.*s",
				 NAME_MAX_LEN - 1, mod_args[i],
				 127, extra_args);
		} else {
			snprintf(combined, sizeof(combined), "%.*s",
				 NAME_MAX_LEN - 1, mod_args[i]);
		}
		snprintf(path, sizeof(path), "%s/%.*s", MODULE_DIR,
			 NAME_MAX_LEN - 1, mod_files[i]);
		int fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			outf("INIT: open %s failed: %s\n", path, strerror(errno));
			continue;
		}
		outf("INIT: loading %s %s\n", mod_files[i], combined);
		if (finit_module(fd, combined, 0) != 0) {
			outf("INIT: finit_module %s failed: %s\n", mod_files[i], strerror(errno));
		} else {
			module_name(mod_files[i], loaded[loaded_count], NAME_MAX_LEN);
			loaded_count++;
		}
		close(fd);
	}
}

static void unload_modules(void)
{
	for (int i = loaded_count - 1; i >= 0; i--) {
		outf("INIT: unloading %s\n", loaded[i]);
		if (delete_module(loaded[i], 0) != 0)
			outf("INIT: delete_module %s failed: %s\n", loaded[i], strerror(errno));
	}
}

static int run_argv(char *const argv[])
{
	char *const envp[] = { (char *)"PATH=/bin:/tests:/", (char *)"HOME=/", NULL };
	int status = 0;

	outf("INIT: exec %s\n", argv[0]);
	pid_t pid = fork();
	if (pid < 0) {
		outf("INIT: fork failed: %s\n", strerror(errno));
		return -1;
	}
	if (pid == 0) {
		execve(argv[0], argv, envp);
		outf("INIT: execve %s failed: %s\n", argv[0], strerror(errno));
		_exit(127);
	}
	pid_t waited;
	do {
		waited = waitpid(pid, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited != pid) {
		outf("INIT: waitpid failed: %s\n", strerror(errno));
		return 1;
	}
	if (WIFEXITED(status)) {
		outf("INIT: %s exited %d\n", argv[0], WEXITSTATUS(status));
		return WEXITSTATUS(status);
	}
	if (WIFSIGNALED(status)) {
		outf("INIT: %s killed by signal %d\n", argv[0], WTERMSIG(status));
		return 128 + WTERMSIG(status);
	}
	return 1;
}

static int cmp_strp(const void *a, const void *b)
{
	return strcmp(*(const char **)a, *(const char **)b);
}

static int run_all_tests(void)
{
	DIR *d = opendir(TEST_DIR);
	struct dirent *de;
	struct stat st;
	char names[MAX_ITEMS][NAME_MAX_LEN];
	const char *ptrs[MAX_ITEMS];
	char path[NAME_MAX_LEN * 2];
	int count = 0, result = 0;

	if (!d)
		return 1;
	while ((de = readdir(d)) != NULL && count < MAX_ITEMS) {
		if (de->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "%s/%s", TEST_DIR, de->d_name);
		if (stat(path, &st) == 0 && S_ISREG(st.st_mode) && access(path, X_OK) == 0) {
			snprintf(names[count], NAME_MAX_LEN, "%s", de->d_name);
			count++;
		}
	}
	closedir(d);

	for (int i = 0; i < count; i++)
		ptrs[i] = names[i];
	qsort(ptrs, (size_t)count, sizeof(ptrs[0]), cmp_strp);
	for (int i = 0; i < count; i++) {
		snprintf(path, sizeof(path), "%s/%s", TEST_DIR, ptrs[i]);
		char *argv[] = { path, NULL };
		if (run_argv(argv) != 0)
			result = 1;
	}
	return count ? result : 1;
}

static int get_cmdline_kv(const char *cmdline, const char *key, char *val, size_t vlen)
{
	size_t klen = strlen(key);
	const char *p = cmdline;

	while ((p = strstr(p, key)) != NULL) {
		if ((p == cmdline || p[-1] == ' ' || p[-1] == '\t') && p[klen] == '=') {
			p += klen + 1;
			size_t i = 0;
			while (i + 1 < vlen && p[i] && p[i] != ' ' && p[i] != '\t' && p[i] != '\n') {
				val[i] = p[i];
				i++;
			}
			val[i] = '\0';
			return 1;
		}
		p += klen;
	}
	return 0;
}

static void append_arg(char *dst, size_t dlen, const char *arg)
{
	if (!arg || !arg[0])
		return;
	size_t cur = strlen(dst);
	if (cur > 0 && cur + 1 < dlen) {
		dst[cur++] = ' ';
		dst[cur] = '\0';
	}
	snprintf(dst + cur, dlen - cur, "%s", arg);
}

static void join_sandbox_cgroup(void)
{
	int fd = open("/sys/fs/cgroup/sandbox/cgroup.procs", O_WRONLY | O_CLOEXEC);
	char pid[32];

	if (fd < 0)
		return;
	int n = snprintf(pid, sizeof(pid), "%d\n", getpid());
	if (n > 0)
		(void)write(fd, pid, (size_t)n);
	close(fd);
}

static void report_file(const char *path)
{
	char value[512];
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0) {
		outf("HOST_STATE %s unavailable: %s\n", path, strerror(errno));
		return;
	}
	ssize_t len = read(fd, value, sizeof(value) - 1);
	close(fd);
	if (len < 0) {
		outf("HOST_STATE %s read failed\n", path);
		return;
	}
	value[len] = '\0';
	outf("HOST_STATE %s %s", path, value);
	if (len == 0 || value[len - 1] != '\n')
		out("\n");
}

static void report_host_state(void)
{
	const char *directory = "/sys/devices/system/cpu/vulnerabilities";
	DIR *dir = opendir(directory);
	struct dirent *entry;

	report_file("/sys/devices/system/clocksource/clocksource0/current_clocksource");
	if (!dir) {
		outf("HOST_STATE %s unavailable: %s\n", directory, strerror(errno));
		return;
	}
	while ((entry = readdir(dir)) != NULL) {
		char path[512];

		if (entry->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name);
		report_file(path);
	}
	closedir(dir);
}

int main(void)
{
	char cmdline[2048] = "";
	char mode[64] = "";
	char pt_mode[32] = "direct";
	char vcpus[16] = "2";
	char grant_mb[16] = "256";
	char initramfs_path[128] = "";
	char guest_cmd[256] = "";
	char bench_suite[64] = "smp-syscall-fpu";
	char mod_extra[256] = "";
	char watch_arg[16] = "";
	char image_path[128] = "/kernelet-image.elf";
	char kill_ms[16] = "";
	char attach[16] = "exec";
	int result;

	mount_one("proc", "/proc", "proc");
	mount_one("sysfs", "/sys", "sysfs");
	mount_one("cgroup2", "/sys/fs/cgroup", "cgroup2");
	mkdir("/sys/fs/cgroup/sandbox", 0755);

	{
		int fd = open("/proc/sys/kernel/printk_devkmsg", O_WRONLY | O_CLOEXEC);
		if (fd >= 0) {
			(void)write(fd, "on\n", 3);
			close(fd);
		}
	}
	mount_one("devtmpfs", "/dev", "devtmpfs");
	ensure_console();

	{
		int fd = open("/proc/cmdline", O_RDONLY);
		if (fd >= 0) {
			ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
			if (n > 0)
				cmdline[n] = '\0';
			close(fd);
		}
	}

	out("\n========================================\n");
	out("INIT: Kernelet host init\n");
	out("========================================\n");
	report_host_state();

	(void)get_cmdline_kv(cmdline, "kernelet_mode", mode, sizeof(mode));
	(void)get_cmdline_kv(cmdline, "kernelet_pt_mode", pt_mode, sizeof(pt_mode));
	(void)get_cmdline_kv(cmdline, "kernelet_vcpus", vcpus, sizeof(vcpus));
	(void)get_cmdline_kv(cmdline, "kernelet_grant_mb", grant_mb, sizeof(grant_mb));
	(void)get_cmdline_kv(cmdline, "kernelet_initramfs", initramfs_path, sizeof(initramfs_path));
	(void)get_cmdline_kv(cmdline, "kernelet_guest_cmd", guest_cmd, sizeof(guest_cmd));
	(void)get_cmdline_kv(cmdline, "kernelet_suite", bench_suite, sizeof(bench_suite));
	(void)get_cmdline_kv(cmdline, "kernelet_mod_args", mod_extra, sizeof(mod_extra));
	(void)get_cmdline_kv(cmdline, "kernelet_watch", watch_arg, sizeof(watch_arg));
	(void)get_cmdline_kv(cmdline, "kernelet_image", image_path, sizeof(image_path));
	(void)get_cmdline_kv(cmdline, "kernelet_kill_ms", kill_ms, sizeof(kill_ms));
	(void)get_cmdline_kv(cmdline, "kernelet_attach", attach, sizeof(attach));

	if (watch_arg[0] != '\0') {
		char kv[32];
		snprintf(kv, sizeof(kv), "watch=%s", watch_arg);
		append_arg(mod_extra, sizeof(mod_extra), kv);
	}

	if (!read_mod_order())
		scan_modules();
	load_modules(mod_extra);

	if (strcmp(mode, "native-syscall") == 0) {
		char *argv[] = { (char *)"/tests/bench_syscall_fpu",
				 (char *)"--suite", bench_suite, NULL };
		result = run_argv(argv);
	} else if (strcmp(mode, "native-mm") == 0) {
		char *argv[] = { (char *)"/tests/bench_mm", NULL };
		result = run_argv(argv);
	} else if (strcmp(mode, "native-safety") == 0) {
		char *argv[] = { (char *)"/tests/test_mm_safety", NULL };
		result = run_argv(argv);
	} else if (strcmp(mode, "native-events") == 0) {
		char *argv[] = { (char *)"/tests/test_event_paths", NULL };
		result = run_argv(argv);
	} else if (strcmp(mode, "native-lifecycle") == 0) {
		char *argv[] = { (char *)"/tests/test_endovisor", image_path, NULL };
		result = run_argv(argv);
	} else if (strncmp(mode, "kernelet-", 9) == 0 ||
		   strcmp(mode, "bench_syscall") == 0 ||
		   strcmp(mode, "bench_mm") == 0 ||
		   strcmp(mode, "safety") == 0) {
		join_sandbox_cgroup();
		if (initramfs_path[0] == '\0') {
			if (strcmp(mode, "kernelet-syscall") == 0 || strcmp(mode, "bench_syscall") == 0)
				snprintf(initramfs_path, sizeof(initramfs_path),
					 "/guests/guest-syscall.cpio");
			else if (strcmp(mode, "kernelet-mm") == 0 || strcmp(mode, "bench_mm") == 0)
				snprintf(initramfs_path, sizeof(initramfs_path),
					 "/guests/guest-mm.cpio");
			else if (strcmp(mode, "kernelet-safety") == 0 || strcmp(mode, "safety") == 0)
				snprintf(initramfs_path, sizeof(initramfs_path),
					 "/guests/guest-safety.cpio");
			else if (strcmp(mode, "kernelet-events") == 0)
				snprintf(initramfs_path, sizeof(initramfs_path),
					 "/guests/guest-events.cpio");
		}
		char *argv[20];
		int idx = 0;
		if (strcmp(attach, "exec") != 0 && strcmp(attach, "ioctl") != 0) {
			outf("INIT: unknown attach method %s\n", attach);
			result = 2;
			goto done;
		}
		argv[idx++] = (char *)"/bin/run-kernelet";
		if (strcmp(attach, "ioctl") == 0)
			argv[idx++] = (char *)"--attach-ioctl";
		argv[idx++] = (char *)"--pt-mode";
		argv[idx++] = pt_mode;
		argv[idx++] = (char *)"--vcpus";
		argv[idx++] = vcpus;
		argv[idx++] = (char *)"--grant-mb";
		argv[idx++] = grant_mb;
		if (initramfs_path[0] != '\0') {
			argv[idx++] = (char *)"--initramfs";
			argv[idx++] = initramfs_path;
		}
		if (guest_cmd[0] != '\0') {
			argv[idx++] = (char *)"--cmdline";
			argv[idx++] = guest_cmd;
		}
		if (kill_ms[0] != '\0') {
			argv[idx++] = (char *)"--kill-after-ms";
			argv[idx++] = kill_ms;
		}
		argv[idx++] = image_path;
		argv[idx] = NULL;
		result = run_argv(argv);
	} else if (mode[0] != '\0') {
		outf("INIT: unknown mode %s\n", mode);
		result = 2;
	} else if (access("/bin/run-kernelet", X_OK) == 0 &&
		   access(image_path, R_OK) == 0 &&
		   access("/guests/guest-syscall.cpio", R_OK) == 0) {
		join_sandbox_cgroup();
		// Run the staged syscall workload when no mode was selected.
		char *argv[] = {
			(char *)"/bin/run-kernelet",
			(char *)"--pt-mode", pt_mode,
			(char *)"--vcpus", vcpus,
			(char *)"--grant-mb", grant_mb,
			(char *)"--initramfs", (char *)"/guests/guest-syscall.cpio",
			image_path, NULL
		};
		result = run_argv(argv);
	} else {
		result = run_all_tests();
	}

done:
	unload_modules();
	outf("INIT: result=%d\n", result);
	out("INIT: done\n");
	sync();

	reboot(RB_POWER_OFF);
	reboot(RB_AUTOBOOT);
	for (;;)
		pause();
}
