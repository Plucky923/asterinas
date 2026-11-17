// SPDX-License-Identifier: GPL-2.0
//
// Minimal generic Linux VM PID 1 for `poc/eval/`.
//
// Mounts `/proc`, `/sys`, `/sys/fs/cgroup/sandbox`, `/dev`, loads
// `endovisor.ko`, reads `/etc/eval-batch.txt`, executes each case either in
// a chroot over the unpacked shared `eval-payload.cpio` (`L`) or in a fresh
// `run-kernelet` sandbox (`K`), unloads kernel modules, and powers off the VM.
// Any mount, cgroup, module, unpack, or runner launch failure is propagated and
// suppresses `INIT: done`.

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAYLOAD_CPIO "/payload/eval-payload.cpio"
#define PAYLOAD_MNT  "/mnt/payload"
#define BATCH_FILE   "/etc/eval-batch.txt"
#define MOD_PATH     "/modules/endovisor.ko"
#define MAX_ARGS     64

static int mount_fs(const char *src, const char *dst, const char *fstype, const char *data)
{
	if (mkdir(dst, 0755) != 0 && errno != EEXIST) {
		fprintf(stderr, "INIT: mkdir %s failed: %s\n", dst, strerror(errno));
		return -1;
	}
	if (mount(src, dst, fstype, 0, data) != 0 && errno != EBUSY) {
		fprintf(stderr, "INIT: mount %s on %s failed: %s\n", fstype, dst, strerror(errno));
		return -1;
	}
	return 0;
}

static int get_kv(const char *cmdline, const char *key, char *out, size_t len)
{
	size_t klen = strlen(key);
	const char *p = cmdline;

	while ((p = strstr(p, key)) != NULL) {
		if ((p == cmdline || p[-1] == ' ' || p[-1] == '\t') && p[klen] == '=') {
			p += klen + 1;
			size_t i = 0;
			while (i + 1 < len && p[i] && p[i] != ' ' && p[i] != '\t' && p[i] != '\n') {
				out[i] = p[i];
				i++;
			}
			out[i] = '\0';
			return 1;
		}
		p += klen;
	}
	return 0;
}

static int run_cmd_wait(char *const argv[], const char *chroot_dir, const char *stdin_path)
{
	pid_t pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	}
	if (pid == 0) {
		if (stdin_path) {
			int fd = open(stdin_path, O_RDONLY);
			if (fd < 0)
				_exit(125);
			dup2(fd, STDIN_FILENO);
			close(fd);
		}
		if (chroot_dir) {
			if (chdir(chroot_dir) != 0)
				_exit(124);
			if (strcmp(chroot_dir, PAYLOAD_MNT) == 0 && stdin_path == NULL) {
				if (chroot(".") != 0 || chdir("/") != 0)
					_exit(123);
			}
		}
		char *const envp[] = { (char *)"PATH=/bin:/usr/bin:/", (char *)"HOME=/", NULL };
		execve(argv[0], argv, envp);
		perror(argv[0]);
		_exit(127);
	}
	int st = 0;
	pid_t waited;
	do {
		waited = waitpid(pid, &st, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited < 0) {
		perror("waitpid");
		return -1;
	}
	if (WIFEXITED(st))
		return WEXITSTATUS(st);
	if (WIFSIGNALED(st))
		return 128 + WTERMSIG(st);
	return -1;
}

static int join_sandbox_cgroup(void)
{
	int fd = open("/sys/fs/cgroup/sandbox/cgroup.procs", O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		perror("open /sys/fs/cgroup/sandbox/cgroup.procs");
		return -1;
	}
	char buf[32];
	int n = snprintf(buf, sizeof(buf), "%d\n", getpid());
	if (n <= 0 || write(fd, buf, (size_t)n) != n) {
		perror("write cgroup.procs");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int prepare_linux_chroot(void)
{
	if (mount_fs("tmpfs", PAYLOAD_MNT, "tmpfs", "size=768M") != 0)
		return -1;
	char *const cpio_argv[] = { (char *)"/bin/busybox", (char *)"cpio", (char *)"-idu", NULL };
	if (run_cmd_wait(cpio_argv, PAYLOAD_MNT, PAYLOAD_CPIO) != 0) {
		fprintf(stderr, "INIT: failed to unpack %s\n", PAYLOAD_CPIO);
		return -1;
	}
	if (mount_fs("proc", PAYLOAD_MNT "/proc", "proc", NULL) != 0)
		return -1;
	mkdir(PAYLOAD_MNT "/sys", 0755);
	if (mount("/sys", PAYLOAD_MNT "/sys", NULL, MS_BIND, NULL) != 0) {
		perror("bind mount /sys into chroot");
		return -1;
	}
	mkdir(PAYLOAD_MNT "/sys/fs", 0755);
	mkdir(PAYLOAD_MNT "/sys/fs/cgroup", 0755);
	if (mount("/sys/fs/cgroup", PAYLOAD_MNT "/sys/fs/cgroup", NULL, MS_BIND, NULL) != 0) {
		perror("bind mount /sys/fs/cgroup into chroot");
		return -1;
	}
	if (mount_fs("devtmpfs", PAYLOAD_MNT "/dev", "devtmpfs", NULL) != 0)
		return -1;
	if (mount_fs("tmpfs", PAYLOAD_MNT "/tmp", "tmpfs", "mode=1777") != 0)
		return -1;
	if (chmod(PAYLOAD_MNT "/tmp", 01777) != 0) {
		perror("chmod /mnt/payload/tmp");
		return -1;
	}
	return 0;
}

static void emit_profile_addrs(int mod_loaded)
{
	FILE *kf = fopen("/proc/kallsyms", "re");
	if (kf) {
		char line[512];
		while (fgets(line, sizeof(line), kf)) {
			char addr[64] = "";
			char sym_type[16] = "";
			char name[128] = "";
			if (sscanf(line, "%63s %15s %127s", addr, sym_type, name) == 3 &&
			    strcmp(name, "_stext") == 0) {
				printf("EVAL_PROF_VMLINUX_STEXT 0x%s\n", addr);
				break;
			}
		}
		fclose(kf);
	}

	if (mod_loaded) {
		DIR *sd = opendir("/sys/module/endovisor/sections");
		if (sd) {
			struct dirent *de;
			while ((de = readdir(sd)) != NULL) {
				if (de->d_name[0] != '.')
					continue;
				if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
					continue;
				char path[320];
				snprintf(path, sizeof(path), "/sys/module/endovisor/sections/%s",
					 de->d_name);
				FILE *sf = fopen(path, "re");
				if (!sf)
					continue;
				char addr[64] = "";
				if (fgets(addr, sizeof(addr), sf)) {
					size_t l = strlen(addr);
					while (l > 0 && (addr[l - 1] == '\n' || addr[l - 1] == '\r'))
						addr[--l] = '\0';
					if (l > 0)
						printf("EVAL_PROF_MOD_SECTION %s=%s\n",
						       de->d_name, addr);
				}
				fclose(sf);
			}
			closedir(sd);
		}
	}
	fflush(stdout);
}

static int read_host_thp_fault_alloc(long long *out)
{
	FILE *f = fopen("/proc/vmstat", "re");
	if (!f)
		return -1;
	char key[128];
	long long val = -1;
	while (fscanf(f, "%127s %lld", key, &val) == 2) {
		if (strcmp(key, "thp_fault_alloc") == 0) {
			fclose(f);
			*out = val;
			return 0;
		}
	}
	fclose(f);
	return -1;
}

static int read_host_thp_policy(char *buf, size_t len)
{
	FILE *f = fopen("/sys/kernel/mm/transparent_hugepage/enabled", "re");
	if (!f)
		return -1;
	if (!fgets(buf, (int)len, f)) {
		fclose(f);
		return -1;
	}
	fclose(f);
	size_t n = strlen(buf);
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = '\0';
	return n > 0 ? 0 : -1;
}

struct grant_acct {
	int ok;
	long long live_sandboxes;
	long long live_grant_grains;
	long long live_meta_pages;
	long long live_kstack_pages;
	long long live_shared_pages;
};

static struct grant_acct read_grant_accounting(void)
{
	struct grant_acct ga;
	memset(&ga, 0, sizeof(ga));
	FILE *f = fopen("/sys/class/misc/endovisor/grant_accounting", "re");
	if (!f)
		return ga;
	char buf[256] = "";
	if (fgets(buf, sizeof(buf), f)) {
		if (sscanf(buf,
			   "live_sandboxes=%lld live_grant_grains=%lld live_meta_pages=%lld live_kstack_pages=%lld live_shared_pages=%lld",
			   &ga.live_sandboxes, &ga.live_grant_grains,
			   &ga.live_meta_pages, &ga.live_kstack_pages,
			   &ga.live_shared_pages) == 5) {
			ga.ok = 1;
		}
	}
	fclose(f);
	return ga;
}

static void print_json_escaped(const char *s)
{
	putchar('"');
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		if (c == '"' || c == '\\') {
			putchar('\\');
			putchar(c);
		} else if (c < 0x20) {
			printf("\\u%04x", c);
		} else {
			putchar(c);
		}
	}
	putchar('"');
}

static void emit_folded_profile_file(const char *path)
{
	FILE *f = fopen(path, "re");
	if (!f)
		return;
	printf("EVAL_PROF_FOLDED_BEGIN\n");
	char line[1024];
	while (fgets(line, sizeof(line), f))
		fputs(line, stdout);
	printf("EVAL_PROF_FOLDED_END\n");
	fflush(stdout);
	fclose(f);
	(void)unlink(path);
}

static int run_batch(const char *role, const char *pt_mode, const char *vcpus,
		     const char *grant_mb, int profile_mode, int prof_wait, int prof_hz)
{
	FILE *f = fopen(BATCH_FILE, "re");
	if (!f) {
		fprintf(stderr, "INIT: missing %s: %s\n", BATCH_FILE, strerror(errno));
		return -1;
	}
	char line[2048];
	int executed = 0;
	int failed = 0;

	while (fgets(line, sizeof(line), f)) {
		size_t len = strlen(line);
		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
			line[--len] = '\0';
		if (len == 0 || line[0] == '#')
			continue;

		char *fields[MAX_ARGS];
		int nf = 0;
		char *p = line;
		while (nf < MAX_ARGS) {
			fields[nf++] = p;
			char *tab = strchr(p, '\t');
			if (!tab)
				break;
			*tab = '\0';
			p = tab + 1;
		}
		if (nf < 6) {
			fprintf(stderr, "INIT: malformed batch row (fields=%d)\n", nf);
			failed++;
			continue;
		}

		const char *case_id = fields[0];
		const char *cpus = fields[1];
		const char *tmp_csv = fields[2];
		const char *copy_csv = fields[3];
		const char *verify_exec = fields[4];

		char *runner_argv[MAX_ARGS + 24];
		int ri = 0;
		runner_argv[ri++] = (char *)"/bin/eval_guest_runner";
		runner_argv[ri++] = (char *)"--case-id";
		runner_argv[ri++] = (char *)case_id;
		runner_argv[ri++] = (char *)"--cpus";
		runner_argv[ri++] = (char *)cpus;

		char tmp_copy[512];
		snprintf(tmp_copy, sizeof(tmp_copy), "%s", tmp_csv);
		if (tmp_copy[0] != '\0') {
			for (char *tok = strtok(tmp_copy, ","); tok && ri + 2 < MAX_ARGS + 16; tok = strtok(NULL, ",")) {
				runner_argv[ri++] = (char *)"--tmpfile";
				runner_argv[ri++] = tok;
			}
		}

		char copy_copy[512];
		snprintf(copy_copy, sizeof(copy_copy), "%s", copy_csv);
		if (copy_copy[0] != '\0') {
			for (char *tok = strtok(copy_copy, ","); tok && ri + 2 < MAX_ARGS + 18; tok = strtok(NULL, ",")) {
				runner_argv[ri++] = (char *)"--copy-file";
				runner_argv[ri++] = tok;
			}
		}

		if (verify_exec[0] != '\0') {
			runner_argv[ri++] = (char *)"--verify-exec";
			runner_argv[ri++] = (char *)verify_exec;
		}

		runner_argv[ri++] = (char *)"--";
		for (int i = 5; i < nf && ri + 1 < MAX_ARGS + 24; i++)
			runner_argv[ri++] = fields[i];
		runner_argv[ri] = NULL;

		int rc = -1;
		if (strcmp(role, "L") == 0) {
			rc = run_cmd_wait(runner_argv, PAYLOAD_MNT, NULL);
			if (rc < 0 || rc >= 123) {
				fprintf(stderr, "INIT: runner launch failed for %s (rc=%d)\n", case_id, rc);
				failed++;
			}
		} else {
			char guest_cmd[1536] = "--";
			for (int i = 1; i < ri; i++) {
				strncat(guest_cmd, " ", sizeof(guest_cmd) - strlen(guest_cmd) - 1);
				strncat(guest_cmd, runner_argv[i], sizeof(guest_cmd) - strlen(guest_cmd) - 1);
			}
			char host_thp_policy[128] = "";
			int thp_pol_ok = (read_host_thp_policy(host_thp_policy, sizeof(host_thp_policy)) == 0);
			long long thp_before = 0, thp_after = 0;
			int thp_b_ok = (read_host_thp_fault_alloc(&thp_before) == 0);

			const char *prof_guest_path = "/tmp/eval-prof-guest.folded";
			char *r_argv[20];
			int k = 0;
			r_argv[k++] = (char *)"/bin/run-kernelet";
			r_argv[k++] = (char *)"--pt-mode";
			r_argv[k++] = (char *)pt_mode;
			r_argv[k++] = (char *)"--vcpus";
			r_argv[k++] = (char *)vcpus;
			r_argv[k++] = (char *)"--grant-mb";
			r_argv[k++] = (char *)grant_mb;
			r_argv[k++] = (char *)"--initramfs";
			r_argv[k++] = (char *)PAYLOAD_CPIO;
			r_argv[k++] = (char *)"--cmdline";
			r_argv[k++] = guest_cmd;
			if (profile_mode) {
				r_argv[k++] = (char *)"--prof-addrs";
				if (prof_wait)
					r_argv[k++] = (char *)"--prof-wait";
				if (prof_hz > 0) {
					r_argv[k++] = (char *)"--prof-guest";
					r_argv[k++] = (char *)prof_guest_path;
				}
			}
			r_argv[k++] = (char *)"/kernelet-image.elf";
			r_argv[k] = NULL;

			rc = run_cmd_wait(r_argv, NULL, prof_wait ? NULL : "/dev/null");
			int thp_a_ok = (read_host_thp_fault_alloc(&thp_after) == 0);
			struct grant_acct ga = read_grant_accounting();

			printf("HOST_CASE_META {\"case_id\":");
			print_json_escaped(case_id);
			printf(",\"host_thp_obs_ok\":%s,\"host_thp_policy\":",
			       (thp_pol_ok && thp_b_ok && thp_a_ok) ? "true" : "false");
			if (thp_pol_ok)
				print_json_escaped(host_thp_policy);
			else
				printf("null");
			printf(",\"host_thp_fault_alloc_delta\":");
			if (thp_b_ok && thp_a_ok)
				printf("%lld", thp_after - thp_before);
			else
				printf("null");
			printf(",\"grant_accounting_ok\":%s,\"live_sandboxes\":%lld,"
			       "\"live_grant_grains\":%lld,\"live_meta_pages\":%lld,"
			       "\"live_kstack_pages\":%lld,\"live_shared_pages\":%lld}\n",
			       ga.ok ? "true" : "false",
			       ga.live_sandboxes, ga.live_grant_grains,
			       ga.live_meta_pages, ga.live_kstack_pages, ga.live_shared_pages);
			if (profile_mode && prof_hz > 0)
				emit_folded_profile_file(prof_guest_path);
			fflush(stdout);

			if (rc < 0 || rc >= 127) {
				fprintf(stderr, "INIT: run-kernelet failed for %s (rc=%d)\n", case_id, rc);
				failed++;
			}
		}
		executed++;
	}
	fclose(f);
	if (executed == 0) {
		fprintf(stderr, "INIT: batch file %s contained zero cases\n", BATCH_FILE);
		return -1;
	}
	return failed == 0 ? 0 : -1;
}

int main(void)
{
	int ok = 1;

	if (mount_fs("proc", "/proc", "proc", NULL) != 0)
		ok = 0;
	if (mount_fs("sysfs", "/sys", "sysfs", NULL) != 0)
		ok = 0;
	if (mount_fs("cgroup2", "/sys/fs/cgroup", "cgroup2", NULL) != 0)
		ok = 0;
	if (mkdir("/sys/fs/cgroup/sandbox", 0755) != 0 && errno != EEXIST) {
		perror("mkdir /sys/fs/cgroup/sandbox");
		ok = 0;
	}
	if (mount_fs("devtmpfs", "/dev", "devtmpfs", NULL) != 0)
		ok = 0;

	char cmdline[2048] = "";
	int cfd = open("/proc/cmdline", O_RDONLY);
	if (cfd < 0) {
		perror("open /proc/cmdline");
		ok = 0;
	} else {
		ssize_t n = read(cfd, cmdline, sizeof(cmdline) - 1);
		if (n > 0)
			cmdline[n] = '\0';
		close(cfd);
	}

	char role[16] = "L";
	char pt_mode[16] = "direct";
	char vcpus[16] = "2";
	char grant_mb[16] = "512";
	char profile_flag[16] = "0";
	char prof_wait_flag[16] = "0";
	char prof_hz_flag[16] = "0";
	char audit_flag[16] = "0";
	(void)get_kv(cmdline, "eval_role", role, sizeof(role));
	(void)get_kv(cmdline, "eval_pt_mode", pt_mode, sizeof(pt_mode));
	(void)get_kv(cmdline, "eval_vcpus", vcpus, sizeof(vcpus));
	(void)get_kv(cmdline, "eval_grant_mb", grant_mb, sizeof(grant_mb));
	(void)get_kv(cmdline, "eval_profile", profile_flag, sizeof(profile_flag));
	(void)get_kv(cmdline, "eval_prof_wait", prof_wait_flag, sizeof(prof_wait_flag));
	(void)get_kv(cmdline, "eval_prof_hz", prof_hz_flag, sizeof(prof_hz_flag));
	(void)get_kv(cmdline, "eval_audit", audit_flag, sizeof(audit_flag));
	int profile_mode = (strcmp(profile_flag, "1") == 0);
	int prof_wait = (strcmp(prof_wait_flag, "1") == 0);
	int prof_hz = atoi(prof_hz_flag);
	int audit_mode = (strcmp(audit_flag, "1") == 0);

	char mod_params[128] = "";
	if (audit_mode)
		strncat(mod_params, "audit=1 ", sizeof(mod_params) - strlen(mod_params) - 1);
	if (profile_mode && prof_hz > 0) {
		char hz_opt[48];
		snprintf(hz_opt, sizeof(hz_opt), "profile_hz=%d", prof_hz);
		strncat(mod_params, hz_opt, sizeof(mod_params) - strlen(mod_params) - 1);
	}

	int mod_loaded = 0;
	int mod_fd = open(MOD_PATH, O_RDONLY | O_CLOEXEC);
	if (mod_fd < 0) {
		fprintf(stderr, "INIT: open %s failed: %s\n", MOD_PATH, strerror(errno));
		ok = 0;
	} else {
		if (syscall(SYS_finit_module, mod_fd, mod_params, 0) == 0) {
			mod_loaded = 1;
		} else {
			fprintf(stderr, "INIT: finit_module %s failed: %s\n", MOD_PATH, strerror(errno));
			ok = 0;
		}
		close(mod_fd);
	}

	if (join_sandbox_cgroup() != 0)
		ok = 0;

	if (ok) {
		if (profile_mode)
			emit_profile_addrs(mod_loaded);
		if (strcmp(role, "L") == 0 && prepare_linux_chroot() != 0)
			ok = 0;
		if (ok && run_batch(role, pt_mode, vcpus, grant_mb, profile_mode, prof_wait, prof_hz) != 0)
			ok = 0;
	}

	if (mod_loaded && syscall(SYS_delete_module, "endovisor", 0) != 0) {
		fprintf(stderr, "INIT: delete_module endovisor failed: %s\n", strerror(errno));
		ok = 0;
	}

	if (ok)
		printf("INIT: done\n");
	else
		printf("INIT: failed\n");
	fflush(stdout);
	sync();
	reboot(RB_POWER_OFF);
	for (;;)
		pause();
}
