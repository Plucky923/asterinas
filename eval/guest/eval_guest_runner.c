// SPDX-License-Identifier: GPL-2.0
//
// Universal single-case guest runner shared identically by `L`, `A`, and `K`.
//
// Prepares declared temporary files and executable copies, verifies helper
// execution when requested, confines and observes the full descendant CPU
// lifecycle without background `/proc` polling (via `SECCOMP_RET_USER_NOTIF` on
// `sched_setaffinity`/`sched_setattr` and/or cgroup v2 `cpuset`, plus strict
// `Cpus_allowed_list` validation), captures `wait4` rusage deltas and per-stage
// `LMBENCH_TIMING_RUSAGE` lines, and emits one `EVAL_CASE_JSON {...}` frame.

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_TMPFILES 16
#define MAX_COPYFILES 16
#define MAX_IO_BYTES (512 * 1024)

struct tmpfile_req {
	char path[256];
	long size_mb;
};

struct copyfile_req {
	char src[256];
	char dst[256];
};

struct mem_buf {
	uint8_t *data;
	size_t len;
	size_t cap;
};

struct timing_stage {
	int valid;
	long intervals;
	long minflt;
	long majflt;
};

static int g_sigchld_pipe[2] = { -1, -1 };

static void sigchld_handler(int sig)
{
	(void)sig;
	if (g_sigchld_pipe[1] >= 0) {
		int saved = errno;
		uint8_t b = 1;
		(void)write(g_sigchld_pipe[1], &b, 1);
		errno = saved;
	}
}

static int buf_append(struct mem_buf *b, const uint8_t *src, size_t n)
{
	if (n > MAX_IO_BYTES - b->len) {
		errno = EOVERFLOW;
		return -1;
	}
	if (b->len + n > b->cap) {
		size_t ncap = b->cap ? b->cap * 2 : 4096;
		while (ncap < b->len + n)
			ncap *= 2;
		uint8_t *nd = realloc(b->data, ncap);
		if (!nd)
			return -1;
		b->data = nd;
		b->cap = ncap;
	}
	memcpy(b->data + b->len, src, n);
	b->len += n;
	return 0;
}

static void print_base64(const uint8_t *data, size_t len)
{
	static const char tbl[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	for (size_t i = 0; i < len; i += 3) {
		uint32_t v = (uint32_t)data[i] << 16;
		int rem = (int)(len - i);
		if (rem > 1)
			v |= (uint32_t)data[i + 1] << 8;
		if (rem > 2)
			v |= (uint32_t)data[i + 2];
		putchar(tbl[(v >> 18) & 0x3f]);
		putchar(tbl[(v >> 12) & 0x3f]);
		putchar(rem > 1 ? tbl[(v >> 6) & 0x3f] : '=');
		putchar(rem > 2 ? tbl[v & 0x3f] : '=');
	}
}

static void print_json_str(const char *s)
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

static int read_thp_fault_alloc(long long *out)
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

static int read_thp_policy(char *buf, size_t len)
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

static uint64_t mono_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void ensure_pid1_mounts(void)
{
	mkdir("/proc", 0755);
	(void)mount("proc", "/proc", "proc", 0, NULL);
	mkdir("/sys", 0755);
	(void)mount("sysfs", "/sys", "sysfs", 0, NULL);
	mkdir("/sys/fs", 0755);
	mkdir("/sys/fs/cgroup", 0755);
	(void)mount("cgroup2", "/sys/fs/cgroup", "cgroup2", 0, NULL);
	mkdir("/dev", 0755);
	(void)mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	mkdir("/tmp", 01777);
	if (access("/tmp/.eval_mounted", F_OK) != 0)
		(void)mount("tmpfs", "/tmp", "tmpfs", 0, "mode=1777");
	chmod("/tmp", 01777);
}

static int prepare_tmpfile(const struct tmpfile_req *req)
{
	int fd = open(req->path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0)
		return -1;
	static uint8_t block[65536];
	static int inited = 0;
	if (!inited) {
		for (size_t i = 0; i < sizeof(block); i++)
			block[i] = (uint8_t)((i * 131 + 17) & 0xff);
		inited = 1;
	}
	size_t total = (size_t)req->size_mb * 1024ULL * 1024ULL;
	size_t written = 0;
	while (written < total) {
		size_t chunk = total - written;
		if (chunk > sizeof(block))
			chunk = sizeof(block);
		ssize_t n = write(fd, block, chunk);
		if (n <= 0) {
			if (n < 0 && errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		written += (size_t)n;
	}
	(void)fsync(fd);
	close(fd);
	return 0;
}

static int prepare_copyfile(const struct copyfile_req *req)
{
	int sfd = open(req->src, O_RDONLY | O_CLOEXEC);
	if (sfd < 0)
		return -1;
	int dfd = open(req->dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
	if (dfd < 0) {
		close(sfd);
		return -1;
	}
	uint8_t buf[32768];
	while (1) {
		ssize_t n = read(sfd, buf, sizeof(buf));
		if (n == 0)
			break;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(sfd);
			close(dfd);
			return -1;
		}
		size_t off = 0;
		while (off < (size_t)n) {
			ssize_t w = write(dfd, buf + off, (size_t)n - off);
			if (w <= 0) {
				if (w < 0 && errno == EINTR)
					continue;
				close(sfd);
				close(dfd);
				return -1;
			}
			off += (size_t)w;
		}
	}
	(void)fchmod(dfd, 0755);
	close(sfd);
	close(dfd);
	return 0;
}

static int verify_executable_runs(const char *path)
{
	if (access(path, X_OK) != 0)
		return -1;
	pid_t pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		int nullfd = open("/dev/null", O_WRONLY);
		if (nullfd >= 0) {
			dup2(nullfd, STDOUT_FILENO);
			dup2(nullfd, STDERR_FILENO);
			close(nullfd);
		}
		char *const argv[] = { (char *)path, NULL };
		execv(path, argv);
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
	return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
}

static int verify_mask_subset(const cpu_set_t *allowed)
{
	cpu_set_t actual;
	CPU_ZERO(&actual);
	if (sched_getaffinity(0, sizeof(actual), &actual) != 0)
		return -1;
	int any = 0;
	for (int c = 0; c < CPU_SETSIZE; c++) {
		if (CPU_ISSET(c, &actual)) {
			any = 1;
			if (!CPU_ISSET(c, allowed))
				return -1;
		}
	}
	return any ? 0 : -1;
}

// Parse a comma-separated CPU range list (such as `0` or `0-1`) into `migrated`.
//
// Returns 0 when at least one CPU was parsed, or -1 if malformed/empty.
static int check_cpu_list_subset(const char *spec, const cpu_set_t *allowed, int *migrated)
{
	const char *p = spec;
	while (*p == ' ' || *p == '\t')
		p++;
	int any_cpu = 0;
	while (*p && *p != '\n' && *p != '\r') {
		char *end = NULL;
		long lo = strtol(p, &end, 10);
		if (end == p)
			return -1;
		long hi = lo;
		p = end;
		if (*p == '-') {
			p++;
			hi = strtol(p, &end, 10);
			if (end == p || hi < lo)
				return -1;
			p = end;
		}
		for (long c = lo; c <= hi; c++) {
			any_cpu = 1;
			if (c < 0 || c >= CPU_SETSIZE || !CPU_ISSET((int)c, allowed))
				*migrated = 1;
		}
		if (*p == ',')
			p++;
		else
			break;
	}
	return any_cpu ? 0 : -1;
}

// Require and verify `Cpus_allowed_list` in `/proc/<pid>/[task/<tid>/]status`.
//
// Returns 0 only when `Cpus_allowed_list:` is present and parsed cleanly.
static int check_status_cpus_allowed(const char *path, const cpu_set_t *allowed, int *migrated)
{
	FILE *f = fopen(path, "re");
	if (!f)
		return -1;
	char line[1024];
	int found = 0;
	int parse_ok = 0;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Cpus_allowed_list:", 18) != 0)
			continue;
		found = 1;
		if (check_cpu_list_subset(line + 18, allowed, migrated) == 0)
			parse_ok = 1;
		break;
	}
	int f_err = ferror(f);
	fclose(f);
	if (f_err || !found || !parse_ok)
		return -1;
	return 0;
}

static int write_text_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	size_t len = strlen(text);
	ssize_t n = write(fd, text, len);
	int saved = errno;
	close(fd);
	errno = saved;
	return (n == (ssize_t)len) ? 0 : -1;
}

static int read_small_file(const char *path, char *buf, size_t len)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ssize_t n = read(fd, buf, len - 1);
	int saved = errno;
	close(fd);
	errno = saved;
	if (n < 0)
		return -1;
	buf[n] = '\0';
	return 0;
}

// Configure cgroup v2 `cpuset` containment when writable (`/sys/fs/cgroup`).
//
// Returns 0 if `cpuset.cpus.effective` matches `allowed`, or -1 if unavailable.
static int setup_case_cpuset(const char *cpus_csv, const cpu_set_t *allowed,
			     char *dir_out, size_t dir_len)
{
	dir_out[0] = '\0';
	if (access("/sys/fs/cgroup/cgroup.controllers", R_OK) != 0)
		return -1;
	(void)write_text_file("/sys/fs/cgroup/cgroup.subtree_control", "+cpuset\n");

	snprintf(dir_out, dir_len, "/sys/fs/cgroup/eval_case_%d", (int)getpid());
	if (mkdir(dir_out, 0755) != 0 && errno != EEXIST) {
		dir_out[0] = '\0';
		return -1;
	}

	char cpus_path[512], eff_path[512], cpus_val[160], eff_val[256];
	snprintf(cpus_path, sizeof(cpus_path), "%s/cpuset.cpus", dir_out);
	snprintf(cpus_val, sizeof(cpus_val), "%s\n", cpus_csv);
	if (write_text_file(cpus_path, cpus_val) != 0) {
		(void)rmdir(dir_out);
		dir_out[0] = '\0';
		return -1;
	}

	snprintf(eff_path, sizeof(eff_path), "%s/cpuset.cpus.effective", dir_out);
	if (read_small_file(eff_path, eff_val, sizeof(eff_val)) != 0) {
		(void)rmdir(dir_out);
		dir_out[0] = '\0';
		return -1;
	}

	int eff_migrated = 0;
	if (check_cpu_list_subset(eff_val, allowed, &eff_migrated) != 0 || eff_migrated) {
		(void)rmdir(dir_out);
		dir_out[0] = '\0';
		return -1;
	}
	return 0;
}

static int verify_case_cpuset(const char *dir, const cpu_set_t *allowed, int *migrated)
{
	if (!dir || !dir[0])
		return -1;
	char eff_path[512], eff_val[256];
	snprintf(eff_path, sizeof(eff_path), "%s/cpuset.cpus.effective", dir);
	if (read_small_file(eff_path, eff_val, sizeof(eff_val)) != 0)
		return -1;
	if (check_cpu_list_subset(eff_val, allowed, migrated) != 0)
		return -1;

	char viol_path[512], viol_val[64];
	snprintf(viol_path, sizeof(viol_path), "%s/cpuset.affinity_violations", dir);
	if (read_small_file(viol_path, viol_val, sizeof(viol_val)) == 0) {
		long long cnt = strtoll(viol_val, NULL, 10);
		if (cnt > 0)
			*migrated = 1;
	}
	return 0;
}

static void cleanup_case_cpuset(const char *dir)
{
	if (!dir || !dir[0])
		return;
	(void)rmdir(dir);
}

static int install_affinity_seccomp_notifier(void)
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (unsigned int)offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 (unsigned int)offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sched_setaffinity, 2, 0),
#ifdef __NR_sched_setattr
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_sched_setattr, 1, 0),
#else
		BPF_JUMP(BPF_JMP | BPF_JA, 0, 0, 0),
#endif
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
		return -1;
	long fd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
			  SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
	return (fd >= 0) ? (int)fd : -1;
}

static int send_fd_status(int sock, uint8_t tag, int fd)
{
	struct msghdr msg;
	struct iovec iov;
	uint8_t buf[1] = { tag };
	char cbuf[CMSG_SPACE(sizeof(int))];

	memset(&msg, 0, sizeof(msg));
	memset(cbuf, 0, sizeof(cbuf));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (fd >= 0) {
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	}
	return sendmsg(sock, &msg, 0) == 1 ? 0 : -1;
}

static int recv_fd_status(int sock, uint8_t *tag, int *out_fd)
{
	struct msghdr msg;
	struct iovec iov;
	uint8_t buf[1] = { 0 };
	char cbuf[CMSG_SPACE(sizeof(int))];

	*out_fd = -1;
	memset(&msg, 0, sizeof(msg));
	memset(cbuf, 0, sizeof(cbuf));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	ssize_t n;
	do {
		n = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
	} while (n < 0 && errno == EINTR);
	if (n != 1)
		return -1;
	*tag = buf[0];
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
			memcpy(out_fd, CMSG_DATA(cmsg), sizeof(int));
			break;
		}
	}
	return 0;
}

static int inspect_remote_cpuset_allowed(int notify_fd, uint64_t cookie,
					 pid_t caller, size_t user_sz, uint64_t user_ptr,
					 const cpu_set_t *allowed)
{
	if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &cookie) != 0)
		return -1;
	if (user_sz == 0 || user_ptr == 0)
		return 0;
	if (user_sz > sizeof(cpu_set_t))
		user_sz = sizeof(cpu_set_t);

	char mem_path[64];
	snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", (int)caller);
	int mfd = open(mem_path, O_RDONLY | O_CLOEXEC);
	if (mfd < 0)
		return -1;

	uint8_t raw[sizeof(cpu_set_t)];
	memset(raw, 0, sizeof(raw));
	ssize_t nr = pread(mfd, raw, user_sz, (off_t)user_ptr);
	close(mfd);
	if (nr != (ssize_t)user_sz)
		return -1;
	if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &cookie) != 0)
		return -1;

	cpu_set_t req_set;
	CPU_ZERO(&req_set);
	memcpy(&req_set, raw, user_sz);

	int any = 0;
	for (int c = 0; c < CPU_SETSIZE; c++) {
		if (CPU_ISSET(c, &req_set)) {
			any = 1;
			if (!CPU_ISSET(c, allowed))
				return 0;
		}
	}
	return any ? 1 : 0;
}

static void handle_seccomp_notif(int notify_fd, const cpu_set_t *allowed, int *migrated)
{
	struct seccomp_notif req;
	struct seccomp_notif_resp resp;

	memset(&req, 0, sizeof(req));
	if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) != 0)
		return;

	memset(&resp, 0, sizeof(resp));
	resp.id = req.id;

	int permit = 0;
	if (req.data.nr == __NR_sched_setaffinity) {
		int verdict = inspect_remote_cpuset_allowed(
			notify_fd, req.id, (pid_t)req.pid,
			(size_t)req.data.args[1], (uint64_t)req.data.args[2], allowed);
		if (verdict == 1)
			permit = 1;
		else
			*migrated = 1;
	} else {
		*migrated = 1;
	}

	if (permit) {
		resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
		resp.error = 0;
	} else {
		resp.flags = 0;
		resp.error = -EPERM;
	}
	(void)ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
}

static int drain_events_until_done(pid_t child_pid, int out_fd, int err_fd,
				   int notify_fd, const cpu_set_t *allowed,
				   int *migrated, struct mem_buf *obuf, struct mem_buf *ebuf)
{
	int open_pipes = 2;
	int child_done = 0;
	int result = 0;
	uint8_t tmp[4096];

	while (open_pipes > 0 || !child_done) {
		struct pollfd pfds[4];
		int nfds = 0;
		int out_idx = -1, err_idx = -1, sig_idx = -1, notif_idx = -1;

		if (out_fd >= 0) {
			out_idx = nfds;
			pfds[nfds++] = (struct pollfd){ .fd = out_fd, .events = POLLIN };
		}
		if (err_fd >= 0) {
			err_idx = nfds;
			pfds[nfds++] = (struct pollfd){ .fd = err_fd, .events = POLLIN };
		}
		if (!child_done && g_sigchld_pipe[0] >= 0) {
			sig_idx = nfds;
			pfds[nfds++] = (struct pollfd){ .fd = g_sigchld_pipe[0], .events = POLLIN };
		}
		if (notify_fd >= 0) {
			notif_idx = nfds;
			pfds[nfds++] = (struct pollfd){ .fd = notify_fd, .events = POLLIN };
		}

		int pr = poll(pfds, (nfds_t)nfds, 100);
		if (pr < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			result = -1;
			break;
		}

		if (notif_idx >= 0 && (pfds[notif_idx].revents & POLLIN))
			handle_seccomp_notif(notify_fd, allowed, migrated);

		int pipe_indices[2] = { out_idx, err_idx };
		int *pipe_fds[2] = { &out_fd, &err_fd };
		struct mem_buf *pipe_bufs[2] = { obuf, ebuf };
		for (int i = 0; i < 2; i++) {
			int idx = pipe_indices[i];
			if (idx < 0)
				continue;
			if (pfds[idx].revents & POLLNVAL) {
				fprintf(stderr, "invalid child output pipe\n");
				result = -1;
				goto out;
			}
			if (pfds[idx].revents & (POLLIN | POLLHUP | POLLERR)) {
				ssize_t n = read(*pipe_fds[i], tmp, sizeof(tmp));
				if (n > 0) {
					if (buf_append(pipe_bufs[i], tmp, (size_t)n) != 0) {
						perror("capture child output");
						result = -1;
						goto out;
					}
				} else if (n < 0 && errno != EINTR && errno != EAGAIN) {
					perror("read child output");
					result = -1;
					goto out;
				} else if (n == 0) {
					close(*pipe_fds[i]);
					*pipe_fds[i] = -1;
					open_pipes--;
				}
			}
		}

		if (sig_idx >= 0 && (pfds[sig_idx].revents & (POLLIN | POLLHUP))) {
			uint8_t drain[32];
			while (read(g_sigchld_pipe[0], drain, sizeof(drain)) > 0)
				;
		}

		if (!child_done) {
			siginfo_t si;
			memset(&si, 0, sizeof(si));
			if (waitid(P_PID, (id_t)child_pid, &si, WEXITED | WNOHANG | WNOWAIT) == 0 &&
			    si.si_pid == child_pid) {
				child_done = 1;
			}
		}
	}

out:
	if (out_fd >= 0)
		close(out_fd);
	if (err_fd >= 0)
		close(err_fd);
	return result;
}

static void parse_lmbench_timing_rusage(const struct mem_buf *ebuf,
					int *out_ok,
					long long *out_minflt,
					long long *out_majflt,
					struct timing_stage **out_stages,
					size_t *out_nstages)
{
	*out_ok = 0;
	*out_minflt = 0;
	*out_majflt = 0;
	*out_stages = NULL;
	*out_nstages = 0;
	if (!ebuf->data || ebuf->len == 0)
		return;

	char *copy = malloc(ebuf->len + 1);
	if (!copy)
		return;
	memcpy(copy, ebuf->data, ebuf->len);
	copy[ebuf->len] = '\0';

	int seen = 0;
	int all_valid = 1;
	long long min_sum = 0;
	long long maj_sum = 0;
	size_t cap = 8;
	struct timing_stage *stages = calloc(cap, sizeof(*stages));
	size_t nstages = 0;

	char *save = NULL;
	for (char *line = strtok_r(copy, "\r\n", &save); line;
	     line = strtok_r(NULL, "\r\n", &save)) {
		int valid = 0;
		long intervals = 0;
		long minflt = 0;
		long majflt = 0;
		if (sscanf(line,
			   "LMBENCH_TIMING_RUSAGE valid=%d intervals=%ld minflt=%ld majflt=%ld",
			   &valid, &intervals, &minflt, &majflt) == 4) {
			seen = 1;
			if (stages && nstages == cap) {
				cap *= 2;
				struct timing_stage *ns = realloc(stages, cap * sizeof(*stages));
				if (ns)
					stages = ns;
			}
			if (stages && nstages < cap) {
				stages[nstages++] = (struct timing_stage){
					.valid = valid,
					.intervals = intervals,
					.minflt = minflt,
					.majflt = majflt,
				};
			}
			if (!valid || intervals <= 0 || minflt < 0 || majflt < 0)
				all_valid = 0;
			else {
				min_sum += minflt;
				maj_sum += majflt;
			}
		}
	}

	free(copy);
	*out_stages = stages;
	*out_nstages = nstages;
	if (seen && all_valid) {
		*out_ok = 1;
		*out_minflt = min_sum;
		*out_majflt = maj_sum;
	}
}

int main(int argc, char **argv)
{
	if (getpid() == 1)
		ensure_pid1_mounts();

	const char *case_id = "unknown";
	const char *cpus_csv = "0";
	const char *verify_exec_path = NULL;
	int poweroff_on_exit = 0;
	struct tmpfile_req tmpfiles[MAX_TMPFILES];
	struct copyfile_req copyfiles[MAX_COPYFILES];
	int n_tmpfiles = 0;
	int n_copyfiles = 0;
	int cmd_idx = -1;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--case-id") == 0 && i + 1 < argc) {
			case_id = argv[++i];
		} else if (strcmp(argv[i], "--cpus") == 0 && i + 1 < argc) {
			cpus_csv = argv[++i];
		} else if (strcmp(argv[i], "--tmpfile") == 0 && i + 1 < argc) {
			if (n_tmpfiles < MAX_TMPFILES) {
				const char *spec = argv[++i];
				const char *colon = strrchr(spec, ':');
				if (colon) {
					size_t plen = (size_t)(colon - spec);
					if (plen >= sizeof(tmpfiles[0].path))
						plen = sizeof(tmpfiles[0].path) - 1;
					memcpy(tmpfiles[n_tmpfiles].path, spec, plen);
					tmpfiles[n_tmpfiles].path[plen] = '\0';
					tmpfiles[n_tmpfiles].size_mb = atol(colon + 1);
					n_tmpfiles++;
				}
			}
		} else if (strcmp(argv[i], "--copy-file") == 0 && i + 1 < argc) {
			if (n_copyfiles < MAX_COPYFILES) {
				const char *spec = argv[++i];
				const char *colon = strrchr(spec, ':');
				if (colon) {
					size_t slen = (size_t)(colon - spec);
					if (slen >= sizeof(copyfiles[0].src))
						slen = sizeof(copyfiles[0].src) - 1;
					memcpy(copyfiles[n_copyfiles].src, spec, slen);
					copyfiles[n_copyfiles].src[slen] = '\0';
					snprintf(copyfiles[n_copyfiles].dst,
						 sizeof(copyfiles[0].dst), "%s", colon + 1);
					n_copyfiles++;
				}
			}
		} else if (strcmp(argv[i], "--verify-exec") == 0 && i + 1 < argc) {
			verify_exec_path = argv[++i];
		} else if (strcmp(argv[i], "--poweroff") == 0) {
			poweroff_on_exit = 1;
		} else if (strcmp(argv[i], "--") == 0) {
			cmd_idx = i + 1;
			break;
		}
	}

	if (cmd_idx < 0 || cmd_idx >= argc) {
		fprintf(stderr, "usage: eval_guest_runner --case-id ID --cpus CSV [--tmpfile PATH:MB] [--copy-file SRC:DST] [--verify-exec PATH] [--poweroff] -- CMD...\n");
		return 2;
	}

	for (int i = 0; i < n_tmpfiles; i++) {
		if (prepare_tmpfile(&tmpfiles[i]) != 0) {
			fprintf(stderr, "failed to prepare tmpfile %s\n", tmpfiles[i].path);
			return 3;
		}
	}
	for (int i = 0; i < n_copyfiles; i++) {
		if (prepare_copyfile(&copyfiles[i]) != 0) {
			fprintf(stderr, "failed to copy %s -> %s\n",
				copyfiles[i].src, copyfiles[i].dst);
			return 3;
		}
	}
	if (verify_exec_path && verify_executable_runs(verify_exec_path) != 0) {
		fprintf(stderr, "pre-exec verification failed for %s\n", verify_exec_path);
		return 6;
	}

	cpu_set_t mask;
	CPU_ZERO(&mask);
	char cpus_buf[128];
	snprintf(cpus_buf, sizeof(cpus_buf), "%s", cpus_csv);
	for (char *tok = strtok(cpus_buf, ","); tok; tok = strtok(NULL, ","))
		CPU_SET(atoi(tok), &mask);

	int migrated = 0;
	if (sched_setaffinity(0, sizeof(mask), &mask) != 0 || verify_mask_subset(&mask) != 0) {
		perror("sched_setaffinity");
		return 4;
	}
	int parent_status_ok = (check_status_cpus_allowed("/proc/self/status", &mask, &migrated) == 0);

	char cgroup_dir[256];
	int cpuset_ok = (setup_case_cpuset(cpus_csv, &mask, cgroup_dir, sizeof(cgroup_dir)) == 0);

	if (pipe2(g_sigchld_pipe, O_CLOEXEC | O_NONBLOCK) != 0)
		return 4;
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigchld_handler;
	sa.sa_flags = SA_NOCLDSTOP | SA_RESTART;
	sigaction(SIGCHLD, &sa, NULL);

	int out_pipe[2], err_pipe[2], sync_sock[2], ack_pipe[2];
	if (pipe2(out_pipe, O_CLOEXEC) != 0 || pipe2(err_pipe, O_CLOEXEC) != 0 ||
	    socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sync_sock) != 0 ||
	    pipe2(ack_pipe, O_CLOEXEC) != 0) {
		cleanup_case_cpuset(cgroup_dir);
		return 4;
	}

	char thp_policy[128] = "";
	int thp_policy_ok = (read_thp_policy(thp_policy, sizeof(thp_policy)) == 0);
	long long thp_before = 0;
	int thp_ok_before = (read_thp_fault_alloc(&thp_before) == 0);
	int cpu_start = sched_getcpu();
	uint64_t t0 = mono_ns();

	pid_t pid = fork();
	if (pid < 0) {
		cleanup_case_cpuset(cgroup_dir);
		return 5;
	}
	if (pid == 0) {
		close(sync_sock[0]);
		close(ack_pipe[1]);
		if (cpuset_ok) {
			char procs_path[320], pid_txt[32];
			snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", cgroup_dir);
			snprintf(pid_txt, sizeof(pid_txt), "%d\n", (int)getpid());
			if (write_text_file(procs_path, pid_txt) != 0)
				_exit(126);
		}
		if (sched_setaffinity(0, sizeof(mask), &mask) != 0 || verify_mask_subset(&mask) != 0)
			_exit(126);
		int ccpu = sched_getcpu();
		if (ccpu < 0 || !CPU_ISSET(ccpu, &mask))
			_exit(126);

		int nfd = install_affinity_seccomp_notifier();
		uint8_t tag = (nfd >= 0) ? 'Y' : 'N';
		if (send_fd_status(sync_sock[1], tag, nfd) != 0)
			_exit(126);
		if (nfd >= 0)
			close(nfd);
		close(sync_sock[1]);

		uint8_t go = 0;
		if (read(ack_pipe[0], &go, 1) != 1 || go != 'G')
			_exit(126);
		close(ack_pipe[0]);

		(void)setenv("LMBENCH_TIMING_RUSAGE", "1", 1);
		dup2(out_pipe[1], STDOUT_FILENO);
		dup2(err_pipe[1], STDERR_FILENO);
		close(out_pipe[0]);
		close(out_pipe[1]);
		close(err_pipe[0]);
		close(err_pipe[1]);
		execvp(argv[cmd_idx], &argv[cmd_idx]);
		perror("execvp");
		_exit(127);
	}

	close(out_pipe[1]);
	close(err_pipe[1]);
	close(sync_sock[1]);
	close(ack_pipe[0]);

	uint8_t seccomp_tag = 'N';
	int notify_fd = -1;
	int handshake_ok = (recv_fd_status(sync_sock[0], &seccomp_tag, &notify_fd) == 0);
	close(sync_sock[0]);

	char child_status_path[64];
	snprintf(child_status_path, sizeof(child_status_path), "/proc/%d/status", (int)pid);
	int child_status_ok = (check_status_cpus_allowed(child_status_path, &mask, &migrated) == 0);

	if (write(ack_pipe[1], "G", 1) != 1) {
		(void)kill(pid, SIGKILL);
	}
	close(ack_pipe[1]);

	int seccomp_ok = (handshake_ok && seccomp_tag == 'Y' && notify_fd >= 0);

	struct mem_buf obuf = {0}, ebuf = {0};
	int captured = drain_events_until_done(pid, out_pipe[0], err_pipe[0],
					       notify_fd, &mask, &migrated, &obuf, &ebuf);
	if (notify_fd >= 0)
		close(notify_fd);
	if (captured < 0)
		(void)kill(pid, SIGKILL);

	int status = 0;
	struct rusage ru;
	memset(&ru, 0, sizeof(ru));
	pid_t waited;
	do {
		waited = wait4(pid, &status, 0, &ru);
	} while (waited < 0 && errno == EINTR);
	if (waited < 0) {
		perror("wait4");
		cleanup_case_cpuset(cgroup_dir);
		free(obuf.data);
		free(ebuf.data);
		return 5;
	}

	uint64_t t1 = mono_ns();
	int cpu_end = sched_getcpu();
	long long thp_after = 0;
	int thp_ok_after = (read_thp_fault_alloc(&thp_after) == 0);

	int cpuset_after_ok = cpuset_ok ? (verify_case_cpuset(cgroup_dir, &mask, &migrated) == 0) : 0;
	cleanup_case_cpuset(cgroup_dir);

	for (int i = 0; i < n_tmpfiles; i++)
		(void)unlink(tmpfiles[i].path);
	for (int i = 0; i < n_copyfiles; i++)
		(void)unlink(copyfiles[i].dst);
	if (captured < 0) {
		free(obuf.data);
		free(ebuf.data);
		return 5;
	}

	int rc = WIFEXITED(status) ? WEXITSTATUS(status)
		: (WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 1);
	int cpu_obs_ok = (parent_status_ok && child_status_ok && (seccomp_ok || cpuset_after_ok)) ? 1 : 0;
	if (cpu_start < 0 || !CPU_ISSET(cpu_start, &mask) ||
	    cpu_end < 0 || !CPU_ISSET(cpu_end, &mask))
		migrated = 1;
	long long utime_us = (long long)ru.ru_utime.tv_sec * 1000000LL + ru.ru_utime.tv_usec;
	long long stime_us = (long long)ru.ru_stime.tv_sec * 1000000LL + ru.ru_stime.tv_usec;

	int timing_ok = 0;
	long long timing_minflt = 0;
	long long timing_majflt = 0;
	struct timing_stage *stages = NULL;
	size_t nstages = 0;
	parse_lmbench_timing_rusage(&ebuf, &timing_ok, &timing_minflt, &timing_majflt,
				    &stages, &nstages);

	int thp_obs_ok = (thp_policy_ok && thp_ok_before && thp_ok_after) ? 1 : 0;

	printf("EVAL_CASE_JSON {\"case_id\":");
	print_json_str(case_id);
	printf(",\"rc\":%d,\"wall_ns\":%llu,\"minflt_delta\":%ld,\"majflt_delta\":%ld,"
	       "\"ru_utime_us\":%lld,\"ru_stime_us\":%lld,\"cpu_start\":%d,\"cpu_end\":%d,"
	       "\"migrated\":%s,\"cpu_obs_ok\":%s,\"thp_obs_ok\":%s,\"thp_policy\":",
	       rc, (unsigned long long)(t1 - t0), ru.ru_minflt, ru.ru_majflt,
	       utime_us, stime_us, cpu_start, cpu_end,
	       migrated ? "true" : "false",
	       cpu_obs_ok ? "true" : "false",
	       thp_obs_ok ? "true" : "false");
	if (thp_policy_ok)
		print_json_str(thp_policy);
	else
		printf("null");
	printf(",\"thp_fault_alloc_delta\":");
	if (thp_ok_before && thp_ok_after)
		printf("%lld", thp_after - thp_before);
	else
		printf("null");
	printf(",\"timing_minflt_delta\":");
	if (timing_ok)
		printf("%lld", timing_minflt);
	else
		printf("null");
	printf(",\"timing_majflt_delta\":");
	if (timing_ok)
		printf("%lld", timing_majflt);
	else
		printf("null");
	printf(",\"timing_stages\":[");
	for (size_t s = 0; s < nstages; s++) {
		printf("%s{\"valid\":%s,\"intervals\":%ld,\"minflt\":%ld,\"majflt\":%ld}",
		       s ? "," : "",
		       stages[s].valid ? "true" : "false",
		       stages[s].intervals, stages[s].minflt, stages[s].majflt);
	}
	printf("],\"stdout_b64\":\"");
	print_base64(obuf.data, obuf.len);
	printf("\",\"stderr_b64\":\"");
	print_base64(ebuf.data, ebuf.len);
	printf("\"}\n");
	fflush(stdout);

	free(stages);
	free(obuf.data);
	free(ebuf.data);

	if (poweroff_on_exit) {
		sync();
		(void)reboot(RB_POWER_OFF);
	}
	return rc;
}
