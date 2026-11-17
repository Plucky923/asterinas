// SPDX-License-Identifier: GPL-2.0
//
// Registers a kernelet PIE ELF, creates an SMP sandbox,
// spawns pinned carrier processes for vCPUs 0..N-1, monitors lifelines,
// optionally triggers SANDBOX_KILL after --kill-after-ms, and prints
// exit status + struct sandbox_stats JSON/CSV summary.
//
// Build: gcc -O2 -static -pthread -I ../endovisor/uapi -o run-kernelet run-kernelet.c

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../endovisor/uapi/endovisor.h"

#define DEVICE_PATH "/dev/endovisor"

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [--pt-mode direct|vma] [--vcpus N] [--grant-mb M]\n"
		"          [--initramfs PATH] [--cmdline STR] [--stats-out PATH]\n"
		"          [--kill-after-ms MS] [--attach-ioctl] [--no-pin]\n"
		"          [--prof-addrs] [--prof-wait] [--prof-guest PATH]\n"
		"          <kernelet-image.elf>\n",
		prog);
	exit(2);
}

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000LL + (long long)(ts.tv_nsec / 1000000L);
}

static unsigned long long now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (unsigned long long)ts.tv_sec * 1000000ULL + (unsigned long long)(ts.tv_nsec / 1000L);
}

static int read_entire_file(const char *path, void **out_buf, size_t *out_len)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	struct stat st;

	if (fd < 0) {
		perror(path);
		return -1;
	}
	if (fstat(fd, &st) != 0) {
		perror("fstat");
		close(fd);
		return -1;
	}
	if (st.st_size <= 0) {
		fprintf(stderr, "%s: empty file\n", path);
		close(fd);
		return -1;
	}
	size_t len = (size_t)st.st_size;
	void *buf = malloc(len);
	if (!buf) {
		perror("malloc");
		close(fd);
		return -1;
	}
	size_t off = 0;
	while (off < len) {
		ssize_t n = read(fd, (char *)buf + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("read");
			free(buf);
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}
	close(fd);
	if (off != len) {
		fprintf(stderr, "%s: short read (%zu/%zu)\n", path, off, len);
		free(buf);
		return -1;
	}
	*out_buf = buf;
	*out_len = len;
	return 0;
}

static volatile sig_atomic_t g_sigchld_seen;

static void sigchld_handler(int sig)
{
	(void)sig;
	g_sigchld_seen = 1;
}

static const char *exit_kind_name(uint32_t kind)
{
	switch (kind) {
	case 0: return "exit";
	case 1: return "panic";
	case 2: return "stack_overflow";
	case 3: return "killed";
	default: return "unknown";
	}
}

static void print_json_escaped(FILE *f, const char *s)
{
	fputc('"', f);
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		if (c == '"' || c == '\\') {
			fputc('\\', f);
			fputc(c, f);
		} else if (c == '\n') {
			fputs("\\n", f);
		} else if (c == '\r') {
			fputs("\\r", f);
		} else if (c < 0x20) {
			fprintf(f, "\\u%04x", c);
		} else {
			fputc(c, f);
		}
	}
	fputc('"', f);
}

static void write_stats_summary(FILE *f, const struct sandbox_stats *st,
				uint32_t pt_mode, uint32_t vcpus, uint32_t grant_mb)
{
	char non_sysret_precheck[24] = "";
	char syscalls[24] = "";

	if (st->non_sysret != UINT64_MAX)
		snprintf(non_sysret_precheck, sizeof(non_sysret_precheck), "%llu",
			 (unsigned long long)st->non_sysret);
	if (st->syscalls != UINT64_MAX)
		snprintf(syscalls, sizeof(syscalls), "%llu",
			 (unsigned long long)st->syscalls);
	fprintf(f,
		"STATS_JSON {\"pt_mode\":%u,\"vcpus\":%u,\"grant_mb\":%u,"
		"\"exit_kind\":%u,\"exit_kind_name\":\"%s\",\"exit_code\":%u,\"exit_msg\":",
		pt_mode, vcpus, grant_mb,
		st->exit_kind, exit_kind_name(st->exit_kind), st->exit_code);
	print_json_escaped(f, st->exit_msg);
	if (st->non_sysret != UINT64_MAX)
		fprintf(f, ",\"non_sysret_precheck\":%s", non_sysret_precheck);
	if (st->syscalls != UINT64_MAX)
		fprintf(f, ",\"syscalls\":%s", syscalls);
	fprintf(f,
		",\"fpu_saves\":%llu,\"fpu_restores\":%llu,"
		"\"vm_creates\":%llu,\"vm_destroys\":%llu,\"vm_flushes\":%llu,"
		"\"vm_maps\":%llu,\"vm_protects\":%llu,\"vm_unmaps\":%llu,"
		"\"exceptions\":%llu,\"page_faults\":%llu,\"virqs\":%llu,"
		"\"forced_yields\":%llu,"
		"\"bench_vm_apply_cycles\":%llu,"
		"\"grant_grains_allocated\":%llu,\"grant_grains_freed\":%llu,"
		"\"image_load_base\":\"0x%llx\"}\n",
		(unsigned long long)st->fpu_saves,
		(unsigned long long)st->fpu_restores,
		(unsigned long long)st->vm_creates,
		(unsigned long long)st->vm_destroys,
		(unsigned long long)st->vm_flushes,
		(unsigned long long)st->vm_maps,
		(unsigned long long)st->vm_protects,
		(unsigned long long)st->vm_unmaps,
		(unsigned long long)st->exceptions,
		(unsigned long long)st->page_faults,
		(unsigned long long)st->virqs,
		(unsigned long long)st->forced_yields,
		(unsigned long long)st->bench_vm_apply_cycles,
		(unsigned long long)st->grant_grains_allocated,
		(unsigned long long)st->grant_grains_freed,
		(unsigned long long)st->image_load_base);

	fprintf(f,
		"STATS_CSV_HDR pt_mode,vcpus,grant_mb,exit_kind,exit_code,"
		"fpu_saves,fpu_restores,vm_creates,vm_destroys,vm_flushes,"
		"vm_maps,vm_protects,vm_unmaps,exceptions,page_faults,virqs,"
		"forced_yields,non_sysret_precheck,bench_vm_apply_cycles,syscalls,"
		"grant_grains_allocated,grant_grains_freed,image_load_base\n");
	fprintf(f,
		"STATS_CSV %u,%u,%u,%u,%u,%llu,%llu,%llu,%llu,%llu,"
		"%llu,%llu,%llu,%llu,%llu,%llu,%llu,%s,%llu,%s,%llu,%llu,0x%llx\n",
		pt_mode, vcpus, grant_mb, st->exit_kind, st->exit_code,
		(unsigned long long)st->fpu_saves,
		(unsigned long long)st->fpu_restores,
		(unsigned long long)st->vm_creates,
		(unsigned long long)st->vm_destroys,
		(unsigned long long)st->vm_flushes,
		(unsigned long long)st->vm_maps,
		(unsigned long long)st->vm_protects,
		(unsigned long long)st->vm_unmaps,
		(unsigned long long)st->exceptions,
		(unsigned long long)st->page_faults,
		(unsigned long long)st->virqs,
		(unsigned long long)st->forced_yields,
		non_sysret_precheck,
		(unsigned long long)st->bench_vm_apply_cycles,
		syscalls,
		(unsigned long long)st->grant_grains_allocated,
		(unsigned long long)st->grant_grains_freed,
		(unsigned long long)st->image_load_base);
}

int main(int argc, char **argv)
{
	uint32_t pt_mode = PT_MODE_DIRECT;
	uint32_t nr_vcpus = 1;
	uint32_t grant_mb = 64;
	const char *initramfs_path = NULL;
	const char *cmdline = "";
	const char *stats_out = NULL;
	const char *image_path = NULL;
	long long kill_after_ms = -1;
	int attach_ioctl = 0;
	int pin_cpus = 1;
	int prof_addrs = 0;
	int prof_wait = 0;
	const char *prof_guest_out = NULL;

	for (int i = 1; i < argc; i++) {
		const char *o = argv[i];
		if (strcmp(o, "--pt-mode") == 0 && i + 1 < argc) {
			const char *m = argv[++i];
			if (strcmp(m, "direct") == 0)
				pt_mode = PT_MODE_DIRECT;
			else if (strcmp(m, "vma") == 0)
				pt_mode = PT_MODE_VMA;
			else
				usage(argv[0]);
		} else if (strcmp(o, "--vcpus") == 0 && i + 1 < argc) {
			nr_vcpus = (uint32_t)atoi(argv[++i]);
		} else if (strcmp(o, "--grant-mb") == 0 && i + 1 < argc) {
			grant_mb = (uint32_t)atoi(argv[++i]);
		} else if (strcmp(o, "--initramfs") == 0 && i + 1 < argc) {
			initramfs_path = argv[++i];
		} else if (strcmp(o, "--cmdline") == 0 && i + 1 < argc) {
			cmdline = argv[++i];
		} else if (strcmp(o, "--stats-out") == 0 && i + 1 < argc) {
			stats_out = argv[++i];
		} else if (strcmp(o, "--kill-after-ms") == 0 && i + 1 < argc) {
			kill_after_ms = atoll(argv[++i]);
		} else if (strcmp(o, "--attach-ioctl") == 0) {
			attach_ioctl = 1;
		} else if (strcmp(o, "--no-pin") == 0) {
			pin_cpus = 0;
		} else if (strcmp(o, "--prof-addrs") == 0) {
			prof_addrs = 1;
		} else if (strcmp(o, "--prof-wait") == 0) {
			prof_wait = 1;
			prof_addrs = 1;
		} else if (strcmp(o, "--prof-guest") == 0 && i + 1 < argc) {
			prof_guest_out = argv[++i];
		} else if (o[0] == '-') {
			usage(argv[0]);
		} else {
			image_path = o;
		}
	}

	if (!image_path || nr_vcpus < 1 || nr_vcpus > MAX_VCPUS ||
	    grant_mb > MAX_GRANT_MB) {
		usage(argv[0]);
	}

	void *elf_buf = NULL;
	size_t elf_len = 0;
	if (read_entire_file(image_path, &elf_buf, &elf_len) != 0)
		return 127;

	void *initramfs_buf = NULL;
	size_t initramfs_len = 0;
	if (initramfs_path) {
		if (read_entire_file(initramfs_path, &initramfs_buf, &initramfs_len) != 0) {
			free(elf_buf);
			return 127;
		}
	}

	int sys_fd = open(DEVICE_PATH, O_RDWR | O_CLOEXEC);
	if (sys_fd < 0) {
		perror(DEVICE_PATH);
		free(initramfs_buf);
		free(elf_buf);
		return 127;
	}

	struct kind_register reg;
	memset(&reg, 0, sizeof(reg));
	reg.elf_ptr = (uint64_t)(uintptr_t)elf_buf;
	reg.elf_len = (uint64_t)elf_len;
	if (ioctl(sys_fd, KIND_REGISTER, &reg) != 0) {
		perror("KIND_REGISTER");
		close(sys_fd);
		free(initramfs_buf);
		free(elf_buf);
		return 127;
	}

	struct sandbox_create cr;
	memset(&cr, 0, sizeof(cr));
	cr.kind_id = reg.kind_id;
	cr.nr_vcpus = nr_vcpus;
	cr.grant_mb = grant_mb;
	cr.max_tasks = DEFAULT_MAX_TASKS;
	cr.pt_mode = pt_mode;
	cr.cmdline_ptr = (uint64_t)(uintptr_t)cmdline;
	cr.cmdline_len = (uint64_t)strlen(cmdline);
	cr.initramfs_ptr = (uint64_t)(uintptr_t)initramfs_buf;
	cr.initramfs_len = (uint64_t)initramfs_len;

	unsigned long long create_t0 = now_us();
	int sandbox_fd = ioctl(sys_fd, SANDBOX_CREATE, &cr);
	unsigned long long grant_create_us = now_us() - create_t0;
	if (sandbox_fd < 0) {
		perror("SANDBOX_CREATE");
		(void)ioctl(sys_fd, KIND_UNREGISTER, &reg.kind_id);
		close(sys_fd);
		free(initramfs_buf);
		free(elf_buf);
		return 127;
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigchld_handler;
	sa.sa_flags = SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sa, NULL);

	long nproc = sysconf(_SC_NPROCESSORS_ONLN);
	if (nproc < 1)
		nproc = 1;

	pid_t pids[MAX_VCPUS];
	int reaped[MAX_VCPUS];
	struct pollfd pfd[MAX_VCPUS + 1];
	memset(pids, 0, sizeof(pids));
	memset(reaped, 0, sizeof(reaped));
	for (uint32_t v = 0; v <= nr_vcpus; v++) {
		pfd[v].fd = -1;
		pfd[v].events = POLLIN;
	}

	pfd[0].fd = sandbox_fd;

	// Print sandbox image load base and synchronize profiler attach before any carrier starts.
	if (prof_addrs) {
		struct sandbox_stats live_st;
		if (ioctl(sandbox_fd, SANDBOX_STATS, &live_st) != 0) {
			perror("SANDBOX_STATS");
			(void)ioctl(sandbox_fd, SANDBOX_KILL);
			goto cleanup_wait;
		}
		printf("EVAL_SANDBOX_LOAD_BASE 0x%llx\n",
		       (unsigned long long)live_st.image_load_base);
		fflush(stdout);
	}
	if (prof_wait) {
		char sync_buf[32];
		if (!fgets(sync_buf, sizeof(sync_buf), stdin) ||
		    strncmp(sync_buf, "GO", 2) != 0) {
			fprintf(stderr, "aborted while waiting for profiler GO handshake\n");
			(void)ioctl(sandbox_fd, SANDBOX_KILL);
			goto cleanup_wait;
		}
	}

	for (uint32_t v = 0; v < nr_vcpus; v++) {
		int exec_fd = -1;
		if (!attach_ioctl) {
			uint32_t idx = v;
			exec_fd = ioctl(sandbox_fd, SANDBOX_GET_VCPU_FD, &idx);
			if (exec_fd < 0) {
				perror("SANDBOX_GET_VCPU_FD");
				(void)ioctl(sandbox_fd, SANDBOX_KILL);
				goto cleanup_wait;
			}
		}

		pid_t pid = fork();
		if (pid < 0) {
			perror("fork");
			if (exec_fd >= 0)
				close(exec_fd);
			(void)ioctl(sandbox_fd, SANDBOX_KILL);
			goto cleanup_wait;
		}
		if (pid == 0) {
			if (pin_cpus) {
				cpu_set_t set;
				CPU_ZERO(&set);
				CPU_SET((int)(v % (uint32_t)nproc), &set);
				if (sched_setaffinity(0, sizeof(set), &set) != 0)
					_exit(126);
			}
			(void)prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

			if (attach_ioctl) {
				uint32_t idx = v;
				if (ioctl(sandbox_fd, SANDBOX_ATTACH_VCPU, &idx) != 0)
					_exit(125);
				_exit(0);
			} else {
				char *const c_argv[] = { (char *)"carrier", NULL };
				char *const c_envp[] = { NULL };
				execveat(exec_fd, "", c_argv, c_envp, AT_EMPTY_PATH);
				_exit(124);
			}
		}

		if (exec_fd >= 0)
			close(exec_fd);
		pids[v] = pid;
		pfd[v + 1].fd = (int)syscall(SYS_pidfd_open, pid, 0);
		pfd[v + 1].events = POLLIN;
		if (pfd[v + 1].fd < 0) {
			perror("pidfd_open");
			(void)ioctl(sandbox_fd, SANDBOX_KILL);
			goto cleanup_wait;
		}
	}

	long long kill_deadline = (kill_after_ms >= 0) ? (now_ms() + kill_after_ms) : -1;
	int kill_sent = 0;

	for (;;) {
		int timeout_ms = -1;
		if (kill_deadline >= 0 && !kill_sent) {
			long long rem = kill_deadline - now_ms();
			timeout_ms = (rem <= 0) ? 0 : (int)rem;
		}

		int ret = poll(pfd, (nfds_t)(nr_vcpus + 1), timeout_ms);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			perror("poll");
			(void)ioctl(sandbox_fd, SANDBOX_KILL);
			break;
		}

		if (kill_deadline >= 0 && !kill_sent && now_ms() >= kill_deadline) {
			(void)ioctl(sandbox_fd, SANDBOX_KILL);
			kill_sent = 1;
		}

		if (pfd[0].revents & POLLIN)
			break;

		for (uint32_t v = 0; v < nr_vcpus; v++) {
			if (pfd[v + 1].fd >= 0 && (pfd[v + 1].revents & POLLIN)) {
				int wst = 0;
				if (waitpid(pids[v], &wst, WNOHANG) > 0)
					reaped[v] = 1;
				close(pfd[v + 1].fd);
				pfd[v + 1].fd = -1;

				// Re-check if sandbox exited at the same moment before killing.
				if (poll(&pfd[0], 1, 0) == 1 && (pfd[0].revents & POLLIN))
					goto done_poll;
				(void)ioctl(sandbox_fd, SANDBOX_KILL);
			}
		}
	}

done_poll:
cleanup_wait:
	for (uint32_t v = 0; v < nr_vcpus; v++) {
		if (pfd[v + 1].fd >= 0)
			close(pfd[v + 1].fd);
	}

	for (uint32_t v = 0; v < nr_vcpus; v++) {
		if (pids[v] > 0 && !reaped[v]) {
			int wst = 0;
			while (waitpid(pids[v], &wst, 0) < 0 && errno == EINTR)
				;
			reaped[v] = 1;
		}
	}

	struct sandbox_stats stats;
	int result = 127;
	ssize_t rn;
	do {
		rn = read(sandbox_fd, &stats, sizeof(stats));
	} while (rn < 0 && errno == EINTR);
	if (rn != (ssize_t)sizeof(stats)) {
		fprintf(stderr, "sandbox result read failed: %zd bytes (errno=%d)\n", rn, errno);
		goto cleanup;
	}

	printf("RUN_KERNELET exit_kind=%s exit_code=%u grant_create_us=%llu exit_msg=\"%s\"\n",
	       exit_kind_name(stats.exit_kind), stats.exit_code, grant_create_us, stats.exit_msg);
	write_stats_summary(stdout, &stats, pt_mode, nr_vcpus, grant_mb);
	if (fflush(stdout) == EOF) {
		perror("stdout");
		goto cleanup;
	}

	if (stats_out) {
		FILE *sf = fopen(stats_out, "w");
		if (sf) {
			write_stats_summary(sf, &stats, pt_mode, nr_vcpus, grant_mb);
			int failed = ferror(sf);
			if (fclose(sf) == EOF)
				failed = 1;
			if (failed) {
				fprintf(stderr, "failed to write stats: %s\n", stats_out);
				goto cleanup;
			}
		} else {
			perror(stats_out);
			goto cleanup;
		}
	}

	if (prof_guest_out) {
		const uint32_t cap = 8192;
		struct sandbox_prof_sample *samples = calloc(cap, sizeof(*samples));
		if (!samples) {
			perror("calloc prof_samples");
			goto cleanup;
		}
		struct sandbox_prof_dump req;
		memset(&req, 0, sizeof(req));
		req.buf_ptr = (uint64_t)(uintptr_t)samples;
		req.capacity = cap;
		if (ioctl(sandbox_fd, SANDBOX_PROF_DUMP, &req) != 0) {
			perror("SANDBOX_PROF_DUMP");
			free(samples);
			goto cleanup;
		}
		FILE *pf = fopen(prof_guest_out, "w");
		if (!pf) {
			perror(prof_guest_out);
			free(samples);
			goto cleanup;
		}
		for (uint32_t s = 0; s < req.count; s++) {
			uint32_t n = samples[s].nr_frames;
			if (n == 0)
				continue;
			if (n > ENDOVISOR_PROF_MAX_FRAMES)
				n = ENDOVISOR_PROF_MAX_FRAMES;
			// Emit folded stack root-to-leaf: `0xroot;...;0xleaf 1`.
			for (uint32_t k = n; k > 0; k--) {
				fprintf(pf, "%s0x%llx",
					(k == n) ? "" : ";",
					(unsigned long long)samples[s].frames[k - 1]);
			}
			fprintf(pf, " 1\n");
		}
		if (fclose(pf) == EOF) {
			free(samples);
			goto cleanup;
		}
		printf("EVAL_PROF_SAMPLES count=%u dropped=%llu path=%s\n",
		       req.count, (unsigned long long)req.dropped, prof_guest_out);
		fflush(stdout);
		free(samples);
	}

	if (stats.exit_kind == 0)
		result = stats.exit_code <= 255 ? (int)stats.exit_code : 1;
	else if (stats.exit_kind == 3 && stats.exit_code > 0 && stats.exit_code < 128)
		result = 128 + (int)stats.exit_code;
	else
		result = 1;

cleanup:
	close(sandbox_fd);
	{
		int unreg_ok = 0;
		for (int tries = 0; tries < 200; tries++) {
			if (ioctl(sys_fd, KIND_UNREGISTER, &reg.kind_id) == 0) {
				unreg_ok = 1;
				break;
			}
			if (errno != EBUSY)
				break;
			struct timespec req = { .tv_sec = 0, .tv_nsec = 5 * 1000 * 1000 };
			nanosleep(&req, NULL);
		}
		if (!unreg_ok) {
			perror("KIND_UNREGISTER");
			result = 127;
		}
	}
	close(sys_fd);
	free(initramfs_buf);
	free(elf_buf);

	return result;
}
