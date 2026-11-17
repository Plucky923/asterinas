// SPDX-License-Identifier: GPL-2.0
// `/dev/endovisor` miscdevice, kind & sandbox lifecycle, `execveat` binfmt,
// direct `SANDBOX_ATTACH_VCPU`, `cpu_slot` verification, and teardown.

#include <linux/anon_inodes.h>
#include <linux/binfmts.h>
#include <linux/capability.h>
#include <linux/cgroup.h>
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kernelet.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/personality.h>
#include <linux/poll.h>
#include <linux/preempt.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/coredump.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/security.h>
#include <linux/shmem_fs.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/thread_info.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/ptrace.h>

#include "endovisor.h"

bool watch_enabled = true;
module_param_named(watch, watch_enabled, bool, 0444);
MODULE_PARM_DESC(watch,
		 "enable per-CPU 1 ms watch timer for ticks, virqs, and bounded preemption (default 1)");

bool audit_enabled = false;
module_param_named(audit, audit_enabled, bool, 0444);
MODULE_PARM_DESC(audit,
		 "enable syscall counts and pre-return SYSRET eligibility diagnostics (default 0)");

int profile_hz = 0;
module_param_named(profile_hz, profile_hz, int, 0444);
MODULE_PARM_DESC(profile_hz,
		 "enable isolated in-sandbox stack sampling when non-zero (default 0)");

DEFINE_STATIC_KEY_FALSE(endovisor_audit_key);
DEFINE_STATIC_KEY_FALSE(endovisor_profile_key);

atomic64_t endo_live_sandboxes = ATOMIC64_INIT(0);
atomic64_t endo_live_grains = ATOMIC64_INIT(0);
atomic64_t endo_live_meta_pages = ATOMIC64_INIT(0);
atomic64_t endo_live_kstack_pages = ATOMIC64_INIT(0);
atomic64_t endo_live_shared_pages = ATOMIC64_INIT(0);

u32 cpu_slot_offset;
struct workqueue_struct *cleanup_wq;

DEFINE_MUTEX(registry_lock);
static struct image_kind image_kinds[MAX_KINDS];
static struct sandbox *sandboxes[MAX_SANDBOXES];

static atomic_t generation_seq = ATOMIC_INIT(1);
static struct linux_binfmt carrier_format;

// ------------------------------------------------------------------
// Reference counting & teardown
// ------------------------------------------------------------------

void sandbox_get(struct sandbox *sandbox)
{
	refcount_inc(&sandbox->refs);
}

void sandbox_put(struct sandbox *sandbox)
{
	if (!refcount_dec_and_test(&sandbox->refs))
		return;
	if (sandbox->prof_samples)
		kvfree(sandbox->prof_samples);
	kfree(sandbox->cmdline);
	kvfree(sandbox);
}

static void sandbox_unpublish(struct sandbox *sandbox)
{
	unsigned int i;

	mutex_lock(&registry_lock);
	if (sandbox->slot >= 0 && sandboxes[sandbox->slot] == sandbox)
		sandboxes[sandbox->slot] = NULL;
	sandbox->slot = -1;
	for (i = 0; i < sandbox->nr_vcpus; i++) {
		if (sandbox->vslot[i].exec_file) {
			fput(sandbox->vslot[i].exec_file);
			sandbox->vslot[i].exec_file = NULL;
		}
	}
	if (sandbox->kind) {
		if (sandbox->kind->nr_sandboxes > 0)
			sandbox->kind->nr_sandboxes--;
		sandbox->kind = NULL;
	}
	mutex_unlock(&registry_lock);
}

static void sandbox_cleanup_resources(struct sandbox *sandbox)
{
	image_stop(sandbox);
	spaces_destroy(sandbox);
	grant_destroy(sandbox);
	sandbox_unpublish(sandbox);

	if (sandbox->counted_live) {
		sandbox->counted_live = false;
		atomic64_dec(&endo_live_sandboxes);
	}
	if (sandbox->cgrp) {
		cgroup_put(sandbox->cgrp);
		sandbox->cgrp = NULL;
	}
	if (sandbox->owner) {
		put_task_struct(sandbox->owner);
		sandbox->owner = NULL;
	}
}

static void cleanup_work(struct work_struct *work)
{
	struct sandbox *sandbox = container_of(work, struct sandbox, cleanup_work);

	// A claimed but not yet attached vCPU may still be leaving `exec`.
	// Startup rechecks `dying` under this mutex before touching resources.
	mutex_lock(&sandbox->mutex);
	sandbox_cleanup_resources(sandbox);
	mutex_unlock(&sandbox->mutex);
	smp_store_release(&sandbox->exited, true);
	wake_up_all(&sandbox->arrive_wq);
	wake_up_all(&sandbox->exit_wq);
	sandbox_put(sandbox);
}

bool sandbox_claim_cleanup_locked(struct sandbox *sandbox)
{
	lockdep_assert_held(&sandbox->lock);
	if (!sandbox->dying || sandbox->exit_claimed ||
	    atomic_read(&sandbox->nr_carriers) != 0)
		return false;
	sandbox->exit_claimed = true;
	sandbox_get(sandbox);
	if (sandbox->sweep_armed) {
		sandbox->sweep_armed = false;
		atomic_dec(&evicting_sandboxes);
	}
	return true;
}

void sandbox_stop(struct sandbox *sandbox, u32 kind, u32 code, const char *msg)
{
	unsigned long flags;
	bool first_mark, claim = false;
	char tail[256];
	bool has_tail = false;

	spin_lock_irqsave(&sandbox->con_lock, flags);
	if (sandbox->con_len > 0) {
		size_t len = min_t(size_t, sandbox->con_len, sizeof(tail) - 1);

		memcpy(tail, sandbox->con_buf, len);
		tail[len] = '\0';
		sandbox->con_len = 0;
		has_tail = true;
	}
	spin_unlock_irqrestore(&sandbox->con_lock, flags);
	if (has_tail)
		printk(KERN_INFO "%s\n", tail);

	spin_lock_irqsave(&sandbox->lock, flags);
	if (!sandbox->dying) {
		sandbox->exit_kind = kind;
		sandbox->exit_code = code;
		strscpy(sandbox->exit_msg, msg ? msg : "", sizeof(sandbox->exit_msg));
	}
	first_mark = !sandbox->dying;
	WRITE_ONCE(sandbox->dying, true);
	claim = sandbox_claim_cleanup_locked(sandbox);
	spin_unlock_irqrestore(&sandbox->lock, flags);

	if (first_mark) {
		kill_carriers(sandbox);
		evict_arm(sandbox);
	}
	if (claim)
		queue_work(cleanup_wq, &sandbox->cleanup_work);
}

// ------------------------------------------------------------------
// Carrier lifeline anon inode
// ------------------------------------------------------------------

static int lifeline_release(struct inode *inode, struct file *file)
{
	struct carrier *c = file->private_data;

	if (c)
		carrier_lifeline_closed(c);
	return 0;
}

static const struct file_operations lifeline_fops = {
	.owner = THIS_MODULE,
	.release = lifeline_release,
};

struct file *lifeline_create(struct carrier *c)
{
	return anon_inode_getfile("[carrier]", &lifeline_fops, c, O_RDONLY);
}

// ------------------------------------------------------------------
// Carrier setup helpers shared by `execveat` and `SANDBOX_ATTACH_VCPU`
// ------------------------------------------------------------------

static void clear_carrier_mappings(void)
{
	struct mm_struct *mm = current->mm;
	unsigned long start[16], len[16];
	struct vm_area_struct *vma;
	int n = 0, i;

	VMA_ITERATOR(vmi, mm, 0);

	mmap_read_lock(mm);
	for_each_vma(vmi, vma) {
		if (n == ARRAY_SIZE(start))
			break;
		start[n] = vma->vm_start;
		len[n] = vma->vm_end - vma->vm_start;
		n++;
	}
	mmap_read_unlock(mm);

	for (i = 0; i < n; i++)
		vm_munmap(start[i], len[i]);
}

static void set_carrier_personality(void)
{
	clear_thread_flag(TIF_ADDR32);
	current_thread_info()->status &= ~TS_COMPAT;
	current->personality &= ~READ_IMPLIES_EXEC;
}

static void ignore_carrier_signals(void)
{
	sigset_t none;
	int sig;

	sigemptyset(&none);
	sigprocmask(SIG_SETMASK, &none, NULL);
	for (sig = 1; sig <= _NSIG; sig++)
		if (!sig_kernel_only(sig))
			kernel_sigaction(sig, SIG_IGN);
}

int sandbox_start(struct sandbox *sandbox)
{
	unsigned int i;

	if (!current->mm || !sandbox->boot_page)
		return -EINVAL;

	for (i = 0; i < KERNEL_HALF_ENTRIES; i++)
		sandbox->boot_page->kernel_half_entries[i] =
			pgd_val(current->mm->pgd[KERNEL_HALF_START + i]);
	wmb();
	return 0;
}

static int carrier_mark_arrived(struct sandbox *sandbox, struct carrier *c,
				    unsigned int vcpu)
{
	unsigned long flags;
	int err;

	lockdep_assert_held(&sandbox->mutex);
	if (!sandbox->started) {
		err = sandbox_start(sandbox);
		if (err)
			return err;
	}
	sandbox->boot_page->vcpu_host_cpu[vcpu] = (u16)task_cpu(current);

	spin_lock_irqsave(&sandbox->lock, flags);
	if (sandbox->dying) {
		spin_unlock_irqrestore(&sandbox->lock, flags);
		return -ESRCH;
	}
	sandbox->started = true;
	sandbox->vcpus[vcpu] = c;
	sandbox->vslot[vcpu].pid = current->pid;
	sandbox->arrived++;
	spin_unlock_irqrestore(&sandbox->lock, flags);
	wake_up_all(&sandbox->arrive_wq);
	set_thread_flag(TIF_NOTIFY_RESUME);
	return 0;
}

// ------------------------------------------------------------------
// Exec descriptors & `linux_binfmt` (`SANDBOX_GET_VCPU_FD`)
// ------------------------------------------------------------------

static struct file *exec_file_make(struct sandbox *sandbox, unsigned int vcpu)
{
	struct exec_header head = {
		.slot = (u16)sandbox->slot,
		.vcpu = vcpu,
	};
	struct inode *inode;
	struct file *file;
	loff_t pos = 0;
	ssize_t n;

	memcpy(head.magic, EXEC_MAGIC, EXEC_MAGIC_LEN);
	file = shmem_file_setup("kernelet-exec", PAGE_SIZE, 0);
	if (IS_ERR(file))
		return file;
	n = kernel_write(file, &head, sizeof(head), &pos);
	if (n != sizeof(head)) {
		fput(file);
		return ERR_PTR(n < 0 ? n : -EIO);
	}
	inode = file_inode(file);
	inode_lock(inode);
	inode->i_uid = GLOBAL_ROOT_UID;
	inode->i_gid = GLOBAL_ROOT_GID;
	inode->i_mode = S_IFREG | 0111;
	inode_unlock(inode);
	return file;
}

struct sandbox *exec_lookup(struct linux_binprm *bprm, unsigned int *vcpu)
{
	const struct exec_header *head = (const void *)bprm->buf;
	struct sandbox *sandbox = NULL;
	struct file *exec_file;

	if (head->slot >= MAX_SANDBOXES)
		return NULL;
	mutex_lock(&registry_lock);
	sandbox = sandboxes[head->slot];
	if (sandbox && head->vcpu < sandbox->nr_vcpus) {
		exec_file = READ_ONCE(sandbox->vslot[head->vcpu].exec_file);
		if (exec_file && file_inode(exec_file) == file_inode(bprm->file)) {
			sandbox_get(sandbox);
			*vcpu = head->vcpu;
		} else {
			sandbox = NULL;
		}
	} else {
		sandbox = NULL;
	}
	mutex_unlock(&registry_lock);
	return sandbox;
}

int exec_claim(struct sandbox *sandbox, unsigned int vcpu)
{
	unsigned long flags;
	int err = 0;

	if (vcpu >= sandbox->nr_vcpus)
		return -EINVAL;

	spin_lock_irqsave(&sandbox->lock, flags);
	if (sandbox->dying)
		err = -ESRCH;
	else if (sandbox->vslot[vcpu].claimed)
		err = -EBUSY;
	else
		sandbox->vslot[vcpu].claimed = true;
	spin_unlock_irqrestore(&sandbox->lock, flags);
	return err;
}

void exec_unclaim(struct sandbox *sandbox, unsigned int vcpu)
{
	unsigned long flags;

	if (vcpu >= sandbox->nr_vcpus)
		return;
	spin_lock_irqsave(&sandbox->lock, flags);
	sandbox->vslot[vcpu].claimed = false;
	spin_unlock_irqrestore(&sandbox->lock, flags);
}

static int load_carrier_binary(struct linux_binprm *bprm)
{
	struct sandbox *sandbox;
	struct carrier *c;
	char comm[TASK_COMM_LEN];
	unsigned int vcpu;
	int err;

	if (memcmp(bprm->buf, EXEC_MAGIC, EXEC_MAGIC_LEN) != 0)
		return -ENOEXEC;

	sandbox = exec_lookup(bprm, &vcpu);
	if (!sandbox)
		return -ENOEXEC;

	err = exec_claim(sandbox, vcpu);
	if (err)
		goto out;

	err = begin_new_exec(bprm);
	if (err) {
		exec_unclaim(sandbox, vcpu);
		goto out;
	}

	// `begin_new_exec` may wait for old threads using this sandbox's mutex.
	// Recheck after it finishes, before accessing any reclaimable resources.
	mutex_lock(&sandbox->mutex);
	if (READ_ONCE(sandbox->dying)) {
		err = -ESRCH;
		exec_unclaim(sandbox, vcpu);
		goto kill;
	}

	set_carrier_personality();
	setup_new_exec(bprm);
	clear_carrier_mappings();
	set_binfmt(&carrier_format);
	finalize_exec(bprm);
	start_thread(task_pt_regs(current), 0, 0);
	ignore_carrier_signals();
	set_mask_bits(&current->mm->flags, MMF_DUMPABLE_MASK, SUID_DUMP_DISABLE);

	snprintf(comm, sizeof(comm), "kernelet/%u/%u",
		 (u32)sandbox->slot & 0xfU, vcpu & 0x3fU);
	task_lock(current);
	strscpy_pad(current->comm, comm, sizeof(current->comm));
	task_unlock(current);

	c = carrier_new(sandbox, vcpu, NULL);
	if (!c) {
		err = READ_ONCE(sandbox->dying) ? -ESRCH : -ENOMEM;
		goto kill;
	}
	err = carrier_attach(c);
	if (err) {
		carrier_lifeline_closed(c);
		goto kill;
	}
	mmget(current->mm);
	c->own_mm = current->mm;

	err = carrier_mark_arrived(sandbox, c, vcpu);
	if (err) {
		sandbox_stop(sandbox, STOP_KILLED, SIGKILL, "carrier startup failed");
		goto kill;
	}
	mutex_unlock(&sandbox->mutex);
	sandbox_put(sandbox);
	return 0;

kill:
	mutex_unlock(&sandbox->mutex);
	force_sig(SIGKILL);
out:
	sandbox_put(sandbox);
	return err;
}

static struct linux_binfmt carrier_format = {
	.module = THIS_MODULE,
	.load_binary = load_carrier_binary,
};

// ------------------------------------------------------------------
// Sandbox file descriptor operations
// ------------------------------------------------------------------

static long get_vcpu_exec_fd(struct sandbox *sandbox, u32 __user *uarg)
{
	struct file *file;
	unsigned long flags;
	u32 vcpu;
	long err = 0;
	int fd;

	if (get_user(vcpu, uarg))
		return -EFAULT;
	if (vcpu >= sandbox->nr_vcpus)
		return -EINVAL;

	mutex_lock(&sandbox->mutex);
	spin_lock_irqsave(&sandbox->lock, flags);
	if (sandbox->dying)
		err = -ESRCH;
	else if (sandbox->vslot[vcpu].claimed)
		err = -EBUSY;
	spin_unlock_irqrestore(&sandbox->lock, flags);
	if (err)
		goto out;

	file = sandbox->vslot[vcpu].exec_file;
	if (!file) {
		file = exec_file_make(sandbox, vcpu);
		if (IS_ERR(file)) {
			err = PTR_ERR(file);
			goto out;
		}
		WRITE_ONCE(sandbox->vslot[vcpu].exec_file, file);
	}
	file = dentry_open(&file->f_path, O_PATH, current_cred());
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto out;
	}
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		fput(file);
		err = fd;
		goto out;
	}
	fd_install(fd, file);
	err = fd;
out:
	mutex_unlock(&sandbox->mutex);
	return err;
}

static long attach_vcpu(struct sandbox *sandbox, u32 __user *uarg)
{
	struct mm_struct *own_mm, *old_mm;
	struct carrier *c;
	char comm[TASK_COMM_LEN];
	u32 vcpu;
	int err;

	if (get_user(vcpu, uarg))
		return -EFAULT;
	if (vcpu >= sandbox->nr_vcpus)
		return -EINVAL;
	mutex_lock(&sandbox->mutex);
	if (READ_ONCE(sandbox->dying)) {
		err = -ESRCH;
		goto out;
	}
	err = -EINVAL;
	if (!thread_group_empty(current))
		goto out;
	// Only carrier exit may close its lifeline.
	// A task sharing `files` could close it while the carrier still runs.
	if (atomic_read(&current->files->count) != 1)
		goto out;
	// Carrier signal dispositions must not change another task's handlers.
	if (refcount_read(&current->sighand->count) != 1)
		goto out;
	if (current->carrier_hooks) {
		err = -EBUSY;
		goto out;
	}

	err = exec_claim(sandbox, vcpu);
	if (err)
		goto out;

	own_mm = kernelet_mm_alloc(sandbox->owner);
	if (!own_mm) {
		exec_unclaim(sandbox, vcpu);
		err = -ENOMEM;
		goto out;
	}
#ifdef CONFIG_MEMCG
	// `own_mm` is an empty kernel-root placeholder; clear `mm->owner` up
	// front so deferred `mmput_async` never outlives `sandbox->owner`.
	WRITE_ONCE(own_mm->owner, NULL);
#endif

	c = carrier_new(sandbox, vcpu, NULL);
	if (!c) {
		mmput(own_mm);
		exec_unclaim(sandbox, vcpu);
		err = READ_ONCE(sandbox->dying) ? -ESRCH : -ENOMEM;
		goto out;
	}
	err = carrier_attach(c);
	if (err) {
		mmput(own_mm);
		carrier_lifeline_closed(c);
		exec_unclaim(sandbox, vcpu);
		goto out;
	}

	// Hold one `mm_users` reference for `current->mm` and one for `c->own_mm`.
	mmget(own_mm);
	set_mask_bits(&own_mm->flags, MMF_DUMPABLE_MASK, SUID_DUMP_DISABLE);
	c->own_mm = own_mm;

	// No recoverable operation follows: old userspace registrations are released.
	old_mm = kernelet_attach_mm(own_mm);
	if (old_mm)
		mmput(old_mm);

	set_carrier_personality();
	start_thread(task_pt_regs(current), 0, 0);
	ignore_carrier_signals();

	snprintf(comm, sizeof(comm), "kernelet/%u/%u",
		 (u32)sandbox->slot & 0xfU, vcpu & 0x3fU);
	task_lock(current);
	strscpy_pad(current->comm, comm, sizeof(current->comm));
	task_unlock(current);

	err = carrier_mark_arrived(sandbox, c, vcpu);
	if (err) {
		sandbox_stop(sandbox, STOP_KILLED, SIGKILL, "carrier startup failed");
		force_sig(SIGKILL);
	}
out:
	mutex_unlock(&sandbox->mutex);
	return err;
}

static void fill_stats(struct sandbox *sandbox, struct sandbox_stats *st)
{
	unsigned long flags;
	struct carrier *c;
	u64 live_syscalls = 0;

	memset(st, 0, sizeof(*st));
	spin_lock_irqsave(&sandbox->lock, flags);
	st->exit_kind = sandbox->exit_kind;
	st->exit_code = sandbox->exit_code;
	strscpy(st->exit_msg, sandbox->exit_msg, sizeof(st->exit_msg));
	list_for_each_entry(c, &sandbox->carriers, link)
		live_syscalls += READ_ONCE(c->syscalls);
	st->image_load_base = (u64)(unsigned long)sandbox->image_base;
	spin_unlock_irqrestore(&sandbox->lock, flags);

	st->fpu_saves = atomic64_read(&sandbox->stats.fpu_saves);
	st->fpu_restores = atomic64_read(&sandbox->stats.fpu_restores);
	st->vm_creates = atomic64_read(&sandbox->stats.vm_creates);
	st->vm_destroys = atomic64_read(&sandbox->stats.vm_destroys);
	st->vm_flushes = atomic64_read(&sandbox->stats.vm_flushes);
	st->vm_maps = atomic64_read(&sandbox->stats.vm_maps);
	st->vm_protects = atomic64_read(&sandbox->stats.vm_protects);
	st->vm_unmaps = atomic64_read(&sandbox->stats.vm_unmaps);
	st->exceptions = atomic64_read(&sandbox->stats.exceptions);
	st->page_faults = atomic64_read(&sandbox->stats.page_faults);
	st->virqs = atomic64_read(&sandbox->stats.virqs);
	st->forced_yields = atomic64_read(&sandbox->stats.forced_yields);
	st->non_sysret = audit_enabled ? atomic64_read(&sandbox->stats.non_sysret) : U64_MAX;
	st->syscalls = audit_enabled ?
		(u64)atomic64_read(&sandbox->stats.syscalls) + live_syscalls : U64_MAX;
	st->grant_grains_allocated = READ_ONCE(sandbox->grant_grains_allocated);
	st->grant_grains_freed = READ_ONCE(sandbox->grant_grains_freed);
}

static long sandbox_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct sandbox *sandbox = file->private_data;
	struct sandbox_stats st;

	switch (cmd) {
	case SANDBOX_GET_VCPU_FD:
		return get_vcpu_exec_fd(sandbox, (u32 __user *)arg);
	case SANDBOX_ATTACH_VCPU:
		return attach_vcpu(sandbox, (u32 __user *)arg);
	case SANDBOX_STATS:
		fill_stats(sandbox, &st);
		if (copy_to_user((void __user *)arg, &st, sizeof(st)))
			return -EFAULT;
		return 0;
	case SANDBOX_KILL:
		sandbox_stop(sandbox, STOP_KILLED, SIGKILL, "killed by holder");
		return 0;
	case SANDBOX_PROF_DUMP: {
		struct sandbox_prof_dump req;
		struct sandbox_prof_sample *copy = NULL;
		u32 to_copy = 0, total = 0;
		u64 dropped = 0;
		unsigned long flags;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		if (req.capacity > 0 && !req.buf_ptr)
			return -EINVAL;

		spin_lock_irqsave(&sandbox->prof_lock, flags);
		total = sandbox->prof_count;
		dropped = sandbox->prof_dropped;
		to_copy = req.capacity ? min(req.capacity, total) : 0;
		spin_unlock_irqrestore(&sandbox->prof_lock, flags);

		if (to_copy > 0 && sandbox->prof_samples) {
			size_t bytes = (size_t)to_copy * sizeof(*copy);

			copy = kvzalloc(bytes, GFP_KERNEL);
			if (!copy)
				return -ENOMEM;
			spin_lock_irqsave(&sandbox->prof_lock, flags);
			to_copy = min(to_copy, sandbox->prof_count);
			memcpy(copy, sandbox->prof_samples,
			       (size_t)to_copy * sizeof(*copy));
			spin_unlock_irqrestore(&sandbox->prof_lock, flags);
			if (copy_to_user(u64_to_user_ptr(req.buf_ptr), copy,
					 (size_t)to_copy * sizeof(*copy))) {
				kvfree(copy);
				return -EFAULT;
			}
			kvfree(copy);
		}
		req.count = req.capacity ? to_copy : total;
		req.dropped = dropped;
		if (copy_to_user((void __user *)arg, &req, sizeof(req)))
			return -EFAULT;
		return 0;
	}
	default:
		return -ENOTTY;
	}
}

static ssize_t sandbox_read(struct file *file, char __user *ubuf,
				size_t len, loff_t *ppos)
{
	struct sandbox *sandbox = file->private_data;
	struct sandbox_stats st;
	int err;

	if (len < sizeof(st))
		return -EINVAL;
	if (!smp_load_acquire(&sandbox->exited)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		err = wait_event_interruptible(sandbox->exit_wq,
					       smp_load_acquire(&sandbox->exited));
		if (err)
			return err;
	}
	fill_stats(sandbox, &st);
	if (copy_to_user(ubuf, &st, sizeof(st)))
		return -EFAULT;
	return sizeof(st);
}

static __poll_t sandbox_poll(struct file *file, poll_table *wait)
{
	struct sandbox *sandbox = file->private_data;

	poll_wait(file, &sandbox->exit_wq, wait);
	return smp_load_acquire(&sandbox->exited) ? (EPOLLIN | EPOLLRDNORM | EPOLLHUP) : 0;
}

static int sandbox_release(struct inode *inode, struct file *file)
{
	struct sandbox *sandbox = file->private_data;

	if (!sandbox)
		return 0;

	sandbox_stop(sandbox, STOP_KILLED, SIGKILL, "descriptor closed");
	sandbox_put(sandbox);
	return 0;
}

static const struct file_operations sandbox_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = sandbox_ioctl,
	.read = sandbox_read,
	.poll = sandbox_poll,
	.release = sandbox_release,
};

// ------------------------------------------------------------------
// Device ioctls (`/dev/endovisor`)
// ------------------------------------------------------------------

static long dev_kind_register(struct kind_register __user *uarg)
{
	struct kind_register reg;
	struct image_kind *kind;
	void *elf = NULL;
	int i, err;

	if (!capable(CAP_SYS_MODULE) || READ_ONCE(modules_disabled))
		return -EPERM;
	if (is_module_sig_enforced())
		return -EKEYREJECTED;
	err = security_locked_down(LOCKDOWN_MODULE_SIGNATURE);
	if (err)
		return err;

	if (copy_from_user(&reg, uarg, sizeof(reg)))
		return -EFAULT;
	if (reg.flags != 0 || reg.elf_len == 0 || reg.elf_len > IMAGE_MAX)
		return -EINVAL;

	err = security_kernel_load_data(LOADING_MODULE, true);
	if (err)
		return err;
	elf = vmalloc(reg.elf_len);
	if (!elf)
		return -ENOMEM;
	if (copy_from_user(elf, u64_to_user_ptr(reg.elf_ptr), reg.elf_len)) {
		vfree(elf);
		return -EFAULT;
	}
	err = security_kernel_post_load_data(elf, reg.elf_len, LOADING_MODULE,
					     "kernelet image");
	if (err) {
		vfree(elf);
		return err;
	}

	kind = kzalloc(sizeof(*kind), GFP_KERNEL);
	if (!kind) {
		vfree(elf);
		return -ENOMEM;
	}

	err = image_load(kind, elf, reg.elf_len);
	vfree(elf);
	if (err) {
		kfree(kind);
		return err;
	}

	err = -ENOSPC;
	mutex_lock(&registry_lock);
	for (i = 0; i < MAX_KINDS; i++) {
		if (image_kinds[i].used)
			continue;
		if (put_user((u32)i, &uarg->kind_id)) {
			err = -EFAULT;
			break;
		}
		image_kinds[i] = *kind;
		image_kinds[i].used = true;
		err = 0;
		break;
	}
	mutex_unlock(&registry_lock);
	if (err)
		image_free(kind);
	kfree(kind);
	return err;
}

static long dev_kind_unregister(u32 __user *uarg)
{
	u32 id;
	int err = 0;

	if (!capable(CAP_SYS_MODULE) || READ_ONCE(modules_disabled))
		return -EPERM;

	if (get_user(id, uarg))
		return -EFAULT;
	if (id >= MAX_KINDS)
		return -EINVAL;

	mutex_lock(&registry_lock);
	if (!image_kinds[id].used)
		err = -ENOENT;
	else if (image_kinds[id].nr_sandboxes != 0)
		err = -EBUSY;
	else
		image_free(&image_kinds[id]);
	mutex_unlock(&registry_lock);
	return err;
}

static long dev_sandbox_create(struct sandbox_create __user *uarg)
{
	struct sandbox_create cr;
	struct sandbox *sandbox = NULL;
	struct image_kind *kind = NULL;
	struct cgroup *cgrp = NULL;
	char *cmdline = NULL;
	int slot = -1, fd, err;

	if (copy_from_user(&cr, uarg, sizeof(cr)))
		return -EFAULT;

	if (cr.flags != 0 ||
	    cr.nr_vcpus == 0 || cr.nr_vcpus > MAX_VCPUS ||
	    cr.grant_mb > MAX_GRANT_MB ||
	    cr.pt_mode > PT_MODE_VMA ||
	    cr.cmdline_len > CMDLINE_MAX ||
	    cr.initramfs_len > INITRAMFS_MAX)
		return -EINVAL;

	if (cr.cmdline_len > 0) {
		cmdline = kmalloc(cr.cmdline_len + 1, GFP_KERNEL);
		if (!cmdline)
			return -ENOMEM;
		if (copy_from_user(cmdline, u64_to_user_ptr(cr.cmdline_ptr),
				   cr.cmdline_len)) {
			kfree(cmdline);
			return -EFAULT;
		}
		cmdline[cr.cmdline_len] = '\0';
	}

	rcu_read_lock();
	cgrp = task_dfl_cgroup(current);
	if (cgrp)
		cgroup_get(cgrp);
	rcu_read_unlock();

	sandbox = kvzalloc(sizeof(*sandbox), GFP_KERNEL);
	if (!sandbox) {
		if (cgrp)
			cgroup_put(cgrp);
		kfree(cmdline);
		return -ENOMEM;
	}

	refcount_set(&sandbox->refs, 1);
	INIT_WORK(&sandbox->cleanup_work, cleanup_work);
	sandbox->slot = -1;
	sandbox->generation = (u32)atomic_inc_return(&generation_seq);
	mutex_init(&sandbox->mutex);
	spin_lock_init(&sandbox->lock);
	spin_lock_init(&sandbox->con_lock);
	spin_lock_init(&sandbox->prof_lock);
	sandbox->con_len = 0;
	if (static_branch_unlikely(&endovisor_profile_key)) {
		sandbox->prof_cap = 8192;
		sandbox->prof_samples = kvcalloc(sandbox->prof_cap,
						 sizeof(*sandbox->prof_samples),
						 GFP_KERNEL);
		if (!sandbox->prof_samples) {
			if (cgrp)
				cgroup_put(cgrp);
			kfree(cmdline);
			kvfree(sandbox);
			return -ENOMEM;
		}
	}
	sandbox->counted_live = true;
	atomic64_inc(&endo_live_sandboxes);
	init_waitqueue_head(&sandbox->arrive_wq);
	init_waitqueue_head(&sandbox->exit_wq);
	INIT_LIST_HEAD(&sandbox->carriers);
	sandbox->nr_vcpus = cr.nr_vcpus;
	sandbox->grant_mb = cr.grant_mb ? cr.grant_mb : 64;
	sandbox->max_tasks = cr.max_tasks ? cr.max_tasks : DEFAULT_MAX_TASKS;
	sandbox->pt_mode = cr.pt_mode;
	sandbox->cmdline = cmdline;
	sandbox->cmdline_len = cr.cmdline_len;
	sandbox->cgrp = cgrp;
	sandbox->owner = get_task_struct(current->group_leader);
	spaces_init(sandbox);

	mutex_lock(&registry_lock);
	if (cr.kind_id >= MAX_KINDS || !image_kinds[cr.kind_id].used) {
		err = -ENOENT;
	} else {
		err = -ENOSPC;
		for (slot = 0; slot < MAX_SANDBOXES; slot++) {
			if (!sandboxes[slot]) {
				kind = &image_kinds[cr.kind_id];
				kind->nr_sandboxes++;
				sandbox->kind = kind;
				sandbox->slot = slot;
				sandboxes[slot] = sandbox;
				err = 0;
				break;
			}
		}
	}
	mutex_unlock(&registry_lock);
	if (err)
		goto fail_resources;

	err = image_start(sandbox);
	if (err)
		goto fail_resources;

	err = grant_init(sandbox, u64_to_user_ptr(cr.initramfs_ptr),
			     cr.initramfs_len);
	if (err)
		goto fail_resources;

	err = sandbox_start(sandbox);
	if (err)
		goto fail_resources;

	fd = anon_inode_getfd("[kernelet]", &sandbox_fops, sandbox,
			      O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		err = fd;
		goto fail_resources;
	}
	return fd;

fail_resources:
	sandbox_cleanup_resources(sandbox);
	sandbox_put(sandbox);
	return err;
}

static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case KIND_REGISTER:
		return dev_kind_register((struct kind_register __user *)arg);
	case SANDBOX_CREATE:
		return dev_sandbox_create((struct sandbox_create __user *)arg);
	case KIND_UNREGISTER:
		return dev_kind_unregister((u32 __user *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations dev_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = dev_ioctl,
};

static ssize_t grant_accounting_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	return sysfs_emit(buf,
			  "live_sandboxes=%lld live_grant_grains=%lld live_meta_pages=%lld live_kstack_pages=%lld live_shared_pages=%lld\n",
			  (long long)atomic64_read(&endo_live_sandboxes),
			  (long long)atomic64_read(&endo_live_grains),
			  (long long)atomic64_read(&endo_live_meta_pages),
			  (long long)atomic64_read(&endo_live_kstack_pages),
			  (long long)atomic64_read(&endo_live_shared_pages));
}
static DEVICE_ATTR_RO(grant_accounting);

static struct attribute *endovisor_attrs[] = {
	&dev_attr_grant_accounting.attr,
	NULL,
};
ATTRIBUTE_GROUPS(endovisor);

static struct miscdevice endovisor_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "endovisor",
	.fops = &dev_fops,
	.groups = endovisor_groups,
	.mode = 0666,
};

// ------------------------------------------------------------------
// Module initialization & exit
// ------------------------------------------------------------------

static int verify_cpu_slot(void)
{
	struct kernelet_cpu_slot saved;
	struct kernelet_cpu_slot *slot_ptr;
	u64 probe = ((u64)0xdeadbeefU << 32) | ((u64)0x1234U << 16) | 0x5678U;
	u64 observed = 0;
	u32 off = kernelet_cpu_slot_gs_offset();

	preempt_disable();
	slot_ptr = this_cpu_ptr(&kernelet_cpu_slot);
	saved = *slot_ptr;
	*(u64 *)slot_ptr = probe;
	barrier();
	asm volatile("movq %%gs:(%1), %0"
		     : "=r"(observed)
		     : "r"((u64)off)
		     : "memory");
	*slot_ptr = saved;
	preempt_enable();

	if (observed != probe) {
		pr_err("endovisor: kernelet_cpu_slot %%gs offset %#x mismatch (wrote %#llx, read %#llx)\n",
		       off, probe, observed);
		return -EINVAL;
	}
	cpu_slot_offset = off;
	return 0;
}

static int __init endovisor_init(void)
{
	int err;

	BUILD_BUG_ON(sizeof(struct entry_table) != ENTRY_TABLE_SIZE);
	BUILD_BUG_ON(sizeof(struct boot_args) != 2352);
	BUILD_BUG_ON(sizeof(struct service_table) != 160);
	BUILD_BUG_ON(offsetof(struct service_table, stop) != 144);
	BUILD_BUG_ON(sizeof(struct vcpu_record) != 128);
	BUILD_BUG_ON(sizeof(struct copy_fault_record) != 64);
	BUILD_BUG_ON(sizeof(struct user_event_record) != 64);

	if (IS_ENABLED(CONFIG_X86_VSYSCALL_EMULATION)) {
		pr_err("endovisor: CONFIG_X86_VSYSCALL_EMULATION must be disabled\n");
		return -ENODEV;
	}

	err = verify_cpu_slot();
	if (err)
		return err;

	cleanup_wq = alloc_workqueue("endovisor", WQ_UNBOUND, 0);
	if (!cleanup_wq)
		return -ENOMEM;

	err = carrier_sched_init();
	if (err)
		goto err_wq;

	err = watch_init();
	if (err)
		goto err_sched;

	err = evict_init();
	if (err)
		goto err_watch;

	register_binfmt(&carrier_format);

	if (audit_enabled)
		static_branch_enable(&endovisor_audit_key);
	if (profile_hz > 0)
		static_branch_enable(&endovisor_profile_key);

	err = misc_register(&endovisor_device);
	if (err)
		goto err_binfmt;

	pr_info("endovisor: loaded (cpu_slot gs_offset=%#x, watch=%d, audit=%d, profile_hz=%d)\n",
		cpu_slot_offset, watch_enabled, audit_enabled, profile_hz);
	return 0;

err_binfmt:
	unregister_binfmt(&carrier_format);
	evict_exit();
err_watch:
	watch_exit();
err_sched:
	carrier_sched_exit();
err_wq:
	destroy_workqueue(cleanup_wq);
	return err;
}

static void __exit endovisor_exit(void)
{
	int i;

	misc_deregister(&endovisor_device);
	unregister_binfmt(&carrier_format);
	evict_exit();
	watch_exit();
	carrier_sched_exit();
	flush_workqueue(cleanup_wq);
	destroy_workqueue(cleanup_wq);

	mutex_lock(&registry_lock);
	for (i = 0; i < MAX_KINDS; i++) {
		if (image_kinds[i].used)
			image_free(&image_kinds[i]);
	}
	mutex_unlock(&registry_lock);

	pr_info("endovisor: unloaded\n");
}

module_init(endovisor_init);
module_exit(endovisor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kernelet contributors");
MODULE_DESCRIPTION("Asterinas-on-Linux endovisor");
