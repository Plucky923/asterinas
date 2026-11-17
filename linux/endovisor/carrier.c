// SPDX-License-Identifier: GPL-2.0
// vCPU carriers, PR #3 non-returning event hooks, PR #7 FPU lifecycle,
// and the `host_services` ABI table for `endovisor`.

#include <linux/compat.h>
#include <linux/entry-common.h>
#include <linux/file.h>
#include <linux/freezer.h>
#include <linux/hrtimer.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kernelet.h>
#include <linux/math64.h>
#include <linux/mm.h>
#include <linux/preempt.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/thread_info.h>
#include <linux/uaccess.h>

#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/segment.h>
#include <asm/trapnr.h>
#include <asm/tsc.h>

#include "endovisor.h"

#define RFLAGS_USER \
	(X86_EFLAGS_CF | X86_EFLAGS_PF | X86_EFLAGS_AF | X86_EFLAGS_ZF | \
	 X86_EFLAGS_SF | X86_EFLAGS_TF | X86_EFLAGS_DF | X86_EFLAGS_OF | \
	 X86_EFLAGS_AC | X86_EFLAGS_ID)

static inline void restore_carrier_fpu(struct carrier *c)
{
	if (unlikely(test_thread_flag(TIF_NEED_FPU_LOAD))) {
		atomic64_inc(&c->sandbox->stats.fpu_restores);
		kernelet_fpu_restore_carrier();
	}
}

static inline void write_cpu_slot(u16 kernelet, u16 vcpu, u32 generation)
{
	struct kernelet_cpu_slot *slot_ptr = this_cpu_ptr(&kernelet_cpu_slot);
	u64 packed = (u64)kernelet | ((u64)vcpu << 16) | ((u64)generation << 32);

	WRITE_ONCE(*(u64 *)slot_ptr, packed);
	WRITE_ONCE(slot_ptr->_reserved, 0);
}

void cpu_slot_set_current(struct carrier *c)
{
	unsigned long flags;

	local_irq_save(flags);
	write_cpu_slot((u16)c->sandbox->slot, (u16)c->vcpu, c->sandbox->generation);
	local_irq_restore(flags);
}

void cpu_slot_clear_current(void)
{
	unsigned long flags;

	local_irq_save(flags);
	write_cpu_slot(U16_MAX, U16_MAX, 0);
	local_irq_restore(flags);
}

// ------------------------------------------------------------------
// Carrier lifecycle
// ------------------------------------------------------------------

struct carrier *carrier_get(struct carrier *c)
{
	refcount_inc(&c->refs);
	return c;
}

void carrier_put(struct carrier *c)
{
	struct sandbox *sandbox = c->sandbox;

	if (!refcount_dec_and_test(&c->refs))
		return;
	if (c->task)
		put_task_struct(c->task);
	kfree(c);
	sandbox_put(sandbox);
}

struct carrier *carrier_new(struct sandbox *sandbox, unsigned int vcpu,
				    struct mm_struct *own_mm)
{
	struct carrier *c;
	u8 *shared_records;
	u64 boot_stack;

	lockdep_assert_held(&sandbox->mutex);
	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		return NULL;

	c->hooks = carrier_hooks;
	c->sandbox = sandbox;
	c->vcpu = vcpu;
	c->state = CARRIER_NEW;
	c->own_mm = own_mm;
	refcount_set(&c->refs, 1);
	INIT_LIST_HEAD(&c->link);
	init_waitqueue_head(&c->idle_wq);

	shared_records = (u8 *)sandbox->shared_vmap + PAGE_SIZE;
	c->vrec = (struct vcpu_record *)(shared_records +
		vcpu * sizeof(struct vcpu_record));
	c->cfrec = (struct copy_fault_record *)(shared_records +
		sandbox->nr_vcpus * sizeof(struct vcpu_record) +
		vcpu * sizeof(struct copy_fault_record));
	c->urec = (struct user_event_record *)(shared_records +
		sandbox->nr_vcpus * (sizeof(struct vcpu_record) +
				  sizeof(struct copy_fault_record)) +
		vcpu * sizeof(struct user_event_record));

	WRITE_ONCE(c->vrec->vcpu, vcpu);
	WRITE_ONCE(c->vrec->irq_off, 1);

	c->task = get_task_struct(current);
	spin_lock(&sandbox->lock);
	if (sandbox->dying) {
		spin_unlock(&sandbox->lock);
		put_task_struct(c->task);
		kfree(c);
		return NULL;
	}
	sandbox_get(sandbox);
	list_add_tail(&c->link, &sandbox->carriers);
	atomic_inc(&sandbox->nr_carriers);
	spin_unlock(&sandbox->lock);

	boot_stack = kstack_alloc(sandbox, true);
	if (!boot_stack) {
		carrier_lifeline_closed(c);
		return NULL;
	}
	c->boot_stack_base = boot_stack;
	WRITE_ONCE(c->vrec->stack_limit, boot_stack);
	return c;
}

int carrier_attach(struct carrier *c)
{
	struct file *file;
	int fd;

	file = lifeline_create(c);
	if (IS_ERR(file))
		return PTR_ERR(file);

	fd = get_unused_fd_flags(0);
	if (fd < 0) {
		file->private_data = NULL;
		fput(file);
		return fd;
	}
	fd_install(fd, file);

	WRITE_ONCE(current->carrier_hooks, &c->hooks);
	set_syscall_work(KERNELET);
	carrier_sched_attach(c);
	cpu_slot_set_current(c);
	return 0;
}

static void carrier_detach_hooks(struct carrier *c)
{
	if (READ_ONCE(current->carrier_hooks) != &c->hooks)
		return;
	clear_syscall_work(KERNELET);
	WRITE_ONCE(current->carrier_hooks, NULL);
	barrier();
	carrier_sched_detach(c);
	cpu_slot_clear_current();
	WRITE_ONCE(c->state, CARRIER_DEAD);
}

static void on_exit(void)
{
	struct carrier *c = current_carrier();

	if (c)
		carrier_detach_hooks(c);
}

static void carrier_detach(struct carrier *c)
{
	struct mm_struct *mm;

	carrier_detach_hooks(c);
	leave_space(c);

	mm = xchg(&c->own_mm, NULL);
	if (mm)
		mmput(mm);
}

void carrier_lifeline_closed(struct carrier *c)
{
	struct sandbox *sandbox = c->sandbox;
	struct vcpu_slot *vs = &sandbox->vslot[c->vcpu];
	struct mm_struct *mm;
	bool live, claim = false;

	// Linux calls `on_exit` before closing the private file table.
	// A copied lifeline may have its final `fput` on another task afterwards.
	if (c->task == current)
		carrier_detach_hooks(c);
	mm = xchg(&c->own_mm, NULL);
	if (mm)
		mmput(mm);

	spin_lock(&sandbox->lock);
	atomic64_add(READ_ONCE(c->syscalls), &sandbox->stats.syscalls);
	WRITE_ONCE(c->syscalls, 0);
	list_del_init(&c->link);
	if (sandbox->vcpus[c->vcpu] == c)
		sandbox->vcpus[c->vcpu] = NULL;
	if (vs->pid == c->task->pid)
		vs->pid = 0;
	live = !sandbox->dying;
	atomic_dec(&sandbox->nr_carriers);
	if (!live)
		claim = sandbox_claim_cleanup_locked(sandbox);
	spin_unlock(&sandbox->lock);

	if (live)
		sandbox_stop(sandbox, STOP_KILLED, SIGKILL, "carrier lost");
	else if (claim)
		queue_work(cleanup_wq, &sandbox->cleanup_work);
	carrier_put(c);
}

void __noreturn carrier_die(struct carrier *c)
{
	struct pt_regs *regs = c->user_regs ? c->user_regs : task_pt_regs(current);

	carrier_detach(c);
	if (!fatal_signal_pending(current))
		force_sig(SIGKILL);
	regs->cs = __USER_CS;
	regs->ss = __USER_DS;
	regs->flags = X86_EFLAGS_IF | X86_EFLAGS_FIXED;
	regs->orig_ax = -1;
	return_to_user(regs, false);
	BUG();
}

static void __noreturn evict_leave_on_linux(void *arg)
{
	struct carrier *c = arg;

	if (unlikely(c->df_overflow)) {
		struct sandbox *sandbox = c->sandbox;

		pr_err("klet[%d/%u]: kernel #DF stack overflow ip_off=0x%lx sp=0x%lx addr=0x%lx\n",
		       sandbox->slot, c->vcpu,
		       c->df_ip - (unsigned long)sandbox->image_base,
		       c->df_sp, c->df_addr);
		sandbox_stop(sandbox, STOP_STACK_OVERFLOW, X86_TRAP_DF,
			     "kernelet stack overflow");
	}
	carrier_die(c);
}

void __noreturn evict_leave(void)
{
	struct carrier *c = current_carrier();

	if (!c) {
		struct pt_regs *regs = task_pt_regs(current);

		if (!fatal_signal_pending(current))
			force_sig(SIGKILL);
		return_to_user(regs, false);
		BUG();
	}
	c->evicted = true;
	jump_linux_stack(c->linux_sp, evict_leave_on_linux, c);
	BUG();
}

void kill_carriers(struct sandbox *sandbox)
{
	struct carrier *c;

	spin_lock(&sandbox->lock);
	list_for_each_entry(c, &sandbox->carriers, link) {
		if (c->task)
			send_sig(SIGKILL, c->task, 1);
		wake_up_all(&c->idle_wq);
	}
	spin_unlock(&sandbox->lock);
	wake_up_all(&sandbox->arrive_wq);
}

// ------------------------------------------------------------------
// Preempt notifiers, vcpu_on_spin, and remote kick
// ------------------------------------------------------------------

static inline bool task_on_cpu(struct task_struct *t)
{
#ifdef CONFIG_SMP
	return READ_ONCE(t->on_cpu) != 0;
#else
	return t == current;
#endif
}

#ifdef CONFIG_PREEMPT_NOTIFIERS
static bool notifiers_up;

static void carrier_sched_in(struct preempt_notifier *pn, int cpu)
{
	struct carrier *c = container_of(pn, struct carrier, pnotifier);

	(void)cpu;
	write_cpu_slot((u16)c->sandbox->slot, (u16)c->vcpu, c->sandbox->generation);

	if (c->off_cpu_ns) {
		u64 now = ktime_get_mono_fast_ns();

		if (now > c->off_cpu_ns)
			c->vrec->stolen_ns += now - c->off_cpu_ns;
		c->off_cpu_ns = 0;
	}

	if (test_thread_flag(TIF_NEED_FPU_LOAD))
		atomic64_inc(&c->sandbox->stats.fpu_restores);
	kernelet_fpu_sched_in();
	watch_arm(c);
}

static void carrier_sched_out(struct preempt_notifier *pn, struct task_struct *next)
{
	struct carrier *c = container_of(pn, struct carrier, pnotifier);

	(void)next;
	write_cpu_slot(U16_MAX, U16_MAX, 0);

	if (!test_thread_flag(TIF_NEED_FPU_LOAD))
		atomic64_inc(&c->sandbox->stats.fpu_saves);

	c->strike1_ns = 0;
	if (READ_ONCE(c->state) == CARRIER_KERNEL &&
	    READ_ONCE(c->depth) == 0 && !READ_ONCE(c->idle) && !c->evicted)
		c->off_cpu_ns = ktime_get_mono_fast_ns();
	else
		c->off_cpu_ns = 0;
}

static struct preempt_ops preempt_ops = {
	.sched_in = carrier_sched_in,
	.sched_out = carrier_sched_out,
};

int carrier_sched_init(void)
{
	preempt_notifier_inc();
	notifiers_up = true;
	return 0;
}

void carrier_sched_exit(void)
{
	if (notifiers_up) {
		notifiers_up = false;
		preempt_notifier_dec();
	}
}

void carrier_sched_attach(struct carrier *c)
{
	if (!notifiers_up || c->pnotifier_on)
		return;
	preempt_notifier_init(&c->pnotifier, &preempt_ops);
	preempt_notifier_register(&c->pnotifier);
	c->pnotifier_on = true;
}

void carrier_sched_detach(struct carrier *c)
{
	if (!c->pnotifier_on)
		return;
	c->pnotifier_on = false;
	preempt_notifier_unregister(&c->pnotifier);
}
#else
int carrier_sched_init(void) { return 0; }
void carrier_sched_exit(void) { }
void carrier_sched_attach(struct carrier *c) { (void)c; }
void carrier_sched_detach(struct carrier *c) { (void)c; }
#endif

static void kick_ipi(void *arg)
{
	struct carrier *c = arg;

	if (!current->carrier_hooks || current->carrier_hooks != &c->hooks)
		return;
	watch_fire_now();
}

void kick_remote(struct carrier *c)
{
	struct task_struct *t = c->task;
	int cpu;

	if (!t || READ_ONCE(c->state) != CARRIER_KERNEL)
		return;
	if (READ_ONCE(c->depth) != 0) {
		// Defer delivery to the end of `svc_dispatch` when returning to
		// Ring-0 image code so coalesced kicks cannot wait 1 ms.
		WRITE_ONCE(c->kick_deferred, true);
		return;
	}
	if (!task_on_cpu(t))
		return;

	cpu = task_cpu(t);
	if (cpu == smp_processor_id()) {
		if (current->carrier_hooks == &c->hooks)
			watch_fire_now();
		return;
	}
	smp_call_function_single(cpu, kick_ipi, c, 0);
}

void virq_raise(struct carrier *c, u32 bit)
{
	atomic64_or(bit, (atomic64_t *)&c->vrec->pending);
	smp_mb__after_atomic();

	if (READ_ONCE(c->idle) && c->task)
		wake_up_process(c->task);
	// Linux's exit loop consumes the notification in every carrier state.
	if (c->task)
		set_notify_resume(c->task);
}

// ------------------------------------------------------------------
// Signal draining and arrival
// ------------------------------------------------------------------

static bool is_fault_signal(int signr, int si_code)
{
	switch (signr) {
	case SIGSEGV:
	case SIGBUS:
	case SIGTRAP:
	case SIGFPE:
		if (si_code == SI_KERNEL)
			return true;
		fallthrough;
	case SIGILL:
		return si_code > 0 && si_code < SI_KERNEL;
	default:
		return false;
	}
}

static bool sig_immutable(int sig)
{
	return current->sighand->action[sig - 1].sa.sa_flags & SA_IMMUTABLE;
}

static int forced_fatal(void)
{
	int sig, found = 0;

	if (!signal_pending(current))
		return 0;
	spin_lock_irq(&current->sighand->siglock);
	for (sig = 1; sig <= _NSIG && !found; sig++) {
		if (sig_immutable(sig) &&
		    (sigismember(&current->pending.signal, sig) ||
		     sigismember(&current->signal->shared_pending.signal, sig)))
			found = sig;
	}
	spin_unlock_irq(&current->sighand->siglock);
	return found;
}

static noinline __cold void __noreturn stop_on_host_signal(struct carrier *c,
							 int signr, int code)
{
	char msg[64];

	snprintf(msg, sizeof(msg), "Host fault signal %d (si_code=%d)", signr, code);
	sandbox_stop(c->sandbox, STOP_KILLED, signr, msg);
	carrier_die(c);
}

static void drain_signals(struct carrier *c)
{
	kernel_siginfo_t info;
	enum pid_type type;
	sigset_t mask;
	int signr;

	if (!signal_pending(current))
		return;

	mask = current->blocked;
	sigaddset(&mask, SIGKILL);
	sigaddset(&mask, SIGSTOP);

	spin_lock_irq(&current->sighand->siglock);
	for (;;) {
		int sig;

		for (sig = 1; sig <= _NSIG; sig++)
			if (sig_immutable(sig))
				sigaddset(&mask, sig);
		signr = dequeue_signal(&mask, &info, &type);
		if (!signr)
			break;
		spin_unlock_irq(&current->sighand->siglock);

		if (!sig_kernel_only(signr) && !sig_immutable(signr) &&
		    current->sighand->action[signr - 1].sa.sa_handler != SIG_IGN)
			kernel_sigaction(signr, SIG_IGN);

		if (is_fault_signal(signr, info.si_code)) {
			// `force_sig` does not update `thread.trap_nr`.
			// Hardware traps reach `on_exception`; unclassified Host faults
			// must not become tenant exceptions using stale architecture state.
			if (info.si_code == SI_KERNEL)
				stop_on_host_signal(c, signr, info.si_code);
			if (!c->exc_pending) {
				c->exc_trap = current->thread.trap_nr;
				c->exc_error = current->thread.error_code;
				c->exc_addr = (unsigned long)info.si_addr;
				c->exc_pending = true;
			}
		}
		spin_lock_irq(&current->sighand->siglock);
	}
	spin_unlock_irq(&current->sighand->siglock);
}

static bool vcpu_await(struct carrier *c)
{
	struct sandbox *sandbox = c->sandbox;

	if (c->vcpu == 0) {
		wait_event_state(sandbox->arrive_wq,
				 READ_ONCE(sandbox->arrived) == sandbox->nr_vcpus ||
				 READ_ONCE(sandbox->dying) || fatal_signal_pending(current),
				 (TASK_KILLABLE | TASK_NOLOAD));
		if (READ_ONCE(sandbox->arrived) != sandbox->nr_vcpus ||
		    READ_ONCE(sandbox->dying) || fatal_signal_pending(current))
			return false;
	} else {
		wait_event_state(c->idle_wq,
				 c->boot_requested || READ_ONCE(sandbox->dying) ||
				 fatal_signal_pending(current),
				 (TASK_KILLABLE | TASK_NOLOAD));
		if (!c->boot_requested || READ_ONCE(sandbox->dying) ||
		    fatal_signal_pending(current))
			return false;
	}
	return true;
}

// ------------------------------------------------------------------
// PR #3 Carrier Event Hooks (`on_syscall`, `on_exception`, `on_resume`, `on_kernel_fault`)
// ------------------------------------------------------------------

static void __noreturn enter_user_event(struct carrier *c, u64 raw_event)
{
	struct sandbox *sandbox = c->sandbox;
	u64 event_rsp = READ_ONCE(c->urec->event_rsp);
	u64 gen = (u64)atomic64_read(&sandbox->kstack_free_gen);
	unsigned long usable = 0, top = 0;

	if (likely(event_rsp == c->cached_event_rsp &&
		   gen == c->cached_kstack_gen))
		goto valid_stack;

	// Order reading `kstack_free_gen` before reading `live_stacks_bitmap`
	// (`kstack_free` clears the bit before bumping `kstack_free_gen`).
	smp_rmb();
	if (unlikely(event_rsp < 8 || !IS_ALIGNED(event_rsp, 16) ||
		     !stack_pool_slot_bounds(sandbox, (unsigned long)(event_rsp - 8),
					     &usable, &top) ||
		     event_rsp < usable + 4096UL || event_rsp > top)) {
		sandbox_stop(sandbox, STOP_STACK_OVERFLOW, 0,
			"invalid user_event_entry stack");
		carrier_die(c);
	}
	c->cached_event_rsp = event_rsp;
	c->cached_kstack_gen = gen;

valid_stack:
	WRITE_ONCE(c->vrec->irq_off, 1);
	WRITE_ONCE(c->state, CARRIER_KERNEL);
	restore_carrier_fpu(c);
	enter_image(sandbox->user_event_entry, event_rsp, raw_event, 0);
	BUG();
}

static bool on_syscall(struct pt_regs *regs)
{
	struct carrier *c = current_carrier();
	struct sandbox *sandbox;

	if (unlikely(!c || READ_ONCE(c->state) != CARRIER_USER))
		return false;
	sandbox = c->sandbox;

#ifdef DEBUG
	if (WARN_ON_ONCE(regs != c->user_regs))
		carrier_die(c);
#endif

	if (unlikely(regs->cs != __USER_CS || in_compat_syscall())) {
		c->exc_trap = X86_TRAP_GP;
		c->exc_error = 0;
		c->exc_addr = 0;
		c->exc_pending = true;
		set_thread_flag(TIF_NOTIFY_RESUME);
		return true;
	}

	if (unlikely(READ_ONCE(sandbox->dying) ||
		     fatal_signal_pending(current)))
		carrier_die(c);

	// PR #3 syscall convention: place syscall number into `ax` and clear `orig_ax`.
	regs->ax = regs->orig_ax;
	regs->orig_ax = -1;
	c->from_syscall = true;
	if (static_branch_unlikely(&endovisor_audit_key))
		WRITE_ONCE(c->syscalls, c->syscalls + 1);

	enter_user_event(c, USER_EVENT_SYSCALL);
}

static bool on_exception(struct pt_regs *regs, unsigned int trapnr,
			     unsigned long error_code, unsigned long addr)
{
	struct carrier *c = current_carrier();
	struct sandbox *sandbox;

	if (!c || READ_ONCE(c->state) != CARRIER_USER)
		return false;
	sandbox = c->sandbox;

	// In VMA baseline mode (`pt_mode == 1`), let `#PF` traverse Linux's VMA handlers.
	if (sandbox->pt_mode == PT_MODE_VMA && trapnr == X86_TRAP_PF)
		return false;

	// Exception entry may use a temporary frame; the published address stays fixed.
	if (regs != c->user_regs)
		*c->user_regs = *regs;

	atomic64_inc(&sandbox->stats.exceptions);
	if (trapnr == X86_TRAP_PF)
		atomic64_inc(&sandbox->stats.page_faults);

	// Finish Linux exception entry before running handlers that may sleep.
	c->exc_trap = trapnr;
	c->exc_error = error_code;
	c->exc_addr = addr;
	c->exc_pending = true;
	set_thread_flag(TIF_NOTIFY_RESUME);
	return true;
}

static void on_resume(struct pt_regs *regs)
{
	struct carrier *c = current_carrier();
	struct sandbox *sandbox;

	if (!c)
		return;
	sandbox = c->sandbox;

	if (READ_ONCE(c->state) == CARRIER_DEAD ||
	    READ_ONCE(sandbox->dying) ||
	    fatal_signal_pending(current))
		carrier_die(c);

	if (forced_fatal())
		return;

	if (READ_ONCE(c->state) == CARRIER_NEW) {
		if (!vcpu_await(c))
			carrier_die(c);

#ifdef DEBUG
		if (WARN_ON_ONCE(regs != task_pt_regs(current)))
			carrier_die(c);
#endif
		// Linux retains this frame and the carrier's kernel stack until exit.
		c->user_regs = regs;
		c->linux_sp = (void *)((unsigned long)regs & ~15UL);
		WRITE_ONCE(c->urec->pt_regs, (u64)(unsigned long)regs);
		WRITE_ONCE(c->vrec->stack_limit, c->boot_stack_base);
		WRITE_ONCE(c->vrec->irq_off, 1);
		WRITE_ONCE(c->state, CARRIER_KERNEL);
		cpu_slot_set_current(c);
		watch_arm(c);
		restore_carrier_fpu(c);

		if (c->vcpu == 0)
			enter_image(sandbox->entry_fn,
					c->boot_stack_base + KSTACK_BYTES,
					(u64)(unsigned long)&host_services,
					(u64)(unsigned long)sandbox->boot_page);
		else
			enter_image(sandbox->vcpu_entry,
					c->boot_stack_base + KSTACK_BYTES,
					0, 0);
		BUG();
	}

	if (READ_ONCE(c->state) == CARRIER_USER) {
		if (!c->exc_pending)
			drain_signals(c);

		if (c->exc_pending) {
			c->exc_pending = false;
			WRITE_ONCE(c->urec->trap_num, c->exc_trap);
			WRITE_ONCE(c->urec->error_code, c->exc_error);
			WRITE_ONCE(c->urec->fault_addr, c->exc_addr);
			c->from_syscall = false;
			enter_user_event(c, USER_EVENT_EXCEPTION);
		}
		if (READ_ONCE(c->vrec->pending)) {
			c->from_syscall = false;
			enter_user_event(c, USER_EVENT_KERNEL_EVENT);
		}
		return;
	}

	carrier_die(c);
}

static bool on_kernel_fault(struct pt_regs *regs, unsigned int trapnr,
				  unsigned long error_code, unsigned long addr)
{
	struct carrier *c = current_carrier();
	struct sandbox *sandbox;

	if (!c || user_mode(regs) || READ_ONCE(c->depth) != 0)
		return false;
	sandbox = c->sandbox;

	if (trapnr == X86_TRAP_DF) {
		// Runs on the IST `#DF` stack with IRQs off: record overflow
		// locklessly and finish teardown on `c->linux_sp` in `evict_leave`.
		if (!in_image_text(sandbox, regs->ip) &&
		    !stack_pool_is_guard_addr(sandbox, addr) &&
		    !(regs->sp >= 8 && stack_pool_is_guard_addr(sandbox, regs->sp - 8)))
			return false;
		c->df_overflow = true;
		c->df_ip = regs->ip;
		c->df_sp = regs->sp;
		c->df_addr = addr;
		c->evicted = true;
		c->doomed = true;
		regs->sp = (unsigned long)c->linux_sp;
		regs->ip = (unsigned long)exit_stub;
		regs->flags |= X86_EFLAGS_IF;
		return true;
	}

	if (!in_image_text(sandbox, regs->ip) &&
	    !(trapnr == X86_TRAP_PF && stack_pool_is_guard_addr(sandbox, addr)))
		return false;

	if (trapnr == X86_TRAP_GP) {
		pr_err("klet[%d/%u]: kernel fault trap=%u err=0x%lx ip_off=0x%lx sp=0x%lx addr=0x%lx\n",
		       sandbox->slot, c->vcpu, trapnr, error_code,
		       regs->ip - (unsigned long)sandbox->image_base, regs->sp, addr);
		kernelet_fpu_reset_carrier();
		sandbox_stop(sandbox, STOP_PANIC, X86_TRAP_GP,
			"kernel #GP in kernelet image");
	} else if (trapnr == X86_TRAP_PF &&
		   stack_pool_is_guard_addr(sandbox, addr)) {
		pr_err("klet[%d/%u]: kernel fault trap=%u err=0x%lx ip_off=0x%lx sp=0x%lx addr=0x%lx\n",
		       sandbox->slot, c->vcpu, trapnr, error_code,
		       regs->ip - (unsigned long)sandbox->image_base, regs->sp, addr);
		sandbox_stop(sandbox, STOP_STACK_OVERFLOW, X86_TRAP_PF,
			"kernelet stack overflow");
	} else {
		pr_err("klet[%d/%u]: kernel fault trap=%u err=0x%lx ip_off=0x%lx sp=0x%lx addr=0x%lx\n",
		       sandbox->slot, c->vcpu, trapnr, error_code,
		       regs->ip - (unsigned long)sandbox->image_base, regs->sp, addr);
		sandbox_stop(sandbox, STOP_PANIC, trapnr,
			"kernel fault in kernelet image");
	}

	c->evicted = true;
	c->doomed = true;
	regs->sp = (unsigned long)c->linux_sp;
	regs->ip = (unsigned long)exit_stub;
	regs->flags |= X86_EFLAGS_IF;
	return true;
}

const struct carrier_event_hooks carrier_hooks = {
	.on_exit = on_exit,
	.on_syscall = on_syscall,
	.on_resume = on_resume,
	.on_exception = on_exception,
	.on_kernel_fault = on_kernel_fault,
};

// ------------------------------------------------------------------
// Returning service bodies (run strictly on `c->linux_sp`)
// ------------------------------------------------------------------

enum svc_op {
	SVC_GRAINS_REQUEST,
	SVC_PT_ROOT_REGISTER,
	SVC_PT_ROOT_UNREGISTER,
	SVC_PT_ACTIVATE,
	SVC_TLB_SHOOTDOWN,
	SVC_KSTACK_ALLOC,
	SVC_KSTACK_FREE,
	SVC_VCPU_BOOT,
	SVC_VCPU_IDLE,
	SVC_VCPU_KICK,
	SVC_VCPU_YIELD,
	SVC_VCPU_ON_SPIN,
	SVC_LOG_WRITE,
	SVC_OOPS,
	SVC_BUFFER,
};

struct svc_args {
	enum svc_op op;
	u64 a0, a1, a2, a3, a4;
	struct mmio_result mmio_res;
};

static u64 image_clock_ns(struct sandbox *sandbox)
{
	u64 cycles = rdtsc_ordered() - sandbox->clock_origin_tsc;

	return mul_u64_u64_div_u64(cycles, NSEC_PER_SEC, sandbox->tsc_freq_hz);
}

static void do_vcpu_boot(struct sandbox *sandbox, u32 vcpu)
{
	struct carrier *target;

	if (vcpu == 0 || vcpu >= sandbox->nr_vcpus)
		return;

	spin_lock(&sandbox->lock);
	target = sandbox->vcpus[vcpu];
	if (target)
		carrier_get(target);
	spin_unlock(&sandbox->lock);
	if (!target)
		return;

	target->boot_requested = true;
	wake_up_all(&target->idle_wq);
	carrier_put(target);
}

static void do_vcpu_kick(struct carrier *caller, struct sandbox *sandbox,
			     u32 vcpu, bool *self_kick)
{
	struct carrier *target;
	u64 pending;

	if (vcpu >= sandbox->nr_vcpus)
		return;

	spin_lock(&sandbox->lock);
	target = sandbox->vcpus[vcpu];
	if (target)
		carrier_get(target);
	spin_unlock(&sandbox->lock);
	if (!target)
		return;

	pending = atomic64_fetch_or(VIRQ_KICK,
				    (atomic64_t *)&target->vrec->pending);
	// The ordered RMW publishes the event before its Linux notification.
	// Notify even a coalesced or local kick: the previous hook may be in progress.
	if (target->task)
		set_notify_resume(target->task);
	if (pending & VIRQ_KICK) {
		carrier_put(target);
		return;
	}

	if (target == caller) {
		if (READ_ONCE(target->state) == CARRIER_KERNEL)
			*self_kick = true;
		carrier_put(target);
		return;
	}

	if (READ_ONCE(target->idle) && target->task)
		wake_up_process(target->task);
	kick_remote(target);
	carrier_put(target);
}

static void do_vcpu_idle(struct carrier *c, u64 deadline_ns)
{
	struct sandbox *sandbox = c->sandbox;
	u64 wait_ns;

	if (deadline_ns == U64_MAX) {
		wait_ns = IDLE_MAX_NS;
	} else if (deadline_ns == 0) {
		wait_ns = IDLE_MAX_NS;
	} else {
		u64 now_ns = image_clock_ns(sandbox);

		if (deadline_ns <= now_ns)
			return;
		wait_ns = min_t(u64, deadline_ns - now_ns, IDLE_MAX_NS);
		if (wait_ns < IDLE_MIN_NS)
			wait_ns = IDLE_MIN_NS;
	}

	set_current_state(TASK_KILLABLE | TASK_FREEZABLE | TASK_NOLOAD);
	WRITE_ONCE(c->idle, true);
	smp_mb();

	if (!READ_ONCE(c->vrec->pending) &&
	    !READ_ONCE(sandbox->dying) && !fatal_signal_pending(current)) {
		ktime_t timeout = ns_to_ktime(wait_ns);

		schedule_hrtimeout(&timeout, HRTIMER_MODE_REL);
	}

	__set_current_state(TASK_RUNNING);
	WRITE_ONCE(c->idle, false);
	virq_raise(c, VIRQ_TICK);
}

static void do_vcpu_yield(void)
{
	if (!cond_resched() && need_resched())
		schedule();
}

static void do_on_spin(struct carrier *c)
{
	struct sandbox *sandbox = c->sandbox;
	unsigned int i;

	if (c->last_on_spin == jiffies)
		return;
	c->last_on_spin = jiffies;

	for (i = 0; i < sandbox->nr_vcpus; i++) {
		struct carrier *o;
		struct task_struct *t;

		spin_lock(&sandbox->lock);
		o = sandbox->vcpus[i];
		if (o && o != c)
			carrier_get(o);
		else
			o = NULL;
		spin_unlock(&sandbox->lock);
		if (!o)
			continue;

		t = o->task;
		if (t && task_is_running(t) && !task_on_cpu(t)) {
			int r = yield_to(t, false);

			carrier_put(o);
			if (r > 0)
				return;
			break;
		}
		carrier_put(o);
	}
	cond_resched();
}

static size_t copy_str_nofault(char *dst, size_t max_len, u64 src_va, u32 len)
{
	size_t n = min_t(size_t, max_len - 1, len);
	size_t i;

	for (i = 0; i < n; i++) {
		if (copy_from_kernel_nofault(&dst[i], (const char *)(unsigned long)src_va + i, 1))
			break;
	}
	dst[i] = '\0';
	return i;
}

static noinline void do_log_write(struct sandbox *sandbox,
				      struct carrier *c, u32 level,
				      u64 mod_va, u32 mod_len,
				      u64 msg_va, u32 msg_len)
{
	char mod[64];
	char *msg;
	size_t n;

	msg = kmalloc(1025, GFP_KERNEL);
	if (!msg)
		return;

	copy_str_nofault(mod, sizeof(mod), mod_va, mod_len);
	n = copy_str_nofault(msg, 1025, msg_va, msg_len);

	if (level == 8U) {
		char *line = kmalloc(1024, GFP_KERNEL);
		size_t i;

		if (line) {
			for (i = 0; i < n; i++) {
				char ch = msg[i];
				bool flush = false;
				unsigned long flags;

				if (ch == '\r')
					continue;
				spin_lock_irqsave(&sandbox->con_lock, flags);
				if (ch == '\n') {
					memcpy(line, sandbox->con_buf, sandbox->con_len);
					line[sandbox->con_len] = '\0';
					sandbox->con_len = 0;
					flush = true;
				} else {
					sandbox->con_buf[sandbox->con_len++] = ch;
					if (sandbox->con_len == sizeof(sandbox->con_buf) - 1) {
						memcpy(line, sandbox->con_buf, sandbox->con_len);
						line[sandbox->con_len] = '\0';
						sandbox->con_len = 0;
						flush = true;
					}
				}
				spin_unlock_irqrestore(&sandbox->con_lock, flags);
				if (flush)
					printk(KERN_INFO "%s\n", line);
			}
			kfree(line);
		}
	} else {
		printk(KERN_INFO "klet[%d/%u %s]: %s\n",
		       sandbox->slot, c->vcpu, mod[0] ? mod : "log", msg);
	}
	kfree(msg);
}

static u64 svc_dispatch(void *arg)
{
	struct svc_args *args = arg;
	struct carrier *c = current_carrier();
	struct sandbox *sandbox = c->sandbox;
	bool self_kick = false;
	u64 ret = 0;

	c->depth++;
	switch (args->op) {
	case SVC_GRAINS_REQUEST:
		ret = (u64)do_grains_request(sandbox, (u32)args->a0, (u32)args->a1);
		break;
	case SVC_PT_ROOT_REGISTER:
		ret = (u64)do_pt_root_register(c, args->a0);
		break;
	case SVC_PT_ROOT_UNREGISTER:
		ret = (u64)do_pt_root_unregister(c, args->a0);
		break;
	case SVC_PT_ACTIVATE:
		ret = (u64)do_pt_activate(c, args->a0);
		break;
	case SVC_TLB_SHOOTDOWN:
		ret = (u64)do_tlb_shootdown(c, args->a0, args->a1, args->a2);
		break;
	case SVC_KSTACK_ALLOC:
		ret = kstack_alloc(sandbox, false);
		break;
	case SVC_KSTACK_FREE:
		ret = (u64)kstack_free(sandbox, args->a0);
		break;
	case SVC_VCPU_BOOT:
		do_vcpu_boot(sandbox, (u32)args->a0);
		ret = 0;
		break;
	case SVC_VCPU_IDLE:
		do_vcpu_idle(c, args->a0);
		ret = 0;
		break;
	case SVC_VCPU_KICK:
		do_vcpu_kick(c, sandbox, (u32)args->a0, &self_kick);
		ret = 0;
		break;
	case SVC_VCPU_YIELD:
		do_vcpu_yield();
		ret = 0;
		break;
	case SVC_VCPU_ON_SPIN:
		do_on_spin(c);
		ret = 0;
		break;
	case SVC_LOG_WRITE:
		do_log_write(sandbox, c, (u32)args->a0, args->a1, (u32)args->a2,
				 args->a3, (u32)args->a4);
		ret = 0;
		break;
	case SVC_OOPS: {
		char msg[512];

		copy_str_nofault(msg, sizeof(msg), args->a0, (u32)args->a1);
		printk(KERN_ERR "klet[%d/%u] OOPS: %s\n",
		       sandbox->slot, c->vcpu, msg);
		ret = 0;
		break;
	}
	case SVC_BUFFER:
		args->mmio_res = do_buffer(c, (u32)args->a0, args->a1,
					       args->a2, args->a3, args->a4);
		ret = 0;
		break;
	}

	if (fatal_signal_pending(current) ||
	    READ_ONCE(sandbox->dying))
		c->doomed = true;

	restore_carrier_fpu(c);
	watch_arm(c);
	c->depth--;
	if (c->depth == 0) {
		bool deferred = xchg(&c->kick_deferred, false);

		if (unlikely(self_kick || deferred)) {
			preempt_disable();
			if (self_kick)
				watch_fire_now();
			else
				watch_fire_soon();
			preempt_enable();
		}
	}
	return ret;
}

static u64 svc_call(enum svc_op op, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4,
			struct mmio_result *mmio_out)
{
	struct carrier *c = current_carrier();
	struct svc_args args = {
		.op = op,
		.a0 = a0, .a1 = a1, .a2 = a2, .a3 = a3, .a4 = a4,
	};
	u64 ret;

	ret = call_on_linux_stack(c->linux_sp, svc_dispatch, &args);
	if (unlikely(READ_ONCE(c->doomed)))
		evict_leave();
	if (mmio_out)
		*mmio_out = args.mmio_res;
	return ret;
}

// ------------------------------------------------------------------
// `host_services` ABI entry points
// ------------------------------------------------------------------

static s64 svc_grains_request(u32 count, u32 contiguous)
{
	return (s64)svc_call(SVC_GRAINS_REQUEST, count, contiguous, 0, 0, 0, NULL);
}

static s64 svc_pt_root_register(u64 root_paddr)
{
	return (s64)svc_call(SVC_PT_ROOT_REGISTER, root_paddr, 0, 0, 0, 0, NULL);
}

static s64 svc_pt_root_unregister(u64 root_paddr)
{
	return (s64)svc_call(SVC_PT_ROOT_UNREGISTER, root_paddr, 0, 0, 0, 0, NULL);
}

static s64 svc_pt_activate(u64 root_paddr)
{
	return (s64)svc_call(SVC_PT_ACTIVATE, root_paddr, 0, 0, 0, 0, NULL);
}

static s64 svc_tlb_shootdown(u64 root_paddr, u64 start, u64 len)
{
	return (s64)svc_call(SVC_TLB_SHOOTDOWN, root_paddr, start, len, 0, 0, NULL);
}

static u64 svc_kstack_alloc(void)
{
	return svc_call(SVC_KSTACK_ALLOC, 0, 0, 0, 0, 0, NULL);
}

static s64 svc_kstack_free(u64 vaddr)
{
	return (s64)svc_call(SVC_KSTACK_FREE, vaddr, 0, 0, 0, 0, NULL);
}

static s64 svc_vcpu_boot(u32 vcpu)
{
	return (s64)svc_call(SVC_VCPU_BOOT, vcpu, 0, 0, 0, 0, NULL);
}

static s64 svc_vcpu_idle(u64 deadline_ns)
{
	return (s64)svc_call(SVC_VCPU_IDLE, deadline_ns, 0, 0, 0, 0, NULL);
}

static s64 svc_vcpu_kick(u32 vcpu)
{
	return (s64)svc_call(SVC_VCPU_KICK, vcpu, 0, 0, 0, 0, NULL);
}

static void svc_vcpu_yield(void)
{
	svc_call(SVC_VCPU_YIELD, 0, 0, 0, 0, 0, NULL);
}

static void svc_vcpu_on_spin(void)
{
	svc_call(SVC_VCPU_ON_SPIN, 0, 0, 0, 0, 0, NULL);
}

static noinline void audit_user_return(struct carrier *c)
{
	struct pt_regs *regs = c->user_regs;

	if (c->from_syscall &&
	    (regs->ip != regs->cx || regs->r11 != regs->flags ||
	     regs->cs != __USER_CS || regs->ss != __USER_DS ||
	     (regs->flags & (X86_EFLAGS_RF | X86_EFLAGS_TF)) ||
	     regs->ip >= TASK_SIZE_MAX))
		atomic64_inc(&c->sandbox->stats.non_sysret);
}

void __noreturn do_user_run_on_linux(struct carrier *c)
{
	struct sandbox *sandbox = c->sandbox;
	struct pt_regs *regs = c->user_regs;
	bool from_syscall = c->from_syscall;
	bool bad_user_addr;

	if (unlikely(READ_ONCE(sandbox->dying) ||
		     fatal_signal_pending(current)))
		carrier_die(c);

	bad_user_addr = regs->ip >= TASK_SIZE_MAX ||
			(((s64)regs->sp >> 47) != 0 && ((s64)regs->sp >> 47) != -1);

	regs->flags = (regs->flags & RFLAGS_USER) | X86_EFLAGS_IF |
		      X86_EFLAGS_FIXED;
	regs->cs = __USER_CS;
	regs->ss = __USER_DS;
	regs->orig_ax = -1;

	if (unlikely(bad_user_addr)) {
		c->exc_trap = X86_TRAP_GP;
		c->exc_error = 0;
		c->exc_addr = 0;
		c->exc_pending = true;
		from_syscall = false;
		set_thread_flag(TIF_NOTIFY_RESUME);
	}

	WRITE_ONCE(c->state, CARRIER_USER);
	WRITE_ONCE(c->vrec->irq_off, 0);
	// No `smp_mb()` is needed here: `virq_raise` and `do_vcpu_kick` order
	// their `vrec->pending` atomic RMW before an unconditional
	// `set_notify_resume(c->task)` regardless of `c->state`/`irq_off`.
	//
	// 1. Local IRQ (`watch_fn`): either fires before `local_irq_disable_exit_to_user`
	//    (setting `TIF_NOTIFY_RESUME` before `read_thread_flags`) or after
	//    Ring-3 `IF=1` return (`irqentry_exit_to_user_mode` -> `on_resume`).
	// 2. Remote running task: `set_notify_resume` runs `lock bts` (`TIF_NOTIFY_RESUME`)
	//    then `kick_process` -> `smp_send_reschedule`. Either `read_thread_flags`
	//    sees `TIF_NOTIFY_RESUME`, or the IPI arrives after `cli` and traps
	//    upon Ring-3 entry (`IF=1`) into `on_resume`.
	// 3. Remote preempted/switching task: `schedule()` cannot run with IRQs off,
	//    so `rq->lock`/`switch_to` orders `lock bts` before the task later runs
	//    `local_irq_disable_exit_to_user` -> `read_thread_flags`.
	// 4. Already-set `TIF_NOTIFY_RESUME`: only `resume_user_mode_work` clears
	//    it, strictly before `on_resume` inside `exit_to_user_mode_loop`, so
	//    `read_thread_flags` or the active pass still invokes `on_resume`
	//    after the producer's `vrec->pending` write.
	barrier();

	if (static_branch_unlikely(&endovisor_audit_key))
		audit_user_return(c);

	return_to_user(regs, from_syscall);
	BUG();
}

static s32 svc_user_run(void *ctx)
{
	struct carrier *c = current_carrier();

	(void)ctx;
	jump_user_run(c->linux_sp, c);
	BUG();
}

static struct mmio_result svc_mmio_read(u32 dev, u32 offset, u32 width)
{
	(void)dev;
	(void)offset;
	(void)width;
	return (struct mmio_result){ .status = -ABI_INVALID, .value = 0 };
}

static s64 svc_mmio_write(u32 dev, u32 offset, u32 width, u64 value)
{
	(void)dev;
	(void)offset;
	(void)width;
	(void)value;
	return -ABI_INVALID;
}

static s64 svc_log_write(u32 level, const u8 *module, u32 module_len,
			     const u8 *text, u32 text_len)
{
	return (s64)svc_call(SVC_LOG_WRITE, level,
				 (u64)(unsigned long)module, module_len,
				 (u64)(unsigned long)text, text_len, NULL);
}

static s64 svc_oops(const u8 *msg, u32 len)
{
	return (s64)svc_call(SVC_OOPS, (u64)(unsigned long)msg, len,
				 0, 0, 0, NULL);
}

struct stop_args {
	struct carrier *c;
	u32 kind;
	u32 code;
	char msg[256];
};

static void __noreturn do_stop_on_linux(void *arg)
{
	struct stop_args *sa = arg;
	struct carrier *c = sa->c;

	sandbox_stop(c->sandbox, sa->kind, sa->code, sa->msg);
	carrier_die(c);
}

static void __noreturn svc_stop(u32 kind, u32 code, const u8 *msg, u32 len)
{
	struct carrier *c = current_carrier();
	struct stop_args sa = {
		.c = c,
		.kind = kind,
		.code = code,
	};

	if (msg && len)
		copy_str_nofault(sa.msg, sizeof(sa.msg),
				     (u64)(unsigned long)msg, len);
	jump_linux_stack(c->linux_sp, do_stop_on_linux, &sa);
	BUG();
}

static struct mmio_result svc_buffer(u32 op, u64 token, u64 arg0,
					     u64 arg1, u64 arg2)
{
	struct mmio_result res = {};

	svc_call(SVC_BUFFER, op, token, arg0, arg1, arg2, &res);
	return res;
}

const struct service_table host_services = {
	.size = sizeof(struct service_table),
	.grains_request = svc_grains_request,
	.pt_root_register = svc_pt_root_register,
	.pt_root_unregister = svc_pt_root_unregister,
	.pt_activate = svc_pt_activate,
	.tlb_shootdown = svc_tlb_shootdown,
	.kstack_alloc = svc_kstack_alloc,
	.kstack_free = svc_kstack_free,
	.vcpu_boot = svc_vcpu_boot,
	.vcpu_idle = svc_vcpu_idle,
	.vcpu_kick = svc_vcpu_kick,
	.vcpu_yield = svc_vcpu_yield,
	.vcpu_on_spin = svc_vcpu_on_spin,
	.user_run = svc_user_run,
	.mmio_read = svc_mmio_read,
	.mmio_write = svc_mmio_write,
	.log_write = svc_log_write,
	.oops = svc_oops,
	.stop = svc_stop,
	.buffer = svc_buffer,
};
