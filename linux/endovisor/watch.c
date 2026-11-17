// SPDX-License-Identifier: GPL-2.0
// Per-CPU watch timer, 7-word `returning_stub!` upcall redirection,
// bounded critical-section preemption, and dying-sandbox eviction sweep.

#include <linux/atomic.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/kernelet.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

#include <asm/irq_regs.h>
#include <asm/processor-flags.h>
#include <asm/ptrace.h>
#include <asm/segment.h>

#include "endovisor.h"

static DEFINE_PER_CPU(struct hrtimer, watch_timer);
static DEFINE_PER_CPU(bool, watch_requested);
static DEFINE_PER_CPU(ktime_t, watch_period_end);
static bool watch_ready;

static DEFINE_PER_CPU(struct hrtimer, sweep_timer);
static bool sweep_ready;
atomic_t evicting_sandboxes = ATOMIC_INIT(0);

static void account_tick(struct carrier *c, struct pt_regs *regs)
{
	atomic64_t *tt = (atomic64_t *)&c->vrec->task_ticks;
	u64 cur, next;
	bool is_user = regs ? user_mode(regs) : (READ_ONCE(c->state) == CARRIER_USER);

	if (is_user) {
		WRITE_ONCE(c->vrec->tick_user, READ_ONCE(c->vrec->tick_user) + 1);
		cur = atomic64_read(tt);
		do {
			if ((u32)cur == U32_MAX)
				break;
			next = cur + 1ULL;
		} while (!atomic64_try_cmpxchg(tt, &cur, next));
		return;
	}

	WRITE_ONCE(c->vrec->tick_kernel, READ_ONCE(c->vrec->tick_kernel) + 1);
	if (READ_ONCE(c->vrec->irq_level) != 0)
		return;

	cur = atomic64_read(tt);
	do {
		if ((u32)(cur >> 32) == U32_MAX)
			break;
		next = cur + (1ULL << 32);
	} while (!atomic64_try_cmpxchg(tt, &cur, next));
}

// Redirect interrupted kernelet execution to `virq_entry` or `yield_entry`.
//
// `returning_stub!` expects `IF == 0` and a 7-word iret-style handoff frame at
// `(orig_rsp & ~15UL) - 56`:
//   `[orig_rip, orig_rsp, orig_rip, cs, orig_flags, orig_rsp, ss]`.
static bool redirect_stub(struct carrier *c, struct pt_regs *regs,
			      unsigned long entry_ip, bool mask_virq)
{
	struct sandbox *sandbox = c->sandbox;
	unsigned long orig_rsp = regs->sp;
	unsigned long orig_rip = regs->ip;
	unsigned long orig_flags = regs->flags;
	unsigned long frame_addr;
	unsigned long limit, top;
	u64 *frame;

	if (!entry_ip || user_mode(regs))
		return false;
	if (READ_ONCE(c->depth) != 0 || READ_ONCE(c->state) != CARRIER_KERNEL)
		return false;
	if (!in_image_text(sandbox, orig_rip))
		return false;
	if (in_stub_range(sandbox, orig_rip) ||
	    in_cpu_access_range(sandbox, orig_rip))
		return false;
	if (!(orig_flags & X86_EFLAGS_IF))
		return false;
	if (READ_ONCE(c->cfrec->pending) != 0)
		return false;
	if (READ_ONCE(c->vrec->irq_level) != 0)
		return false;

	// Derive the live slot bounds directly from `orig_rsp` rather than
	// trusting `c->vrec->stack_limit` in writable shared memory.
	if (orig_rsp < 8 ||
	    !stack_pool_slot_bounds(sandbox, orig_rsp - 8, &limit, &top))
		return false;
	{
		unsigned long safe_base = orig_rsp;
		unsigned long regs_addr = (unsigned long)regs;
		unsigned long cur_sp = current_stack_pointer;

		if (regs_addr >= limit && regs_addr < top)
			safe_base = min(safe_base, regs_addr);
		if (cur_sp >= limit && cur_sp < top)
			safe_base = min(safe_base, cur_sp);
		if (safe_base < limit + 128UL + 56UL)
			return false;
		frame_addr = ((safe_base - 128UL) & ~15UL) - 56UL;
	}
	if (frame_addr < limit + UPCALL_STACK_RESERVE || frame_addr >= top)
		return false;

	frame = (u64 *)frame_addr;
	frame[0] = orig_rip;
	frame[1] = orig_rsp;
	frame[2] = orig_rip;
	frame[3] = __KERNEL_CS;
	frame[4] = orig_flags;
	frame[5] = orig_rsp;
	frame[6] = __KERNEL_DS;

	if (mask_virq)
		WRITE_ONCE(c->vrec->irq_off, 1);
	smp_wmb();

	regs->sp = frame_addr;
	regs->ip = entry_ip;
	regs->flags &= ~X86_EFLAGS_IF;
	return true;
}

static bool in_critical(struct carrier *c)
{
	return READ_ONCE(c->vrec->irq_off) != 0 ||
	       READ_ONCE(c->vrec->guards) != 0 ||
	       READ_ONCE(c->vrec->irq_level) != 0;
}

static enum hrtimer_restart watch_fn(struct hrtimer *timer)
{
	struct pt_regs *regs = get_irq_regs();
	struct carrier *c;
	struct sandbox *sandbox;
	bool tick = true;
	bool requested;
	u64 now;

	requested = this_cpu_read(watch_requested);
	if (requested) {
		this_cpu_write(watch_requested, false);
		if (ktime_before(hrtimer_cb_get_time(timer),
				 this_cpu_read(watch_period_end)))
			tick = false;
	}

	if (!current->carrier_hooks)
		return HRTIMER_NORESTART;

	c = current_carrier();
	if (!c)
		return HRTIMER_NORESTART;
	sandbox = c->sandbox;
	if (READ_ONCE(c->state) == CARRIER_DEAD ||
	    READ_ONCE(sandbox->dying))
		return HRTIMER_NORESTART;

	// Evict carriers hit by a fatal signal while running image text.
	if (regs && !user_mode(regs) && READ_ONCE(c->depth) == 0 &&
	    READ_ONCE(c->state) == CARRIER_KERNEL &&
	    in_image_text(sandbox, regs->ip) && fatal_signal_pending(current)) {
		c->evicted = true;
		c->doomed = true;
		regs->ip = (unsigned long)exit_stub;
		regs->sp = (unsigned long)c->linux_sp;
		regs->flags |= X86_EFLAGS_IF;
		return HRTIMER_NORESTART;
	}

	if (tick) {
		if (static_branch_unlikely(&endovisor_profile_key))
			watch_sample_profile(c, regs);
		account_tick(c, regs);
		virq_raise(c, VIRQ_TICK);
	}

	if (!regs || user_mode(regs) || READ_ONCE(c->depth) != 0 ||
	    READ_ONCE(c->state) != CARRIER_KERNEL ||
	    !in_image_text(sandbox, regs->ip)) {
		c->strike1_ns = 0;
		goto again;
	}

	if (!in_critical(c)) {
		c->strike1_ns = 0;
		if (redirect_stub(c, regs, sandbox->virq_entry, true)) {
			atomic64_inc(&sandbox->stats.virqs);
			goto again;
		}
		if (need_resched())
			redirect_stub(c, regs, sandbox->yield_entry, false);
		goto again;
	}

	if (!tick)
		goto again;

	if (!need_resched()) {
		c->strike1_ns = 0;
		goto again;
	}

	// Two-strike bound: force yield if critical kernelet code still wants CPU after >= 1 ms.
	now = ktime_get_mono_fast_ns();
	if (!c->strike1_ns) {
		c->strike1_ns = now;
		goto again;
	}
	if (now - c->strike1_ns < NSEC_PER_MSEC)
		goto again;

	if (redirect_stub(c, regs, sandbox->yield_entry, false)) {
		c->strike1_ns = 0;
		atomic64_inc(&sandbox->stats.forced_yields);
	}

again:
	if (!tick) {
		hrtimer_set_expires(timer, this_cpu_read(watch_period_end));
		return HRTIMER_RESTART;
	}
	hrtimer_forward_now(timer, ns_to_ktime(WATCH_INTERVAL_NS));
	return HRTIMER_RESTART;
}

void watch_fire_now(void)
{
	struct hrtimer *timer = this_cpu_ptr(&watch_timer);
	ktime_t end;

	if (!watch_enabled || !watch_ready ||
	    this_cpu_read(watch_requested))
		return;

	if (hrtimer_active(timer))
		end = hrtimer_get_expires(timer);
	else
		end = ktime_add_ns(ktime_get(), WATCH_INTERVAL_NS);

	this_cpu_write(watch_period_end, end);
	this_cpu_write(watch_requested, true);
	hrtimer_start(timer, 0, HRTIMER_MODE_REL_PINNED_HARD);
}

// Schedules a near-immediate watch check after returning from `svc_dispatch`
// back onto the image stack so deferred Ring-0 kicks are delivered promptly.
void watch_fire_soon(void)
{
	struct hrtimer *timer = this_cpu_ptr(&watch_timer);
	ktime_t end;

	if (!watch_enabled || !watch_ready ||
	    this_cpu_read(watch_requested))
		return;

	if (hrtimer_active(timer))
		end = hrtimer_get_expires(timer);
	else
		end = ktime_add_ns(ktime_get(), WATCH_INTERVAL_NS);

	this_cpu_write(watch_period_end, end);
	this_cpu_write(watch_requested, true);
	hrtimer_start(timer, ns_to_ktime(2000), HRTIMER_MODE_REL_PINNED_HARD);
}

void watch_arm(struct carrier *c)
{
	struct hrtimer *timer;

	if ((!watch_enabled && !static_branch_unlikely(&endovisor_profile_key)) ||
	    !watch_ready)
		return;

	timer = this_cpu_ptr(&watch_timer);
	if (!hrtimer_active(timer))
		hrtimer_start(timer, ns_to_ktime(WATCH_INTERVAL_NS),
			      HRTIMER_MODE_REL_PINNED_HARD);
}

void watch_sample_profile(struct carrier *c, struct pt_regs *regs)
{
	struct sandbox *sandbox = c->sandbox;
	struct sandbox_prof_sample sample;
	unsigned long flags;
	unsigned long bp, usable = 0, top = 0;
	bool on_kstack;
	u32 n = 0;

	if (!regs || !sandbox->prof_samples)
		return;

	memset(&sample, 0, sizeof(sample));
	sample.vcpu = c->vcpu;
	sample.frames[n++] = regs->ip;

	if (user_mode(regs))
		goto record;

	on_kstack = stack_pool_slot_bounds(sandbox, regs->sp, &usable, &top);
	bp = regs->bp;
	while (n < ENDOVISOR_PROF_MAX_FRAMES && bp && (bp & 0x7UL) == 0) {
		unsigned long pair[2];

		if (on_kstack) {
			if (bp < usable || bp + sizeof(pair) > top)
				break;
		} else if (bp < PAGE_OFFSET) {
			break;
		}

		if (copy_from_kernel_nofault(pair, (const void *)bp, sizeof(pair)) != 0)
			break;
		if (pair[1]) {
			if (on_kstack) {
				if (in_image_text(sandbox, pair[1]) ||
				    in_stub_range(sandbox, pair[1]) ||
				    pair[1] >= (unsigned long)TASK_SIZE_MAX)
					sample.frames[n++] = pair[1];
			} else {
				sample.frames[n++] = pair[1];
			}
		}
		if (pair[0] <= bp || pair[0] - bp > 65536UL)
			break;
		bp = pair[0];
	}

	// Fallback conservative scan over active kernelet stack when frame pointers are omitted.
	if (on_kstack && n < 3) {
		unsigned long sp = regs->sp & ~0x7UL;
		unsigned long scan_end = min(top, sp + 4096UL);
		unsigned long p;

		for (p = sp;
		     p + sizeof(unsigned long) <= scan_end && n < ENDOVISOR_PROF_MAX_FRAMES;
		     p += sizeof(unsigned long)) {
			unsigned long ret = 0;

			if (copy_from_kernel_nofault(&ret, (const void *)p, sizeof(ret)) != 0)
				break;
			if (in_image_text(sandbox, ret) || in_stub_range(sandbox, ret)) {
				if (sample.frames[n - 1] != ret)
					sample.frames[n++] = ret;
			}
		}
	}

record:
	sample.nr_frames = n;
	spin_lock_irqsave(&sandbox->prof_lock, flags);
	if (sandbox->prof_count < sandbox->prof_cap)
		sandbox->prof_samples[sandbox->prof_count++] = sample;
	else
		sandbox->prof_dropped++;
	spin_unlock_irqrestore(&sandbox->prof_lock, flags);
}

int watch_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct hrtimer *timer = per_cpu_ptr(&watch_timer, cpu);

		hrtimer_init(timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_HARD);
		timer->function = watch_fn;
	}
	watch_ready = true;
	return 0;
}

void watch_exit(void)
{
	int cpu;

	watch_ready = false;
	for_each_possible_cpu(cpu)
		hrtimer_cancel(per_cpu_ptr(&watch_timer, cpu));
}

// ------------------------------------------------------------------
// Dying-sandbox eviction sweep
// ------------------------------------------------------------------

static enum hrtimer_restart sweep(struct hrtimer *timer)
{
	struct pt_regs *regs = get_irq_regs();
	struct carrier *c;
	struct sandbox *sandbox;

	if (atomic_read(&evicting_sandboxes) == 0)
		return HRTIMER_NORESTART;

	if (!regs || user_mode(regs) || !current->carrier_hooks)
		goto again;

	c = current_carrier();
	if (!c)
		goto again;
	sandbox = c->sandbox;

	if (!READ_ONCE(sandbox->dying) || READ_ONCE(c->depth) != 0 ||
	    READ_ONCE(c->evicted) || READ_ONCE(c->state) != CARRIER_KERNEL)
		goto again;
	if (!in_image_text(sandbox, regs->ip))
		goto again;

	c->evicted = true;
	c->doomed = true;
	regs->ip = (unsigned long)exit_stub;
	regs->sp = (unsigned long)c->linux_sp;
	regs->flags |= X86_EFLAGS_IF;

again:
	hrtimer_forward_now(timer, ns_to_ktime(SWEEP_INTERVAL_NS));
	return HRTIMER_RESTART;
}

static void sweep_arm_local(void *unused)
{
	struct hrtimer *timer = this_cpu_ptr(&sweep_timer);

	if (!hrtimer_active(timer))
		hrtimer_start(timer, ns_to_ktime(SWEEP_INTERVAL_NS),
			      HRTIMER_MODE_REL_PINNED_HARD);
}

void evict_arm(struct sandbox *sandbox)
{
	unsigned long flags;
	bool arm = false;

	if (!sweep_ready)
		return;

	spin_lock_irqsave(&sandbox->lock, flags);
	if (sandbox->dying && !sandbox->exit_claimed &&
	    atomic_read(&sandbox->nr_carriers) != 0 && !sandbox->sweep_armed) {
		sandbox->sweep_armed = true;
		atomic_inc(&evicting_sandboxes);
		arm = true;
	}
	spin_unlock_irqrestore(&sandbox->lock, flags);

	if (arm)
		on_each_cpu(sweep_arm_local, NULL, 1);
}

int evict_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct hrtimer *timer = per_cpu_ptr(&sweep_timer, cpu);

		hrtimer_init(timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL_HARD);
		timer->function = sweep;
	}
	sweep_ready = true;
	return 0;
}

void evict_exit(void)
{
	int cpu;

	sweep_ready = false;
	for_each_possible_cpu(cpu)
		hrtimer_cancel(per_cpu_ptr(&sweep_timer, cpu));
}
