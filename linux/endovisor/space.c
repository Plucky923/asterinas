// SPDX-License-Identifier: GPL-2.0
// Address space (`mm_struct`) management for Direct-PTE (`pt_mode == 0`) and
// VMA-baseline (`pt_mode == 1`) execution in `endovisor`.

#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/kernelet.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/pfn.h>
#include <linux/pgtable.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/coredump.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait_bit.h>

#include <asm/cpufeature.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/trapnr.h>
#include <asm/tsc.h>

#include "endovisor.h"

extern void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
			       unsigned long end, unsigned int stride_shift,
			       bool freed_tables);

static struct user_space *space_find_rcu(struct sandbox *sandbox, u64 root_paddr)
{
	struct user_space *sp;

	hash_for_each_possible_rcu(sandbox->spaces_ht, sp, hnode, root_paddr) {
		if (sp->root_paddr == root_paddr && READ_ONCE(sp->live))
			return sp;
	}
	return NULL;
}

static struct user_space *space_get(struct sandbox *sandbox, u64 root_paddr)
{
	struct user_space *sp;

	if (!root_paddr)
		return NULL;
	rcu_read_lock();
	sp = space_find_rcu(sandbox, root_paddr);
	if (sp && !atomic_inc_not_zero(&sp->users))
		sp = NULL;
	if (sp && !READ_ONCE(sp->live)) {
		if (atomic_dec_and_test(&sp->users))
			wake_up_var(&sp->users);
		sp = NULL;
	}
	rcu_read_unlock();
	return sp;
}

static void space_put(struct user_space *sp)
{
	if (atomic_dec_and_test(&sp->users))
		wake_up_var(&sp->users);
}

// ------------------------------------------------------------------
// VMA baseline handlers (`pt_mode == 1`)
// ------------------------------------------------------------------

static vm_fault_t space_report(struct vm_fault *vmf, bool mkwrite)
{
	struct vm_area_struct *vma = vmf->vma;
	struct user_space *sp = vma->vm_file ? vma->vm_file->private_data : NULL;
	struct carrier *c = current_carrier();
	bool user = !!(vmf->flags & FAULT_FLAG_USER);
	bool write = mkwrite || !!(vmf->flags & FAULT_FLAG_WRITE);
	bool exec = !!(vmf->flags & FAULT_FLAG_INSTRUCTION);
	struct sandbox *sandbox;
	u64 err_code;

	if (!sp)
		return VM_FAULT_SIGBUS;
	sandbox = sp->sandbox;
	if (!c || c->sandbox != sandbox || READ_ONCE(sandbox->dying))
		return VM_FAULT_SIGBUS;
	if (!user)
		return VM_FAULT_SIGBUS;

	err_code = (mkwrite ? 1ULL : 0ULL) | (write ? 2ULL : 0ULL) | 4ULL |
		   (exec ? 16ULL : 0ULL);
	if (c->urec) {
		WRITE_ONCE(c->urec->trap_num, X86_TRAP_PF);
		WRITE_ONCE(c->urec->error_code, err_code);
		WRITE_ONCE(c->urec->fault_addr, vmf->address);
	}
	c->exc_trap = X86_TRAP_PF;
	c->exc_error = err_code;
	c->exc_addr = vmf->address;
	c->exc_pending = true;
	set_thread_flag(TIF_NOTIFY_RESUME);
	atomic64_inc(&sandbox->stats.exceptions);
	atomic64_inc(&sandbox->stats.page_faults);
	return VM_FAULT_NOPAGE;
}

static vm_fault_t space_fault(struct vm_fault *vmf)
{
	return space_report(vmf, false);
}

static vm_fault_t space_pfn_mkwrite(struct vm_fault *vmf)
{
	return space_report(vmf, true);
}

static const struct vm_operations_struct space_vm_ops = {
	.fault = space_fault,
	.pfn_mkwrite = space_pfn_mkwrite,
};

static int space_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct user_space *sp = file->private_data;

	if (!current->carrier_hooks || !sp || vma->vm_mm != sp->mm)
		return -EINVAL;

	vm_flags_set(vma, VM_PFNMAP | VM_IO | VM_DONTEXPAND | VM_DONTDUMP |
			  VM_DONTCOPY);
	vma->vm_ops = &space_vm_ops;
	return 0;
}

static const struct file_operations space_fops = {
	.owner = THIS_MODULE,
	.mmap = space_mmap,
	.llseek = noop_llseek,
};

static int space_make_area(struct user_space *sp)
{
	struct mm_struct *prev, *back;
	struct vm_area_struct *vma;
	unsigned long ret;
	bool ok = false;

	mmget(sp->mm);
	prev = kernelet_switch_mm(sp->mm);

	ret = vm_mmap(sp->file, WINDOW_START, TASK_SIZE_MAX - WINDOW_START,
		      PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_FIXED,
		      WINDOW_START);
	if (!IS_ERR_VALUE(ret) && ret == WINDOW_START) {
		mmap_read_lock(sp->mm);
		vma = vma_lookup(sp->mm, WINDOW_START);
		ok = vma && vma->vm_start == WINDOW_START &&
		     vma->vm_end == TASK_SIZE_MAX &&
		     (vma->vm_flags & VM_PFNMAP) && (vma->vm_flags & VM_SHARED);
		mmap_read_unlock(sp->mm);
	}

	back = kernelet_switch_mm(prev);
	if (back)
		mmput(back);

	if (IS_ERR_VALUE(ret))
		return (int)ret;
	if (!ok)
		return -EINVAL;
	sp->start = WINDOW_START;
	sp->end = TASK_SIZE_MAX;
	return 0;
}

// ------------------------------------------------------------------
// Space lifecycle (`pt_root_register`, `pt_root_unregister`, `pt_activate`)
// ------------------------------------------------------------------

s64 do_pt_root_register(struct carrier *c, u64 root_paddr)
{
	struct sandbox *sandbox = c->sandbox;
	struct user_space *sp;
	struct mm_struct *mm;
	struct file *file = NULL;
	int err;

	if (root_paddr != 0) {
		sp = space_get(sandbox, root_paddr);
		if (!sp)
			return -ABI_INVALID;
		space_put(sp);
		return 0;
	}

	sp = kzalloc(sizeof(*sp), GFP_KERNEL);
	if (!sp)
		return -ENOMEM;

	mm = kernelet_mm_alloc(sandbox->owner);
	if (!mm) {
		kfree(sp);
		return -ENOMEM;
	}
	set_mask_bits(&mm->flags, MMF_DUMPABLE_MASK, SUID_DUMP_DISABLE);

	sp->sandbox = sandbox;
	sp->mm = mm;
	sp->start = WINDOW_START;
	sp->end = TASK_SIZE_MAX;

	if (sandbox->pt_mode == PT_MODE_VMA) {
		file = anon_inode_create_getfile("[user-space]", &space_fops,
						 sp, O_RDWR, NULL);
		if (IS_ERR(file)) {
			err = PTR_ERR(file);
			mmput(mm);
			kfree(sp);
			return err;
		}
		sp->file = file;
		err = space_make_area(sp);
		if (err) {
			fput(file);
			mmput(mm);
			kfree(sp);
			return err;
		}
	}

	sp->root_paddr = (u64)__pa(mm->pgd);
	atomic_set(&sp->users, 1);
	smp_store_release(&sp->live, true);

	spin_lock(&sandbox->spaces_lock);
	hash_add_rcu(sandbox->spaces_ht, &sp->hnode, sp->root_paddr);
	spin_unlock(&sandbox->spaces_lock);

	atomic64_inc(&sandbox->stats.vm_creates);
	return (s64)sp->root_paddr;
}

static void space_teardown(struct sandbox *sandbox, struct carrier *c,
			   struct user_space *sp)
{
	struct mm_struct *mm = sp->mm;
	struct file *file = sp->file;

	if (!atomic_dec_and_test(&sp->users))
		wait_var_event(&sp->users, atomic_read(&sp->users) == 0);

	// Detach calling carrier if it still holds `sp->mm`.
	if (c && current->mm == mm && c->own_mm) {
		struct mm_struct *old;

		mmget(c->own_mm);
		old = kernelet_switch_mm(c->own_mm);
		if (old && old != c->own_mm)
			mmput(old);
	}

	if (mm) {
		if (sandbox->pt_mode == PT_MODE_VMA) {
			struct vm_area_struct *vma;

			mmap_read_lock(mm);
			vma = vma_lookup(mm, sp->start);
			if (vma && vma->vm_file == file && (vma->vm_flags & VM_PFNMAP))
				zap_vma_ptes(vma, sp->start, sp->end - sp->start);
			mmap_read_unlock(mm);
		} else {
			// Direct PTE mode: clear user PGD entries 0..255 without
			// inspecting or freeing Asterinas-owned lower page tables.
			memset(mm->pgd, 0, KERNEL_HALF_START * sizeof(pgd_t));
			if (boot_cpu_has(X86_FEATURE_PTI)) {
				pgd_t *user_pgd = (pgd_t *)((unsigned long)mm->pgd + PAGE_SIZE);

				memset(user_pgd, 0, KERNEL_HALF_START * sizeof(pgd_t));
			}
			smp_wmb();
		}
		flush_tlb_mm_range(mm, 0, TLB_FLUSH_ALL, 0, true);
#ifdef CONFIG_MEMCG
		WRITE_ONCE(mm->owner, NULL);
#endif
	}

	sp->file = NULL;
	if (file)
		fput(file);

	atomic64_inc(&sandbox->stats.vm_destroys);

	// The image may release its lower page tables as soon as this returns.
	synchronize_rcu();
	if (mm)
		mmput(mm);
	kfree(sp);
}

s64 do_pt_root_unregister(struct carrier *c, u64 root_paddr)
{
	struct sandbox *sandbox = c->sandbox;
	struct user_space *sp;

	if (!root_paddr)
		return -ABI_INVALID;

	spin_lock(&sandbox->spaces_lock);
	sp = space_find_rcu(sandbox, root_paddr);
	if (sp) {
		WRITE_ONCE(sp->live, false);
		hash_del_rcu(&sp->hnode);
	}
	spin_unlock(&sandbox->spaces_lock);

	if (!sp)
		return -ABI_INVALID;

	space_teardown(sandbox, c, sp);
	return 0;
}

// Non-sleeping root activation.
s64 do_pt_activate(struct carrier *c, u64 root_paddr)
{
	struct sandbox *sandbox = c->sandbox;
	struct mm_struct *target, *old;

	if (root_paddr == 0) {
		target = c->own_mm;
		if (!target)
			return -ABI_STATE;
		if (current->mm != target) {
			mmget(target);
			old = kernelet_switch_mm(target);
			if (old && old != target)
				mmput_async(old);
		}
		return 0;
	}

	rcu_read_lock();
	{
		struct user_space *sp = space_find_rcu(sandbox, root_paddr);

		target = sp ? sp->mm : NULL;
		if (target && !mmget_not_zero(target))
			target = NULL;
	}
	rcu_read_unlock();

	if (!target)
		return -ABI_INVALID;

	if (current->mm != target) {
		old = kernelet_switch_mm(target);
		if (old && old != target)
			mmput_async(old);
	} else {
		mmput_async(target);
	}
	return 0;
}

void leave_space(struct carrier *c)
{
	struct mm_struct *old;

	if (!c->own_mm || !current->mm || current->mm == c->own_mm)
		return;

	mmget(c->own_mm);
	old = kernelet_switch_mm(c->own_mm);
	if (old && old != c->own_mm)
		mmput(old);
}

s64 do_tlb_shootdown(struct carrier *c, u64 root_paddr, u64 start, u64 len)
{
	struct user_space *sp;

	if (root_paddr == 0) {
		if (start != 0 || len != U64_MAX)
			return -ABI_INVALID;
		if (current->mm)
			flush_tlb_mm_range(current->mm, 0, TLB_FLUSH_ALL, 0, false);
		atomic64_inc(&c->sandbox->stats.vm_flushes);
		return 0;
	}

	sp = space_get(c->sandbox, root_paddr);
	if (!sp)
		return -ABI_INVALID;

	// `UserPtConfig::CAN_PRUNE_SUBTREE` is `false` for kernelet spaces, so
	// intermediate page-table frames stay live until `do_pt_root_unregister`
	// runs `flush_tlb_mm_range(..., true)` and `synchronize_rcu()`.
	atomic64_inc(&c->sandbox->stats.vm_flushes);
	if (len == U64_MAX) {
		flush_tlb_mm_range(sp->mm, 0, TLB_FLUSH_ALL, 0, false);
	} else {
		if ((start & ~PAGE_MASK) || (len & ~PAGE_MASK) ||
		    start + len < start || start + len > TASK_SIZE_MAX) {
			space_put(sp);
			return -ABI_INVALID;
		}
		if (len)
			flush_tlb_mm_range(sp->mm, start, start + len,
					   PAGE_SHIFT, false);
	}
	space_put(sp);
	return 0;
}

void spaces_init(struct sandbox *sandbox)
{
	spin_lock_init(&sandbox->spaces_lock);
	hash_init(sandbox->spaces_ht);
}

void spaces_destroy(struct sandbox *sandbox)
{
	struct user_space *sp;
	struct hlist_node *tmp;
	HLIST_HEAD(dead);
	int bkt;

	spin_lock(&sandbox->spaces_lock);
	hash_for_each_safe(sandbox->spaces_ht, bkt, tmp, sp, hnode) {
		WRITE_ONCE(sp->live, false);
		hash_del_rcu(&sp->hnode);
		hlist_add_head(&sp->hnode, &dead);
	}
	spin_unlock(&sandbox->spaces_lock);

	hlist_for_each_entry_safe(sp, tmp, &dead, hnode) {
		hlist_del(&sp->hnode);
		space_teardown(sandbox, NULL, sp);
	}

	if (sandbox->owner) {
		put_task_struct(sandbox->owner);
		sandbox->owner = NULL;
	}
}

// ------------------------------------------------------------------
// `buffer` VMA baseline ops
// ------------------------------------------------------------------

static int prot_to_pgprot(u64 prot_bits, pgprot_t *out)
{
	unsigned long vm_flags = VM_SHARED;

	if (prot_bits & ~(KLET_PROT_READ | KLET_PROT_WRITE | KLET_PROT_EXEC))
		return -ABI_INVALID;
	if (!(prot_bits & KLET_PROT_READ))
		return -ABI_INVALID;
	vm_flags |= VM_READ;
	if (prot_bits & KLET_PROT_WRITE)
		vm_flags |= VM_WRITE;
	if (prot_bits & KLET_PROT_EXEC)
		vm_flags |= VM_EXEC;
	*out = vm_get_page_prot(vm_flags);
	return 0;
}

static struct vm_area_struct *space_lock_vma(struct user_space *sp)
{
	struct vm_area_struct *vma;

	mmap_read_lock(sp->mm);
	vma = vma_lookup(sp->mm, sp->start);
	if (!vma || vma->vm_file != sp->file || !(vma->vm_flags & VM_PFNMAP)) {
		mmap_read_unlock(sp->mm);
		return NULL;
	}
	return vma;
}

struct pte_protect_ctx {
	pgprot_t prot;
	bool done;
};

static int pte_protect_cb(pte_t *pte, unsigned long addr, void *data)
{
	struct pte_protect_ctx *ctx = data;
	pte_t old = ptep_get(pte), new;

	if (!pte_present(old))
		return -EINVAL;
	do {
		new = pte_modify(old, ctx->prot);
	} while (!try_cmpxchg64((u64 *)&pte->pte, (u64 *)&old.pte, pte_val(new)));
	ctx->done = true;
	return 0;
}

static struct mmio_result res(s64 status, u64 value)
{
	return (struct mmio_result){ .status = status, .value = value };
}

static struct mmio_result op_vm_map(struct sandbox *sandbox, u64 root_paddr,
					    u64 va, u64 paddr, u64 prot_bits)
{
	struct user_space *sp;
	struct vm_area_struct *vma;
	pgprot_t pgprot;
	vm_fault_t vmf;
	int err;

	if (sandbox->pt_mode != PT_MODE_VMA)
		return res(-ABI_STATE, 0);
	err = prot_to_pgprot(prot_bits, &pgprot);
	if (err)
		return res(err, 0);
	if ((va & ~PAGE_MASK) || (paddr & ~PAGE_MASK))
		return res(-ABI_INVALID, 0);
	if (!pfn_valid(paddr >> PAGE_SHIFT) || !in_grant(sandbox, paddr, PAGE_SIZE))
		return res(-ABI_NOT_OWNED, 0);

	sp = space_get(sandbox, root_paddr);
	if (!sp)
		return res(-ABI_INVALID, 0);
	if (va < sp->start || va >= sp->end) {
		space_put(sp);
		return res(-ABI_INVALID, 0);
	}

	atomic64_inc(&sandbox->stats.vm_maps);
	vma = space_lock_vma(sp);
	if (!vma) {
		space_put(sp);
		return res(-ABI_INVALID, 0);
	}
	vmf = vmf_insert_pfn_prot(vma, va, paddr >> PAGE_SHIFT, pgprot);
	mmap_read_unlock(sp->mm);
	space_put(sp);

	if (vmf & VM_FAULT_OOM)
		return res(-ABI_LIMIT, 0);
	if (vmf != VM_FAULT_NOPAGE)
		return res(-ABI_INVALID, 0);
	return res(0, 0);
}

static struct mmio_result op_vm_protect(struct sandbox *sandbox, u64 root_paddr,
						u64 va, u64 prot_bits)
{
	struct user_space *sp;
	struct vm_area_struct *vma;
	struct pte_protect_ctx ctx = { .done = false };
	int err;

	if (sandbox->pt_mode != PT_MODE_VMA)
		return res(-ABI_STATE, 0);
	if (va & ~PAGE_MASK)
		return res(-ABI_INVALID, 0);

	sp = space_get(sandbox, root_paddr);
	if (!sp)
		return res(-ABI_INVALID, 0);
	if (va < sp->start || va >= sp->end) {
		space_put(sp);
		return res(-ABI_INVALID, 0);
	}

	atomic64_inc(&sandbox->stats.vm_protects);
	vma = space_lock_vma(sp);
	if (!vma) {
		space_put(sp);
		return res(-ABI_INVALID, 0);
	}

	if (!(prot_bits & KLET_PROT_READ)) {
		// Linux `VM_PFNMAP` has no `!R` present PTE; zap instead.
		zap_vma_ptes(vma, va, PAGE_SIZE);
		mmap_read_unlock(sp->mm);
		space_put(sp);
		return res(0, 0);
	}

	err = prot_to_pgprot(prot_bits, &ctx.prot);
	if (!err)
		err = apply_to_page_range(sp->mm, va, PAGE_SIZE,
					  pte_protect_cb, &ctx);
	mmap_read_unlock(sp->mm);
	space_put(sp);
	return res((err || !ctx.done) ? -ABI_INVALID : 0, 0);
}

static struct mmio_result op_vm_unmap(struct sandbox *sandbox, u64 root_paddr,
					      u64 va, u64 len)
{
	struct user_space *sp;
	struct vm_area_struct *vma;
	u64 end;

	if (sandbox->pt_mode != PT_MODE_VMA)
		return res(-ABI_STATE, 0);
	if ((va & ~PAGE_MASK) || (len & ~PAGE_MASK) || len == 0 || va + len < va)
		return res(-ABI_INVALID, 0);

	sp = space_get(sandbox, root_paddr);
	if (!sp)
		return res(-ABI_INVALID, 0);

	atomic64_inc(&sandbox->stats.vm_unmaps);
	end = min_t(u64, va + len, sp->end);
	if (va < sp->start)
		va = sp->start;
	if (va < end) {
		vma = space_lock_vma(sp);
		if (!vma) {
			space_put(sp);
			return res(-ABI_INVALID, 0);
		}
		zap_vma_ptes(vma, va, end - va);
		mmap_read_unlock(sp->mm);
	}
	space_put(sp);
	return res(0, 0);
}

struct mmio_result do_buffer(struct carrier *c, u32 op, u64 token,
				     u64 arg0, u64 arg1, u64 arg2)
{
	struct sandbox *sandbox = c->sandbox;

	switch (op) {
	case BUFFER_VM_MAP:
		return op_vm_map(sandbox, token, arg0, arg1, arg2);
	case BUFFER_VM_PROTECT:
		return op_vm_protect(sandbox, token, arg0, arg1);
	case BUFFER_VM_UNMAP:
		return op_vm_unmap(sandbox, token, arg0, arg1);
	default:
		return res(-ABI_INVALID, 0);
	}
}
