// SPDX-License-Identifier: GPL-2.0
// Grant allocator, sparse `meta_base` window, guarded stack pool, initramfs
// mapping, and boot/shared page builder for `endovisor`.

#include <linux/bitmap.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/log2.h>
#include <linux/mm.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <asm/cpufeature.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/tsc.h>

#include "endovisor.h"

static u32 fpu_area_size(void)
{
	u32 eax, ebx, ecx, edx;

	if (!boot_cpu_has(X86_FEATURE_XSAVE))
		return 512;
	cpuid_count(0xd, 0, &eax, &ebx, &ecx, &edx);
	if (ebx < 512)
		return 512;
	if (ebx > 4096)
		return 4096;
	return ebx;
}

static void init_meta_page(struct page *page)
{
	u8 *base = page_address(page);
	size_t off;

	for (off = 0; off < PAGE_SIZE; off += META_SLOT_BYTES)
		*(u64 *)(base + off + META_REF_COUNT_OFFSET) = U64_MAX;
}

static int add_grain_locked(struct sandbox *sandbox, struct page *head_page)
{
	u64 paddr = page_to_phys(head_page);
	u64 section = paddr / META_SECTION_BYTES;
	u32 block, grain_in_sec;
	unsigned long va;
	struct grain_record *rec;
	struct page *meta_pages[META_PAGES_PER_GRAIN] = {};
	unsigned int i;
	int err;

	if (sandbox->nr_grains >= sandbox->max_grains)
		return -ENOSPC;
	if (section >= sandbox->nr_phys_sections)
		return -ERANGE;

	block = sandbox->meta_section_index[section];
	if (block == NO_META_BLOCK) {
		if (sandbox->nr_meta_blocks >= sandbox->max_meta_sections)
			return -ENOSPC;
		block = sandbox->nr_meta_blocks;
	}

	for (i = 0; i < META_PAGES_PER_GRAIN; i++) {
		meta_pages[i] = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!meta_pages[i]) {
			err = -ENOMEM;
			goto fail_pages;
		}
		init_meta_page(meta_pages[i]);
	}

	grain_in_sec = (paddr % META_SECTION_BYTES) / GRAIN_SIZE;
	va = (unsigned long)sandbox->meta_area->addr +
	     (unsigned long)block * GRAIN_SIZE +
	     (unsigned long)grain_in_sec * META_PAGES_PER_GRAIN * PAGE_SIZE;

	err = vm_area_map_pages(sandbox->meta_area, va,
				va + META_PAGES_PER_GRAIN * PAGE_SIZE,
				meta_pages);
	if (err) {
		vm_area_unmap_pages(sandbox->meta_area, va,
				    va + META_PAGES_PER_GRAIN * PAGE_SIZE);
		goto fail_pages;
	}

	if (sandbox->meta_section_index[section] == NO_META_BLOCK) {
		sandbox->nr_meta_blocks++;
		WRITE_ONCE(sandbox->meta_block_sections[block], (u32)section);
		smp_store_release(&sandbox->meta_section_index[section], block);
	}

	// Publish grain bitmap and descriptor after metadata mappings are live.
	{
		u64 old_bmp = READ_ONCE(sandbox->meta_grain_bitmap[block]);

		smp_store_release(&sandbox->meta_grain_bitmap[block],
				  old_bmp | (1ULL << grain_in_sec));
	}

	rec = &sandbox->grains[sandbox->nr_grains++];
	rec->head_page = head_page;
	rec->paddr = paddr;
	rec->block = block;
	rec->grain_in_sec = grain_in_sec;
	memcpy(rec->meta_pages, meta_pages, sizeof(meta_pages));

	// Published descriptors are immutable, including during later refills.
	sandbox->grant_table[sandbox->nr_runs].paddr = paddr;
	sandbox->grant_table[sandbox->nr_runs].grains = 1;
	sandbox->grant_table[sandbox->nr_runs].reserved = 0;
	sandbox->nr_runs++;

	if (paddr + GRAIN_SIZE > sandbox->max_paddr)
		WRITE_ONCE(sandbox->max_paddr, paddr + GRAIN_SIZE);
	smp_store_release(&sandbox->info_page->max_paddr, sandbox->max_paddr);
	smp_store_release(&sandbox->info_page->meta_blocks, sandbox->nr_meta_blocks);
	smp_store_release(&sandbox->info_page->runs, sandbox->nr_runs);
	sandbox->grant_grains_allocated++;
	atomic64_inc(&endo_live_grains);
	atomic64_add(META_PAGES_PER_GRAIN, &endo_live_meta_pages);
	return 0;

fail_pages:
	for (i = 0; i < META_PAGES_PER_GRAIN; i++)
		if (meta_pages[i])
			__free_page(meta_pages[i]);
	return err;
}

s64 do_grains_request(struct sandbox *sandbox, u32 count, u32 contiguous)
{
	u32 allocated = 0;
	u32 batch;
	size_t bytes;

	if (count == 0 || count > MAX_GRAINS_PER_REQUEST)
		return -ABI_INVALID;

	mutex_lock(&sandbox->grant_mutex);
	if (sandbox->nr_grains >= sandbox->max_grains)
		goto out;
	if (count > sandbox->max_grains - sandbox->nr_grains) {
		if (contiguous) {
			mutex_unlock(&sandbox->grant_mutex);
			return -ABI_LIMIT;
		}
		count = sandbox->max_grains - sandbox->nr_grains;
	}

	batch = contiguous ? count : 1;
	bytes = (size_t)batch * GRAIN_SIZE;
	if (get_order(bytes) > MAX_PAGE_ORDER)
		goto out;

	while (allocated < count) {
		void *memory;
		u32 i;

		memory = alloc_pages_exact(bytes,
					 GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN);
		if (!memory)
			break;
		for (i = 0; i < batch; i++) {
			struct page *grain = virt_to_page(memory + (size_t)i * GRAIN_SIZE);

			if (add_grain_locked(sandbox, grain))
				break;
			allocated++;
		}
		if (i != batch) {
			free_pages_exact(memory + (size_t)i * GRAIN_SIZE,
					 (size_t)(batch - i) * GRAIN_SIZE);
			break;
		}
	}
out:
	mutex_unlock(&sandbox->grant_mutex);
	return allocated;
}

static unsigned long stack_slot_base(struct sandbox *sandbox, unsigned int idx)
{
	return sandbox->stack_pool_start + (unsigned long)idx * KSTACK_STRIDE;
}

static unsigned long stack_slot_usable(struct sandbox *sandbox, unsigned int idx)
{
	return stack_slot_base(sandbox, idx) + KSTACK_BYTES;
}

u64 kstack_alloc(struct sandbox *sandbox, bool is_boot)
{
	unsigned int start, end, i;
	int slot = -1;
	unsigned long usable;

	mutex_lock(&sandbox->stack_mutex);
	start = is_boot ? 0 : sandbox->nr_vcpus;
	end = is_boot ? sandbox->nr_vcpus : sandbox->kstack_slots;

	for (i = start; i < end; i++) {
		if (!sandbox->kstack_table[i].allocated) {
			slot = (int)i;
			break;
		}
	}
	if (slot < 0) {
		mutex_unlock(&sandbox->stack_mutex);
		return 0;
	}

	usable = stack_slot_usable(sandbox, slot);
	if (!sandbox->kstack_table[slot].mapped) {
		struct page **pages = kvcalloc(KSTACK_PAGES, sizeof(*pages), GFP_KERNEL);
		int err;

		if (!pages) {
			mutex_unlock(&sandbox->stack_mutex);
			return 0;
		}
		for (i = 0; i < KSTACK_PAGES; i++) {
			pages[i] = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
			if (!pages[i]) {
				while (i--)
					__free_page(pages[i]);
				kvfree(pages);
				mutex_unlock(&sandbox->stack_mutex);
				return 0;
			}
		}
		// Leave `[slot_base, slot_base + KSTACK_BYTES)` unmapped as guard.
		err = vm_area_map_pages(sandbox->stack_area, usable,
					usable + KSTACK_BYTES, pages);
		if (err) {
			vm_area_unmap_pages(sandbox->stack_area, usable,
					    usable + KSTACK_BYTES);
			for (i = 0; i < KSTACK_PAGES; i++)
				__free_page(pages[i]);
			kvfree(pages);
			mutex_unlock(&sandbox->stack_mutex);
			return 0;
		}
		sandbox->kstack_table[slot].pages = pages;
		sandbox->kstack_table[slot].mapped = true;
		atomic64_add(KSTACK_PAGES, &endo_live_kstack_pages);
	}

	sandbox->kstack_table[slot].allocated = true;
	set_bit(slot, sandbox->live_stacks_bitmap);
	mutex_unlock(&sandbox->stack_mutex);
	return usable;
}

s64 kstack_free(struct sandbox *sandbox, u64 vaddr)
{
	unsigned long offset;
	unsigned int slot;

	if (vaddr < sandbox->stack_pool_start || vaddr >= sandbox->stack_pool_end)
		return -ABI_INVALID;
	offset = vaddr - sandbox->stack_pool_start;
	if ((offset % KSTACK_STRIDE) != KSTACK_BYTES)
		return -ABI_INVALID;
	slot = offset / KSTACK_STRIDE;
	if (slot >= sandbox->kstack_slots)
		return -ABI_INVALID;

	mutex_lock(&sandbox->stack_mutex);
	if (!sandbox->kstack_table[slot].allocated) {
		mutex_unlock(&sandbox->stack_mutex);
		return -ABI_INVALID;
	}
	clear_bit(slot, sandbox->live_stacks_bitmap);
	// Publish the cleared live bit before advancing `kstack_free_gen` so a
	// concurrent `enter_user_event` slow path cannot cache a freed slot
	// under the new generation.
	smp_mb__after_atomic();
	atomic64_inc(&sandbox->kstack_free_gen);
	sandbox->kstack_table[slot].allocated = false;
	mutex_unlock(&sandbox->stack_mutex);
	return 0;
}

// Resolves `addr` inside a live allocated stack slot and outputs its `[usable, top]` bounds.
bool stack_pool_slot_bounds(struct sandbox *sandbox, unsigned long addr,
			    unsigned long *usable_out, unsigned long *top_out)
{
	unsigned long offset, usable;
	unsigned int slot;

	BUILD_BUG_ON(!is_power_of_2(KSTACK_STRIDE));
	if (addr < sandbox->stack_pool_start || addr >= sandbox->stack_pool_end)
		return false;
	offset = addr - sandbox->stack_pool_start;
	if ((offset & (KSTACK_STRIDE - 1)) < KSTACK_BYTES)
		return false;
	slot = offset >> ilog2(KSTACK_STRIDE);
	if (slot >= sandbox->kstack_slots ||
	    !test_bit(slot, sandbox->live_stacks_bitmap))
		return false;
	usable = stack_slot_usable(sandbox, slot);
	*usable_out = usable;
	*top_out = usable + KSTACK_BYTES;
	return true;
}

bool stack_pool_contains(struct sandbox *sandbox, unsigned long addr)
{
	unsigned long usable, top;

	return stack_pool_slot_bounds(sandbox, addr, &usable, &top);
}

bool stack_pool_is_guard_addr(struct sandbox *sandbox, unsigned long addr)
{
	unsigned long offset;
	unsigned int slot;

	if (addr < sandbox->stack_pool_start || addr >= sandbox->stack_pool_end)
		return false;
	offset = addr - sandbox->stack_pool_start;
	slot = offset / KSTACK_STRIDE;
	return (offset % KSTACK_STRIDE) < KSTACK_BYTES &&
	       slot < sandbox->kstack_slots;
}

void stack_pool_destroy(struct sandbox *sandbox)
{
	unsigned int i, j;

	if (sandbox->kstack_table) {
		for (i = 0; i < sandbox->kstack_slots; i++) {
			if (sandbox->kstack_table[i].mapped) {
				unsigned long usable = stack_slot_usable(sandbox, i);

				vm_area_unmap_pages(sandbox->stack_area, usable,
						    usable + KSTACK_BYTES);
			}
		}
	}
	if (sandbox->stack_area) {
		free_vm_area(sandbox->stack_area);
		sandbox->stack_area = NULL;
	}
	vm_unmap_aliases();
	if (sandbox->kstack_table) {
		for (i = 0; i < sandbox->kstack_slots; i++) {
			struct page **pages = sandbox->kstack_table[i].pages;

			if (!pages)
				continue;
			for (j = 0; j < KSTACK_PAGES; j++)
				if (pages[j]) {
					__free_page(pages[j]);
					atomic64_dec(&endo_live_kstack_pages);
				}
			kvfree(pages);
		}
		kvfree(sandbox->kstack_table);
		sandbox->kstack_table = NULL;
	}
	bitmap_free(sandbox->live_stacks_bitmap);
	sandbox->live_stacks_bitmap = NULL;
}

int grant_init(struct sandbox *sandbox, const u8 __user *uinitrd, size_t initrd_len)
{
	struct sysinfo si;
	u64 max_ram_bytes, max_indexed_bytes;
	unsigned int record_pages, run_pages, index_pages, reverse_pages, bitmap_pages;
	unsigned int i;
	struct boot_args *boot;
	u8 *shared_base;
	int err = -ENOMEM;

	mutex_init(&sandbox->grant_mutex);
	mutex_init(&sandbox->stack_mutex);
	if (check_add_overflow(sandbox->max_tasks, sandbox->nr_vcpus,
			       &sandbox->kstack_slots) || sandbox->kstack_slots == U32_MAX)
		return -EINVAL;

	sandbox->max_grains = max_t(unsigned int, 1, DIV_ROUND_UP(sandbox->grant_mb, 2));
	if (sandbox->max_grains > MAX_GRAINS_TOTAL)
		sandbox->max_grains = MAX_GRAINS_TOTAL;
	sandbox->max_meta_sections = sandbox->max_grains;

	si_meminfo(&si);
	max_ram_bytes = (u64)si.totalram << PAGE_SHIFT;
	max_indexed_bytes = max_t(u64, 1ULL << 40,
				  round_up(max_ram_bytes * 4, META_SECTION_BYTES));
	sandbox->nr_phys_sections = max_indexed_bytes / META_SECTION_BYTES;

	sandbox->meta_area = get_vm_area((unsigned long)sandbox->max_meta_sections * GRAIN_SIZE,
				       VM_ALLOC | VM_SPARSE);
	if (!sandbox->meta_area)
		goto fail;

	sandbox->grains = kvcalloc(sandbox->max_grains, sizeof(*sandbox->grains), GFP_KERNEL);
	if (!sandbox->grains)
		goto fail;

	record_pages = DIV_ROUND_UP(sandbox->nr_vcpus * 256U, PAGE_SIZE);
	run_pages = DIV_ROUND_UP((u64)sandbox->max_meta_sections * GRAINS_PER_SECTION *
				 sizeof(struct run_desc), PAGE_SIZE);
	index_pages = DIV_ROUND_UP((u64)sandbox->nr_phys_sections * sizeof(u32), PAGE_SIZE);
	reverse_pages = DIV_ROUND_UP((u64)sandbox->max_meta_sections * sizeof(u32), PAGE_SIZE);
	bitmap_pages = DIV_ROUND_UP((u64)sandbox->max_meta_sections * sizeof(u64), PAGE_SIZE);
	sandbox->total_shared_pages = 1 + record_pages + 1 + run_pages +
				   index_pages + reverse_pages + bitmap_pages;

	sandbox->shared_pages = kvcalloc(sandbox->total_shared_pages,
				      sizeof(*sandbox->shared_pages), GFP_KERNEL);
	if (!sandbox->shared_pages)
		goto fail;
	for (i = 0; i < sandbox->total_shared_pages; i++) {
		sandbox->shared_pages[i] = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!sandbox->shared_pages[i])
			goto fail;
		atomic64_inc(&endo_live_shared_pages);
	}

	sandbox->shared_vmap = vmap(sandbox->shared_pages, sandbox->total_shared_pages,
				 VM_MAP, PAGE_KERNEL);
	if (!sandbox->shared_vmap)
		goto fail;

	shared_base = sandbox->shared_vmap;
	sandbox->boot_page = (struct boot_args *)shared_base;
	sandbox->info_page = (struct info_page *)(shared_base + (1 + record_pages) * PAGE_SIZE);
	sandbox->grant_table = (struct run_desc *)(shared_base + (2 + record_pages) * PAGE_SIZE);
	sandbox->meta_section_index = (u32 *)(shared_base +
		(2 + record_pages + run_pages) * PAGE_SIZE);
	sandbox->meta_block_sections = (u32 *)(shared_base +
		(2 + record_pages + run_pages + index_pages) * PAGE_SIZE);
	sandbox->meta_grain_bitmap = (u64 *)(shared_base +
		(2 + record_pages + run_pages + index_pages + reverse_pages) * PAGE_SIZE);

	memset(sandbox->meta_section_index, 0xff, index_pages * PAGE_SIZE);
	memset(sandbox->meta_block_sections, 0xff, reverse_pages * PAGE_SIZE);

	// Copy and map initramfs read-only if supplied.
	if (initrd_len > 0) {
		size_t left = initrd_len, pos = 0;

		sandbox->nr_initramfs_pages = DIV_ROUND_UP(initrd_len, PAGE_SIZE);
		sandbox->initramfs_pages = kvcalloc(sandbox->nr_initramfs_pages,
						 sizeof(*sandbox->initramfs_pages),
						 GFP_KERNEL);
		if (!sandbox->initramfs_pages)
			goto fail;
		for (i = 0; i < sandbox->nr_initramfs_pages; i++) {
			size_t chunk = min_t(size_t, PAGE_SIZE, left);

			sandbox->initramfs_pages[i] = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
			if (!sandbox->initramfs_pages[i])
				goto fail;
			if (copy_from_user(page_address(sandbox->initramfs_pages[i]),
					   uinitrd + pos, chunk)) {
				err = -EFAULT;
				goto fail;
			}
			pos += chunk;
			left -= chunk;
		}
		sandbox->initramfs_vmap = vmap(sandbox->initramfs_pages,
					    sandbox->nr_initramfs_pages,
					    VM_MAP, PAGE_KERNEL_RO);
		if (!sandbox->initramfs_vmap) {
			err = -ENOMEM;
			goto fail;
		}
		sandbox->initramfs_len = initrd_len;
	}

	// Capture TSC calibration and populate `BootArgs`.
	sandbox->tsc_freq_hz = tsc_khz ? (u64)tsc_khz * 1000ULL : 1000000000ULL;
	sandbox->clock_origin_tsc = rdtsc_ordered();
	sandbox->monotonic_base_ns = ktime_get_ns();
	sandbox->realtime_base_ns = ktime_get_real_ns();

	boot = sandbox->boot_page;
	boot->size = sizeof(*boot);
	boot->generation = sandbox->generation;
	memcpy(boot->source_hash, sandbox->kind->entry_table.source_hash,
	       sizeof(boot->source_hash));
	boot->tsc_freq_hz = sandbox->tsc_freq_hz;
	boot->clock_origin_tsc = sandbox->clock_origin_tsc;
	boot->kernelet = (u16)sandbox->slot;
	boot->num_vcpus = (u16)sandbox->nr_vcpus;
	for (i = 0; i < MAX_VCPUS; i++)
		boot->vcpu_host_cpu[i] = (u16)i;
	boot->cpu_slot_gs_offset = cpu_slot_offset;
	boot->cpu_local_replica_bytes = sandbox->cpu_local_pages_per_vcpu * PAGE_SIZE;
	boot->linear_map_base = (u64)(unsigned long)__va(0);
	boot->meta_base = (u64)(unsigned long)sandbox->meta_area->addr;
	boot->vcpu_records = PAGE_SIZE;
	boot->info_page = (1 + record_pages) * PAGE_SIZE;
	boot->grant_table = (2 + record_pages) * PAGE_SIZE;
	boot->meta_section_index = boot->grant_table + run_pages * PAGE_SIZE;
	boot->meta_block_sections = boot->meta_section_index + index_pages * PAGE_SIZE;
	boot->meta_grain_bitmap = boot->meta_block_sections + reverse_pages * PAGE_SIZE;
	boot->max_meta_sections = sandbox->max_meta_sections;
	boot->max_tasks = sandbox->max_tasks;
	boot->fpu_area_bytes = fpu_area_size();
	boot->cmdline_offset = sizeof(*boot);
	boot->cmdline_len = (u32)sandbox->cmdline_len;
	if (sandbox->cmdline_len)
		memcpy((u8 *)boot + boot->cmdline_offset, sandbox->cmdline, sandbox->cmdline_len);
	boot->devices_offset = ALIGN(boot->cmdline_offset + boot->cmdline_len, 8);
	boot->num_devices = 0;
	boot->pti_enabled = boot_cpu_has(X86_FEATURE_PTI) ? 1 : 0;
	boot->nx_supported = (__supported_pte_mask & _PAGE_NX) ? 1 : 0;
	boot->pgtable_levels = pgtable_l5_enabled() ? 5 : 4;
	boot->pt_mode = (u8)sandbox->pt_mode;
	boot->realtime_base_ns = sandbox->realtime_base_ns;
	boot->monotonic_base_ns = sandbox->monotonic_base_ns;
	boot->initramfs_base = (u64)(unsigned long)sandbox->initramfs_vmap;
	boot->initramfs_len = sandbox->initramfs_len;

	// Initialize shared per-vCPU records.
	for (i = 0; i < sandbox->nr_vcpus; i++) {
		struct vcpu_record *vrec = (struct vcpu_record *)
			(shared_base + PAGE_SIZE + i * sizeof(struct vcpu_record));

		vrec->vcpu = i;
		vrec->irq_off = 1;
		vrec->cpu_local_base = (u64)(unsigned long)
			((u8 *)sandbox->cpu_local_vmap +
			 (size_t)i * sandbox->cpu_local_pages_per_vcpu * PAGE_SIZE);
	}

	// Reserve the 512 KiB-strided guarded stack pool.
	sandbox->stack_area = get_vm_area((unsigned long)(sandbox->kstack_slots + 1) *
					KSTACK_STRIDE,
					VM_ALLOC | VM_SPARSE);
	if (!sandbox->stack_area) {
		err = -ENOMEM;
		goto fail;
	}
	sandbox->stack_pool_start = ALIGN((unsigned long)sandbox->stack_area->addr,
				       KSTACK_STRIDE);
	sandbox->stack_pool_end = sandbox->stack_pool_start +
			       (unsigned long)sandbox->kstack_slots * KSTACK_STRIDE;
	sandbox->kstack_table = kvcalloc(sandbox->kstack_slots,
				      sizeof(*sandbox->kstack_table), GFP_KERNEL);
	sandbox->live_stacks_bitmap = bitmap_zalloc(sandbox->kstack_slots, GFP_KERNEL);
	if (!sandbox->kstack_table || !sandbox->live_stacks_bitmap) {
		err = -ENOMEM;
		goto fail;
	}

	// Allocate initial grant grains up to `grant_mb`.
	for (i = 0; i < sandbox->max_grains; i++) {
		void *memory = alloc_pages_exact(GRAIN_SIZE,
					 GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN);

		if (!memory) {
			err = -ENOMEM;
			goto fail;
		}
		err = add_grain_locked(sandbox, virt_to_page(memory));
		if (err) {
			free_pages_exact(memory, GRAIN_SIZE);
			goto fail;
		}
	}

	pr_info("endovisor: sandbox %d: grant %u MiB (%u grains, %u runs, %u meta blocks), pt_mode=%u\n",
		sandbox->slot, sandbox->nr_grains * 2, sandbox->nr_grains,
		sandbox->nr_runs, sandbox->nr_meta_blocks, sandbox->pt_mode);
	return 0;

fail:
	grant_destroy(sandbox);
	return err;
}

void grant_destroy(struct sandbox *sandbox)
{
	unsigned int i, j;

	stack_pool_destroy(sandbox);

	if (sandbox->initramfs_vmap) {
		vunmap(sandbox->initramfs_vmap);
		sandbox->initramfs_vmap = NULL;
	}
	if (sandbox->initramfs_pages) {
		for (i = 0; i < sandbox->nr_initramfs_pages; i++)
			if (sandbox->initramfs_pages[i])
				__free_page(sandbox->initramfs_pages[i]);
		kvfree(sandbox->initramfs_pages);
		sandbox->initramfs_pages = NULL;
	}

	if (sandbox->meta_area && sandbox->grains) {
		for (i = 0; i < sandbox->nr_grains; i++) {
			struct grain_record *rec = &sandbox->grains[i];
			unsigned long va = (unsigned long)sandbox->meta_area->addr +
					   (unsigned long)rec->block * GRAIN_SIZE +
					   (unsigned long)rec->grain_in_sec *
					   META_PAGES_PER_GRAIN * PAGE_SIZE;

			vm_area_unmap_pages(sandbox->meta_area, va,
					    va + META_PAGES_PER_GRAIN * PAGE_SIZE);
		}
	}
	if (sandbox->meta_area) {
		free_vm_area(sandbox->meta_area);
		sandbox->meta_area = NULL;
	}
	vm_unmap_aliases();

	if (sandbox->grains) {
		for (i = 0; i < sandbox->nr_grains; i++) {
			struct grain_record *rec = &sandbox->grains[i];

			for (j = 0; j < META_PAGES_PER_GRAIN; j++)
				if (rec->meta_pages[j]) {
					__free_page(rec->meta_pages[j]);
					atomic64_dec(&endo_live_meta_pages);
				}
			if (rec->head_page) {
				free_pages_exact(page_address(rec->head_page), GRAIN_SIZE);
				atomic64_dec(&endo_live_grains);
				sandbox->grant_grains_freed++;
			}
		}
		kvfree(sandbox->grains);
		sandbox->grains = NULL;
	}

	if (sandbox->shared_vmap) {
		vunmap(sandbox->shared_vmap);
		sandbox->shared_vmap = NULL;
	}
	if (sandbox->shared_pages) {
		for (i = 0; i < sandbox->total_shared_pages; i++)
			if (sandbox->shared_pages[i]) {
				__free_page(sandbox->shared_pages[i]);
				atomic64_dec(&endo_live_shared_pages);
			}
		kvfree(sandbox->shared_pages);
		sandbox->shared_pages = NULL;
	}
}
