// SPDX-License-Identifier: GPL-2.0
// Restricted PIE ELF validator and per-sandbox image mapper for `endovisor`.
//
// Validates self-contained x86-64 `ET_DYN` kernelet images (`<= 256 MiB`,
// 3 `PT_LOAD` segments `RX`/`R`/`RW` with 2 MiB-aligned `rodata`/`data`,
// `SHT_INIT_ARRAY` allowed, 144-byte `EntryTable` at `0x1000`, `ENDBR64` on all
// entry targets). Shared `RX`/`RO`/gap pages are allocated once per kind; each
// sandbox maps those shared pages alongside its own private relocated `RW`
// segment and per-vCPU `cpu_local` replicas.

#include <linux/elf.h>
#include <linux/mm.h>
#include <linux/overflow.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include <asm/set_memory.h>

#include "endovisor.h"

#ifndef DT_GNU_HASH
#define DT_GNU_HASH		0x6ffffef5
#endif
#ifndef DT_FLAGS
#define DT_FLAGS		30
#endif
#ifndef DF_BIND_NOW
#define DF_BIND_NOW		0x8
#endif
#ifndef DF_1_NOW
#define DF_1_NOW		0x1
#endif
#ifndef DF_1_PIE
#define DF_1_PIE		0x08000000
#endif
#ifndef DT_RELR
#define DT_RELR			36
#define DT_RELRSZ		35
#define DT_RELRENT		37
#endif
#ifndef SHT_INIT_ARRAY
#define SHT_INIT_ARRAY		14
#define SHT_FINI_ARRAY		15
#define SHT_PREINIT_ARRAY	16
#endif
#ifndef SHF_TLS
#define SHF_TLS			0x400
#endif

static bool range_fits(u64 offset, u64 size, u64 limit)
{
	return offset <= limit && size <= limit - offset;
}

static const struct image_segment *find_seg_memsz(
	const struct image_kind *kind, u64 offset, u64 size)
{
	unsigned int i;

	for (i = 0; i < kind->nr_segments; i++) {
		const struct image_segment *seg = &kind->segments[i];

		if (offset >= seg->offset &&
		    range_fits(offset - seg->offset, size, seg->memsz))
			return seg;
	}
	return NULL;
}

static const struct image_segment *find_seg_filesz(
	const struct image_kind *kind, u64 offset, u64 size)
{
	unsigned int i;

	for (i = 0; i < kind->nr_segments; i++) {
		const struct image_segment *seg = &kind->segments[i];

		if (offset >= seg->offset &&
		    range_fits(offset - seg->offset, size, seg->filesz))
			return seg;
	}
	return NULL;
}

static int image_sections(const u8 *buf, size_t len, const Elf64_Ehdr *eh)
{
	const Elf64_Shdr *sh;
	unsigned int i;

	if (!eh->e_shoff && !eh->e_shnum)
		return 0;
	if (!eh->e_shnum || eh->e_shentsize != sizeof(*sh) ||
	    !IS_ALIGNED(eh->e_shoff, __alignof__(*sh)) ||
	    !range_fits(eh->e_shoff, (u64)eh->e_shnum * sizeof(*sh), len))
		return -ENOEXEC;

	sh = (const Elf64_Shdr *)(buf + eh->e_shoff);
	for (i = 0; i < eh->e_shnum; i++) {
		const Elf64_Shdr *s = &sh[i];
		unsigned int j;

		if (s->sh_type != SHT_NOBITS &&
		    !range_fits(s->sh_offset, s->sh_size, len))
			return -ENOEXEC;
		if (s->sh_flags & SHF_ALLOC) {
			// `SHT_INIT_ARRAY` is permitted; TLS and fini/preinit are not.
			if ((s->sh_flags & SHF_TLS) ||
			    s->sh_type == SHT_FINI_ARRAY ||
			    s->sh_type == SHT_PREINIT_ARRAY)
				return -ENOEXEC;
		}
		if (s->sh_type != SHT_SYMTAB && s->sh_type != SHT_DYNSYM)
			continue;
		if (s->sh_entsize != sizeof(Elf64_Sym) ||
		    s->sh_size % sizeof(Elf64_Sym) ||
		    !IS_ALIGNED(s->sh_offset, __alignof__(Elf64_Sym)))
			return -ENOEXEC;
		for (j = 1; j < s->sh_size / sizeof(Elf64_Sym); j++) {
			const Elf64_Sym *sym = (const Elf64_Sym *)(buf + s->sh_offset) + j;

			if (sym->st_shndx == SHN_UNDEF ||
			    sym->st_shndx == SHN_COMMON ||
			    ELF64_ST_TYPE(sym->st_info) == STT_TLS)
				return -ENOEXEC;
		}
	}
	return 0;
}

static int reloc_compare(const void *a, const void *b)
{
	const struct image_reloc *x = a, *y = b;

	return x->offset < y->offset ? -1 : x->offset > y->offset;
}

static int image_layout(struct image_kind *kind, const u8 *buf, size_t len,
			    Elf64_Phdr *dynamic,
			    u64 seg_file_off[IMAGE_SEGMENTS])
{
	const Elf64_Ehdr *eh = (const Elf64_Ehdr *)buf;
	const Elf64_Phdr *ph;
	u64 prev_end = 0;
	unsigned int i, dynamics = 0;
	bool seen_text = false, seen_rodata = false, seen_data = false;
	int err;

	if (len < sizeof(*eh) || memcmp(eh->e_ident, ELFMAG, SELFMAG) ||
	    eh->e_ident[EI_CLASS] != ELFCLASS64 ||
	    eh->e_ident[EI_DATA] != ELFDATA2LSB ||
	    eh->e_ident[EI_VERSION] != EV_CURRENT ||
	    eh->e_version != EV_CURRENT ||
	    eh->e_type != ET_DYN || eh->e_machine != EM_X86_64 ||
	    eh->e_ehsize != sizeof(*eh) || eh->e_phentsize != sizeof(*ph) ||
	    !eh->e_phnum || eh->e_phnum > 64 ||
	    !IS_ALIGNED(eh->e_phoff, __alignof__(*ph)) ||
	    !range_fits(eh->e_phoff, (u64)eh->e_phnum * sizeof(*ph), len))
		return -ENOEXEC;

	err = image_sections(buf, len, eh);
	if (err)
		return err;

	ph = (const Elf64_Phdr *)(buf + eh->e_phoff);
	for (i = 0; i < eh->e_phnum; i++) {
		const Elf64_Phdr *p = &ph[i];
		struct image_segment *seg;

		if (p->p_type == PT_INTERP)
			return -ENOEXEC;
		if (p->p_type == PT_DYNAMIC) {
			if (++dynamics != 1 || p->p_filesz != p->p_memsz ||
			    !p->p_filesz || p->p_filesz % sizeof(Elf64_Dyn) ||
			    !IS_ALIGNED(p->p_vaddr, __alignof__(Elf64_Dyn)) ||
			    !range_fits(p->p_offset, p->p_filesz, len))
				return -ENOEXEC;
			*dynamic = *p;
			continue;
		}
		if (p->p_type == PT_GNU_STACK) {
			if (p->p_flags & PF_X)
				return -ENOEXEC;
			continue;
		}
		if (p->p_type != PT_LOAD)
			continue;

		if (kind->nr_segments >= IMAGE_SEGMENTS || !p->p_memsz ||
		    p->p_filesz > p->p_memsz ||
		    !IS_ALIGNED(p->p_vaddr, PAGE_SIZE) ||
		    !p->p_align || !is_power_of_2(p->p_align) ||
		    p->p_align < PAGE_SIZE ||
		    (p->p_offset % PAGE_SIZE) != (p->p_vaddr % PAGE_SIZE) ||
		    p->p_vaddr < prev_end ||
		    !range_fits(p->p_offset, p->p_filesz, len) ||
		    !range_fits(p->p_vaddr, p->p_memsz, IMAGE_MAX))
			return -ENOEXEC;

		if (p->p_flags == (PF_R | PF_X)) {
			if (seen_text || seen_rodata || seen_data ||
			    p->p_memsz != p->p_filesz)
				return -ENOEXEC;
			seen_text = true;
		} else if (p->p_flags == PF_R) {
			if (!seen_text || seen_rodata || seen_data ||
			    !IS_ALIGNED(p->p_vaddr, SZ_2M) ||
			    p->p_memsz != p->p_filesz)
				return -ENOEXEC;
			seen_rodata = true;
		} else if (p->p_flags == (PF_R | PF_W)) {
			if (!seen_text || !seen_rodata || seen_data ||
			    !IS_ALIGNED(p->p_vaddr, SZ_2M))
				return -ENOEXEC;
			seen_data = true;
		} else {
			return -ENOEXEC;
		}

		seg = &kind->segments[kind->nr_segments];
		seg->offset = p->p_vaddr;
		seg->filesz = p->p_filesz;
		seg->memsz = p->p_memsz;
		seg->flags = p->p_flags;
		seg_file_off[kind->nr_segments] = p->p_offset;
		kind->nr_segments++;

		prev_end = PAGE_ALIGN(p->p_vaddr + p->p_memsz);
		if (p->p_flags & PF_W)
			kind->data_size += PAGE_ALIGN(p->p_memsz);
		else
			kind->text_size += PAGE_ALIGN(p->p_memsz);
	}

	if (!seen_text || !seen_rodata || !seen_data || dynamics != 1)
		return -ENOEXEC;
	if (prev_end > IMAGE_MAX)
		return -ENOEXEC;

	kind->image_size = prev_end;
	kind->nr_pages = prev_end >> PAGE_SHIFT;
	kind->entry_offset = eh->e_entry;
	return 0;
}

static int image_dynamic(struct image_kind *kind, const u8 *buf,
			     const Elf64_Phdr *dyn_ph,
			     const u64 seg_file_off[IMAGE_SEGMENTS])
{
	const Elf64_Dyn *dyn = (const Elf64_Dyn *)(buf + dyn_ph->p_offset);
	const struct image_segment *rela_seg;
	u64 rela = 0, relasz = 0, relaent = 0, pltrelsz = 0;
	bool found_rela = false, found_size = false, found_ent = false;
	bool terminated = false, jmprel_present = false;
	u64 rela_file_off;
	unsigned int i;

	for (i = 0; i < dyn_ph->p_filesz / sizeof(*dyn); i++) {
		u64 val = dyn[i].d_un.d_val;

		switch (dyn[i].d_tag) {
		case DT_NULL:
			terminated = true;
			goto done;
		case DT_NEEDED:
		case DT_REL:
		case DT_RELSZ:
		case DT_RELENT:
		case DT_RELR:
			return -ENOEXEC;
		case DT_RELRSZ:
			if (val != 0)
				return -ENOEXEC;
			break;
		case DT_RELRENT:
			break;
		case DT_JMPREL:
			jmprel_present = true;
			break;
		case DT_PLTRELSZ:
			pltrelsz = val;
			break;
		case DT_RELA:
			if (found_rela)
				return -ENOEXEC;
			found_rela = true;
			rela = val;
			break;
		case DT_RELASZ:
			if (found_size)
				return -ENOEXEC;
			found_size = true;
			relasz = val;
			break;
		case DT_RELAENT:
			if (found_ent)
				return -ENOEXEC;
			found_ent = true;
			relaent = val;
			break;
		default:
			break;
		}
	}
done:
	if (!terminated || (jmprel_present && pltrelsz != 0))
		return -ENOEXEC;
	if (!found_rela) {
		if (relasz != 0)
			return -ENOEXEC;
		return 0;
	}
	if (!found_size || (found_ent && relaent != sizeof(Elf64_Rela)) ||
	    (relasz % sizeof(Elf64_Rela)) ||
	    !IS_ALIGNED(rela, __alignof__(Elf64_Rela)))
		return -ENOEXEC;

	rela_seg = find_seg_filesz(kind, rela, relasz);
	if (!rela_seg || (rela_seg->flags & PF_W))
		return -ENOEXEC;
	rela_file_off = seg_file_off[rela_seg - kind->segments] +
			(rela - rela_seg->offset);

	kind->nr_relocs = relasz / sizeof(Elf64_Rela);
	if (!kind->nr_relocs)
		return 0;
	kind->relocs = kvcalloc(kind->nr_relocs, sizeof(*kind->relocs), GFP_KERNEL);
	if (!kind->relocs)
		return -ENOMEM;

	for (i = 0; i < kind->nr_relocs; i++) {
		const Elf64_Rela *r = (const Elf64_Rela *)(buf + rela_file_off) + i;
		const struct image_segment *seg =
			find_seg_memsz(kind, r->r_offset, sizeof(u64));

		if (ELF64_R_TYPE(r->r_info) != R_X86_64_RELATIVE ||
		    ELF64_R_SYM(r->r_info) ||
		    !IS_ALIGNED(r->r_offset, sizeof(u64)) ||
		    !seg || !(seg->flags & PF_W) ||
		    r->r_addend < 0 ||
		    (u64)r->r_addend > kind->image_size)
			return -ENOEXEC;

		kind->relocs[i].offset = r->r_offset;
		kind->relocs[i].addend = r->r_addend;
	}

	sort(kind->relocs, kind->nr_relocs, sizeof(*kind->relocs),
	     reloc_compare, NULL);
	for (i = 1; i < kind->nr_relocs; i++)
		if (kind->relocs[i - 1].offset == kind->relocs[i].offset)
			return -ENOEXEC;

	return 0;
}

static bool check_endbr64(const struct image_kind *kind, const u8 *buf,
			      const u64 seg_file_off[IMAGE_SEGMENTS],
			      u64 vaddr)
{
	static const u8 endbr64[4] = { 0xf3, 0x0f, 0x1e, 0xfa };
	const struct image_segment *text = &kind->segments[0];
	u64 foff;

	if (vaddr < text->offset ||
	    !range_fits(vaddr - text->offset, sizeof(endbr64), text->filesz))
		return false;
	foff = seg_file_off[0] + (vaddr - text->offset);
	return memcmp(buf + foff, endbr64, sizeof(endbr64)) == 0;
}

static int validate_ex_table(const struct image_kind *kind, const u8 *buf,
				 const u64 seg_file_off[IMAGE_SEGMENTS])
{
	const struct entry_table *et = &kind->entry_table;
	const struct image_segment *text = &kind->segments[0];
	const struct image_segment *rodata = &kind->segments[1];
	u64 table_len, foff, i;
	s64 prev_fault = S64_MIN;
	bool has_prev = false;

	if (et->ex_table_end_offset < et->ex_table_start_offset)
		return -ENOEXEC;
	table_len = et->ex_table_end_offset - et->ex_table_start_offset;
	if (table_len % EX_TABLE_ENTRY_SIZE)
		return -ENOEXEC;
	if (table_len == 0)
		return 0;

	if (et->ex_table_start_offset < rodata->offset ||
	    !range_fits(et->ex_table_start_offset - rodata->offset,
			    table_len, rodata->filesz))
		return -ENOEXEC;

	foff = seg_file_off[1] + (et->ex_table_start_offset - rodata->offset);
	for (i = 0; i < table_len / EX_TABLE_ENTRY_SIZE; i++) {
		u64 entry_vaddr = et->ex_table_start_offset + i * EX_TABLE_ENTRY_SIZE;
		const s64 *pair = (const s64 *)(buf + foff + i * EX_TABLE_ENTRY_SIZE);
		s64 fault = (s64)entry_vaddr + pair[0];
		s64 recovery = (s64)(entry_vaddr + 8) + pair[1];

		if (fault < (s64)text->offset ||
		    (u64)fault >= text->offset + text->filesz ||
		    recovery < (s64)text->offset ||
		    (u64)recovery >= text->offset + text->filesz)
			return -ENOEXEC;
		if (has_prev && fault <= prev_fault)
			return -ENOEXEC;
		prev_fault = fault;
		has_prev = true;
	}
	return 0;
}

static int image_entry(struct image_kind *kind, const u8 *buf,
			   const u64 seg_file_off[IMAGE_SEGMENTS])
{
	const struct image_segment *text = &kind->segments[0];
	const struct image_segment *data = &kind->segments[2];
	const struct image_segment *et_seg;
	struct entry_table *et = &kind->entry_table;
	u64 foff, cpu_local_len, stub_len, access_len;
	const u64 *targets;
	unsigned int i;

	et_seg = find_seg_filesz(kind, ENTRY_TABLE_OFFSET, ENTRY_TABLE_SIZE);
	if (!et_seg || (et_seg->flags & PF_W))
		return -ENOEXEC;

	foff = seg_file_off[et_seg - kind->segments] +
	       (ENTRY_TABLE_OFFSET - et_seg->offset);
	memcpy(et, buf + foff, sizeof(*et));
	if (et->size != ENTRY_TABLE_SIZE)
		return -EPROTO;

	for (i = 0; i < kind->nr_relocs; i++) {
		u64 off = kind->relocs[i].offset;

		if (off >= ENTRY_TABLE_OFFSET &&
		    off < ENTRY_TABLE_OFFSET + ENTRY_TABLE_SIZE)
			return -ENOEXEC;
	}

	{
		const u64 check_targets[] = {
			kind->entry_offset,
			et->vcpu_entry_offset,
			et->virq_entry_offset,
			et->yield_entry_offset,
			et->exit_entry_offset,
			et->user_event_entry_offset,
		};

		targets = check_targets;
		for (i = 0; i < ARRAY_SIZE(check_targets); i++) {
			if (!check_endbr64(kind, buf, seg_file_off, targets[i]))
				return -ENOEXEC;
		}
	}

	if (et->stub_range_end_offset <= et->stub_range_start_offset)
		return -ENOEXEC;
	stub_len = et->stub_range_end_offset - et->stub_range_start_offset;
	if (et->stub_range_start_offset < text->offset ||
	    !range_fits(et->stub_range_start_offset - text->offset,
			    stub_len, text->filesz))
		return -ENOEXEC;
	if (et->virq_entry_offset < et->stub_range_start_offset ||
	    et->virq_entry_offset >= et->stub_range_end_offset ||
	    et->yield_entry_offset < et->stub_range_start_offset ||
	    et->yield_entry_offset >= et->stub_range_end_offset ||
	    et->exit_entry_offset < et->stub_range_start_offset ||
	    et->exit_entry_offset >= et->stub_range_end_offset)
		return -ENOEXEC;

	if (et->cpu_access_end_offset <= et->cpu_access_start_offset)
		return -ENOEXEC;
	access_len = et->cpu_access_end_offset - et->cpu_access_start_offset;
	if (et->cpu_access_start_offset < text->offset ||
	    !range_fits(et->cpu_access_start_offset - text->offset,
			    access_len, text->filesz))
		return -ENOEXEC;
	if (et->cpu_access_start_offset < et->stub_range_end_offset &&
	    et->stub_range_start_offset < et->cpu_access_end_offset)
		return -ENOEXEC;

	if (et->cpu_local_end_offset < et->cpu_local_start_offset)
		return -ENOEXEC;
	cpu_local_len = et->cpu_local_end_offset - et->cpu_local_start_offset;
	if (cpu_local_len > 0) {
		if (et->cpu_local_start_offset < data->offset ||
		    !range_fits(et->cpu_local_start_offset - data->offset,
				    cpu_local_len, data->filesz))
			return -ENOEXEC;
	}

	return validate_ex_table(kind, buf, seg_file_off);
}

int image_load(struct image_kind *kind, const void *buf, size_t len)
{
	Elf64_Phdr dynamic = {};
	u64 seg_file_off[IMAGE_SEGMENTS] = {};
	const struct image_segment *data_seg;
	unsigned int i, j;
	int err;

	err = image_layout(kind, buf, len, &dynamic, seg_file_off);
	if (err)
		goto fail;
	err = image_dynamic(kind, buf, &dynamic, seg_file_off);
	if (err)
		goto fail;
	err = image_entry(kind, buf, seg_file_off);
	if (err)
		goto fail;

	data_seg = &kind->segments[2];
	if (data_seg->filesz) {
		kind->image = vzalloc(data_seg->filesz);
		err = -ENOMEM;
		if (!kind->image)
			goto fail;
		memcpy(kind->image, (const u8 *)buf + seg_file_off[2], data_seg->filesz);
	}

	kind->filler_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	kind->shared_pages = kvcalloc(kind->nr_pages, sizeof(*kind->shared_pages),
				      GFP_KERNEL);
	err = -ENOMEM;
	if (!kind->filler_page || !kind->shared_pages)
		goto fail;

	// Populate RX (`text`) and RO (`rodata`) pages from the ELF buffer.
	for (i = 0; i < 2; i++) {
		const struct image_segment *seg = &kind->segments[i];
		unsigned int start_pg = seg->offset >> PAGE_SHIFT;
		unsigned int end_pg = PAGE_ALIGN(seg->offset + seg->memsz) >> PAGE_SHIFT;

		for (j = start_pg; j < end_pg; j++) {
			struct page *page = alloc_page(GFP_KERNEL | __GFP_ZERO);
			size_t seg_off = ((size_t)j << PAGE_SHIFT) - seg->offset;
			size_t copy_len = 0;

			if (!page)
				goto fail;
			if (seg_off < seg->filesz)
				copy_len = min_t(size_t, PAGE_SIZE, seg->filesz - seg_off);
			if (copy_len)
				memcpy(page_address(page),
				       (const u8 *)buf + seg_file_off[i] + seg_off,
				       copy_len);
			kind->shared_pages[j] = page;
		}
	}

	// Fill any alignment gap pages outside `data_seg` with the shared zero page.
	{
		unsigned int data_start = data_seg->offset >> PAGE_SHIFT;
		unsigned int data_end = PAGE_ALIGN(data_seg->offset + data_seg->memsz) >> PAGE_SHIFT;

		for (j = 0; j < kind->nr_pages; j++) {
			if (j >= data_start && j < data_end)
				continue;
			if (!kind->shared_pages[j])
				kind->shared_pages[j] = kind->filler_page;
		}
	}

	pr_info("endovisor: PIE image loaded: span %zu B, shared %zu B, private %zu B, %u relocs\n",
		kind->image_size, kind->text_size, kind->data_size, kind->nr_relocs);
	return 0;
fail:
	image_free(kind);
	return err;
}

static void image_stop_locked(struct sandbox *sandbox)
{
	unsigned int i;

	if (sandbox->cpu_local_vmap) {
		vunmap(sandbox->cpu_local_vmap);
		sandbox->cpu_local_vmap = NULL;
	}
	if (sandbox->cpu_local_pages) {
		for (i = 0; i < sandbox->nr_cpu_local_pages; i++)
			if (sandbox->cpu_local_pages[i])
				__free_page(sandbox->cpu_local_pages[i]);
		kvfree(sandbox->cpu_local_pages);
		sandbox->cpu_local_pages = NULL;
	}
	if (sandbox->image_base) {
		vunmap(sandbox->image_base);
		vm_unmap_aliases();
		sandbox->image_base = NULL;
	}
	if (sandbox->image_pages) {
		for (i = 0; i < sandbox->kind->nr_pages; i++)
			if (!sandbox->kind->shared_pages[i] && sandbox->image_pages[i])
				__free_page(sandbox->image_pages[i]);
		kvfree(sandbox->image_pages);
		sandbox->image_pages = NULL;
	}
	sandbox->text_lo = sandbox->text_hi = 0;
}

void image_stop(struct sandbox *sandbox)
{
	mutex_lock(&registry_lock);
	image_stop_locked(sandbox);
	mutex_unlock(&registry_lock);
}

int image_start(struct sandbox *sandbox)
{
	struct image_kind *kind = sandbox->kind;
	const struct image_segment *text = &kind->segments[0];
	const struct image_segment *data = &kind->segments[2];
	const struct entry_table *et = &kind->entry_table;
	unsigned long base;
	unsigned int i, vcpu;
	int err = -ENOMEM;

	mutex_lock(&registry_lock);
	sandbox->image_pages = kvcalloc(kind->nr_pages, sizeof(*sandbox->image_pages), GFP_KERNEL);
	if (!sandbox->image_pages)
		goto fail;

	for (i = 0; i < kind->nr_pages; i++) {
		size_t off, copy_len = 0;

		if (kind->shared_pages[i]) {
			sandbox->image_pages[i] = kind->shared_pages[i];
			continue;
		}
		sandbox->image_pages[i] = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!sandbox->image_pages[i])
			goto fail;
		off = ((size_t)i << PAGE_SHIFT) - data->offset;
		if (off < data->filesz)
			copy_len = min_t(size_t, PAGE_SIZE, data->filesz - off);
		if (copy_len)
			memcpy(page_address(sandbox->image_pages[i]),
			       kind->image + off, copy_len);
	}

	sandbox->image_base = vmap(sandbox->image_pages, kind->nr_pages, VM_MAP,
				PAGE_KERNEL_RO);
	if (!sandbox->image_base)
		goto fail;

	err = set_memory_rw((unsigned long)sandbox->image_base + data->offset,
			    PAGE_ALIGN(data->memsz) >> PAGE_SHIFT);
	if (err)
		goto fail;

	base = (unsigned long)sandbox->image_base;
	for (i = 0; i < kind->nr_relocs; i++) {
		const struct image_reloc *r = &kind->relocs[i];

		*(u64 *)(base + r->offset) = (u64)base + r->addend;
	}

	err = set_memory_rox(base + text->offset,
			     PAGE_ALIGN(text->memsz) >> PAGE_SHIFT);
	if (err)
		goto fail;

	// Allocate and populate per-vCPU `cpu_local` replicas from the relocated template.
	sandbox->cpu_local_size = et->cpu_local_end_offset - et->cpu_local_start_offset;
	sandbox->cpu_local_pages_per_vcpu =
		max_t(unsigned int, 1, DIV_ROUND_UP(sandbox->cpu_local_size, PAGE_SIZE));
	sandbox->nr_cpu_local_pages = sandbox->nr_vcpus * sandbox->cpu_local_pages_per_vcpu;
	sandbox->cpu_local_pages = kvcalloc(sandbox->nr_cpu_local_pages,
					 sizeof(*sandbox->cpu_local_pages), GFP_KERNEL);
	if (!sandbox->cpu_local_pages) {
		err = -ENOMEM;
		goto fail;
	}
	for (i = 0; i < sandbox->nr_cpu_local_pages; i++) {
		sandbox->cpu_local_pages[i] = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!sandbox->cpu_local_pages[i]) {
			err = -ENOMEM;
			goto fail;
		}
	}
	sandbox->cpu_local_vmap = vmap(sandbox->cpu_local_pages, sandbox->nr_cpu_local_pages,
				    VM_MAP, PAGE_KERNEL);
	if (!sandbox->cpu_local_vmap) {
		err = -ENOMEM;
		goto fail;
	}
	if (sandbox->cpu_local_size > 0) {
		const void *tpl = (const void *)(base + et->cpu_local_start_offset);
		size_t stride = (size_t)sandbox->cpu_local_pages_per_vcpu * PAGE_SIZE;

		for (vcpu = 0; vcpu < sandbox->nr_vcpus; vcpu++)
			memcpy((u8 *)sandbox->cpu_local_vmap + vcpu * stride,
			       tpl, sandbox->cpu_local_size);
	}

	sandbox->entry_fn = base + kind->entry_offset;
	sandbox->vcpu_entry = base + et->vcpu_entry_offset;
	sandbox->virq_entry = base + et->virq_entry_offset;
	sandbox->yield_entry = base + et->yield_entry_offset;
	sandbox->exit_entry = base + et->exit_entry_offset;
	sandbox->user_event_entry = base + et->user_event_entry_offset;
	sandbox->text_lo = base + text->offset;
	sandbox->text_hi = base + text->offset + text->memsz;
	sandbox->stub_lo = base + et->stub_range_start_offset;
	sandbox->stub_hi = base + et->stub_range_end_offset;
	sandbox->cpu_access_lo = base + et->cpu_access_start_offset;
	sandbox->cpu_access_hi = base + et->cpu_access_end_offset;

	mutex_unlock(&registry_lock);
	return 0;
fail:
	image_stop_locked(sandbox);
	mutex_unlock(&registry_lock);
	return err;
}

void image_free(struct image_kind *kind)
{
	unsigned int i;

	if (kind->shared_pages) {
		for (i = 0; i < kind->nr_pages; i++) {
			struct page *page = kind->shared_pages[i];

			if (!page || page == kind->filler_page)
				continue;
			// Restore direct-map permissions changed by `set_memory_rox()`.
			if (WARN_ON(set_memory_rw((unsigned long)page_address(page), 1)))
				continue;
			__free_page(page);
		}
		kvfree(kind->shared_pages);
	}
	if (kind->filler_page)
		__free_page(kind->filler_page);
	kvfree(kind->relocs);
	vfree(kind->image);
	memset(kind, 0, sizeof(*kind));
}
