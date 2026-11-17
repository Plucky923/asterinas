/* SPDX-License-Identifier: GPL-2.0 */
// Internal declarations and ABI mirrors for `endovisor.ko`.

#ifndef ENDOVISOR_INTERNAL_H
#define ENDOVISOR_INTERNAL_H

#include <linux/atomic.h>
#include <linux/hashtable.h>
#include <linux/hrtimer.h>
#include <linux/jump_label.h>
#include <linux/kernelet.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "uapi/endovisor.h"

struct linux_binprm;

// ------------------------------------------------------------------
// Exact C <-> Rust ABI (`poc/ostd/src/kernelet/abi.rs`)
// ------------------------------------------------------------------

#define ENTRY_TABLE_OFFSET		0x1000UL
#define ENTRY_TABLE_SIZE		144ULL
#define EX_TABLE_ENTRY_SIZE		16ULL

struct entry_table {
	u64 size;
	u64 vcpu_entry_offset;
	u64 virq_entry_offset;
	u64 cpu_local_start_offset;
	u64 cpu_local_end_offset;
	u8 source_hash[32];
	u64 ex_table_start_offset;
	u64 ex_table_end_offset;
	u64 yield_entry_offset;
	u64 exit_entry_offset;
	u64 stub_range_start_offset;
	u64 stub_range_end_offset;
	u64 cpu_access_start_offset;
	u64 cpu_access_end_offset;
	u64 user_event_entry_offset;
} __packed;

#define KERNEL_HALF_START		256
#define KERNEL_HALF_ENTRIES		(512 - KERNEL_HALF_START)

struct boot_args {
	u32 size;
	u32 generation;
	u8 source_hash[32];
	u64 tsc_freq_hz;
	u64 clock_origin_tsc;
	u16 kernelet;
	u16 num_vcpus;
	u16 vcpu_host_cpu[MAX_VCPUS];
	u32 cpu_slot_gs_offset;
	u32 cpu_local_replica_bytes;
	u64 linear_map_base;
	u64 kernel_half_entries[KERNEL_HALF_ENTRIES];
	u64 meta_base;
	u32 grant_table;
	u32 meta_section_index;
	u32 meta_block_sections;
	u32 meta_grain_bitmap;
	u32 max_meta_sections;
	u32 info_page;
	u32 vcpu_records;
	u32 max_tasks;
	u32 fpu_area_bytes;
	u32 cmdline_offset;
	u32 cmdline_len;
	u32 devices_offset;
	u32 num_devices;
	u8 pti_enabled;
	u8 nx_supported;
	u8 pgtable_levels;
	u8 pt_mode;
	u64 realtime_base_ns;
	u64 monotonic_base_ns;
	u64 initramfs_base;
	u64 initramfs_len;
};

struct run_desc {
	u64 paddr;
	u32 grains;
	u32 reserved;
};

struct info_page {
	u32 runs;
	u32 meta_blocks;
	u64 max_paddr;
	u32 dying;
	u32 reserved;
};

struct vcpu_record {
	u64 pending;
	u64 pending_lines[4];
	u64 tick_user;
	u64 tick_kernel;
	u64 tick_l2;
	u64 stolen_ns;
	u64 nonrunning_tsc;
	u32 guards;
	u32 irq_off;
	u32 vcpu;
	u32 irq_level;
	u64 stack_limit;
	u64 cpu_local_base;
	u64 parked_ns;
	u64 task_ticks;
} __aligned(64);

struct copy_fault_record {
	u64 addr;
	u64 error;
	u32 pending;
	u8 _pad[44];
} __aligned(64);

struct user_event_record {
	u64 pt_regs;
	u64 event_rsp;
	u64 event_stack_limit;
	u64 trap_num;
	u64 error_code;
	u64 fault_addr;
	u64 _pad[2];
} __aligned(64);

struct mmio_result {
	s64 status;
	u64 value;
};

struct service_table {
	u64 size;
	s64 (*grains_request)(u32 count, u32 contiguous);
	s64 (*pt_root_register)(u64 root_paddr);
	s64 (*pt_root_unregister)(u64 root_paddr);
	s64 (*pt_activate)(u64 root_paddr);
	s64 (*tlb_shootdown)(u64 root_paddr, u64 start, u64 len);
	u64 (*kstack_alloc)(void);
	s64 (*kstack_free)(u64 vaddr);
	s64 (*vcpu_boot)(u32 vcpu);
	s64 (*vcpu_idle)(u64 deadline_ns);
	s64 (*vcpu_kick)(u32 vcpu);
	void (*vcpu_yield)(void);
	void (*vcpu_on_spin)(void);
	s32 (*user_run)(void *ctx);
	struct mmio_result (*mmio_read)(u32 dev, u32 offset, u32 width);
	s64 (*mmio_write)(u32 dev, u32 offset, u32 width, u64 value);
	s64 (*log_write)(u32 level, const u8 *module, u32 module_len,
			 const u8 *text, u32 text_len);
	s64 (*oops)(const u8 *msg, u32 len);
	void (*stop)(u32 kind, u32 code, const u8 *msg, u32 len) __noreturn;
	struct mmio_result (*buffer)(u32 op, u64 token, u64 arg0,
					 u64 arg1, u64 arg2);
};

// `UserEvent` discriminants passed to `user_event_entry(raw_event)`.
#define USER_EVENT_SYSCALL		0ULL
#define USER_EVENT_EXCEPTION	1ULL
#define USER_EVENT_KERNEL_EVENT	2ULL

// ABI negative status codes (returned negated).
#define ABI_NOT_OWNED		2
#define ABI_INVALID			3
#define ABI_LIMIT			4
#define ABI_STATE			5

// Stop kinds.
#define STOP_EXIT			0U
#define STOP_PANIC			1U
#define STOP_STACK_OVERFLOW		2U
#define STOP_KILLED			3U

// Virtual IRQ bits.
#define VIRQ_TICK			(1ULL << 0)
#define VIRQ_KICK			(1ULL << 1)
#define VIRQ_LINES			(1ULL << 2)

// `buffer` op codes (VMA baseline).
#define BUFFER_VM_MAP			0x100U
#define BUFFER_VM_PROTECT		0x101U
#define BUFFER_VM_UNMAP			0x102U

#define KLET_PROT_READ			(1U << 0)
#define KLET_PROT_WRITE			(1U << 1)
#define KLET_PROT_EXEC			(1U << 2)

// Grant & metadata constants.
#define GRAIN_ORDER			9
#define GRAIN_SIZE			(2UL << 20)
#define META_SECTION_BYTES		(128UL << 20)
#define GRAINS_PER_SECTION		(META_SECTION_BYTES / GRAIN_SIZE)
#define META_SLOT_BYTES		64UL
#define META_REF_COUNT_OFFSET	40UL
#define META_PAGES_PER_GRAIN	((GRAIN_SIZE / PAGE_SIZE) * META_SLOT_BYTES / PAGE_SIZE)
#define NO_META_BLOCK		U32_MAX
#define MAX_GRAINS_PER_REQUEST	32U
#define MAX_GRAINS_TOTAL		(MAX_GRANT_MB / 2U)
#define MAX_META_SECTIONS		MAX_GRAINS_TOTAL

// Guarded stack pool constants (`KSTACK_MAPPING_BYTES == 256 KiB`).
#define KSTACK_PAGES		64UL
#define KSTACK_BYTES		(KSTACK_PAGES * PAGE_SIZE)
#define KSTACK_STRIDE		(2UL * KSTACK_BYTES)
#define UPCALL_STACK_RESERVE	(64UL * 1024)

// Watch & idle timings.
#define WATCH_INTERVAL_NS		(1000UL * 1000UL)
#define IDLE_MAX_NS			WATCH_INTERVAL_NS
#define IDLE_MIN_NS			(50UL * 1000UL)
#define SWEEP_INTERVAL_NS		(1000UL * 1000UL)

// Registry limits.
#define MAX_KINDS			16
#define MAX_SANDBOXES		16
#define WINDOW_START		0x10000UL

// Exec descriptor magic for `SANDBOX_GET_VCPU_FD`.
#define EXEC_MAGIC			"KERNELET\0"
#define EXEC_MAGIC_LEN		(sizeof(EXEC_MAGIC))

struct exec_header {
	char magic[EXEC_MAGIC_LEN];
	u16 slot;
	u32 vcpu;
} __packed;

// ------------------------------------------------------------------
// Endovisor-internal types
// ------------------------------------------------------------------

struct image_segment {
	u64 offset;
	u64 filesz;
	u64 memsz;
	u32 flags;
};

struct image_reloc {
	u64 offset;
	s64 addend;
};

#define IMAGE_SEGMENTS		3

struct image_kind {
	bool used;
	u8 *image;			// Template for RW segment initialization
	size_t image_size;
	struct page *filler_page;	// Shared zero page for alignment gaps
	struct page **shared_pages;	// Non-NULL for shared RX/RO/gap pages
	unsigned int nr_pages;
	unsigned int nr_segments;
	unsigned int nr_relocs;
	struct image_segment segments[IMAGE_SEGMENTS];
	struct image_reloc *relocs;
	struct entry_table entry_table;
	u64 entry_offset;
	size_t text_size;
	size_t data_size;
	unsigned int nr_sandboxes;
};

struct grain_record {
	struct page *head_page;
	u64 paddr;
	u32 block;
	u32 grain_in_sec;
	struct page *meta_pages[META_PAGES_PER_GRAIN];
};

struct stack_slot {
	struct page **pages;
	bool mapped;
	bool allocated;
};

struct user_space {
	struct sandbox *sandbox;
	struct hlist_node hnode;
	u64 root_paddr;
	bool live;
	struct mm_struct *mm;
	struct file *file;
	unsigned long start;
	unsigned long end;
	atomic_t users;
};

enum carrier_state {
	CARRIER_NEW = 0,
	CARRIER_KERNEL,
	CARRIER_USER,
	CARRIER_DEAD,
};

struct carrier {
	struct carrier_event_hooks hooks;
	struct sandbox *sandbox;
	struct task_struct *task;
	enum carrier_state state;
	unsigned int vcpu;

	// Shared ABI records for this vCPU (inside `sandbox->shared_vmap`).
	struct vcpu_record *vrec;
	struct copy_fault_record *cfrec;
	struct user_event_record *urec;

	// Boot stack base (`usable_base`, mapped 256 KiB above 256 KiB guard).
	u64 boot_stack_base;

	// Linux stack anchor (just below `task_pt_regs(current)`) and live user regs.
	void *linux_sp;
	struct pt_regs *user_regs;
	bool from_syscall;

	// Cached `event_rsp` validation (invalidated via `sandbox->kstack_free_gen`).
	u64 cached_event_rsp;
	u64 cached_kstack_gen;

	// Carrier's own empty mm (for `pt_activate(0)` and safe teardown).
	struct mm_struct *own_mm;

	// Host service depth (0 = running image or user, >0 = inside Linux service).
	int depth;
	bool doomed;
	bool evicted;
	bool idle;
	bool boot_requested;
	bool kick_deferred;
	// Deferred `#DF` stack-guard overflow report consumed off the IST stack.
	bool df_overflow;
	unsigned long df_ip;
	unsigned long df_sp;
	unsigned long df_addr;
	wait_queue_head_t idle_wq;

	// Pending exception (e.g. VMA `#PF` or drained fault signal).
	bool exc_pending;
	u64 exc_trap;
	u64 exc_error;
	u64 exc_addr;

	// Timing & forced-yield strike tracking.
	u64 off_cpu_ns;
	u64 strike1_ns;
	unsigned long last_on_spin;

#ifdef CONFIG_PREEMPT_NOTIFIERS
	struct preempt_notifier pnotifier;
	bool pnotifier_on;
#endif

	// Per-carrier syscall counter (flushed into `sandbox->stats.syscalls` on detach).
	u64 syscalls;

	refcount_t refs;
	struct list_head link;
};

struct vcpu_slot {
	bool claimed;
	pid_t pid;
	struct file *exec_file;
};

struct runtime_stats {
	atomic64_t fpu_saves;
	atomic64_t fpu_restores;
	atomic64_t vm_creates;
	atomic64_t vm_destroys;
	atomic64_t vm_flushes;
	atomic64_t vm_maps;
	atomic64_t vm_protects;
	atomic64_t vm_unmaps;
	atomic64_t exceptions;
	atomic64_t page_faults;
	atomic64_t virqs;
	atomic64_t forced_yields;
	atomic64_t non_sysret;
	atomic64_t syscalls;
};

struct sandbox {
	refcount_t refs;
	struct image_kind *kind;
	int slot;
	u32 generation;

	// Image mapping (`image_base` + `cpu_local` replicas + `shared_vmap`).
	void *image_base;
	struct page **image_pages;
	void *cpu_local_vmap;
	struct page **cpu_local_pages;
	unsigned int nr_cpu_local_pages;
	unsigned int cpu_local_pages_per_vcpu;
	size_t cpu_local_size;

	// Validated image entry & range addresses in kernel VA.
	unsigned long entry_fn;
	unsigned long vcpu_entry;
	unsigned long virq_entry;
	unsigned long yield_entry;
	unsigned long exit_entry;
	unsigned long user_event_entry;
	unsigned long text_lo;
	unsigned long text_hi;
	unsigned long stub_lo;
	unsigned long stub_hi;
	unsigned long cpu_access_lo;
	unsigned long cpu_access_hi;

	// Contiguous shared pages: BootPage | VcpuShared | InfoPage | GrantTable | MetaIdx | MetaRev | MetaBmp.
	void *shared_vmap;
	struct page **shared_pages;
	unsigned int total_shared_pages;
	struct boot_args *boot_page;	// Direct-map VA of page 0
	struct info_page *info_page;	// Direct-map VA of InfoPage
	struct run_desc *grant_table;	// Direct-map VA of RunDesc[]
	u32 *meta_section_index;		// Direct-map VA
	u32 *meta_block_sections;		// Direct-map VA
	u64 *meta_grain_bitmap;			// Direct-map VA
	unsigned int nr_phys_sections;

	// Sparse `meta_base` vmalloc window.
	struct vm_struct *meta_area;
	u32 max_meta_sections;
	u32 nr_meta_blocks;

	// Physical memory grant (2 MiB grains).
	struct mutex grant_mutex;
	struct grain_record *grains;
	unsigned int max_grains;
	unsigned int nr_grains;
	unsigned int nr_runs;
	u64 max_paddr;

	// Guarded stack pool (512 KiB stride: 256 KiB guard + 256 KiB usable).
	struct mutex stack_mutex;
	struct vm_struct *stack_area;
	unsigned long stack_pool_start;
	unsigned long stack_pool_end;
	unsigned int kstack_slots;
	struct stack_slot *kstack_table;
	unsigned long *live_stacks_bitmap;
	atomic64_t kstack_free_gen;

	// Initramfs read-only vmap.
	void *initramfs_vmap;
	struct page **initramfs_pages;
	unsigned int nr_initramfs_pages;
	u64 initramfs_len;

	// Sandbox configuration.
	unsigned int nr_vcpus;
	u32 grant_mb;
	u32 max_tasks;
	u32 pt_mode;
	char *cmdline;
	size_t cmdline_len;
	struct cgroup *cgrp;
	struct task_struct *owner;

	// Address spaces (`pt_root_register` / `pt_root_unregister`).
	spinlock_t spaces_lock;
	DECLARE_HASHTABLE(spaces_ht, 8);

	// Carriers and arrival coordination.
	spinlock_t lock;
	struct mutex mutex;
	struct carrier *vcpus[MAX_VCPUS];
	struct vcpu_slot vslot[MAX_VCPUS];
	struct list_head carriers;
	atomic_t nr_carriers;
	wait_queue_head_t arrive_wq;
	unsigned int arrived;
	bool started;

	// Lifecycle & exit state.
	bool dying;
	bool exited;
	// A claimed cleanup owns one reference until its work finishes.
	bool exit_claimed;
	bool sweep_armed;
	u32 exit_kind;
	u32 exit_code;
	char exit_msg[256];
	wait_queue_head_t exit_wq;
	struct work_struct cleanup_work;

	// Console (`LEVEL_CONSOLE == 8`) line buffer for unprefixed serial output.
	spinlock_t con_lock;
	char con_buf[1024];
	unsigned int con_len;

	// TSC calibration snapshot.
	u64 tsc_freq_hz;
	u64 clock_origin_tsc;
	u64 realtime_base_ns;
	u64 monotonic_base_ns;

	struct runtime_stats stats;
	u64 grant_grains_allocated;
	u64 grant_grains_freed;
	bool counted_live;

	// Isolated profiling ring (allocated only when `profile_hz > 0`).
	spinlock_t prof_lock;
	struct sandbox_prof_sample *prof_samples;
	u32 prof_cap;
	u32 prof_count;
	u64 prof_dropped;
};

// Module parameters and shared globals (`main.c`).
extern bool watch_enabled;
extern bool audit_enabled;
extern int profile_hz;
DECLARE_STATIC_KEY_FALSE(endovisor_audit_key);
DECLARE_STATIC_KEY_FALSE(endovisor_profile_key);
extern atomic64_t endo_live_sandboxes;
extern atomic64_t endo_live_grains;
extern atomic64_t endo_live_meta_pages;
extern atomic64_t endo_live_kstack_pages;
extern atomic64_t endo_live_shared_pages;
extern u32 cpu_slot_offset;
extern struct workqueue_struct *cleanup_wq;
extern struct mutex registry_lock;
extern const struct service_table host_services;
extern const struct carrier_event_hooks carrier_hooks;
extern atomic_t evicting_sandboxes;

static inline struct carrier *carrier_of(struct carrier_event_hooks *hooks)
{
	return container_of(hooks, struct carrier, hooks);
}

static inline struct carrier *current_carrier(void)
{
	return current->carrier_hooks ? carrier_of(current->carrier_hooks) : NULL;
}

static inline bool in_image_text(struct sandbox *sandbox, unsigned long ip)
{
	return ip >= sandbox->text_lo && ip < sandbox->text_hi;
}

static inline bool in_stub_range(struct sandbox *sandbox, unsigned long ip)
{
	return ip >= sandbox->stub_lo && ip < sandbox->stub_hi;
}

static inline bool in_cpu_access_range(struct sandbox *sandbox, unsigned long ip)
{
	return ip >= sandbox->cpu_access_lo && ip < sandbox->cpu_access_hi;
}

static inline bool in_grant(struct sandbox *sandbox, u64 paddr, u64 len)
{
	u64 section;
	u32 block;
	u64 bitmap;
	u32 grain;

	if (len == 0 || paddr + len < paddr)
		return false;
	if (paddr >= READ_ONCE(sandbox->max_paddr))
		return false;
	if ((paddr >> 21) != ((paddr + len - 1) >> 21))
		return false;
	section = paddr / META_SECTION_BYTES;
	if (section >= sandbox->nr_phys_sections)
		return false;
	block = READ_ONCE(sandbox->meta_section_index[section]);
	if (block == NO_META_BLOCK || block >= sandbox->max_meta_sections)
		return false;
	bitmap = READ_ONCE(sandbox->meta_grain_bitmap[block]);
	grain = (paddr % META_SECTION_BYTES) / GRAIN_SIZE;
	return (bitmap & (1ULL << grain)) != 0;
}

// `switch.S`
// Each trampoline receives a 16-byte-aligned stack top.
// `enter_user_event` validates task tops; bootstrap allocation and the carrier's
// fixed `linux_sp` establish the same alignment for all other callers.
void enter_image(unsigned long entry, unsigned long new_rsp,
		     u64 arg0, u64 arg1);
void jump_linux_stack(void *linux_sp, void (*fn)(void *), void *arg);
void jump_user_run(void *linux_sp, struct carrier *c);
u64 call_on_linux_stack(void *linux_sp, u64 (*fn)(void *), void *arg);
void return_to_user(struct pt_regs *regs, bool from_syscall);
void exit_stub(void);

// `main.c`
struct file *lifeline_create(struct carrier *c);
void sandbox_get(struct sandbox *sandbox);
void sandbox_put(struct sandbox *sandbox);
void sandbox_stop(struct sandbox *sandbox, u32 kind, u32 code, const char *msg);
bool sandbox_claim_cleanup_locked(struct sandbox *sandbox);
struct sandbox *exec_lookup(struct linux_binprm *bprm, unsigned int *vcpu);
int exec_claim(struct sandbox *sandbox, unsigned int vcpu);
void exec_unclaim(struct sandbox *sandbox, unsigned int vcpu);
int sandbox_start(struct sandbox *sandbox);

// `image.c`
int image_load(struct image_kind *kind, const void *buf, size_t len);
void image_free(struct image_kind *kind);
int image_start(struct sandbox *sandbox);
void image_stop(struct sandbox *sandbox);

// `grant.c`
int grant_init(struct sandbox *sandbox, const u8 __user *uinitrd, size_t initrd_len);
void grant_destroy(struct sandbox *sandbox);
s64 do_grains_request(struct sandbox *sandbox, u32 count, u32 contiguous);
u64 kstack_alloc(struct sandbox *sandbox, bool is_boot);
s64 kstack_free(struct sandbox *sandbox, u64 vaddr);
bool stack_pool_contains(struct sandbox *sandbox, unsigned long addr);
bool stack_pool_slot_bounds(struct sandbox *sandbox, unsigned long addr,
			    unsigned long *usable_out, unsigned long *top_out);
bool stack_pool_is_guard_addr(struct sandbox *sandbox, unsigned long addr);
void stack_pool_destroy(struct sandbox *sandbox);

// `space.c`
void spaces_init(struct sandbox *sandbox);
void spaces_destroy(struct sandbox *sandbox);
s64 do_pt_root_register(struct carrier *c, u64 root_paddr);
s64 do_pt_root_unregister(struct carrier *c, u64 root_paddr);
s64 do_pt_activate(struct carrier *c, u64 root_paddr);
s64 do_tlb_shootdown(struct carrier *c, u64 root_paddr, u64 start, u64 len);
struct mmio_result do_buffer(struct carrier *c, u32 op, u64 token,
				     u64 arg0, u64 arg1, u64 arg2);
void leave_space(struct carrier *c);

// `carrier.c`
struct carrier *carrier_new(struct sandbox *sandbox, unsigned int vcpu,
				    struct mm_struct *own_mm);
struct carrier *carrier_get(struct carrier *c);
void carrier_put(struct carrier *c);
int carrier_attach(struct carrier *c);
void carrier_lifeline_closed(struct carrier *c);
void carrier_die(struct carrier *c) __noreturn;
void evict_leave(void) __noreturn;
void kill_carriers(struct sandbox *sandbox);
void virq_raise(struct carrier *c, u32 bit);
void kick_remote(struct carrier *c);
void carrier_sched_attach(struct carrier *c);
void carrier_sched_detach(struct carrier *c);
int carrier_sched_init(void);
void carrier_sched_exit(void);
void cpu_slot_set_current(struct carrier *c);
void cpu_slot_clear_current(void);
void __noreturn do_user_run_on_linux(struct carrier *c);

// `watch.c`
int watch_init(void);
void watch_exit(void);
void watch_arm(struct carrier *c);
void watch_fire_now(void);
void watch_fire_soon(void);
int evict_init(void);
void evict_exit(void);
void evict_arm(struct sandbox *sandbox);
void watch_sample_profile(struct carrier *c, struct pt_regs *regs);

#endif /* ENDOVISOR_INTERNAL_H */
