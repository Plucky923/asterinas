// SPDX-License-Identifier: MPL-2.0

//! Virtual memory space management.
//!
//! The [`VmSpace`] struct is provided to manage the virtual memory space of a
//! user. Cursors are used to traverse and modify over the virtual memory space
//! concurrently. The VM space cursor [`self::Cursor`] is just a wrapper over
//! the page table cursor, providing efficient, powerful concurrent accesses
//! to the page table.

use core::{ops::Range, sync::atomic::Ordering};

use super::{AnyUFrameMeta, PagingLevel, page_table::PageTableConfig};
#[cfg(not(feature = "kernelet"))]
use crate::arch::mm::current_page_table_paddr;
#[cfg(not(feature = "kernelet"))]
use crate::mm::kspace::KERNEL_PAGE_TABLE;
use crate::{
    Error,
    arch::mm::{PageTableEntry, PagingConsts},
    cpu::{AtomicCpuSet, CpuSet, PinCurrentCpu},
    cpu_local_cell,
    io::IoMem,
    mm::{
        Frame, HasPaddrRange, PAGE_SIZE, PageProperty, PrivilegedPageFlags, UFrame, VmReader,
        VmWriter,
        frame::FrameRef,
        io::Fallible,
        page_prop::{CachePolicy, PageFlags},
        page_table::{self, PageTable, PageTableFrag},
        tlb::{TlbFlushOp, TlbFlusher},
    },
    prelude::*,
    sync::{RcuDrop, SpinLock},
    task::{DisabledPreemptGuard, atomic_mode::AsAtomicModeGuard, disable_preempt},
};

/// A virtual address space for user-mode tasks, enabling safe manipulation of user-space memory.
///
/// The `VmSpace` type provides memory isolation guarantees between user-space and
/// kernel-space. For example, given an arbitrary user-space pointer, one can read and
/// write the memory location referred to by the user-space pointer without the risk of
/// breaking the memory safety of the kernel space.
///
/// # Task Association Semantics
///
/// As far as OSTD is concerned, a `VmSpace` is not necessarily associated with a task. Once a
/// `VmSpace` is activated (see [`VmSpace::activate`]), it remains activated until another
/// `VmSpace` is activated **possibly by another task running on the same CPU**.
///
/// This means that it's up to the kernel to ensure that a task's `VmSpace` is always activated
/// while the task is running. This can be done by using the injected post schedule handler
/// (see [`inject_post_schedule_handler`]) to always activate the correct `VmSpace` after each
/// context switch.
///
/// If the kernel otherwise decides not to ensure that the running task's `VmSpace` is always
/// activated, the kernel must deal with race conditions when calling methods that require the
/// `VmSpace` to be activated, e.g., user-mode execution, [`VmSpace::reader`],
/// [`VmSpace::writer`]. Otherwise, the behavior is unspecified, though it's guaranteed _not_ to
/// compromise the kernel's memory safety.
///
/// # Memory Backing
///
/// A newly-created `VmSpace` is not backed by any physical memory pages. To
/// provide memory pages for a `VmSpace`, one can allocate and map physical
/// memory ([`UFrame`]s) to the `VmSpace` using the cursor.
///
/// A `VmSpace` can also attach a page fault handler, which will be invoked to
/// handle page faults generated from user space.
///
/// [`inject_post_schedule_handler`]: crate::task::inject_post_schedule_handler
#[derive(Debug)]
pub struct VmSpace {
    #[cfg(feature = "kernelet")]
    resources: RcuDrop<VmResources>,
    #[cfg(not(feature = "kernelet"))]
    resources: VmResources,
    cpus: AtomicCpuSet,
}

// Page tables and I/O mappings remain owned until both RCU domains are clear.
#[derive(Debug)]
struct VmResources {
    pt: PageTable<UserPtConfig>,
    iomems: SpinLock<Vec<IoMem>>,
    #[cfg(feature = "kernelet")]
    linux_pgd_paddr: Paddr,
}

#[cfg(feature = "kernelet")]
impl Drop for VmResources {
    fn drop(&mut self) {
        // Kernelet RCU callbacks run in sleepable task context. The Host must
        // finish its readers before Rust releases the lower-level page tables.
        let result =
            (crate::kernelet::entry::services().pt_root_unregister)(self.linux_pgd_paddr as u64);
        assert_eq!(
            result, 0,
            "Host refused to unregister a user page-table root"
        );
    }
}

impl VmSpace {
    /// Creates a new VM address space.
    pub fn new() -> Self {
        #[cfg(feature = "kernelet")]
        {
            let boot = crate::kernelet::entry::boot_args();
            let pgd = (crate::kernelet::entry::services().pt_root_register)(0);
            if pgd <= 0 {
                crate::kernelet::entry::stop_panic(format_args!(
                    "Host refused to allocate a Linux user page-table root: {pgd}"
                ));
            }
            let linux_pgd_paddr = pgd as Paddr;
            let pt = PageTable::new_kernelet_user_page_table();
            if boot.pt_mode == 0 {
                pt.set_linux_pgd_paddr(linux_pgd_paddr);
            }
            Self {
                resources: RcuDrop::new(VmResources {
                    pt,
                    iomems: SpinLock::new(Vec::new()),
                    linux_pgd_paddr,
                }),
                cpus: AtomicCpuSet::new(CpuSet::new_empty()),
            }
        }
        #[cfg(not(feature = "kernelet"))]
        Self {
            resources: VmResources {
                pt: KERNEL_PAGE_TABLE.get().unwrap().create_user_page_table(),
                iomems: SpinLock::new(Vec::new()),
            },
            cpus: AtomicCpuSet::new(CpuSet::new_empty()),
        }
    }

    #[cfg(feature = "kernelet")]
    pub(crate) fn linux_pgd_paddr(&self) -> Paddr {
        self.resources.linux_pgd_paddr
    }

    #[cfg(feature = "kernelet")]
    pub(crate) fn current_activated_page_table<'a>(
        _guard: &'a DisabledPreemptGuard,
    ) -> Option<&'a PageTable<UserPtConfig>> {
        let ptr = ACTIVATED_VM_SPACE.load();
        if ptr.is_null() {
            return None;
        }
        // SAFETY: `ACTIVATED_VM_SPACE` owns an `Arc` reference to that `VmSpace`
        // until this CPU switches spaces or deactivates, which cannot happen
        // while `_guard` disables preemption.
        let vmspace = unsafe { &*ptr };
        Some(vmspace.page_table())
    }

    fn page_table(&self) -> &PageTable<UserPtConfig> {
        &self.resources.pt
    }

    /// Installs the kernel root and releases this CPU's active-space reference.
    pub fn deactivate() {
        let irq_guard = crate::irq::disable_local();
        #[cfg(not(feature = "kernelet"))]
        {
            KERNEL_PAGE_TABLE.get().unwrap().activate();
        }
        #[cfg(feature = "kernelet")]
        {
            let status = (crate::kernelet::entry::services().pt_activate)(0);
            assert_eq!(
                status, 0,
                "Host refused to deactivate a user page-table root"
            );
        }
        let last_ptr = ACTIVATED_VM_SPACE.load();
        ACTIVATED_VM_SPACE.store(core::ptr::null());
        if !last_ptr.is_null() {
            // SAFETY: The CPU cell owns exactly one reference from `into_raw`.
            let last = unsafe { Arc::from_raw(last_ptr) };
            last.cpus.remove(irq_guard.current_cpu(), Ordering::Relaxed);
        }
        #[cfg(feature = "kernelet")]
        if let Some(task) = crate::task::Task::current() {
            // Release the Task's cache only after the Host installed its kernel
            // root and this CPU released its active-space reference.
            drop(task.replace_active_vm_space(None, &irq_guard));
        }
    }

    fn record_activation(self: &Arc<Self>, cpu: crate::cpu::CpuId) {
        let last_ptr = ACTIVATED_VM_SPACE.load();
        if last_ptr == Arc::as_ptr(self) {
            return;
        }
        self.cpus.add(cpu, Ordering::Acquire);
        ACTIVATED_VM_SPACE.store(Arc::into_raw(self.clone()));
        if !last_ptr.is_null() {
            // SAFETY: Replacing the CPU cell transfers its unique raw reference.
            let last = unsafe { Arc::from_raw(last_ptr) };
            last.cpus.remove(cpu, Ordering::Relaxed);
        }
    }

    /// Gets an immutable cursor in the virtual address range.
    ///
    /// The cursor behaves like a lock guard, exclusively owning a sub-tree of
    /// the page table, preventing others from creating a cursor in it. So be
    /// sure to drop the cursor as soon as possible.
    ///
    /// The creation of the cursor may block if another cursor having an
    /// overlapping range is alive.
    pub fn cursor<'a, G: AsAtomicModeGuard>(
        &'a self,
        guard: &'a G,
        va: &Range<Vaddr>,
    ) -> Result<Cursor<'a>> {
        Ok(Cursor(self.page_table().cursor(guard, va)?))
    }

    /// Gets an mutable cursor in the virtual address range.
    ///
    /// The same as [`Self::cursor`], the cursor behaves like a lock guard,
    /// exclusively owning a sub-tree of the page table, preventing others
    /// from creating a cursor in it. So be sure to drop the cursor as soon as
    /// possible.
    ///
    /// The creation of the cursor may block if another cursor having an
    /// overlapping range is alive. The modification to the mapping by the
    /// cursor may also block or be overridden the mapping of another cursor.
    pub fn cursor_mut<'a, G: AsAtomicModeGuard>(
        &'a self,
        guard: &'a G,
        va: &Range<Vaddr>,
    ) -> Result<CursorMut<'a>> {
        Ok(CursorMut {
            pt_cursor: self.page_table().cursor_mut(guard, va)?,
            #[cfg(not(feature = "kernelet"))]
            flusher: TlbFlusher::new(&self.cpus, disable_preempt()),
            #[cfg(feature = "kernelet")]
            flusher: TlbFlusher::for_user_root(&self.cpus, disable_preempt(), self),
            vmspace: self,
        })
    }

    /// Activates the page table on the current CPU.
    pub fn activate(self: &Arc<Self>) {
        #[cfg(feature = "kernelet")]
        {
            let _irq_guard = crate::irq::disable_local();
            let preempt_guard = disable_preempt();
            let cpu = preempt_guard.current_cpu();

            if ACTIVATED_VM_SPACE.load() == Arc::as_ptr(self) {
                return;
            }

            let status =
                (crate::kernelet::entry::services().pt_activate)(self.linux_pgd_paddr() as u64);
            assert_eq!(status, 0, "Host refused to activate a user page-table root");
            self.record_activation(cpu);
            if let Some(task) = crate::task::Task::current() {
                drop(task.replace_active_vm_space(Some(self.clone()), &_irq_guard));
            }
            return;
        }

        #[cfg(not(feature = "kernelet"))]
        {
            let preempt_guard = disable_preempt();
            let cpu = preempt_guard.current_cpu();

            let last_ptr = ACTIVATED_VM_SPACE.load();
            if last_ptr == Arc::as_ptr(self) {
                return;
            }

            self.page_table().activate();
            self.record_activation(cpu);
        }
    }

    /// Creates a reader to read data from the user space of the current task.
    ///
    /// Returns `Err` if this `VmSpace` doesn't belong to the user space of the current task
    /// or the `vaddr` and `len` do not represent a user space memory range.
    ///
    /// Users must ensure that no other page table is activated in the current task during the
    /// lifetime of the created `VmReader`. This guarantees that the `VmReader` can operate correctly.
    pub fn reader(&self, vaddr: Vaddr, len: usize) -> Result<VmReader<'_, Fallible>> {
        #[cfg(feature = "kernelet")]
        let is_active = ACTIVATED_VM_SPACE.load() == core::ptr::from_ref(self);
        #[cfg(not(feature = "kernelet"))]
        let is_active = current_page_table_paddr() == self.page_table().root_paddr();
        if !is_active || !super::is_in_user_space(vaddr, len) {
            return Err(Error::AccessDenied);
        }

        // SAFETY: The memory range is in user space, as checked above.
        Ok(unsafe { VmReader::<Fallible>::from_user_space(vaddr as *const u8, len) })
    }

    /// Creates a writer to write data into the user space.
    ///
    /// Returns `Err` if this `VmSpace` doesn't belong to the user space of the current task
    /// or the `vaddr` and `len` do not represent a user space memory range.
    ///
    /// Users must ensure that no other page table is activated in the current task during the
    /// lifetime of the created `VmWriter`. This guarantees that the `VmWriter` can operate correctly.
    pub fn writer(&self, vaddr: Vaddr, len: usize) -> Result<VmWriter<'_, Fallible>> {
        #[cfg(feature = "kernelet")]
        let is_active = ACTIVATED_VM_SPACE.load() == core::ptr::from_ref(self);
        #[cfg(not(feature = "kernelet"))]
        let is_active = current_page_table_paddr() == self.page_table().root_paddr();
        if !is_active || !super::is_in_user_space(vaddr, len) {
            return Err(Error::AccessDenied);
        }

        // `VmWriter` is neither `Sync` nor `Send`, so it will not live longer than the current
        // task. This ensures that the correct page table is activated during the usage period of
        // the `VmWriter`.
        //
        // SAFETY: The memory range is in user space, as checked above.
        Ok(unsafe { VmWriter::<Fallible>::from_user_space(vaddr as *mut u8, len) })
    }

    /// Creates a reader/writer pair to read data from and write data into the user space.
    ///
    /// Returns `Err` if this `VmSpace` doesn't belong to the user space of the current task
    /// or the `vaddr` and `len` do not represent a user space memory range.
    ///
    /// Users must ensure that no other page table is activated in the current task during the
    /// lifetime of the created `VmReader` and `VmWriter`. This guarantees that the `VmReader`
    /// and the `VmWriter` can operate correctly.
    ///
    /// This method is semantically equivalent to calling [`Self::reader`] and [`Self::writer`]
    /// separately, but it avoids double checking the validity of the memory region.
    pub fn reader_writer(
        &self,
        vaddr: Vaddr,
        len: usize,
    ) -> Result<(VmReader<'_, Fallible>, VmWriter<'_, Fallible>)> {
        #[cfg(feature = "kernelet")]
        let is_active = ACTIVATED_VM_SPACE.load() == core::ptr::from_ref(self);
        #[cfg(not(feature = "kernelet"))]
        let is_active = current_page_table_paddr() == self.page_table().root_paddr();
        if !is_active || !super::is_in_user_space(vaddr, len) {
            return Err(Error::AccessDenied);
        }

        // SAFETY: The memory range is in user space, as checked above.
        let reader = unsafe { VmReader::<Fallible>::from_user_space(vaddr as *const u8, len) };

        // `VmWriter` is neither `Sync` nor `Send`, so it will not live longer than the current
        // task. This ensures that the correct page table is activated during the usage period of
        // the `VmWriter`.
        //
        // SAFETY: The memory range is in user space, as checked above.
        let writer = unsafe { VmWriter::<Fallible>::from_user_space(vaddr as *mut u8, len) };

        Ok((reader, writer))
    }
}

impl Default for VmSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl VmSpace {
    /// Finds the [`IoMem`] that contains the given physical address.
    ///
    /// It is a private method for internal use only. Please refer to
    /// [`CursorMut::find_iomem_by_paddr`] for more details.
    fn find_iomem_by_paddr(&self, paddr: Paddr) -> Option<(IoMem, usize)> {
        let iomems = self.resources.iomems.lock();
        for iomem in iomems.iter() {
            let start = iomem.paddr();
            let end = start + iomem.size();
            if paddr >= start && paddr < end {
                let offset = paddr - start;
                return Some((iomem.clone(), offset));
            }
        }
        None
    }
}

/// The cursor for querying over the VM space without modifying it.
///
/// It exclusively owns a sub-tree of the page table, preventing others from
/// reading or modifying the same sub-tree. Two read-only cursors can not be
/// created from the same virtual address range either.
pub struct Cursor<'a>(page_table::Cursor<'a, UserPtConfig>);

impl Cursor<'_> {
    /// Queries the mapping at the current virtual address.
    ///
    /// If the cursor is pointing to a valid virtual address that is locked,
    /// it will return the virtual address range and the mapped item.
    pub fn query(&mut self) -> Result<(Range<Vaddr>, Option<VmQueriedItem<'_>>)> {
        let (range, item) = self.0.query()?;
        Ok((range, item.map(VmQueriedItem::from)))
    }

    /// Moves the cursor forward to the next mapped virtual address.
    ///
    /// If there is mapped virtual address following the current address within
    /// next `len` bytes, it will return that mapped address. In this case,
    /// the cursor will stop at the mapped address.
    ///
    /// Otherwise, it will return `None`. And the cursor may stop at any
    /// address after `len` bytes.
    ///
    /// # Panics
    ///
    /// Panics if:
    ///  - the length is longer than the remaining range of the cursor;
    ///  - the length is not page-aligned.
    pub fn find_next(&mut self, len: usize) -> Option<Vaddr> {
        self.0.find_next(len)
    }

    /// Jumps to the virtual address.
    ///
    /// If the target address is out of the range, this method will return `Err`.
    ///
    /// # Panics
    ///
    /// This method panics if the address has bad alignment.
    pub fn jump(&mut self, va: Vaddr) -> Result<()> {
        self.0.jump(va)?;
        Ok(())
    }

    /// Gets the virtual address of the current slot.
    pub fn virt_addr(&self) -> Vaddr {
        self.0.virt_addr()
    }
}

/// The cursor for modifying the mappings in VM space.
///
/// It exclusively owns a sub-tree of the page table, preventing others from
/// reading or modifying the same sub-tree.
pub struct CursorMut<'a> {
    pt_cursor: page_table::CursorMut<'a, UserPtConfig>,
    // We have a read lock so the CPU set in the flusher is always a superset
    // of actual activated CPUs.
    flusher: TlbFlusher<'a, DisabledPreemptGuard>,
    // References to the `VmSpace`
    vmspace: &'a VmSpace,
}

impl<'a> CursorMut<'a> {
    /// Queries the mapping at the current virtual address.
    ///
    /// This is the same as [`Cursor::query`].
    ///
    /// If the cursor is pointing to a valid virtual address that is locked,
    /// it will return the virtual address range and the mapped item.
    pub fn query(&mut self) -> Result<(Range<Vaddr>, Option<VmQueriedItem<'_>>)> {
        let (range, item) = self.pt_cursor.query()?;
        Ok((range, item.map(VmQueriedItem::from)))
    }

    /// Moves the cursor forward to the next mapped virtual address.
    ///
    /// This is the same as [`Cursor::find_next`].
    pub fn find_next(&mut self, len: usize) -> Option<Vaddr> {
        self.pt_cursor.find_next(len)
    }

    /// Jumps to the virtual address.
    ///
    /// This is the same as [`Cursor::jump`].
    ///
    /// # Panics
    ///
    /// This method panics if the address has bad alignment.
    pub fn jump(&mut self, va: Vaddr) -> Result<()> {
        self.pt_cursor.jump(va)?;
        Ok(())
    }

    /// Gets the virtual address of the current slot.
    pub fn virt_addr(&self) -> Vaddr {
        self.pt_cursor.virt_addr()
    }

    /// Gets the dedicated TLB flusher for this cursor.
    pub fn flusher(&mut self) -> &mut TlbFlusher<'a, DisabledPreemptGuard> {
        &mut self.flusher
    }

    /// Maps a frame into the current slot.
    ///
    /// This method will bring the cursor to the next slot after the modification.
    ///
    /// # Panics
    ///
    /// Panics if:
    ///  - the current virtual address is already mapped;
    ///  - the current virtual address is outside the cursor's range.
    pub fn map(&mut self, frame: UFrame, prop: PageProperty) {
        #[cfg(feature = "kernelet")]
        let (va, paddr) = (self.virt_addr(), frame.paddr());
        let item = VmItem::new_tracked(frame, prop);

        // SAFETY: It is safe to map untyped memory into the userspace.
        unsafe { self.pt_cursor.map(item) };

        #[cfg(feature = "kernelet")]
        if crate::kernelet::entry::boot_args().pt_mode == 1 && prop.flags.contains(PageFlags::R) {
            let res = (crate::kernelet::entry::services().buffer)(
                crate::kernelet::abi::OP_VM_MAP,
                self.vmspace.linux_pgd_paddr() as u64,
                va as u64,
                paddr as u64,
                page_flags_to_klet_prot(prop.flags),
            );
            assert_eq!(res.status, 0, "Host refused OP_VM_MAP: {}", res.status);
        }
    }

    /// Maps a range of [`IoMem`] into the current slot.
    ///
    /// The memory region to be mapped is the [`IoMem`] range starting at
    /// `offset` and extending to `offset + len`, or to the end of [`IoMem`],
    /// whichever comes first. This method will bring the cursor to the next
    /// slot after the modification.
    ///
    /// # Limitations
    ///
    /// Once an instance of `IoMem` is mapped to a `VmSpace`,
    /// then the `IoMem` instance will only be dropped when the `VmSpace` is
    /// dropped, not when all the mappings backed by the `IoMem` are destroyed
    /// with the `unmap` method.
    ///
    /// # Panics
    ///
    /// Panics if
    ///  - `len`, `offset`, or the address range of the `IoMem` instance is
    ///    not aligned to the page size;
    ///  - the current virtual address is already mapped.
    pub fn map_iomem(&mut self, io_mem: IoMem, prop: PageProperty, len: usize, offset: usize) {
        assert_eq!(len % PAGE_SIZE, 0);
        assert_eq!(offset % PAGE_SIZE, 0);

        let io_mem_paddr = io_mem.paddr();
        let io_mem_size = io_mem.size();
        assert_eq!(io_mem_paddr % PAGE_SIZE, 0);
        assert_eq!(io_mem_size % PAGE_SIZE, 0);

        if offset >= io_mem_size {
            return;
        }

        let paddr_begin = io_mem_paddr + offset;
        let paddr_end = if io_mem_size - offset < len {
            io_mem_paddr + io_mem_size
        } else {
            io_mem_paddr + len + offset
        };

        #[cfg(feature = "kernelet")]
        assert!(
            !io_mem.is_virtual(),
            "virtual device IoMem cannot be mapped directly into a user VmSpace"
        );

        for current_paddr in (paddr_begin..paddr_end).step_by(PAGE_SIZE) {
            #[cfg(feature = "kernelet")]
            assert!(
                crate::kernelet::image_grant::has_meta(current_paddr),
                "kernelet VmSpace cannot map ungranted physical address {current_paddr:#x}"
            );
            #[cfg(feature = "kernelet")]
            let va = self.virt_addr();
            // SAFETY: It is safe to map I/O memory into the userspace.
            unsafe {
                self.pt_cursor
                    .map(VmItem::new_untracked_io(current_paddr, prop))
            };
            #[cfg(feature = "kernelet")]
            if crate::kernelet::entry::boot_args().pt_mode == 1 && prop.flags.contains(PageFlags::R)
            {
                let res = (crate::kernelet::entry::services().buffer)(
                    crate::kernelet::abi::OP_VM_MAP,
                    self.vmspace.linux_pgd_paddr() as u64,
                    va as u64,
                    current_paddr as u64,
                    page_flags_to_klet_prot(prop.flags),
                );
                assert_eq!(
                    res.status, 0,
                    "Host refused OP_VM_MAP (iomem): {}",
                    res.status
                );
            }
        }

        fn io_mem_contains(parent: &IoMem, child: &IoMem) -> bool {
            parent.paddr() <= child.paddr() && child.end_paddr() <= parent.end_paddr()
        }

        // If the `iomems` list in `VmSpace` does not contain the current I/O
        // memory, push it to maintain the correct reference count.
        let mut iomems = self.vmspace.resources.iomems.lock();
        if !iomems.iter().any(|iomem| io_mem_contains(iomem, &io_mem)) {
            iomems.retain(|iomem| !io_mem_contains(&io_mem, iomem));
            iomems.push(io_mem);
        }
    }

    /// Finds an [`IoMem`] that was previously mapped to by [`Self::map_iomem`] and contains the
    /// physical address.
    ///
    /// This method can recover the originally mapped `IoMem` from the physical address returned by
    /// [`Self::query`]. If the query returns a [`VmQueriedItem::MappedIoMem`], this method is
    /// guaranteed to succeed with the specific physical address. However, if the corresponding
    /// mapping is subsequently unmapped, it is unspecified whether this method will still succeed
    /// or not.
    ///
    /// On success, this method returns the `IoMem` and the offset from the `IoMem` start to the
    /// given physical address. Otherwise, this method returns `None`.
    pub fn find_iomem_by_paddr(&self, paddr: Paddr) -> Option<(IoMem, usize)> {
        self.vmspace.find_iomem_by_paddr(paddr)
    }

    /// Clears the mapping starting from the current slot,
    /// and returns the number of unmapped pages.
    ///
    /// This method will bring the cursor forward by at least `len` bytes
    /// in the virtual address space, but not past the end of the cursor's range.
    ///
    /// Already-absent mappings encountered by the cursor will be skipped. It
    /// is valid to unmap a range that is not mapped.
    ///
    /// It must issue and dispatch a TLB flush after the operation. Otherwise,
    /// the memory safety will be compromised. Please call this function less
    /// to avoid the overhead of TLB flush. Using a large `len` is wiser than
    /// splitting the operation into multiple small ones.
    ///
    /// # Panics
    ///
    /// Panics if:
    ///  - the length is longer than the remaining range of the cursor;
    ///  - the length is not page-aligned.
    pub fn unmap(&mut self, len: usize) -> usize {
        #[cfg(feature = "kernelet")]
        let start_va = self.virt_addr();
        let end_va = self.virt_addr() + len;
        let mut num_unmapped: usize = 0;
        #[cfg(feature = "kernelet")]
        let mut unmapped_any = false;
        loop {
            // SAFETY:
            // 1. It is safe to unmap memory in the userspace.
            // 2. We drop the unmapped items only after flushing TLB entries, which is safe.
            let Some(frag) = (unsafe { self.pt_cursor.take_next(end_va - self.virt_addr()) })
            else {
                break; // No more mappings in the range.
            };
            #[cfg(feature = "kernelet")]
            {
                unmapped_any = true;
            }

            match frag {
                PageTableFrag::Mapped { va, item, .. } => {
                    // SAFETY: If the item is not a scalar (e.g., a frame
                    // pointer), we will drop it after the RCU grace period
                    // (see `issue_tlb_flush_with`).
                    let (item, panic_guard) = unsafe { RcuDrop::into_inner(item) };

                    match item {
                        VmItem {
                            mapped_item: MappedItem::TrackedFrame(old_frame),
                            ..
                        } => {
                            num_unmapped += 1;

                            let rcu_frame = RcuDrop::new(old_frame);
                            panic_guard.forget();
                            let rcu_frame = Frame::rcu_from_unsized(rcu_frame);
                            self.flusher
                                .issue_tlb_flush_with(TlbFlushOp::for_single(va), rcu_frame);
                        }
                        VmItem {
                            mapped_item: MappedItem::UntrackedIoMem { .. },
                            ..
                        } => {
                            panic_guard.forget();

                            // Flush the TLB entry for the current address, but
                            // in the current design, we cannot drop the
                            // corresponding `IoMem`. This is because we manage
                            // the range of I/O as a whole, but the frames
                            // handled here might be one segment of it.
                            self.flusher.issue_tlb_flush(TlbFlushOp::for_single(va));
                        }
                    }
                }
                PageTableFrag::StrayPageTable {
                    pt,
                    va,
                    len,
                    num_frames,
                } => {
                    num_unmapped += num_frames;

                    self.flusher.issue_tlb_flush_with(
                        TlbFlushOp::for_range(va..va + len),
                        Frame::rcu_from_unsized(pt),
                    );
                }
            }
        }

        #[cfg(feature = "kernelet")]
        if crate::kernelet::entry::boot_args().pt_mode == 1 {
            if unmapped_any {
                let res = (crate::kernelet::entry::services().buffer)(
                    crate::kernelet::abi::OP_VM_UNMAP,
                    self.vmspace.linux_pgd_paddr() as u64,
                    start_va as u64,
                    len as u64,
                    0,
                );
                assert_eq!(res.status, 0, "Host refused OP_VM_UNMAP: {}", res.status);
            }
            // `zap_vma_ptes` already flushed the TLB; retire unmapped frames
            // after an RCU grace period without a redundant shootdown.
            self.flusher.retire_without_shootdown();
            return num_unmapped;
        }

        self.flusher.dispatch_tlb_flush();

        num_unmapped
    }

    /// Applies the operation to the next slot of mapping within the range.
    ///
    /// The range to be found in is the current virtual address with the
    /// provided length.
    ///
    /// The function stops and yields the actually protected range if it has
    /// actually protected a page, no matter if the following pages are also
    /// required to be protected.
    ///
    /// It also makes the cursor moves forward to the next page after the
    /// protected one. If no mapped pages exist in the following range, the
    /// cursor will stop at the end of the range and return [`None`].
    ///
    /// Note that it will **NOT** flush the TLB after the operation. Please
    /// make the decision yourself on when and how to flush the TLB using
    /// [`Self::flusher`].
    ///
    /// # Panics
    ///
    /// Panics if:
    ///  - the length is longer than the remaining range of the cursor;
    ///  - the length is not page-aligned.
    pub fn protect_next(
        &mut self,
        len: usize,
        mut op: impl FnMut(&mut PageFlags, &mut CachePolicy),
    ) -> Option<Range<Vaddr>> {
        #[cfg(feature = "kernelet")]
        if crate::kernelet::entry::boot_args().pt_mode == 1 {
            // SAFETY: It is safe to set `PageFlags` and `CachePolicy` of memory
            // in the userspace.
            let (va_range, paddr, old_prop, new_prop) = unsafe {
                self.pt_cursor.protect_next_tracked(len, &mut |prop| {
                    op(&mut prop.flags, &mut prop.cache);
                })
            }?;
            let old_r = old_prop.flags.contains(PageFlags::R);
            let new_r = new_prop.flags.contains(PageFlags::R);
            let old_prot = page_flags_to_klet_prot(old_prop.flags);
            let new_prot = page_flags_to_klet_prot(new_prop.flags);
            let root = self.vmspace.linux_pgd_paddr() as u64;
            let buf = crate::kernelet::entry::services().buffer;
            if old_r && !new_r {
                let res = buf(
                    crate::kernelet::abi::OP_VM_UNMAP,
                    root,
                    va_range.start as u64,
                    va_range.len() as u64,
                    0,
                );
                assert_eq!(res.status, 0, "Host refused OP_VM_UNMAP: {}", res.status);
            } else if !old_r && new_r {
                let res = buf(
                    crate::kernelet::abi::OP_VM_MAP,
                    root,
                    va_range.start as u64,
                    paddr as u64,
                    new_prot,
                );
                assert_eq!(res.status, 0, "Host refused OP_VM_MAP: {}", res.status);
            } else if new_r && old_prot != new_prot {
                let res = buf(
                    crate::kernelet::abi::OP_VM_PROTECT,
                    root,
                    va_range.start as u64,
                    new_prot,
                    0,
                );
                assert_eq!(res.status, 0, "Host refused OP_VM_PROTECT: {}", res.status);
            }
            return Some(va_range);
        }

        // SAFETY: It is safe to set `PageFlags` and `CachePolicy` of memory
        // in the userspace.
        unsafe {
            self.pt_cursor.protect_next(len, &mut |prop| {
                op(&mut prop.flags, &mut prop.cache);
            })
        }
    }
}

#[cfg(feature = "kernelet")]
fn page_flags_to_klet_prot(flags: PageFlags) -> u64 {
    use crate::kernelet::abi::{KLET_PROT_EXEC, KLET_PROT_READ, KLET_PROT_WRITE};
    let mut prot = 0u64;
    if flags.contains(PageFlags::R) {
        prot |= KLET_PROT_READ;
    }
    if flags.contains(PageFlags::W) {
        prot |= KLET_PROT_WRITE;
    }
    if flags.contains(PageFlags::X) {
        prot |= KLET_PROT_EXEC;
    }
    prot
}

cpu_local_cell! {
    /// The `Arc` pointer to the activated VM space on this CPU. If the pointer
    /// is NULL, it means that the activated page table is merely the kernel
    /// page table.
    // TODO: If we are enabling ASID, we need to maintain the TLB state of each
    // CPU, rather than merely the activated `VmSpace`. When ASID is enabled,
    // the non-active `VmSpace`s can still have their TLB entries in the CPU!
    static ACTIVATED_VM_SPACE: *const VmSpace = core::ptr::null();
}

#[cfg(ktest)]
pub(super) fn get_activated_vm_space() -> *const VmSpace {
    ACTIVATED_VM_SPACE.load()
}

#[cfg(all(ktest, not(feature = "kernelet")))]
mod native_activation_test {
    use super::{VmSpace, get_activated_vm_space};
    use crate::{arch::mm::current_page_table_paddr, prelude::*, task::disable_preempt};

    #[ktest]
    fn native_roots_release_cpu_references_after_switch_and_deactivate() {
        let first = Arc::new(VmSpace::new());
        let second = Arc::new(VmSpace::new());
        let first_table = first.page_table();
        let second_table = second.page_table();
        let _guard = disable_preempt();
        VmSpace::deactivate();
        let first_refs = first_table.root_reference_count();
        let second_refs = second_table.root_reference_count();
        for _ in 0..3 {
            first.activate();
            first.activate();
            assert_eq!(current_page_table_paddr(), first_table.root_paddr());
            assert_eq!(first_table.root_reference_count(), first_refs + 1);
            second.activate();
            assert_eq!(current_page_table_paddr(), second_table.root_paddr());
            assert_eq!(first_table.root_reference_count(), first_refs);
            assert_eq!(second_table.root_reference_count(), second_refs + 1);
            VmSpace::deactivate();
            VmSpace::deactivate();
            assert!(get_activated_vm_space().is_null());
            assert_eq!(first_table.root_reference_count(), first_refs);
            assert_eq!(second_table.root_reference_count(), second_refs);
            assert_eq!(Arc::strong_count(&first), 1);
            assert_eq!(Arc::strong_count(&second), 1);
        }
    }
}

/// The result of a query over the VM space.
pub enum VmQueriedItem<'a> {
    /// The current slot is mapped, the frame within is allocated from the
    /// physical memory.
    MappedRam {
        /// The mapped frame.
        frame: FrameRef<'a, dyn AnyUFrameMeta>,
        /// The property of the slot.
        prop: PageProperty,
    },
    /// The current slot is mapped, the frame within is allocated from the
    /// MMIO memory.
    MappedIoMem {
        /// The physical address of the corresponding I/O memory.
        paddr: Paddr,
        /// The property of the slot.
        prop: PageProperty,
    },
}

impl VmQueriedItem<'_> {
    /// Returns the page property of the mapped item.
    pub fn prop(&self) -> &PageProperty {
        match self {
            Self::MappedRam { prop, .. } => prop,
            Self::MappedIoMem { prop, .. } => prop,
        }
    }
}

/// Internal representation of a VM item.
///
/// This is kept private to ensure memory safety. The public interface
/// should use `VmQueriedItem` for querying mapping information.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct VmItem {
    prop: PageProperty,
    mapped_item: MappedItem,
}

/// A reference to a VM item.
#[derive(Debug)]
pub(crate) struct VmItemRef<'a> {
    prop: PageProperty,
    mapped_item: MappedItemRef<'a>,
}

#[derive(Clone, Debug, PartialEq)]
enum MappedItem {
    TrackedFrame(UFrame),
    UntrackedIoMem { paddr: Paddr, level: PagingLevel },
}

#[derive(Debug)]
enum MappedItemRef<'a> {
    TrackedFrame(FrameRef<'a, dyn AnyUFrameMeta>),
    UntrackedIoMem { paddr: Paddr, level: PagingLevel },
}

impl VmItem {
    /// Creates a new `VmItem` that maps a tracked frame.
    pub(super) fn new_tracked(frame: UFrame, prop: PageProperty) -> Self {
        Self {
            prop,
            mapped_item: MappedItem::TrackedFrame(frame),
        }
    }

    /// Creates a new `VmItem` that maps an untracked I/O memory.
    fn new_untracked_io(paddr: Paddr, prop: PageProperty) -> Self {
        Self {
            prop,
            mapped_item: MappedItem::UntrackedIoMem { paddr, level: 1 },
        }
    }
}

impl<'a> From<VmItemRef<'a>> for VmQueriedItem<'a> {
    fn from(item: VmItemRef<'a>) -> Self {
        match item.mapped_item {
            MappedItemRef::TrackedFrame(frame) => VmQueriedItem::MappedRam {
                frame,
                prop: item.prop,
            },
            MappedItemRef::UntrackedIoMem { paddr, level } => {
                debug_assert_eq!(level, 1);
                VmQueriedItem::MappedIoMem {
                    paddr,
                    prop: item.prop,
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct UserPtConfig {}

// SAFETY: `item_raw_info`, `item_into_raw`, `item_from_raw`, and
// `item_ref_from_raw` are correctly implemented with respect to the `Item` and
// `ItemRef` types.
unsafe impl PageTableConfig for UserPtConfig {
    const TOP_LEVEL_INDEX_RANGE: Range<usize> = 0..256;
    #[cfg(feature = "kernelet")]
    const CAN_PRUNE_SUBTREE: bool = false;

    type E = PageTableEntry;
    type C = PagingConsts;

    type Item = VmItem;
    type ItemRef<'a> = VmItemRef<'a>;

    fn item_raw_info(item: &Self::Item) -> (Paddr, PagingLevel, PageProperty) {
        match &item.mapped_item {
            MappedItem::TrackedFrame(frame) => {
                let mut prop = item.prop;
                prop.priv_flags -= PrivilegedPageFlags::AVAIL1; // Clear AVAIL1 for tracked frames
                let level = frame.map_level();
                let paddr = frame.paddr();
                (paddr, level, prop)
            }
            MappedItem::UntrackedIoMem { paddr, level } => {
                let mut prop = item.prop;
                prop.priv_flags |= PrivilegedPageFlags::AVAIL1; // Set AVAIL1 for I/O memory
                (*paddr, *level, prop)
            }
        }
    }

    unsafe fn item_from_raw(paddr: Paddr, level: PagingLevel, prop: PageProperty) -> Self::Item {
        debug_assert_eq!(level, 1);
        if prop.priv_flags.contains(PrivilegedPageFlags::AVAIL1) {
            // `AVAIL1` is set, this is I/O memory.
            VmItem::new_untracked_io(paddr, prop)
        } else {
            // `AVAIL1` is clear, this is tracked memory.
            // SAFETY: The caller ensures safety.
            let frame = unsafe { Frame::<dyn AnyUFrameMeta>::from_raw(paddr) };
            VmItem::new_tracked(frame, prop)
        }
    }

    unsafe fn item_ref_from_raw<'a>(
        paddr: Paddr,
        level: PagingLevel,
        prop: PageProperty,
    ) -> Self::ItemRef<'a> {
        debug_assert_eq!(level, 1);
        if prop.priv_flags.contains(PrivilegedPageFlags::AVAIL1) {
            // `AVAIL1` is set, this is I/O memory.
            VmItemRef {
                prop,
                mapped_item: MappedItemRef::UntrackedIoMem { paddr, level },
            }
        } else {
            // `AVAIL1` is clear, this is tracked memory.
            // SAFETY: The caller ensures that the frame outlives `'a` and that
            // the type matches the frame.
            let frame_ref = unsafe { FrameRef::<dyn AnyUFrameMeta>::borrow_paddr(paddr) };
            VmItemRef {
                prop,
                mapped_item: MappedItemRef::TrackedFrame(frame_ref),
            }
        }
    }
}
