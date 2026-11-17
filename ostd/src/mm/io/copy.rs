// SPDX-License-Identifier: MPL-2.0

//! Generalized memory copy and fill operations for different memory types.
//!
//! This module provides [`Memcpy`] and [`Memset`] traits that generalize
//! the classic C `memcpy` and `memset` for typed memory categories
//! ([`Infallible`], [`Fallible`], [`Io`]).
//!
//! # Examples
//!
//! Infallible kernel-to-kernel copy:
//!
//! ```ignore
//! // SAFETY: Both pointers are valid kernel memory for `len` bytes.
//! unsafe { memcpy::<Infallible, Infallible>(dst, src, len) };
//! ```
//!
//! Fallible copy from user space into kernel space:
//!
//! ```ignore
//! // SAFETY: `dst` is valid kernel memory; `src` is in user space.
//! let copied = unsafe { memcpy::<Infallible, Fallible>(dst, src, len) };
//! if copied < len {
//!     // A page fault occurred after `copied` bytes.
//! }
//! ```
//!
//! Fallible zero-fill of user memory:
//!
//! ```ignore
//! // SAFETY: `dst` is in user space for `len` bytes.
//! let filled = unsafe { memset::<Fallible>(dst, 0u8, len) };
//! if filled < len {
//!     // A page fault occurred after `filled` bytes.
//! }
//! ```
//!
//! Kernel buffer to MMIO data-region copy (for example, framebuffer upload):
//!
//! ```ignore
//! // SAFETY: `src_kbuf` points to valid kernel bytes,
//! // and `dst_io` points to a valid MMIO data region for `len` bytes.
//! unsafe { memcpy::<Io, Infallible>(dst_io, src_kbuf, len) };
//! ```

#[cfg(feature = "kernelet")]
use core::sync::atomic::{AtomicU32, Ordering};

use super::{Fallible, Infallible, Io};
use crate::arch::io::io_mem::{
    copy_from_mmio, copy_from_mmio_fallible, copy_to_mmio, copy_to_mmio_fallible, memset_mmio,
};
#[cfg(not(feature = "kernelet"))]
use crate::arch::mm::{__memcpy_fallible, __memset_fallible};
#[cfg(feature = "kernelet")]
use crate::{
    arch::{cpu::context::PageFaultErrorCode, mm::PageTableEntry},
    mm::{
        MAX_USERSPACE_VADDR, Paddr, PageFlags, PagingConstsTrait, Vaddr,
        fault::publish_image_copy_fault,
        kspace::KERNEL_BASE_VADDR,
        paddr_to_vaddr, page_size,
        page_table::{PageTable, PteScalar, PteTrait, load_pte, pte_index},
        vm_space::{UserPtConfig, VmSpace},
    },
    task::disable_preempt,
};

#[cfg(feature = "kernelet")]
#[inline]
unsafe fn copy_opaque(dst: *mut u8, src: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: Caller ensures `dst` is valid for writes and `src` is valid for reads
    // of `len` bytes, and the direction flag is clear per the x86-64 SysV ABI.
    unsafe {
        core::arch::asm!(
            "rep movsb",
            inout("rdi") dst => _,
            inout("rsi") src => _,
            inout("rcx") len => _,
            options(nostack, preserves_flags)
        );
    }
}

#[cfg(feature = "kernelet")]
#[inline]
unsafe fn fill_opaque(dst: *mut u8, value: u8, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: Caller ensures `dst` is valid for writes of `len` bytes,
    // and the direction flag is clear per the x86-64 SysV ABI.
    unsafe {
        core::arch::asm!(
            "rep stosb",
            inout("rdi") dst => _,
            inout("rcx") len => _,
            in("al") value,
            options(nostack, preserves_flags)
        );
    }
}

/// Walks the user page table locklessly under preemption disabled.
///
/// On success, returns the resolved byte physical address and the remaining bytes
/// contiguous within that page. On missing or insufficient permission, returns
/// `Err(present_bit_if_mapped)`.
#[cfg(feature = "kernelet")]
fn page_walk_user(
    pt: &PageTable<UserPtConfig>,
    va: Vaddr,
    write: bool,
) -> Result<(Paddr, usize), usize> {
    if va >= MAX_USERSPACE_VADDR {
        return Err(0);
    }

    let mut pt_addr = paddr_to_vaddr(pt.root_paddr());
    for cur_level in (1..=UserPtConfig::NR_LEVELS).rev() {
        let offset = pte_index::<UserPtConfig>(va, cur_level);
        // SAFETY: Caller holds `DisabledPreemptGuard` (RCU read-side critical section),
        // keeping `pt` and all reachable page table nodes alive; `offset < 512`.
        let cur_pte = unsafe {
            load_pte(
                (pt_addr as *mut PageTableEntry).add(offset),
                Ordering::Acquire,
            )
        };
        match cur_pte.to_repr(cur_level) {
            PteScalar::Absent => return Err(0),
            PteScalar::PageTable(next_pt_addr, _) => {
                pt_addr = paddr_to_vaddr(next_pt_addr);
            }
            PteScalar::Mapped(frame_paddr, prop) => {
                if !prop.flags.contains(PageFlags::R) {
                    return Err(0);
                }
                if write && !prop.flags.contains(PageFlags::W) {
                    return Err(PageFaultErrorCode::PRESENT.bits());
                }
                let page_sz = page_size::<UserPtConfig>(cur_level);
                let in_page_off = va & (page_sz - 1);
                return Ok((frame_paddr + in_page_off, page_sz - in_page_off));
            }
        }
    }
    Err(0)
}

#[cfg(feature = "kernelet")]
fn copy_user_rcu(dst: *mut u8, src: *const u8, len: usize) -> usize {
    if len == 0 {
        return 0;
    }

    let dst_addr = dst as usize;
    let src_addr = src as usize;
    if dst_addr >= MAX_USERSPACE_VADDR && src_addr >= MAX_USERSPACE_VADDR {
        if dst_addr >= KERNEL_BASE_VADDR && src_addr >= KERNEL_BASE_VADDR {
            // SAFETY: Both pointers are valid kernel memory for `len` bytes.
            unsafe { copy_opaque(dst, src, len) };
            return len;
        }
        return 0;
    }

    let _preempt_guard = disable_preempt();
    let pt = VmSpace::current_activated_page_table(&_preempt_guard);
    let mut copied = 0;

    while copied < len {
        let rem = len - copied;
        let cur_dst = dst.wrapping_add(copied);
        let cur_src = src.wrapping_add(copied);
        let cur_dst_va = cur_dst as usize;
        let cur_src_va = cur_src as usize;

        let (dst_kptr, dst_avail) = if cur_dst_va < MAX_USERSPACE_VADDR {
            let Some(pt) = pt else {
                publish_image_copy_fault(cur_dst_va, true, 0);
                return copied;
            };
            match page_walk_user(pt, cur_dst_va, true) {
                Ok((paddr, avail)) => (paddr_to_vaddr(paddr) as *mut u8, avail),
                Err(present) => {
                    publish_image_copy_fault(cur_dst_va, true, present);
                    return copied;
                }
            }
        } else if cur_dst_va >= KERNEL_BASE_VADDR {
            (cur_dst, rem)
        } else {
            return copied;
        };

        let (src_kptr, src_avail) = if cur_src_va < MAX_USERSPACE_VADDR {
            let Some(pt) = pt else {
                publish_image_copy_fault(cur_src_va, false, 0);
                return copied;
            };
            match page_walk_user(pt, cur_src_va, false) {
                Ok((paddr, avail)) => (paddr_to_vaddr(paddr) as *const u8, avail),
                Err(present) => {
                    publish_image_copy_fault(cur_src_va, false, present);
                    return copied;
                }
            }
        } else if cur_src_va >= KERNEL_BASE_VADDR {
            (cur_src, rem)
        } else {
            return copied;
        };

        let chunk = rem.min(dst_avail).min(src_avail);
        // SAFETY: Both pointers are valid direct-map or kernel addresses for `chunk`
        // bytes, and any mapped user frames remain pinned through `_preempt_guard`.
        unsafe { copy_opaque(dst_kptr, src_kptr, chunk) };
        copied += chunk;
    }

    copied
}

#[cfg(feature = "kernelet")]
fn memset_user_rcu(dst: *mut u8, value: u8, len: usize) -> usize {
    if len == 0 {
        return 0;
    }

    let dst_addr = dst as usize;
    if dst_addr >= MAX_USERSPACE_VADDR {
        if dst_addr >= KERNEL_BASE_VADDR {
            // SAFETY: `dst` is valid kernel memory for `len` bytes.
            unsafe { fill_opaque(dst, value, len) };
            return len;
        }
        return 0;
    }

    let _preempt_guard = disable_preempt();
    let pt = VmSpace::current_activated_page_table(&_preempt_guard);
    let mut filled = 0;

    while filled < len {
        let rem = len - filled;
        let cur_dst = dst.wrapping_add(filled);
        let va = cur_dst as usize;
        if va >= MAX_USERSPACE_VADDR {
            return filled;
        }
        let Some(pt) = pt else {
            publish_image_copy_fault(va, true, 0);
            return filled;
        };
        let (paddr, avail) = match page_walk_user(pt, va, true) {
            Ok(res) => res,
            Err(present) => {
                publish_image_copy_fault(va, true, present);
                return filled;
            }
        };
        let chunk = rem.min(avail);
        // SAFETY: `paddr_to_vaddr(paddr)` is valid direct-map memory for `chunk`
        // bytes, and the frame remains pinned through `_preempt_guard`.
        unsafe { fill_opaque(paddr_to_vaddr(paddr) as *mut u8, value, chunk) };
        filled += chunk;
    }

    filled
}

#[cfg(feature = "kernelet")]
pub(super) fn atomic_load_user_rcu(ptr: *const u32) -> u64 {
    let va = ptr as usize;
    if !va.is_multiple_of(align_of::<u32>()) {
        if va < MAX_USERSPACE_VADDR {
            publish_image_copy_fault(va, false, 0);
        }
        return !0u64;
    }
    if va >= MAX_USERSPACE_VADDR {
        if va >= KERNEL_BASE_VADDR {
            // SAFETY: `ptr` is valid aligned kernel memory for `u32`.
            return unsafe { AtomicU32::from_ptr(ptr.cast_mut()).load(Ordering::Relaxed) } as u64;
        }
        return !0u64;
    }

    let _preempt_guard = disable_preempt();
    let Some(pt) = VmSpace::current_activated_page_table(&_preempt_guard) else {
        publish_image_copy_fault(va, false, 0);
        return !0u64;
    };
    match page_walk_user(pt, va, false) {
        Ok((paddr, avail)) if avail >= size_of::<u32>() => {
            let kptr = paddr_to_vaddr(paddr) as *mut u32;
            // SAFETY: `kptr` points to an aligned, mapped `u32` in the direct map,
            // pinned for the duration of `_preempt_guard`.
            unsafe { AtomicU32::from_ptr(kptr).load(Ordering::Relaxed) as u64 }
        }
        Ok(_) => {
            publish_image_copy_fault(va, false, 0);
            !0u64
        }
        Err(present) => {
            publish_image_copy_fault(va, false, present);
            !0u64
        }
    }
}

#[cfg(feature = "kernelet")]
pub(super) fn atomic_cmpxchg_user_rcu(ptr: *mut u32, old_val: u32, new_val: u32) -> u64 {
    let va = ptr as usize;
    if !va.is_multiple_of(align_of::<u32>()) {
        if va < MAX_USERSPACE_VADDR {
            publish_image_copy_fault(va, true, 0);
        }
        return !0u64;
    }
    if va >= MAX_USERSPACE_VADDR {
        if va >= KERNEL_BASE_VADDR {
            // SAFETY: `ptr` is valid aligned kernel memory for `u32`.
            let atomic = unsafe { AtomicU32::from_ptr(ptr) };
            return match atomic.compare_exchange(
                old_val,
                new_val,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(v) | Err(v) => v as u64,
            };
        }
        return !0u64;
    }

    let _preempt_guard = disable_preempt();
    let Some(pt) = VmSpace::current_activated_page_table(&_preempt_guard) else {
        publish_image_copy_fault(va, true, 0);
        return !0u64;
    };
    match page_walk_user(pt, va, true) {
        Ok((paddr, avail)) if avail >= size_of::<u32>() => {
            let kptr = paddr_to_vaddr(paddr) as *mut u32;
            // SAFETY: `kptr` points to an aligned, writable `u32` in the direct map,
            // pinned for the duration of `_preempt_guard`.
            let atomic = unsafe { AtomicU32::from_ptr(kptr) };
            match atomic.compare_exchange(old_val, new_val, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(v) | Err(v) => v as u64,
            }
        }
        Ok(_) => {
            publish_image_copy_fault(va, true, 0);
            !0u64
        }
        Err(present) => {
            publish_image_copy_fault(va, true, present);
            !0u64
        }
    }
}

/// Copies `len` bytes from `src` to `dst`.
///
/// This is a generalized `memcpy` that dispatches
/// to the appropriate implementation based on the memory types.
/// Infallible-to-infallible copies return `()`.
/// Copies involving fallible memory are fallible
/// and return the number of bytes successfully copied.
///
/// # Safety
///
/// - `src` must point to a virtual memory region of type `Src`
///   that allows memory reads.
/// - `dst` must point to a virtual memory region of type `Dst`
///   that allows memory writes.
pub(crate) unsafe fn memcpy<Dst: Memcpy<Src>, Src>(
    dst: *mut u8,
    src: *const u8,
    len: usize,
) -> Dst::Result {
    // SAFETY: The safety is upheld by the caller.
    unsafe { Dst::memcpy(dst, src, len) }
}

/// Fills `len` bytes of memory at `dst` with the specified `value`.
///
/// This is a generalized `memset` that dispatches
/// to the appropriate implementation based on the memory type.
/// Infallible memory fills return `()`.
/// Fallible memory fills return the number of bytes successfully set.
///
/// # Safety
///
/// - `dst` must point to a virtual memory region of type `Dst`
///   that allows memory writes.
pub(crate) unsafe fn memset<Dst: Memset>(dst: *mut u8, value: u8, len: usize) -> Dst::Result {
    // SAFETY: The safety is upheld by the caller.
    unsafe { Dst::memset(dst, value, len) }
}

/// Generalizes `memcpy` for different memory types.
///
/// The destination type is `Self` and the source type is `Src`,
/// following the `memcpy(dst, src, len)` argument convention.
///
/// When the source and destination virtual/physical memory regions overlap,
/// the copy may produce unexpected bytes in the destination.
/// The exact behavior is up to the implementation.
///
/// # Safety
///
/// Assuming the caller upholds the preconditions of [`Memcpy::memcpy`],
/// the memory copy implementation must not cause soundness problems.
/// The exact safety conditions depend on the type of the source and destination memory.
/// For example, when both sides are infallible memory,
/// the implementation must copy exactly `len` bytes from `src` to `dst`.
pub(crate) unsafe trait Memcpy<Src> {
    /// The result type of the copy operation.
    ///
    /// Infallible copies return `()`.
    /// Fallible copies return the number of bytes successfully copied
    /// as `usize`.
    type Result;

    /// Copies `len` bytes from `src` to `dst`.
    ///
    /// # Safety
    ///
    /// - `src` must point to a virtual memory region of type `Src`
    ///   that allows memory reads.
    /// - `dst` must point to a virtual memory region of type `Self`
    ///   that allows memory writes.
    unsafe fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> Self::Result;
}

/// Generalizes `memset` for different memory types.
///
/// # Safety
///
/// The implementation must correctly fill `len` bytes at `dst` with `value`
/// when the caller upholds the preconditions of [`Memset::memset`].
pub(crate) unsafe trait Memset {
    /// The result type of the fill operation.
    type Result;

    /// Fills `len` bytes of memory at `dst` with the specified `value`.
    ///
    /// # Safety
    ///
    /// - `dst` must point to a virtual memory region of type `Self`
    ///   that allows memory writes.
    unsafe fn memset(dst: *mut u8, value: u8, len: usize) -> Self::Result;
}

// SAFETY: Delegates to `volatile_copy_memory`,
// which correctly copies bytes between valid kernel memory regions.
unsafe impl Memcpy<Infallible> for Infallible {
    type Result = ();

    unsafe fn memcpy(dst: *mut u8, src: *const u8, len: usize) {
        // This method is implemented by calling `volatile_copy_memory`. Note that even with the
        // "volatile" keyword, data races are still considered undefined behavior (UB) in both the
        // Rust documentation and the C/C++ standards. In general, UB makes the behavior of the
        // entire program unpredictable, usually due to compiler optimizations that assume the
        // absence of UB. However, in this particular case, considering that the Linux kernel uses
        // the "volatile" keyword to implement `READ_ONCE` and `WRITE_ONCE`, the compiler is
        // extremely unlikely to break our code unless it also breaks the Linux kernel.
        //
        // For more details and future possibilities, see
        // <https://github.com/asterinas/asterinas/pull/1001#discussion_r1667317406>.

        // SAFETY: The safety is upheld by the caller.
        unsafe { core::intrinsics::volatile_copy_memory(dst, src, len) };
    }
}

// SAFETY: Delegates to `copy_user_rcu` under `kernelet` or `__memcpy_fallible`,
// which handle page faults when copying from fallible to infallible memory.
unsafe impl Memcpy<Fallible> for Infallible {
    type Result = usize;

    unsafe fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> usize {
        #[cfg(feature = "kernelet")]
        {
            copy_user_rcu(dst, src, len)
        }
        #[cfg(not(feature = "kernelet"))]
        {
            // SAFETY: The safety is upheld by the caller.
            let failed_bytes = unsafe { __memcpy_fallible(dst, src, len) };
            len - failed_bytes
        }
    }
}

// SAFETY: Delegates to `copy_from_mmio`, which correctly copies from MMIO
// to kernel memory using MMIO-safe load/store operations.
unsafe impl Memcpy<Io> for Infallible {
    type Result = ();

    unsafe fn memcpy(dst: *mut u8, src: *const u8, len: usize) {
        // SAFETY: The safety is upheld by the caller.
        unsafe { copy_from_mmio(dst, src, len) };
    }
}

// SAFETY: Delegates to `copy_user_rcu` under `kernelet` or `__memcpy_fallible`,
// which handle page faults when copying from infallible to fallible memory.
unsafe impl Memcpy<Infallible> for Fallible {
    type Result = usize;

    unsafe fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> usize {
        #[cfg(feature = "kernelet")]
        {
            copy_user_rcu(dst, src, len)
        }
        #[cfg(not(feature = "kernelet"))]
        {
            // SAFETY: The safety is upheld by the caller.
            let failed_bytes = unsafe { __memcpy_fallible(dst, src, len) };
            len - failed_bytes
        }
    }
}

// SAFETY: Delegates to `copy_user_rcu` under `kernelet` or `__memcpy_fallible`,
// which handle page faults when copying between fallible memory regions.
unsafe impl Memcpy<Fallible> for Fallible {
    type Result = usize;

    unsafe fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> usize {
        #[cfg(feature = "kernelet")]
        {
            copy_user_rcu(dst, src, len)
        }
        #[cfg(not(feature = "kernelet"))]
        {
            // SAFETY: The safety is upheld by the caller.
            let failed_bytes = unsafe { __memcpy_fallible(dst, src, len) };
            len - failed_bytes
        }
    }
}

// SAFETY: Delegates to `copy_from_mmio_fallible`,
// which preserves fallible semantics and handles CVM/non-CVM differences.
unsafe impl Memcpy<Io> for Fallible {
    type Result = usize;

    unsafe fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> usize {
        // SAFETY: The safety is upheld by the caller.
        unsafe { copy_from_mmio_fallible(dst, src, len) }
    }
}

// SAFETY: Delegates to `copy_to_mmio`, which copies from kernel memory
// to MMIO using MMIO-safe load/store operations.
unsafe impl Memcpy<Infallible> for Io {
    type Result = ();

    unsafe fn memcpy(dst: *mut u8, src: *const u8, len: usize) {
        // SAFETY: The safety is upheld by the caller.
        unsafe { copy_to_mmio(src, dst, len) };
    }
}

// SAFETY: Delegates to `copy_to_mmio_fallible`,
// which preserves fallible semantics and handles CVM/non-CVM differences.
unsafe impl Memcpy<Fallible> for Io {
    type Result = usize;

    unsafe fn memcpy(dst: *mut u8, src: *const u8, len: usize) -> usize {
        // SAFETY: The safety is upheld by the caller.
        unsafe { copy_to_mmio_fallible(src, dst, len) }
    }
}

// SAFETY: Delegates to `volatile_set_memory`,
// which correctly fills bytes in valid kernel memory.
unsafe impl Memset for Infallible {
    type Result = ();

    unsafe fn memset(dst: *mut u8, value: u8, len: usize) {
        // SAFETY: The safety is upheld by the caller.
        unsafe { core::intrinsics::volatile_set_memory(dst, value, len) };
    }
}

// SAFETY: Delegates to `memset_user_rcu` under `kernelet` or `__memset_fallible`,
// which handle page faults when filling fallible memory.
unsafe impl Memset for Fallible {
    type Result = usize;

    unsafe fn memset(dst: *mut u8, value: u8, len: usize) -> usize {
        #[cfg(feature = "kernelet")]
        {
            memset_user_rcu(dst, value, len)
        }
        #[cfg(not(feature = "kernelet"))]
        {
            // SAFETY: The safety is upheld by the caller.
            let failed_bytes = unsafe { __memset_fallible(dst, value, len) };
            len - failed_bytes
        }
    }
}

// SAFETY: Delegates to architecture MMIO fill entry,
// which uses MMIO-safe stores on CVM guests and optimized string ops otherwise.
unsafe impl Memset for Io {
    type Result = ();

    unsafe fn memset(dst: *mut u8, value: u8, len: usize) {
        // SAFETY: The safety is upheld by the caller.
        unsafe { memset_mmio(dst, value, len) };
    }
}
