// SPDX-License-Identifier: MPL-2.0

//! Robust futex list support.

use ostd::mm::{FallibleVmRead, Infallible, VmSpace, VmWriter};

use crate::{
    error::{Errno, Error, Result},
    futex,
};

const ROBUST_LIST_LIMIT: isize = 2048;
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3FFF_FFFF;

#[derive(Clone, Copy, Debug)]
struct RobustList {
    next: usize,
}

/// Head of Linux's per-thread robust futex list.
#[derive(Clone, Copy, Debug)]
pub struct RobustListHead {
    list: RobustList,
    futex_offset: isize,
    list_op_pending: usize,
}

impl RobustListHead {
    /// Byte size of `struct robust_list_head` on this target.
    pub const BYTE_LEN: usize = size_of::<usize>() + size_of::<isize>() + size_of::<usize>();

    /// Reads a robust-list head from user memory.
    pub fn read_from_user(vm_space: &VmSpace, addr: usize) -> Result<Self> {
        let list = RobustList {
            next: read_usize(vm_space, addr)?,
        };
        let futex_offset = read_isize(vm_space, addr + size_of::<usize>())?;
        let list_op_pending = read_usize(vm_space, addr + size_of::<usize>() + size_of::<isize>())?;

        Ok(Self {
            list,
            futex_offset,
            list_op_pending,
        })
    }

    /// Returns an iterator for all futexes in the robust list.
    ///
    /// The futex referred to by `list_op_pending`, if any, is returned last.
    pub fn futexes<'a>(&'a self, vm_space: &'a VmSpace) -> FutexIter<'a> {
        FutexIter::new(vm_space, self)
    }

    fn pending_futex_addr(&self) -> Option<usize> {
        if self.list_op_pending == 0 {
            None
        } else {
            self.futex_addr(self.list_op_pending)
        }
    }

    fn futex_addr(&self, entry_ptr: usize) -> Option<usize> {
        self.futex_offset
            .checked_add(entry_ptr as isize)
            .map(|result| result as usize)
    }
}

/// Iterator over user-space robust futex addresses.
pub struct FutexIter<'a> {
    vm_space: &'a VmSpace,
    robust_list: &'a RobustListHead,
    entry_ptr: usize,
    count: isize,
}

impl<'a> FutexIter<'a> {
    fn new(vm_space: &'a VmSpace, robust_list: &'a RobustListHead) -> Self {
        Self {
            vm_space,
            robust_list,
            entry_ptr: robust_list.list.next,
            count: 0,
        }
    }

    fn set_end(&mut self) {
        self.count = -1;
    }

    fn is_end(&self) -> bool {
        self.count < 0
    }
}

impl Iterator for FutexIter<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_end() {
            return None;
        }

        let end_ptr = self.robust_list.list.next;
        while self.entry_ptr != end_ptr || self.count == 0 {
            if self.count == ROBUST_LIST_LIMIT {
                break;
            }
            if self.entry_ptr == 0 {
                return None;
            }

            let futex_addr = if self.entry_ptr != self.robust_list.list_op_pending {
                self.robust_list.futex_addr(self.entry_ptr)
            } else {
                None
            };
            let Ok(robust_list) = read_robust_list(self.vm_space, self.entry_ptr) else {
                return None;
            };

            self.entry_ptr = robust_list.next;
            self.count += 1;
            if futex_addr.is_some() {
                return futex_addr;
            }
        }

        self.set_end();
        self.robust_list.pending_futex_addr()
    }
}

/// Wakes robust futex waiters owned by an exiting task.
pub fn wake_robust_list(vm_space: &VmSpace, robust_list: Option<RobustListHead>, tid: u32) {
    let Some(list_head) = robust_list else {
        return;
    };

    for futex_addr in list_head.futexes(vm_space) {
        if let Err(error) = wake_robust_futex(vm_space, futex_addr, tid) {
            ostd::early_println!(
                "[kernel] exit: cannot wake robust futex at 0x{:x}: {:?}",
                futex_addr,
                error
            );
            return;
        }
    }
}

/// Marks a robust futex owner-dead and wakes one waiter when required.
pub fn wake_robust_futex(vm_space: &VmSpace, futex_addr: usize, tid: u32) -> Result<()> {
    if !futex_addr.is_multiple_of(align_of::<u32>()) {
        return Err(Error::new(Errno::EINVAL));
    }

    let (reader, writer) = vm_space.reader_writer(futex_addr, size_of::<u32>())?;
    let mut old_val: u32 = reader.atomic_load()?;
    loop {
        if old_val & FUTEX_TID_MASK != tid {
            break;
        }

        let new_val = (old_val & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
        match writer.atomic_compare_exchange(&reader, old_val, new_val)? {
            (cur_val, false) => old_val = cur_val,
            (_, true) => {
                if new_val & FUTEX_WAITERS != 0 {
                    futex::futex_wake(futex_addr, 1)?;
                }
                break;
            }
        }
    }

    Ok(())
}

fn read_robust_list(vm_space: &VmSpace, addr: usize) -> Result<RobustList> {
    Ok(RobustList {
        next: read_usize(vm_space, addr)?,
    })
}

fn read_usize(vm_space: &VmSpace, addr: usize) -> Result<usize> {
    let bytes = read_array::<{ size_of::<usize>() }>(vm_space, addr)?;
    Ok(usize::from_ne_bytes(bytes))
}

fn read_isize(vm_space: &VmSpace, addr: usize) -> Result<isize> {
    let bytes = read_array::<{ size_of::<isize>() }>(vm_space, addr)?;
    Ok(isize::from_ne_bytes(bytes))
}

fn read_array<const LEN: usize>(vm_space: &VmSpace, addr: usize) -> Result<[u8; LEN]> {
    let mut bytes = [0u8; LEN];
    let mut reader = vm_space.reader(addr, LEN)?;
    let mut writer = VmWriter::<Infallible>::from(bytes.as_mut_slice());
    let copied_len = reader
        .read_fallible(&mut writer)
        .map_err(|(error, _copied_len)| error)?;
    if copied_len != LEN {
        return Err(Error::new(Errno::EFAULT));
    }
    Ok(bytes)
}
