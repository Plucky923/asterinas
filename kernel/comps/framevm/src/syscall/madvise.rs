// SPDX-License-Identifier: MPL-2.0

use core::ops::Range;

use ostd::mm::{MAX_USERSPACE_VADDR, VmSpace};

use super::{Errno, Error, PAGE_SIZE, Result, discard_range, is_range_fully_mapped};

/// Gives memory usage advice for a mapped range.
pub(super) fn sys_madvise(
    addr: usize,
    len: usize,
    behavior: i32,
    vm_space: &VmSpace,
) -> Result<isize> {
    let behavior = MadviseBehavior::try_from(behavior)?;
    let range = checked_madvise_range(addr, len)?;

    if range.is_empty() {
        return Ok(0);
    }

    if behavior == MadviseBehavior::MADV_DONTNEED {
        discard_range(vm_space, addr, len)?;
        return Ok(0);
    }

    if behavior.is_dummy_noop() {
        if !is_user_range_fully_mapped(vm_space, &range)? {
            return Err(Error::new(Errno::ENOMEM));
        }
        return Ok(0);
    }

    Err(Error::with_message(
        Errno::EINVAL,
        "the madvise behavior is not supported yet",
    ))
}

#[expect(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MadviseBehavior {
    MADV_NORMAL,
    MADV_RANDOM,
    MADV_SEQUENTIAL,
    MADV_WILLNEED,
    MADV_DONTNEED,
    MADV_FREE,
    MADV_REMOVE,
    MADV_DONTFORK,
    MADV_DOFORK,
    MADV_MERGEABLE,
    MADV_UNMERGEABLE,
    MADV_HUGEPAGE,
    MADV_NOHUGEPAGE,
    MADV_DONTDUMP,
    MADV_DODUMP,
    MADV_WIPEONFORK,
    MADV_KEEPONFORK,
    MADV_COLD,
    MADV_PAGEOUT,
    MADV_POPULATE_READ,
    MADV_POPULATE_WRITE,
    MADV_DONTNEED_LOCKED,
    MADV_HWPOISON,
    MADV_SOFT_OFFLINE,
}

impl TryFrom<i32> for MadviseBehavior {
    type Error = Error;

    fn try_from(value: i32) -> Result<Self> {
        match value {
            0 => Ok(Self::MADV_NORMAL),
            1 => Ok(Self::MADV_RANDOM),
            2 => Ok(Self::MADV_SEQUENTIAL),
            3 => Ok(Self::MADV_WILLNEED),
            4 => Ok(Self::MADV_DONTNEED),
            8 => Ok(Self::MADV_FREE),
            9 => Ok(Self::MADV_REMOVE),
            10 => Ok(Self::MADV_DONTFORK),
            11 => Ok(Self::MADV_DOFORK),
            12 => Ok(Self::MADV_MERGEABLE),
            13 => Ok(Self::MADV_UNMERGEABLE),
            14 => Ok(Self::MADV_HUGEPAGE),
            15 => Ok(Self::MADV_NOHUGEPAGE),
            16 => Ok(Self::MADV_DONTDUMP),
            17 => Ok(Self::MADV_DODUMP),
            18 => Ok(Self::MADV_WIPEONFORK),
            19 => Ok(Self::MADV_KEEPONFORK),
            20 => Ok(Self::MADV_COLD),
            21 => Ok(Self::MADV_PAGEOUT),
            22 => Ok(Self::MADV_POPULATE_READ),
            23 => Ok(Self::MADV_POPULATE_WRITE),
            24 => Ok(Self::MADV_DONTNEED_LOCKED),
            100 => Ok(Self::MADV_HWPOISON),
            101 => Ok(Self::MADV_SOFT_OFFLINE),
            _ => Err(Error::new(Errno::EINVAL)),
        }
    }
}

impl MadviseBehavior {
    fn is_dummy_noop(self) -> bool {
        matches!(
            self,
            Self::MADV_NORMAL
                | Self::MADV_RANDOM
                | Self::MADV_SEQUENTIAL
                | Self::MADV_WILLNEED
                | Self::MADV_FREE
                | Self::MADV_MERGEABLE
                | Self::MADV_UNMERGEABLE
                | Self::MADV_HUGEPAGE
                | Self::MADV_NOHUGEPAGE
        )
    }
}

fn checked_madvise_range(addr: usize, len: usize) -> Result<Range<usize>> {
    if !addr.is_multiple_of(PAGE_SIZE) {
        return Err(Error::new(Errno::EINVAL));
    }
    if len == 0 {
        return Ok(addr..addr);
    }

    let end = addr.checked_add(len).ok_or(Error::new(Errno::EINVAL))?;
    let end = align_up_checked(end, PAGE_SIZE)?;
    if end > max_user_page_addr() {
        return Err(Error::new(Errno::EINVAL));
    }
    Ok(addr..end)
}

fn is_user_range_fully_mapped(vm_space: &VmSpace, range: &Range<usize>) -> Result<bool> {
    is_range_fully_mapped(vm_space, range)
}

fn max_user_page_addr() -> usize {
    MAX_USERSPACE_VADDR / PAGE_SIZE * PAGE_SIZE
}

fn align_up_checked(value: usize, align: usize) -> Result<usize> {
    value
        .checked_add(align - 1)
        .map(|value| value / align * align)
        .ok_or(Error::new(Errno::EINVAL))
}
