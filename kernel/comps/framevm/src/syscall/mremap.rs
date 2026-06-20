// SPDX-License-Identifier: MPL-2.0

//! `mremap` syscall support for anonymous user mappings.

use ostd::mm::VmSpace;

use super::{
    Errno, Error, ExistingMapping, PAGE_SIZE, Result, is_range_fully_mapped, map_anonymous,
    page_flags_at, unmap_range,
};

/// Resizes an existing mapping.
pub(super) fn sys_mremap(
    old_addr: usize,
    old_size: usize,
    new_size: usize,
    flags: i32,
    new_addr: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    let flags = MremapFlags::from_bits(flags).ok_or(Error::new(Errno::EINVAL))?;
    if !old_addr.is_multiple_of(PAGE_SIZE) || old_size == 0 || new_size == 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    let old_size = align_up_checked(old_size)?;
    let new_size = align_up_checked(new_size)?;
    let old_end = old_addr
        .checked_add(old_size)
        .ok_or(Error::new(Errno::ENOMEM))?;
    if !is_range_fully_mapped(vm_space, &(old_addr..old_end))? {
        return Err(Error::new(Errno::ENOMEM));
    }

    if flags.contains(MremapFlags::MREMAP_FIXED) {
        if !flags.contains(MremapFlags::MREMAP_MAYMOVE) || !new_addr.is_multiple_of(PAGE_SIZE) {
            return Err(Error::new(Errno::EINVAL));
        }
        return Err(Error::new(Errno::EOPNOTSUPP));
    }

    if new_size == old_size {
        return Ok(old_addr as isize);
    }
    if new_size < old_size {
        unmap_range(vm_space, old_addr + new_size, old_size - new_size)?;
        return Ok(old_addr as isize);
    }

    if flags.contains(MremapFlags::MREMAP_MAYMOVE) {
        return Err(Error::new(Errno::EOPNOTSUPP));
    }

    let old_tail_page = old_end
        .checked_sub(PAGE_SIZE)
        .ok_or(Error::new(Errno::EINVAL))?;
    let page_flags = page_flags_at(vm_space, old_tail_page)?;
    map_anonymous(
        vm_space,
        old_end,
        new_size - old_size,
        page_flags,
        ExistingMapping::ErrorIfExists,
    )
    .map_err(|error| match error.errno() {
        Errno::EEXIST => Error::new(Errno::ENOMEM),
        _ => error,
    })?;
    Ok(old_addr as isize)
}

fn align_up_checked(size: usize) -> Result<usize> {
    size.checked_add(PAGE_SIZE - 1)
        .map(|size| size / PAGE_SIZE * PAGE_SIZE)
        .ok_or(Error::new(Errno::ENOMEM))
}

bitflags::bitflags! {
    struct MremapFlags: i32 {
        const MREMAP_MAYMOVE = 1 << 0;
        const MREMAP_FIXED = 1 << 1;
    }
}
