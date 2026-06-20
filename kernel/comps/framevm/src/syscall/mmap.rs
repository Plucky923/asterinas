// SPDX-License-Identifier: MPL-2.0

use alloc::vec;

use ostd::mm::{PageFlags, VmSpace};

use super::{
    Errno, Error, ExistingMapping, PAGE_SIZE, Result, current_fd_file, map_anonymous,
    protect_range, unmap_range, write_to_user,
};
use crate::fd_table::FileLike;

/// Maps memory into the current address space.
pub(super) fn sys_mmap(
    addr: usize,
    len: usize,
    prot: usize,
    flags: usize,
    fd: isize,
    offset: usize,
    vm_space: &VmSpace,
) -> Result<isize> {
    const MAP_TYPE_MASK: usize = 0x0f;
    const MAP_SHARED: usize = 0x01;
    const MAP_PRIVATE: usize = 0x02;
    const MAP_SHARED_VALIDATE: usize = 0x03;
    const MAP_FIXED: usize = 0x10;
    const MAP_ANONYMOUS: usize = 0x20;
    const MAP_FIXED_NOREPLACE: usize = 0x100000;

    if len == 0 {
        return Err(Error::new(Errno::EINVAL));
    }
    let is_fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
    if is_fixed && !addr.is_multiple_of(PAGE_SIZE) {
        return Err(Error::new(Errno::EINVAL));
    }
    if !offset.is_multiple_of(PAGE_SIZE) {
        return Err(Error::new(Errno::EINVAL));
    }
    match flags & MAP_TYPE_MASK {
        MAP_PRIVATE => {}
        MAP_SHARED | MAP_SHARED_VALIDATE => return Err(Error::new(Errno::EOPNOTSUPP)),
        _ => return Err(Error::new(Errno::EINVAL)),
    }
    let page_flags = page_flags_from_mmap_prot(prot);

    let map_addr = if is_fixed { addr } else { 0 };
    let existing_mapping = if flags & MAP_FIXED_NOREPLACE != 0 {
        ExistingMapping::ErrorIfExists
    } else if flags & MAP_FIXED != 0 {
        ExistingMapping::Replace
    } else {
        ExistingMapping::Skip
    };

    if flags & MAP_ANONYMOUS == 0 {
        let fd = i32::try_from(fd).map_err(|_| Error::new(Errno::EBADF))?;
        let file = current_fd_file(fd)?.ok_or(Error::new(Errno::EBADF))?;
        return map_private_file(
            vm_space,
            file.as_ref(),
            map_addr,
            len,
            offset,
            page_flags,
            existing_mapping,
        )
        .map(|addr| addr as isize);
    }

    Ok(map_anonymous(vm_space, map_addr, len, page_flags, existing_mapping)? as isize)
}

fn map_private_file(
    vm_space: &VmSpace,
    file: &dyn FileLike,
    addr: usize,
    len: usize,
    offset: usize,
    page_flags: PageFlags,
    existing_mapping: ExistingMapping,
) -> Result<usize> {
    let map_len = len
        .checked_add(PAGE_SIZE - 1)
        .map(|len| len / PAGE_SIZE * PAGE_SIZE)
        .ok_or(Error::new(Errno::ENOMEM))?;
    if offset
        .checked_add(map_len)
        .is_none_or(|end| end >= isize::MAX as usize)
    {
        return Err(Error::new(Errno::EOVERFLOW));
    }

    let map_addr = map_anonymous(
        vm_space,
        addr,
        len,
        PageFlags::R | PageFlags::W,
        existing_mapping,
    )?;

    let result = fill_private_mapping(vm_space, file, map_addr, len, offset)
        .and_then(|_| protect_range(vm_space, map_addr, len, page_flags));
    if let Err(error) = result {
        let _ = unmap_range(vm_space, map_addr, len);
        return Err(error);
    }

    Ok(map_addr)
}

fn fill_private_mapping(
    vm_space: &VmSpace,
    file: &dyn FileLike,
    map_addr: usize,
    len: usize,
    offset: usize,
) -> Result<()> {
    const COPY_CHUNK_SIZE: usize = PAGE_SIZE;

    let mut copied = 0usize;
    let mut buffer = vec![0; COPY_CHUNK_SIZE.min(len)];
    while copied < len {
        let read_len = buffer.len().min(len - copied);
        let file_offset = offset
            .checked_add(copied)
            .ok_or(Error::new(Errno::EINVAL))?;
        let bytes_read = file.read_at(file_offset, &mut buffer[..read_len])?;
        if bytes_read == 0 {
            return Ok(());
        }

        write_to_user(vm_space, map_addr + copied, &buffer[..bytes_read])?;
        copied += bytes_read;
    }

    Ok(())
}

pub(super) fn page_flags_from_prot(prot: usize) -> Result<PageFlags> {
    const PROT_READ: usize = 0x1;
    const PROT_WRITE: usize = 0x2;
    const PROT_EXEC: usize = 0x4;
    const SUPPORTED_PROT: usize = PROT_READ | PROT_WRITE | PROT_EXEC;

    if prot & !SUPPORTED_PROT != 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    Ok(page_flags_from_mmap_prot(prot))
}

fn page_flags_from_mmap_prot(prot: usize) -> PageFlags {
    const PROT_READ: usize = 0x1;
    const PROT_WRITE: usize = 0x2;
    const PROT_EXEC: usize = 0x4;

    let mut page_flags = PageFlags::empty();
    if prot & PROT_READ != 0 {
        page_flags |= PageFlags::R;
    }
    if prot & PROT_WRITE != 0 {
        page_flags |= PageFlags::R | PageFlags::W;
    }
    if prot & PROT_EXEC != 0 {
        page_flags |= PageFlags::X;
    }
    page_flags
}
