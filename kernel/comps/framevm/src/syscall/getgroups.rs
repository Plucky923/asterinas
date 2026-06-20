// SPDX-License-Identifier: MPL-2.0

//! Returns supplementary group IDs.

use ostd::mm::VmSpace;

use super::{Errno, Error, Result, SyscallReturn, write_to_user};
use crate::{context::Context, process::Gid};

pub fn sys_getgroups(
    size: i32,
    group_list_addr: usize,
    ctx: &Context,
    vm_space: &VmSpace,
) -> Result<SyscallReturn> {
    if size < 0 {
        return Err(Error::new(Errno::EINVAL));
    }

    let credentials = ctx.posix_thread.credentials();
    let groups = credentials.groups();
    if size == 0 {
        return Ok(SyscallReturn::Return(groups.len() as isize));
    }
    if groups.len() > size as usize {
        return Err(Error::new(Errno::EINVAL));
    }

    for (idx, gid) in groups.iter().copied().enumerate() {
        let addr = group_list_addr
            .checked_add(idx * size_of::<u32>())
            .ok_or(Error::new(Errno::EFAULT))?;
        write_gid(vm_space, addr, gid)?;
    }

    Ok(SyscallReturn::Return(groups.len() as isize))
}

fn write_gid(vm_space: &VmSpace, addr: usize, gid: Gid) -> Result<()> {
    let raw_gid = <Gid as Into<u32>>::into(gid);
    write_to_user(vm_space, addr, &raw_gid.to_ne_bytes())
}
